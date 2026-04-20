# Network Diagram — Operation SHATTERED CROWN

```
                    [Attacker — Kali Linux]
                             │
                    [lab-net  DHCP]
                             │
     ┌───────────────────────┼───────────────────────────────────┐
     │                       │         cyberange.local           │
     │          Single Flat Network (lab-net)                    │
     │          All machines on same /24 segment                 │
     │          DC provides DNS for name resolution              │
     │                       │                                   │
     │  ┌────────────────────┴────────────────────────┐          │
     │  │                                             │          │
     │  │  M1: DC02                                   │          │
     │  │  Windows Server 2019                        │          │
     │  │  AD DS + DNS + WEF Collector                │          │
     │  │  Ports: 53, 88, 135, 389, 445, 636, 5985    │          │
     │  │  RBCD vuln: SRV07-SQL$ GenericWrite on DC02 │          │
     │  │                                             │          │
     │  └─────────────────────────────────────────────┘          │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │                                          │             │
     │  │  M2: SRV04-WEB                           │             │
     │  │  Windows Server 2019                     │             │
     │  │  IIS — Corporate Web Portal              │             │
     │  │  App Pool: CYBERANGE\svc_web             │             │
     │  │  Port 80 — Windows Authentication        │             │
     │  │  SPRAY TARGET                            │             │
     │  │                                          │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │                                          │             │
     │  │  M3: SRV05-API                           │             │
     │  │  Windows Server 2019                     │             │
     │  │  WinRM Backend                           │             │
     │  │  HTTP SPN on machine account             │             │
     │  │  Port 5985 — Kerberos Auth               │             │
     │  │  DELEGATION TARGET                       │             │
     │  │                                          │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │                                          │             │
     │  │  M4: SRV06-OPT                           │             │
     │  │  Windows Server 2019                     │             │
     │  │  Operations Monitoring                   │             │
     │  │  LSASS: no RunAsPPL, WDigest=1           │             │
     │  │  Cached: svc_sql + backup_admin (DA)     │             │
     │  │  Port 445 — SMB                          │             │
     │  │  CREDENTIAL HARVEST                      │             │
     │  │                                          │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     │  ┌──────────────────────────────────────────┐             │
     │  │                                          │             │
     │  │  M5: SRV07-SQL                           │             │
     │  │  Windows Server 2019                     │             │
     │  │  MSSQL Server (SQLEXPRESS)               │             │
     │  │  Service: CYBERANGE\svc_sql              │             │
     │  │  xp_cmdshell ON, SeImpersonatePrivilege  │             │
     │  │  Port 1433 — SQL                         │             │
     │  │  SRV07-SQL$ has GenericWrite on DC02     │             │
     │  │  PRIVESC + RBCD PIVOT                    │             │
     │  │                                          │             │
     │  └──────────────────────────────────────────┘             │
     │                                                           │
     └───────────────────────────────────────────────────────────┘
```

## Attack Path Overlay

```
     ┌─────────────┐
     │  ATTACKER   │
     │  (Kali)     │
     └──────┬──────┘
            │
            │ 1. Password Spray
            │    → svc_web:Summer2025!
            ▼
     ┌─────────────┐         ┌─────────────┐
     │  SRV04-WEB  │────────→│  SRV05-API  │
     │  (M2)       │ 2. S4U  │  (M3)       │
     │  Spray      │ Deleg.  │  secretsdump│
     └─────────────┘         └──────┬──────┘
                                    │
                                    │ 3. PTH (local admin hash)
                                    ▼
                             ┌─────────────┐
                             │  SRV06-OPT  │
                             │  (M4)       │
                             │  LSASS Dump │
                             └──────┬──────┘
                                    │
                                    │ 4. Silver Ticket (svc_sql hash)
                                    ▼
                             ┌─────────────┐
                             │ SRV07-SQL   │
                             │ (M5)        │
                             │ xp_cmdshell │
                             │ PrintSpoofer│
                             └──────┬──────┘
                                    │
                                    │ 5. RBCD (SRV07-SQL$ → DC02)
                                    ▼
                             ┌─────────────┐
                             │    DC02     │
                             │   (M1)      │
                             │  DCSync     │
                             │  GAME OVER  │
                             └─────────────┘
```

## Port Matrix

| Source | Target | Port | Protocol | Purpose |
|--------|--------|------|----------|---------|
| Attacker | DC02 | 88 | Kerberos | TGT/TGS requests, spray |
| Attacker | DC02 | 445 | SMB | RID brute, share enum |
| Attacker | DC02 | 389 | LDAP | Domain enumeration |
| Attacker | SRV05-API | 445 | SMB | secretsdump via CIFS ticket |
| Attacker | SRV06-OPT | 445 | SMB | PTH lateral, LSASS dump |
| Attacker | SRV07-SQL | 1433 | MSSQL | Silver Ticket SQL access |
| SRV07-SQL | Attacker | 445 | SMB | PrintSpoofer upload + hive exfil |
| Attacker | DC02 | 445 | SMB | DCSync (final dump) |

## Discovery (No Static IPs)

All machines receive IPs via DHCP. The DC registers its IP into DNS at boot. Member servers discover the DC by scanning the local /24 for port 88 (Kerberos). The attacker discovers machines the same way:

```bash
# Find DC (port 88)
nmap -p 88 --open <SUBNET>.0/24

# Set DNS to DC
echo "nameserver <DC_IP>" > /etc/resolv.conf

# All other machines resolve via DNS
dig SRV04-WEB.cyberange.local
dig SRV05-API.cyberange.local
dig SRV06-OPT.cyberange.local
dig SRV07-SQL.cyberange.local
```
