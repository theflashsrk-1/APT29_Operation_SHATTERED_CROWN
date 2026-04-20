# Operation SHATTERED CROWN — Full Storyline

## Intelligence Brief

**Operation:** SHATTERED CROWN
**Classification:** CONFIDENTIAL // EXERCISE ONLY
**Issuing Authority:** Corporate Incident Response Division (CIRD)
**Target Organization:** CybeRange Financial Services
**Threat Actor:** APT29 / Midnight Blizzard (SVR-attributed)
**Date:** [EXERCISE DATE]

---

## Situation

CROWN ACTUAL — Threat intelligence indicates that APT29 (tracked internally as MIDNIGHT CROWN) has shifted focus from cloud identity providers to on-premises Active Directory infrastructure at mid-market financial services firms. HUMINT and SIGINT sources confirm the group is targeting Kerberos delegation misconfigurations — a class of vulnerability that exists in over 60% of enterprise AD deployments and is almost never remediated because it requires deep understanding of service principal names, delegation types, and trust chain architecture.

CybeRange Financial Services operates a standard Windows Server 2019 Active Directory environment with five servers. The infrastructure was built by a small IT team that followed Microsoft's default configurations. Delegation was enabled for a web service account to allow seamless single sign-on between the company's public web portal and internal API backend. The SQL database server was granted write permissions on the Domain Controller's computer object for an automated patching workflow that was never removed. These are not exotic vulnerabilities — they are Tuesday afternoon in corporate IT.

---

## Red Team Brief (MIDNIGHT CROWN Operators)

You are operators for MIDNIGHT CROWN. Your mission is to achieve full domain compromise of CybeRange Financial Services' Active Directory environment, starting from zero access on the corporate network with no credentials. Your final objective is a complete dump of NTDS.dit — every credential in the domain.

**Entry Point:** Network access to the corporate LAN segment. No credentials.
**Final Objective:** DCSync or NTDS.dit extraction from the Domain Controller.
**ROE:** No destructive actions. No ransomware. No data exfiltration beyond credentials. This is an intelligence collection operation — collect everything, break nothing.

### Phase 1 — Initial Access: The Spray

CybeRange Financial has no account lockout policy. The IT team disabled it after too many helpdesk tickets from users locking themselves out. Your first step is to enumerate domain users through null SMB sessions or RID brute-forcing against the Domain Controller, then spray a list of seasonal passwords against every account. One of the service accounts — `svc_web` — uses a password that matches a common pattern: `Summer2025!`.

With valid domain credentials, enumerate the environment. Look for SPNs, delegation configurations, and group memberships. The `svc_web` account has constrained delegation configured to `HTTP/SRV05-API.cyberange.local`.

### Phase 2 — Delegation Abuse: The Crown Jewel

Constrained delegation with protocol transition (`TrustedToAuthForDelegation`) is the most dangerous delegation type in Active Directory. It allows the delegated account to request service tickets on behalf of ANY domain user — including Domain Admins — without that user ever authenticating. This is by design. Microsoft built it this way.

Use S4U2Self to obtain a forwardable ticket for Administrator, then S4U2Proxy to present that ticket to the target service. The trick: use `-altservice` to rewrite the SPN from `HTTP/SRV05-API` to `CIFS/SRV05-API`. Kerberos does not validate the service type in the ticket — once the KDC issues the S4U2Proxy ticket, you can change the service name to anything. This gives you full SMB access as Administrator on SRV05-API.

Dump the local SAM database from SRV05-API. Extract the local Administrator NT hash. In this environment, the same local Administrator password was set during OS imaging across all member servers. This is common — most organizations deploy from a golden image with a shared local admin password.

### Phase 3 — Lateral Movement: The Harvest

Pass the local Administrator hash to SRV06-OPT using `--local-auth`. This server is the operations monitoring box. Its LSASS process has no protection — no RunAsPPL, no Credential Guard, WDigest is enabled. Two scheduled tasks maintain active logon sessions: one for `svc_sql` (the SQL service account) and one for `backup_admin` (a Domain Admin used for backup operations).

Dump LSASS. Extract the `svc_sql` NT hash. This hash is the key to the next phase.

### Phase 4 — Silver Ticket: The Silent Entry

Forge a Silver Ticket for `MSSQLSvc/SRV07-SQL.cyberange.local:1433` using the `svc_sql` NT hash. Silver Tickets are validated by the target service, not the Domain Controller. This means your access to the SQL server generates zero events on DC02 — no Event 4769, no TGS request, nothing. The Domain Controller never knows you authenticated. This is the defining characteristic of Silver Ticket attacks and the reason they are so dangerous.

Connect to MSSQL. The `svc_sql` account has `SeImpersonatePrivilege` because it runs the SQL Server service. Use `xp_cmdshell` for OS command execution, upload `PrintSpoofer64.exe` through an SMB server on your machine, and escalate from `svc_sql` to `NT AUTHORITY\SYSTEM`. As SYSTEM, dump the registry hives (SAM, SYSTEM, SECURITY). The SECURITY hive contains the `SRV07-SQL$` machine account NT hash in the `$MACHINE.ACC` LSA secret.

### Phase 5 — RBCD: The Kill Shot

This is the final escalation. `SRV07-SQL$` has `GenericWrite` on DC02's computer object in Active Directory. This permission was granted when the IT team configured an automated patch management workflow — the SQL server needed to write attributes to the DC for reporting purposes. Nobody removed it afterward.

`GenericWrite` on a computer object allows you to modify `msDS-AllowedToActOnBehalfOfOtherIdentity` — the attribute that controls Resource-Based Constrained Delegation. Create a new machine account (`COMP$`) using the default MachineAccountQuota of 10 (another default nobody changes). Write the RBCD attribute on DC02 to trust `COMP$`. Now perform S4U2Self/S4U2Proxy from `COMP$` to impersonate Administrator on `CIFS/DC02.cyberange.local`.

You now have a Kerberos ticket for Administrator on the Domain Controller. Run `secretsdump`. Extract NTDS.dit. Every credential in the domain is yours. Operation complete.

---

## Blue Team Brief (CybeRange SOC)

You are the Security Operations Center at CybeRange Financial Services. A threat intelligence feed flagged anomalous Kerberos activity originating from within your network. Your mission is to detect, analyze, document, and remediate each stage of the intrusion.

**For each phase you must:**

- Identify the specific log evidence of the attack
- Name the technique used (MITRE ATT&CK ID and name)
- Identify the affected account, service, or system
- Provide actionable remediation steps

**Key Log Sources:**

- DC02: Security Event Log — Events 4768, 4769, 4771 (Kerberos), 4741 (computer creation), 5136 (DS object modification), 4624/4625 (logon)
- SRV04-WEB: IIS logs (`C:\inetpub\logs`), Security Event Log
- SRV05-API: Security Event Log — Event 4624 Type 3 (network logon with delegated credentials)
- SRV06-OPT: Security Event Log — Event 4624, Sysmon Event 10 (LSASS access), Event 4688 (process creation)
- SRV07-SQL: Security Event Log — Event 4624 (Silver Ticket — no matching 4769 on DC02), SQL Server Audit Log, Event 4688 (PrintSpoofer, reg.exe)

**Critical Detection Opportunity:** In Step 4, the attacker uses a Silver Ticket. This means SRV07-SQL logs a successful logon (Event 4624) but DC02 has NO corresponding Event 4769 for that service ticket. This discrepancy — a logon without a ticket request — is the definitive indicator of a Silver Ticket attack. Cross-correlating SRV07-SQL logon events against DC02 TGS requests is the detection method.

---

## Chain of Compromise — Summary

```
[Attacker — Corporate LAN]
         │
         │ No credentials
         ▼
┌─────────────────────────────────┐
│  M2: SRV04-WEB                  │  PHASE 1
│  IIS Corporate Portal           │  Password Spray (Summer2025!)
│  svc_web app pool identity      │  → svc_web credentials obtained
└──────────────┬──────────────────┘
               │  svc_web : Summer2025!
               │  Constrained Delegation → HTTP/SRV05-API
               ▼
┌─────────────────────────────────┐
│  M3: SRV05-API                  │  PHASE 2
│  WinRM API Backend              │  S4U2Self + S4U2Proxy
│  Port 5985                      │  -altservice CIFS → Admin
│                                 │  → secretsdump → local admin hash
└──────────────┬──────────────────┘
               │  Local Admin hash (shared across member servers)
               │  --local-auth PTH
               ▼
┌─────────────────────────────────┐
│  M4: SRV06-OPT                  │  PHASE 3
│  Operations Monitoring           │  PTH → LSASS Dump
│  No RunAsPPL, WDigest=1         │  → svc_sql hash + backup_admin hash
│  Cached: svc_sql, backup_admin  │
└──────────────┬──────────────────┘
               │  svc_sql NT hash
               │  Silver Ticket forgery
               ▼
┌─────────────────────────────────┐
│  M5: SRV07-SQL                  │  PHASE 4
│  MSSQL Server (SQLEXPRESS)      │  Silver Ticket → xp_cmdshell
│  xp_cmdshell enabled            │  PrintSpoofer → SYSTEM
│  SeImpersonatePrivilege         │  → SRV07-SQL$ machine hash
└──────────────┬──────────────────┘
               │  SRV07-SQL$ machine hash
               │  GenericWrite on DC02
               ▼
┌─────────────────────────────────┐
│  M1: DC02                       │  PHASE 5
│  Domain Controller              │  RBCD write → S4U → DA
│  AD DS + DNS                    │  secretsdump → NTDS.dit
│  Full Domain Compromise         │  OPERATION COMPLETE
└─────────────────────────────────┘
```
