# APT29 — Operation SHATTERED CROWN — Participant Assessment

## Challenge Verification Questions

> **Instructions:**
>
> - Each Rangehas **3 MCQs** (choose the single best answer) and **2 Static Answer** questions
> - Questions are based on information gathered **during exploitation** — you must have solved the challenge to answer correctly
> - Static Question 1 in each Rangeis always the **Credential/Hash Submission**
> - Answers are provided at the end of this document for facilitator use only

---



---

# Range1 — Broken Perimeter (M2: SRV04-WEB → DC02)

### *Password Spray via Kerberos Pre-Authentication*

---

### MCQ 1.1

**After enumerating domain users via RID brute-force against DC02, you perform a password spray. Which Kerberos event ID is generated on DC02 for each failed spray attempt?**

- A) 4768 — TGT Request
- B) 4769 — TGS Request
- C) 4771 — Kerberos Pre-Authentication Failed
- D) 4625 — Account Failed to Log On
- E) 4776 — NTLM Authentication

---

### MCQ 1.2

**The svc_web account is vulnerable to password spraying because of a specific domain policy misconfiguration. What is the Account Lockout Threshold set to on DC02?**

- A) 3 attempts
- B) 5 attempts
- C) 10 attempts
- D) 0 (disabled)
- E) 50 attempts

---

### MCQ 1.3

**After cracking svc_web's password, you run `impacket-findDelegation` to enumerate delegation settings. What delegation type is configured for svc_web?**

- A) Unconstrained Delegation
- B) Constrained Delegation without Protocol Transition
- C) Constrained Delegation with Protocol Transition
- D) Resource-Based Constrained Delegation
- E) No Delegation

---

### Static Question 1.4 — Credential Submission

**Submit the password obtained for svc_web via password spray:**

**Answer:** `Summer2025!`

---

### Static Question 1.5

**What is the target SPN listed in svc_web's `msDS-AllowedToDelegateTo` attribute?**

**Answer:** `HTTP/SRV05-API.cyberange.local`

---



---

# Range2 — Broken Trust (M3: SRV05-API)

### *S4U2Self / S4U2Proxy Constrained Delegation Abuse*

---

### MCQ 2.1

**When using impacket-getST to perform S4U2Proxy delegation abuse, you specify `-altservice CIFS/SRV05-API.cyberange.local`. Why is the `-altservice` flag necessary?**

- A) The target service only accepts CIFS connections
- B) Kerberos validates the service type in the ticket and blocks HTTP access
- C) The original SPN is HTTP but you need SMB/CIFS access for secretsdump — Kerberos does not validate the service name in the ticket
- D) The S4U2Proxy protocol requires an alternate service to be specified
- E) WinRM does not support Kerberos authentication

---

### MCQ 2.2

**After successfully impersonating Administrator on SRV05-API and running secretsdump, the output contains `Administrator:500:aad3b435b51404eeaad3b435b51404ee:<HASH>:::`. What does the `:500:` represent?**

- A) The user's password length
- B) The Kerberos ticket lifetime in seconds
- C) The user's Relative Identifier (RID) — 500 is the built-in Administrator
- D) The SAM database index number
- E) The NT hash version number

---

### MCQ 2.3

**The local Administrator hash extracted from SRV05-API also works on SRV06-OPT and SRV07-SQL. What is the most likely reason for this?**

- A) All machines share the same domain Administrator account
- B) The local Administrator password was set identically during OS image deployment across all member servers
- C) Active Directory replicates local SAM databases between domain members
- D) The Group Policy Object pushes the same local admin hash to all machines
- E) LSASS caches remote Administrator credentials from all machines

---

### Static Question 2.4 — Hash Submission

**Submit the local Administrator NT hash extracted from SRV05-API via secretsdump:**

**Answer:** `[HASH — extracted during exploitation]`

---

### Static Question 2.5

**What Impacket tool and exact command flags did you use to perform the S4U2Proxy attack? Provide the full command (replace IPs and passwords with placeholders).**

**Answer:** `impacket-getST 'cyberange.local/svc_web:<PASSWORD>' -spn 'HTTP/SRV05-API.cyberange.local' -impersonate Administrator -altservice 'CIFS/SRV05-API.cyberange.local' -dc-ip <DC_IP>`

---



---

# Range3 — Silent Harvest (M4: SRV06-OPT)

### *Pass-the-Hash Lateral Movement + LSASS Credential Dump*

---

### MCQ 3.1

**When authenticating to SRV06-OPT with the local Administrator hash, you must use the `--local-auth` flag in nxc. What does this flag do?**

- A) Authenticates against the domain controller using the local account
- B) Bypasses UAC remote restrictions on the target
- C) Tells the tool to authenticate against the target's local SAM database instead of the domain
- D) Enables NTLM authentication instead of Kerberos
- E) Disables encryption on the SMB session

---

### MCQ 3.2

**SRV06-OPT has three specific configurations that make LSASS credential dumping possible. Which of the following is NOT one of them?**

- A) RunAsPPL is set to 0 (disabled)
- B) WDigest UseLogonCredential is set to 1
- C) Credential Guard is disabled
- D) Windows Defender Real-Time Protection is enabled
- E) LocalAccountTokenFilterPolicy is set to 1

---

### MCQ 3.3

**The svc_sql credentials are cached in LSASS on SRV06-OPT because of a specific mechanism. What creates the cached logon session?**

- A) svc_sql has an interactive RDP session open
- B) A Group Policy Object pre-caches service account credentials
- C) A scheduled task running as CYBERANGE\svc_sql creates a batch logon (Type 4) that caches credentials in LSASS
- D) svc_sql is a member of the local Administrators group
- E) The LSASS process automatically caches all domain service accounts

---

### Static Question 3.4 — Hash Submission

**Submit the svc_sql NT hash extracted from LSASS on SRV06-OPT:**

**Answer:** `[HASH — extracted during exploitation]`

---

### Static Question 3.5

**Besides svc_sql, which other domain account's credentials are cached in LSASS on SRV06-OPT, and what group is that account a member of?**

**Answer:** `backup_admin — Domain Admins`

---



---

# Range4 — Phantom Ticket (M5: SRV07-SQL)

### *Silver Ticket Forgery + MSSQL xp_cmdshell + PrintSpoofer*

---

### MCQ 4.1

**You forge a Silver Ticket for MSSQLSvc/SRV07-SQL.cyberange.local:1433. What is the critical difference between a Silver Ticket and a Golden Ticket in terms of detection?**

- A) Silver Tickets generate Event 4769 on the DC; Golden Tickets do not
- B) Golden Tickets are validated by the target service; Silver Tickets are validated by the DC
- C) Silver Tickets are validated by the target service only — the DC never sees the authentication, generating no Event 4769
- D) Both tickets generate identical events on the DC
- E) Silver Tickets require the krbtgt hash; Golden Tickets require the service account hash

---

### MCQ 4.2

**After connecting to MSSQL via the Silver Ticket, you execute `xp_cmdshell 'whoami /priv'` and observe `SeImpersonatePrivilege` is enabled. What tool do you use to escalate from svc_sql to SYSTEM?**

- A) Mimikatz — token::elevate
- B) JuicyPotato
- C) PrintSpoofer64.exe — exploits SeImpersonatePrivilege via named pipe impersonation
- D) Rubeus — tgtdeleg
- E) PsExec — runs commands as SYSTEM

---

### MCQ 4.3

**After escalating to SYSTEM on SRV07-SQL, you dump the SECURITY registry hive. The SRV07-SQL$ machine account NT hash is found in which LSA secret?**

- A) `_SC_MSSQLSERVER`
- B) `DefaultPassword`
- C) `$MACHINE.ACC`
- D) `NL$KM`
- E) `DPAPI_SYSTEM`

---

### Static Question 4.4 — Hash Submission

**Submit the SRV07-SQL$ machine account NT hash extracted from the SECURITY hive:**

**Answer:** `[HASH — extracted during exploitation]`

---

### Static Question 4.5

**The SECURITY hive also contains the svc_sql cleartext password in an LSA secret. What is the LSA secret name, and what is the password?**

**Answer:** `_SC_MSSQL$SQLEXPRESS` — `SqlStr0ng!Pass99`

---



---

# Range5 — Crown Fall (M1: DC02)

### *Resource-Based Constrained Delegation (RBCD) Abuse*

---

### MCQ 5.1

**You use SRV07-SQL$'s machine hash to write the RBCD attribute on DC02. What is the exact AD attribute name that gets modified?**

- A) msDS-AllowedToDelegateTo
- B) msDS-AllowedToActOnBehalfOfOtherIdentity
- C) userAccountControl
- D) servicePrincipalName
- E) msDS-SupportedEncryptionTypes

---

### MCQ 5.2

**Before writing RBCD, you create a new machine account COMP$ using impacket-addcomputer. What domain setting allows any authenticated user to create machine accounts by default?**

- A) AdminSDHolder
- B) ms-DS-MachineAccountQuota (default value: 10)
- C) AllowedToCreateMachineAccounts GPO
- D) Domain Admins group membership
- E) TrustedForDelegation attribute

---

### MCQ 5.3

**After writing RBCD and performing S4U from COMP$ to impersonate Administrator on CIFS/DC02, you run secretsdump. What operation does secretsdump perform on the Domain Controller to extract all domain hashes?**

- A) Reads the SAM registry hive remotely
- B) Performs DCSync — replicates NTDS.dit data via MS-DRSR (Directory Replication Service)
- C) Dumps LSASS process memory
- D) Reads the NTDS.dit file directly via SMB
- E) Queries LDAP for userPassword attributes

---

### Static Question 5.4 — Evidence Submission

**What Windows Event ID on DC02 indicates that the msDS-AllowedToActOnBehalfOfOtherIdentity attribute was modified (directory service object change)?**

**Answer:** `5136`

---

### Static Question 5.5

**Provide the exact impacket-rbcd command you used to write the RBCD delegation (use placeholders for hashes and IPs):**

**Answer:** `impacket-rbcd 'cyberange.local/SRV07-SQL$' -hashes ':<MACHINE_HASH>' -delegate-to 'DC02$' -delegate-from 'COMP$' -action write -dc-ip <DC_IP>`

---



---

# FACILITATOR ANSWER KEY

### (Do not distribute to participants)

| Q# | Question | Answer |
|----|----------|--------|
| 1.1 | Kerberos event for failed spray | **C** — 4771 |
| 1.2 | Account Lockout Threshold | **D** — 0 (disabled) |
| 1.3 | Delegation type on svc_web | **C** — Constrained with Protocol Transition |
| 1.4 | svc_web password | `Summer2025!` |
| 1.5 | Target SPN | `HTTP/SRV05-API.cyberange.local` |
| 2.1 | Why -altservice is needed | **C** |
| 2.2 | What :500: represents | **C** — RID |
| 2.3 | Why hash works on multiple machines | **B** — Same image password |
| 2.4 | Local admin hash | *Extracted during exploitation* |
| 2.5 | Full S4U command | See answer above |
| 3.1 | What --local-auth does | **C** |
| 3.2 | What is NOT a protection disabled | **D** — Defender is actually disabled |
| 3.3 | Why svc_sql creds are cached | **C** — Scheduled task batch logon |
| 3.4 | svc_sql hash | *Extracted during exploitation* |
| 3.5 | Other cached account | `backup_admin — Domain Admins` |
| 4.1 | Silver vs Golden Ticket detection | **C** |
| 4.2 | Tool for SeImpersonate escalation | **C** — PrintSpoofer |
| 4.3 | Machine hash LSA secret | **C** — $MACHINE.ACC |
| 4.4 | Machine hash | *Extracted during exploitation* |
| 4.5 | LSA secret with SQL password | `_SC_MSSQL$SQLEXPRESS` — `SqlStr0ng!Pass99` |
| 5.1 | RBCD attribute name | **B** |
| 5.2 | What allows machine account creation | **B** — MachineAccountQuota |
| 5.3 | What secretsdump does on DC | **B** — DCSync |
| 5.4 | Event ID for attribute modification | `5136` |
| 5.5 | RBCD command | See answer above |

---

## Scoring Guide

| Score | Percentage | Assessment |
|-------|------------|------------|
| 25/25 | 100% | Full Chain Compromised — DOMAIN BREACH |
| 20–24 | 80–96% | Deep Penetration — Minor gaps |
| 15–19 | 60–76% | Partial Compromise — Training recommended |
| 10–14 | 40–56% | Limited Access — Significant gaps |
| < 10 | < 40% | Insufficient — Remedial training required |

> **Note:** A participant who submits correct hashes but cannot answer the knowledge questions likely used hints or shared answers. Hash + knowledge answers together indicate genuine exploitation skill.
