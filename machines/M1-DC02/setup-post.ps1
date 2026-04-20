# M1: DC02 — Post-Promotion (run after reboot as CYBERANGE\Administrator)
Import-Module ActiveDirectory
# OUs
"CorpServers","CorpUsers","ServiceAccounts" | ForEach-Object { New-ADOrganizationalUnit -Name $_ -Path "DC=cyberange,DC=local" -ErrorAction SilentlyContinue }
# Service Accounts
New-ADUser -Name "svc_web" -SamAccountName "svc_web" -UserPrincipalName "svc_web@cyberange.local" -Path "OU=ServiceAccounts,DC=cyberange,DC=local" -AccountPassword (ConvertTo-SecureString "Summer2025!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@cyberange.local" -Path "OU=ServiceAccounts,DC=cyberange,DC=local" -AccountPassword (ConvertTo-SecureString "SqlStr0ng!Pass99" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true
New-ADUser -Name "backup_admin" -SamAccountName "backup_admin" -UserPrincipalName "backup_admin@cyberange.local" -Path "OU=ServiceAccounts,DC=cyberange,DC=local" -AccountPassword (ConvertTo-SecureString "Backup@dmin2025!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "backup_admin"
# Regular Users
@("jsmith","mjones","agarcia","bwilson","clee","dkhan","enguyen","fpatel","gmartin","hbrown") | ForEach-Object { New-ADUser -Name $_ -SamAccountName $_ -UserPrincipalName "$_@cyberange.local" -Path "OU=CorpUsers,DC=cyberange,DC=local" -AccountPassword (ConvertTo-SecureString "Welcome#2025!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true }
# SPNs
Set-ADUser -Identity "svc_web" -ServicePrincipalNames @{Add="HTTP/SRV04-WEB.cyberange.local"}
Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add="MSSQLSvc/SRV07-SQL.cyberange.local:1433"; Add="MSSQLSvc/SRV07-SQL.cyberange.local"; Add="MSSQLSvc/SRV07-SQL.cyberange.local\SQLEXPRESS"}
# Password Policy — no lockout
Set-ADDefaultDomainPasswordPolicy -Identity "cyberange.local" -LockoutThreshold 0 -LockoutDuration "00:00:00" -LockoutObservationWindow "00:00:00" -MinPasswordLength 8
# Constrained Delegation: svc_web -> HTTP/SRV05-API (with protocol transition)
Set-ADUser -Identity "svc_web" -TrustedForDelegation $false
Set-ADUser -Identity "svc_web" -Add @{'msDS-AllowedToDelegateTo'=@('HTTP/SRV05-API.cyberange.local','HTTP/SRV05-API')}
Set-ADAccountControl -Identity "svc_web" -TrustedToAuthForDelegation $true
# Audit Policies
"Kerberos Authentication Service","Kerberos Service Ticket Operations","Logon","Computer Account Management","User Account Management","Directory Service Changes","Directory Service Access","Sensitive Privilege Use" | ForEach-Object { auditpol /set /subcategory:"$_" /success:enable /failure:enable }
# Disable Defender + Firewall
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
Write-Host "[+] DC02 post-promotion setup complete." -ForegroundColor Green
