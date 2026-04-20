# M1: DC02 — RBCD Vulnerability (run AFTER all machines joined domain)
Import-Module ActiveDirectory
$srv07 = Get-ADComputer -Identity "SRV07-SQL"
$dc02  = Get-ADComputer -Identity "DC02"
$acl = Get-Acl "AD:\$($dc02.DistinguishedName)"
$sid = New-Object System.Security.Principal.SecurityIdentifier $srv07.SID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericWrite", "Allow")
$acl.AddAccessRule($ace)
Set-Acl "AD:\$($dc02.DistinguishedName)" $acl
Write-Host "[+] SRV07-SQL$ has GenericWrite on DC02" -ForegroundColor Green
