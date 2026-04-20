# M5: SRV07-SQL — MSSQL Server (Silver Ticket + PrivEsc Target)
if ($env:COMPUTERNAME -ne "SRV07-SQL") { Rename-Computer -NewName "SRV07-SQL" -Force; Restart-Computer -Force; exit }
# Install SQL Server Express (silent — requires installer at C:\SQLSetup\)
# C:\SQLSetup\setup.exe /Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=Install /FEATURES=SQLEngine /INSTANCENAME=SQLEXPRESS /SQLSVCACCOUNT="CYBERANGE\svc_sql" /SQLSVCPASSWORD="SqlStr0ng!Pass99" /SQLSYSADMINACCOUNTS="CYBERANGE\Domain Admins" "CYBERANGE\svc_sql" /SECURITYMODE=SQL /SAPWD="SaP@ss2025!" /TCPENABLED=1 /NPENABLED=1
# Enable xp_cmdshell (run after SQL install)
Import-Module SQLPS -DisableNameChecking -ErrorAction SilentlyContinue
Invoke-Sqlcmd -ServerInstance "SRV07-SQL\SQLEXPRESS" -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;" -ErrorAction SilentlyContinue
# Create test database
Invoke-Sqlcmd -ServerInstance "SRV07-SQL\SQLEXPRESS" -Query "CREATE DATABASE CorpData;" -ErrorAction SilentlyContinue
Invoke-Sqlcmd -ServerInstance "SRV07-SQL\SQLEXPRESS" -Query "USE CorpData; CREATE TABLE Employees (ID INT PRIMARY KEY IDENTITY, FirstName NVARCHAR(50), LastName NVARCHAR(50), SSN NVARCHAR(11), Salary DECIMAL(10,2)); INSERT INTO Employees VALUES ('John','Smith','123-45-6789',85000),('Mary','Jones','234-56-7890',92000),('Ana','Garcia','345-67-8901',78000);" -ErrorAction SilentlyContinue
# Firewall
New-NetFirewallRule -DisplayName "Allow MSSQL" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Write-Host "[+] SRV07-SQL setup complete." -ForegroundColor Green
