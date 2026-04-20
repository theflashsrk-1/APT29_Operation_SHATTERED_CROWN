# M4: SRV06-OPT — Operations Server (LSASS Dump Target)
if ($env:COMPUTERNAME -ne "SRV06-OPT") { Rename-Computer -NewName "SRV06-OPT" -Force; Restart-Computer -Force; exit }
# Disable LSASS protections
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Type DWORD -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWORD -Force
# Cached svc_sql session (creates logon in LSASS)
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo CorpOps Monitor && timeout /t 86400"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "CorpOpsHealthMonitor" -Action $action -Trigger $trigger -User "CYBERANGE\svc_sql" -Password "SqlStr0ng!Pass99" -Force
Start-ScheduledTask -TaskName "CorpOpsHealthMonitor"
# Cached backup_admin DA session (bonus forensic target)
$action2 = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Backup Agent && timeout /t 86400"
Register-ScheduledTask -TaskName "CorpBackupAgent" -Action $action2 -Trigger $trigger -User "CYBERANGE\backup_admin" -Password "Backup@dmin2025!" -Force
Start-ScheduledTask -TaskName "CorpBackupAgent"
Enable-PSRemoting -Force
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Write-Host "[+] SRV06-OPT setup complete. svc_sql + backup_admin cached in LSASS." -ForegroundColor Green
