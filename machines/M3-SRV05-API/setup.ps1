# M3: SRV05-API — WinRM API Backend (Delegation Target)
if ($env:COMPUTERNAME -ne "SRV05-API") { Rename-Computer -NewName "SRV05-API" -Force; Restart-Computer -Force; exit }
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true
# Register HTTP SPN on machine account (run on DC02 or with DA creds):
# setspn -A HTTP/SRV05-API.cyberange.local SRV05-API$
# setspn -A HTTP/SRV05-API SRV05-API$
Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWORD -Force
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
Write-Host "[+] SRV05-API setup complete." -ForegroundColor Green
