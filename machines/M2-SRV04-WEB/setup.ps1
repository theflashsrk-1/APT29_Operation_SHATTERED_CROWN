# M2: SRV04-WEB — IIS Web Frontend (Password Spray Target)
if ($env:COMPUTERNAME -ne "SRV04-WEB") { Rename-Computer -NewName "SRV04-WEB" -Force; Restart-Computer -Force; exit }
# Join domain (set DNS to DC first)
# Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "<DC_IP>"
# Add-Computer -DomainName "cyberange.local" -Credential (Get-Credential) -OUPath "OU=CorpServers,DC=cyberange,DC=local" -Force; Restart-Computer
Install-WindowsFeature Web-Server, Web-Asp-Net45, Web-Windows-Auth -IncludeManagementTools
Import-Module WebAdministration
New-Item -Path "C:\inetpub\corpweb" -ItemType Directory -Force
'<html><body><h1>Corp Internal Portal</h1><p>Server: SRV04-WEB</p></body></html>' | Out-File "C:\inetpub\corpweb\index.html"
New-WebAppPool -Name "CorpWebPool"
Set-ItemProperty "IIS:\AppPools\CorpWebPool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\CorpWebPool" -Name processModel.userName -Value "CYBERANGE\svc_web"
Set-ItemProperty "IIS:\AppPools\CorpWebPool" -Name processModel.password -Value "Summer2025!"
New-Website -Name "CorpWeb" -PhysicalPath "C:\inetpub\corpweb" -ApplicationPool "CorpWebPool" -Port 80
Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" -Name "enabled" -Value "true" -PSPath "IIS:\Sites\CorpWeb"
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value "false" -PSPath "IIS:\Sites\CorpWeb"
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain -Enabled False
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
Write-Host "[+] SRV04-WEB setup complete." -ForegroundColor Green
