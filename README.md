BootStrap
========

Release Notes:

Change from using PullServerIP and PullServerName to just PullServerAddress. Logic included when passing just an IP to create HOSTS entry using CN from PullServer endpoint cert.

Allow specifying PullServerAddress on PullServer. This creates endpoint cert with the name entered, making things DNS-compatible. If a name is not specified, hostname will be used as in previous versions.

Add NIC info to MSMQ message / node data.


Server
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerAddress 'pullserver.example.local' -secrets @{'branch_rsConfigs' = 'universal';'mR' = 'DDI_rsConfigs';'git_username' = 'rsWinAutomationSupport';'gitBr' = 'universal';'git_oAuthToken' = 'YOUROAUTHTOKEN';'shared_key' = ''}
```
Client
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerAddress 'pullserver.example.local' -dsc_config 'Template-Client.ps1' -shared_key ''
```
