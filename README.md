BootStrap
========
Testing updates to DSC Platform

Change from using PullServerIP and PullServerName to just PullServerAddress.

Add NIC info to MSMQ message / node data.


Server
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -secrets @{'branch_rsConfigs' = 'master';'mR' = 'DDI_rsConfigs';'git_username' = 'AutomationSupport';'gitBr' = 'master';'git_oAuthToken' = 'YOUROAUTHTOKEN','shared_key' = ''}
```
Client
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerAddress 'pullserver' -dsc_config 'Client.ps1' -shared_key ''
```
