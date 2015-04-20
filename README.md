BootStrap
========
Server
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/master/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -secrets @{'branch_rsConfigs' = 'master';'mR' = 'DDI_rsConfigs';'git_username' = 'AutomationSupport';'gitBr' = 'master';'git_oAuthToken' = 'YOUROAUTHTOKEN','shared_key' = ''}
```
Client
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/master/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerName 'PullServer' -PullServerIP '' -dsc_config 'Client.ps1' -shared_key ''
```
