BootStrap
========

```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/master/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -secrets @{'branch_rsConfigs' = 'master';'mR' = 'DDI_rsConfigs';'git_username' = 'AutomationSupport';'provBr' = 'master';'gitBr' = 'master';'git_oAuthToken' = 'YOUROAUTHTOKEN'}
```