# BootStrap

Script to bootstrap a Pull server or a managed client.

## Script parameters
### Pull server
* **git_username** – GitHub organisation or username within which the config repository resides
* **mR** – name of the private configuration repository in Github
* **branch_rsConfigs** – the branch the configuration repository to clone
* **gitBr** – branch or tag to clone for the rsPackageSourceManager module [rsPackageSourceManager](https://github.com/rsWinAutomationSupport/rsPackageSourceManager)
* **git_oAuthToken** – Your or customer git oAuth token to use for GitHub authentication in order to clone a private repo
* **shared_key** – shared secret to store on the pull server for use in authenticating any new clients

### Client
* **PullServerAddress** – IP or domain name of the pull server to which this node should be connecting
* **dsc_config** – the name of the DSC script that should be used to generate this client’s configuration
* **shared_key** – shared secret to use during registration with the pull server – must be the same string that was used to bootstrap the pull server

### Platform-specific parameters
#### Rackspace Public Cloud
* **RSCloud** - Switch parameter to ensure that the script waits for RS Cloud provisioning tasks to complete before kicking off DSC provisioning tasks
* **RCv2** - Switch parameter to enable a check for RackConnect v2 provisioning status
* **RSWaitTimeout** - Cloud provisioning timeout (Default: 1800 seconds)

## Release Notes

Change from using PullServerIP and PullServerName to just PullServerAddress. Logic included when passing just an IP to create HOSTS entry using CN from PullServer endpoint cert.

Allow specifying PullServerAddress on PullServer. This creates endpoint cert with the name entered, making things DNS-compatible. If a name is not specified, hostname will be used as in previous versions.

Add NIC info to MSMQ message / node data.


### Server
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerAddress 'pullserver.example.local' -secrets @{'branch_rsConfigs' = 'universal';'mR' = 'DDI_rsConfigs';'git_username' = 'rsWinAutomationSupport';'gitBr' = 'universal';'git_oAuthToken' = 'YOUROAUTHTOKEN';'shared_key' = 'xxxxxxxxxxxxxxxxxx'}
```
### Client
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerAddress 'pullserver.example.local' -dsc_config 'Template-Client.ps1' -shared_key 'xxxxxxxxxxxxxxxxxx'
```
### Rackspace Cloud Client with RackConnect v2
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/wmf4/boot.ps1' -OutFile 'boot.ps1'
.\boot.ps1 -PullServerAddress 'pullserver.example.local' -dsc_config 'Template-Client.ps1' -shared_key 'xxxxxxxxxxxxxxxxxx' -RSCloud -RCv2
```