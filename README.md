# rsBoot Module

Bootstrap module to handle fully-automated deployment of a DSC Pull server and clients.


### Example usage
#### Server
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "branch_rsConfigs" = "<source_config_branch";
                    "mR" = "<config_repo_name>";
                    "git_username" = "<gir_org/username>";
                    "gitBr" = "v1.0.3";
                    "git_oAuthToken" = "..................";
                    "shared_key" = ".................."
                    }
& 'C:\boot.ps1' -PullServerConfig 'rsPullServer.ps1' -BootParameters $BootParameters -Verbose
```
#### Client
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                        "dsc_config" = "Template-Client.ps1";
                        "shared_key" = "..................";
                        "PreBoot" = @{"RackspaceCloud.ps1" = ""}
                   }
& 'C:\boot.ps1' -PullServerAddress "0.0.0.0" -BootParameters $BootParameters -Verbose
```
