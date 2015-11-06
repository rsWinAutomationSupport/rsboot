# rsBoot Module

Experimental bootstrap module to handle fully-automated deployment of a DSC Pull server and clients.

### Changelog

support the latest version of rsBoot (ModulePOC branch) that I was working on, which addresses a few things from the original universal bootstrap process. This is still a work in progress, but for anyone interested here is a list of things it solves for:

- Remove makecert.exe dependency (no longer installed) Distribution of this file is not in line wiht MS licensing agreement for the Windows SDK.
- Created a PS Module to hold any extra scripts and cmdlets that we do not need ot add to boot.ps1 itself
- Added support to plug additional pre-bootstrap scripts to allow for easy inclusion of code that must be executed before any major changes to target system take place: RS Servermill wait logic for example
- Parameterise a lot of previously hard-coded variables and simplifies future parameterisation efforts (Install paths, git versions, etc)
- boot.ps1 is a bit more graceful with github connectivity, so will waif until it can reach the internet before trying, and possibly failing, to download an additional artefacts
- Switch default DevOps directory to '$env:ProgramFiles\DSCAutomation' and NodeInfoPath to the DSCAutomation path
- The install directory and secrets.json are now in a folder that is not readable by local Users group. I really want to change how we handle this by encrypting this file with pull server's cert (similar to databags) and handle decryption within pull server's config file in the future - all subsequent calls for data within this file would be done only from pull server config and passed to relevant modules as needed.
- Move to latest Windows git client (2.6.1) - no longer has the git pull bug on Xen clients
- More verbose output into the bootstrap transcript/log file
- Initial DSC bootstrap configs for Pull and client have been separated to simplify future maintenance (still part of boot.ps1)
- Boot LCM configuration block is now included within pull and client DSC configuration blocks and meta config mof is now generated along side the boot mof at the same time
- a few other tweaks that remove hard-coded paths/variables (not all for now) and should allow deployment on systems with system drive being something other than C:
- Should mostly be compatible with previous 'universal' deployments after some minor changes to rsPlatform module versions and a slight tweak to Pull server config file by adding the following line to rsMofs configuration:
```
configHashPath = [Environment]::GetEnvironmentVariable('defaultPath','Machine')
```

## Example usage

### Basic or manual deployment
#### IP address for Pull server
*Server*
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
*Client*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                        "dsc_config" = "Template-Client.ps1";
                        "shared_key" = "..................";
                        "PreBoot" = @{"RackspaceCloud.ps1" = ""}
                   }
& 'C:\boot.ps1' -PullServerAddress "0.0.0.0" -BootParameters $BootParameters -Verbose
```

#### Using DNS address for Pull server:
*Server*
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
& 'C:\boot.ps1' -PullServerAddress "pull.domain.local" -PullServerConfig 'rsPullServer.ps1' -BootParameters $BootParameters -Verbose
```
*Client*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                        "dsc_config" = "Template-Client.ps1";
                        "shared_key" = "..................";
                   }
& 'C:\boot.ps1' -PullServerAddress "pull.domain.local" -BootParameters $BootParameters -Verbose
```

### Deployment with a prebootstrap script

*Server*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "branch_rsConfigs" = "<source_config_branch";
                    "mR" = "<config_repo_name>";
                    "git_username" = "<gir_org/username>";
                    "gitBr" = "v1.0.3";
                    "git_oAuthToken" = "..................";
                    "shared_key" = "..................";
					"PreBoot" = @{"RackspaceCloud.ps1" = ""};
                    }
& 'C:\boot.ps1' -PullServerConfig 'rsPullServer.ps1' -BootParameters $BootParameters -Verbose
```
*Client*
```PoSh
Invoke-WebRequest 'https://raw.githubusercontent.com/rsWinAutomationSupport/rsboot/ModulePOC/bootstrap/boot.ps1' -OutFile 'c:\boot.ps1'
$BootParameters = @{
                    "dsc_config" = "Template-Client.ps1";
                    "shared_key" = "..................";
                    "PreBoot" = @{"RackspaceCloud.ps1" = ""}
                   }
& 'C:\boot.ps1' -PullServerAddress "0.0.0.0" -BootParameters $BootParameters -Verbose
```

**Notes on PreBoot option:** 
PreBoot scripts can be passed parameters too as a hashtable:
```
"PreBoot" = @{"RackspaceCloud.ps1" = @{"param1" = "test"; "param2" = "test2"}}
``` 

We can also pass multiple PreBoot scripts to be executed in particular order and with their own parameters:

```
"PreBoot" = [ordered]@{"s1.ps1" = @{"param1" = "test";"param2" = "test2"};
					   "s2.ps1" = @{"param2" = "test"}};
```
The above will first execute the scripts in this order:
```
> s1.ps1 -param1 "test" -param2 "test2"
> s2.ps1 -param2 "test"
```