<#
.Synopsis
   Bootstrap script for initialising a DSC Pull server or one of its clients.
.DESCRIPTION
   Bootstrap script for initialising a DSC Pull server or one of its clients.
.EXAMPLE
   boot.ps1 -PullConfig "rsPullServer.ps1" -BootParameters @{} -Verbose

   Bootstrap a DSC Pull server
.EXAMPLE
   boot.ps1 -BootParameters @{} -Verbose
   
   Bootstrap a Client
#>
#requires -Version 4.0

[CmdletBinding()]
Param
(
    # defaultPath - Main installation directory (Default: <system_drive>:\Program Files\DSCAutomation)
    #               Will also contain the configuration repository
    [string] $DefaultPath = (Join-Path $env:ProgramFiles -ChildPath DSCAutomation),

    # NodeInfoPath - The path to json file where node metadata will be recorded
    [string] $NodeInfoPath = (Join-Path $defaultPath -ChildPath nodeinfo.json),

    # BootModuleZipURL - Link to the Zip file for the Bootstrap module
    [string] $BootModuleZipURL = "https://github.com/rsWinAutomationSupport/rsboot/archive/ModulePOC.zip",

    # ModuleName - Name of the main bootstrap module
    [string] $ModuleName = "rsBoot",

    # File name of DSC configuration file of pull server
    [string] $PullServerConfig,

    [int] $PullPort = 8080,

    # BootParameters - Hashtable that contains bootstrap parameters for the type of server being built
    [hashtable] $BootParameters
)

#########################################################################################################
# Helper functions
#region##################################################################################################
Configuration PullBoot
{  
    param 
    (
        [hashtable] $BootParameters,
        [string] $PullConfigInstallPath
    )
    node $env:COMPUTERNAME 
    {
        File DevOpsDir
        {
            DestinationPath = $PullConfigInstallPath
            Ensure = 'Present'
            Type = 'Directory'
        }
        Script GetWMF4 
        {
            SetScript = {
                $Uri = 'http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu'
                Write-Verbose "Downloading WMF4"
                Invoke-WebRequest -Uri $Uri -OutFile 'C:\Windows\temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -UseBasicParsing
            }

            TestScript = {
                if( $PSVersionTable.PSVersion.Major -ge 4 ) 
                {
                    return $true
                }
                if( -not (Test-Path -Path 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu') ) 
                {
                    Write-Verbose "WMF4 Installer not found locally"
                    return $false
                }
                else
                {
                    return $true
                }
            }

            GetScript = {
                return @{
                    'Result' = 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu'
                }
            }
            DependsOn = @('[File]DevOpsDir')
        }
        Script InstallWMF4 
        {
            SetScript = {
                Write-Verbose "Installing WMF4"
                Start-Process -Wait -FilePath 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -ArgumentList '/quiet' -Verbose
                Write-Verbose "Setting DSC reboot flag"
                Start-Sleep -Seconds 30
                $global:DSCMachineStatus = 1 
            }
            TestScript = {
                if($PSVersionTable.PSVersion.Major -ge 4) 
                {
                    return $true
                }
                else 
                {
                    Write-Verbose "Current PowerShell version is lower than the requried v4"
                    return $false
                }
            }
            GetScript = {
                return @{'Result' = $PSVersionTable.PSVersion.Major}
            }
            DependsOn = '[Script]GetWMF4'
        }
        Package InstallGit 
        {
            Name = 'Git version 2.6.2'
            Path = 'https://github.com/git-for-windows/git/releases/download/v2.6.2.windows.1/Git-2.6.2-64-bit.exe'
            ProductId = ''
            Arguments = '/VERYSILENT /DIR "C:\Program Files\Git\"'
            Ensure = 'Present'
        }
        Script SetGitPath
        {
            SetScript = {
                if (-not(Test-Path "C:\Program Files\Git\bin"))
                {
                    Throw "Git bin folder was not found - check that git client is actualy installed"
                }
                $currentPath = ([System.Environment]::GetEnvironmentVariable("Path","Machine")).Split(";")
                if (-not($currentPath.Contains("C:\Program Files\Git\bin")))
                {
                    $env:Path = $env:Path + ";C:\Program Files\Git\bin"
                    [Environment]::SetEnvironmentVariable( "Path", $env:Path, [System.EnvironmentVariableTarget]::Machine )
                }
                else
                {
                    Write-Verbose 'Global path variable already contains "C:\Program Files\Git\bin"'
                }
            }
            TestScript = {
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                return [bool](Get-Command git.exe -ErrorAction SilentlyContinue)
                 
            }
            GetScript = {
                @{EnvPath = $([System.Environment]::GetEnvironmentVariable("Path","Machine")) }
            }
            DependsOn = '[Package]InstallGit'
        }
        Script UpdateGitConfig 
        {
            SetScript = {
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                Start-Process -Wait 'git.exe' -ArgumentList "config --system user.email $env:COMPUTERNAME@localhost.local"
                Start-Process -Wait 'git.exe' -ArgumentList "config --system user.name $env:COMPUTERNAME"
            }
            TestScript = {
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $GitConfig = & git config --list

                if( [bool]($GitConfig -match $env:COMPUTERNAME) )
                {
                    return $true
                }
                else
                {
                    return $false
                }
            }
            GetScript = {
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $GitConfig = & git config --list
                @{"Result" = $($GitConfig -match $env:COMPUTERNAME)}
            }
            DependsOn = '[Script]SetGitPath'
        }
        Script Clone_rsConfigs 
        {
            SetScript = {
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $BootParams = $using:BootParameters
                $gitArguments = "clone --branch $($BootParams.branch_rsConfigs) https://$($BootParams.git_Oauthtoken)@github.com/$($BootParams.git_username)/$($BootParams.mR).git"
                Set-Location $using:PullConfigInstallPath -Verbose
                Start-Process -Wait 'git.exe' -ArgumentList $gitArguments
            }
            TestScript = {
                $BootParams = $using:BootParameters
                if(Test-Path -Path $(Join-Path $using:PullConfigInstallPath $BootParams.mR)) 
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }
            GetScript = {
                $BootParams = $using:BootParameters
                return @{'Result' = (Test-Path -Path $(Join-Path $using:PullConfigInstallPath $BootParams.mR) -PathType Container)}
            }
            DependsOn = '[Script]UpdateGitConfig'
        }
        File rsPlatformDir 
        {
            SourcePath = (Join-Path $PullConfigInstallPath "$($BootParameters.mR)\rsPlatform")
            DestinationPath = 'C:\Program Files\WindowsPowerShell\Modules\rsPlatform'
            Type = 'Directory'
            Recurse = $true
            MatchSource = $true
            Ensure = 'Present'
            DependsOn = '[Script]Clone_rsConfigs'
        }
        Script ClonersPackageSourceManager 
        {
            SetScript = {
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $BootParams = $using:BootParameters
                Set-Location 'C:\Program Files\WindowsPowerShell\Modules\'
                Start-Process -Wait 'git.exe' -ArgumentList "clone --branch $($BootParams.gitBr) https://github.com/rsWinAutomationSupport/rsPackageSourceManager.git"
            }
            TestScript = {
                return ([bool](Get-DscResource rsGit -ErrorAction SilentlyContinue))
            }
            GetScript = {
                return @{'Result' = ([bool] (Get-DscResource rsGit -ErrorAction SilentlyContinue ))}
            }
            DependsOn = '[File]rsPlatformDir'
        }
        #Creates PullServer Certificate that resides on DSC endpoint
        Script CreateServerCertificate 
        {
            SetScript = {
                $BootParams = $using:BootParameters
                Import-Module -Name rsBoot -Force

                Get-ChildItem -Path Cert:\LocalMachine\My\ |
                Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"} | 
                Remove-Item
                
                $EndDate = (Get-Date).AddYears(25) | Get-Date -Format MM/dd/yyyy
                New-SelfSignedCertificateEx -Subject "CN=$($BootParams.PullServerAddress)" -NotAfter $EndDate -StoreLocation LocalMachine -StoreName My -Exportable -KeyLength 2048
            }
            TestScript = {
                $BootParams = $using:BootParameters
                if( Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"} ) 
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }
            GetScript = {
                $BootParams = $using:BootParameters
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"}).Thumbprint
                }
            }
        }
        WindowsFeature IIS 
        {
            Ensure = 'Present'
            Name = 'Web-Server'
        }
        WindowsFeature DSCServiceFeature 
        {
            Ensure = 'Present'
            Name = 'DSC-Service'
            DependsOn = '[WindowsFeature]IIS'
        }
        Script InstallRootCertificate 
        {
            SetScript = {
                $BootParams = $using:BootParameters
                Get-ChildItem -Path Cert:\LocalMachine\Root\ |
                Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"} |
                Remove-Item
                $store = Get-Item Cert:\LocalMachine\Root
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                $store.Add( $(New-Object System.Security.Cryptography.X509Certificates.X509Certificate -ArgumentList @(,(Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=$($BootParams.PullServerAddress)").RawData)) )
                $store.Close()
            }
            TestScript = {
                $BootParams = $using:BootParameters
                if((Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"}).Thumbprint -eq (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"}).Thumbprint) 
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }
            GetScript = {
                $BootParams = $using:BootParameters
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq "CN=$($BootParams.PullServerAddress)"}).Thumbprint
                }
            }
            DependsOn = '[Script]CreateServerCertificate'
        }
    } 
}

#endregion

#########################################################################################################
# Local environment configuration
#region##################################################################################################

# Bootstrap log configuration
$TimeDate = (Get-Date -Format ddMMMyyyy_hh-mm-ss).ToString()
$LogPath = (Join-Path $env:SystemRoot -ChildPath "Temp\DSCBootstrap_$TimeDate.log")
#Start-Transcript -Path $LogPath -Force

Write-Verbose "Configuring local environment..."
Write-Verbose "Setting LocalMachine execurtion policy to RemoteSigned"
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force

Write-Verbose "Setting environment variables"
[Environment]::SetEnvironmentVariable('defaultPath',$DefaultPath,'Machine')
[Environment]::SetEnvironmentVariable('nodeInfoPath',$NodeInfoPath,'Machine')

Write-Verbose " - DefaultPath location: $DefaultPath"
Write-Verbose " - NodeInfoPath location: $NodeInfoPath"

if (-not(Test-Path $DefaultPath))
{
    Write-Verbose "Creating configuration directory: $DefaultPath"
    New-Item -Path $DefaultPath -ItemType Directory
}
else
{
    Write-Verbose "Configuration directory already exists"
}

Write-Verbose "Setting folder permissions for $DefaultPath"

#Disable persmission inheritance on $defaultPath
$objACL = Get-ACL -Path $defaultPath
$objACL.SetAccessRuleProtection($True, $True)
Set-ACL $DefaultPath $objACL

# Remove BUILTIN\Users access to $defaultPath
$colRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute" 
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None 
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
$objType =[System.Security.AccessControl.AccessControlType]::Allow 
$objUser = New-Object System.Security.Principal.NTAccount("BUILTIN\Users") 
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
    ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 
$objACL = Get-ACL -Path $defaultPath
$objACL.RemoveAccessRuleAll($objACE) 
Set-ACL $defaultPath $objACL

if (($BootParameters -eq $null) -or ($BootParameters -eq ''))
{
    Write-Verbose "BootParameters were not provided, checking local secrets.."
    if (Test-Path "$DefaultPath\BootParameters.xml")
    {
        Write-Verbose "Reading contents of $DefaultPath\BootParameters.xml"
        $BootParameters = Import-Clixml "$DefaultPath\BootParameters.xml"
    }
    else
    {
        Throw "BootParameters were not provided and BootParameters.xml not found!"
        exit
    }
}
else
{
    Write-Verbose "Saving boot parameters to $DefaultPath\BootParameters.xml"
    $BootParameters | Export-Clixml -Path "$DefaultPath\BootParameters.xml" -Force
}

#endregion

#########################################################################################################
# Create a task to persist bootstrap accross reboots
#region##################################################################################################
Write-Verbose "Preparing to create a 'DSCBoot' task"

foreach( $key in ($PSBoundParameters.Keys -notmatch 'BootParameters') )
{
    $arguments += "-$key $($PSBoundParameters[$key]) "
}
if (Get-ScheduledTask -TaskName 'DSCBoot' -ErrorAction SilentlyContinue)
{
    Write-Verbose "Removing an existing 'DSCBoot' task..."
    Unregister-ScheduledTask -TaskName DSCBoot -Confirm:$false
}
$Action = New-ScheduledTaskAction –Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -file $PSCommandPath $arguments"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$Settings = New-ScheduledTaskSettingsSet
$Task = New-ScheduledTask -Action $Action -Principal $Principal -Trigger $Trigger -Settings $Settings
Write-Verbose "Creating the 'DSCBoot' task"
Register-ScheduledTask DSCBoot -InputObject $Task
#endregion

#########################################################################################################
# Download & install rsBoot module
#region##################################################################################################
$Target = "github.com"
Write-Verbose "Checking connectivity to '$Target'..."
if (-not (Test-Connection $Target -Quiet))
{
    do
    {
        Write-Host "Waiting for network connectivity to '$Target' to be established..."
        Sleep -Seconds 20
    }
    until (-not (Test-Connection $Target -Quiet))
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$WinTemp = "$env:windir\Temp"
$ModuleFileName = $BootModuleZipURL.Split("/")[-1]
$ZipPath = "$WinTemp\$ModuleFileName"

$PSModuleLocation = "$Env:ProgramFiles\WindowsPowerShell\Modules\"

Write-Verbose "Downloading the Bootstrap PS module"
Invoke-WebRequest -Uri $BootModuleZipURL -OutFile $ZipPath
Unblock-File -Path $ZipPath

# Retreive Archive root folder name
$ZipRootName = ([System.IO.Compression.ZipFile]::OpenRead($ZipPath).Entries.FullName[0]).Trim("/")
# Extract archive to temporary location
if (Test-Path "$WinTemp\$ZipRootName")
{
    Remove-Item -LiteralPath "$WinTemp\$ZipRootName" -Recurse -Force
}
[System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $WinTemp)

Rename-Item "$WinTemp\$ZipRootName" -NewName "$WinTemp\$ModuleName"

$ModuleFolder = Join-Path $PSModuleLocation -Childpath $ModuleName
if (Test-Path "$PSModuleLocation\$ModuleName")
{
    Write-Verbose "Found existing rsBoot module instance, removing it..."
    Remove-Item -Path "$PSModuleLocation\$ModuleName" -Recurse -Force
}
Write-Verbose "Installing rsBoot module"
Move-Item -Path "$WinTemp\$ModuleName" -Destination $PSModuleLocation
Write-Verbose "Importing $ModuleName module"
Import-Module -Name $ModuleName -Force -Verbose
#endregion

#########################################################################################################
# Execute pre-bootstrap scripts
#region##################################################################################################
if ($BootParameters.PreBoot -ne $null)
{
    Invoke-PreBootScript -Scripts $BootParameters.PreBoot -Verbose
}
#endregion

#########################################################################################################
# Execute main bootstrap process
#region##################################################################################################
# Determine if we're building a Pull server or a client
if ($PullServerConfig -ne $null)
{
    Write-Verbose "Initiating DSC Pull Server bootstrap..."
    if(!($PullServerAddress))
    {
        $PullServerAddress = $env:COMPUTERNAME
    }
    # Need $pullserver_config parameter/variable
    Write-Secrets -PullServerAddress $PullServerAddress -pullserver_config $PullServerConfig `
                  -BootParameters $BootParameters -Path $DefaultPath
    
    Write-Verbose "Configuring WinRM"
    Enable-WinRM

    Write-Verbose "Starting Pull Server Boot DSC configuration run"
    PullBoot -BootParameters $BootParameters `
             -PullConfigInstallPath $DefaultPath `
             -OutputPath (Join-Path $DefaultPath -ChildPath DSCboot)

    Start-DscConfiguration -Path (Join-Path $DefaultPath -ChildPath DSCboot) -Wait -Verbose -Force

    <#
    Set-LCM
    #PullServer - Run RsPlatform and then PullServer config file
    if($secrets){
        Set-rsPlatform
        Set-Pull -pullserver_config $pullserver_config
    }#>
}

<#
else
{
    Write-Verbose "Initiating DSC Client bootstrap..."

    # Check if PullServerAddress provided is an IP
    if($PullServerAddress -notmatch '[a-zA-Z]')
    {
        $PullServerAddress = Get-PullServerInfo -PullServerAddress $PullServerAddress -PullPort $PullPort
    }

    
    # Get-NICInfo
    Enable-WinRM
    # Boot -PullServerAddress $PullServerAddress -OutputPath $defaultPath -Verbose
    # Start-DscConfiguration -Force -Path $defaultPath -Wait -Verbose
    Set-LCM
    Start-DscConfiguration -UseExisting -Wait -Force -Verbose
}
#>
#endregion






if (Get-ScheduledTask -TaskName 'DSCBoot' -ErrorAction SilentlyContinue)
{
    Write-Verbose "Removing the 'DSCBoot' task..."
    Unregister-ScheduledTask -TaskName DSCBoot -Confirm:$false
}
#Stop-Transcript


