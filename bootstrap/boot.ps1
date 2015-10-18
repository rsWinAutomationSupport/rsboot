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
    [string] $PullConfig,

    [int] $PullPort = 8080,

    # BootParameters - Hashtable that contains bootstrap parameters for the type of server being built
    [hashtable] $BootParameters
)

#########################################################################################################
# Helper functions
#region##################################################################################################


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

if (-not(Test-Path $defaultPath))
{
    Write-Verbose "Creating configuration directory: $defaultPath"
    New-Item -Path $defaultPath -ItemType Directory
}
else
{
    Write-Verbose "Configuration directory already exists"
}

Write-Verbose "Setting folder permissions for $DefaultPath"

#Disable persmission inheritance on $defaultPath
$objACL = Get-ACL -Path $defaultPath
$objACL.SetAccessRuleProtection($True, $True)
Set-ACL $defaultPath $objACL

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

<#
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
#>
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
    Enable-WinRM

    <#
    
    
    # Boot -PullServerAddress $PullServerAddress -OutputPath $defaultPath -Verbose
    # Start-DscConfiguration -Force -Path $defaultPath -Wait -Verbose
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


