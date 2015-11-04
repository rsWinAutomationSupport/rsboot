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
    [string] $DefaultInstallPath = (Join-Path $env:ProgramFiles -ChildPath DSCAutomation),

    # NodeInfoPath - The path to json file where node metadata will be recorded
    [string] $NodeInfoPath = (Join-Path $DefaultInstallPath -ChildPath nodeinfo.json),

    # BootModuleZipURL - Link to the Zip file for the Bootstrap module
    [string] $BootModuleZipURL = "https://github.com/rsWinAutomationSupport/rsboot/archive/ModulePOC.zip",

    # ModuleName - Name of the main bootstrap module
    [string] $ModuleName = "rsBoot",

    # File name of DSC configuration file of pull server
    [string] $PullServerConfig,

    [int] $PullServerPort = 8080,

    # BootParameters - Hashtable that contains bootstrap parameters
    [hashtable] $BootParameters,

    # Valid FQDN Hostname or IP Address of the pull server
    [string] $PullServerAddress
)

#########################################################################################################
# Bootstrap DSC Configuration definitions for Pull Server (PullBoot) and Client (ClientBoot)
#region##################################################################################################

# Initial Pull Server DSC Configuration
Configuration PullBoot
{  
    param 
    (
        [hashtable] $BootParameters,
        [string] $PullConfigInstallPath,
        [string] $GitPackageName = "Git version 2.6.2",
        [string] $GitInstallDir  = "C:\Program Files\Git\",
        [string] $GitSourceUrl   = "https://github.com/git-for-windows/git/releases/download/v2.6.2.windows.1/Git-2.6.2-64-bit.exe"
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
            Name      = $GitPackageName
            Path      = $GitSourceUrl
            ProductId = ""
            Arguments = "/VERYSILENT /DIR $GitInstallDir"
            Ensure    = 'Present'
        }
        Script SetGitPath
        {
            SetScript = {
                $GitBinPath = (Join-Path $using:GitInstallDir "bin")
                Write-Verbose "Setting Git executable path to $GitBinPath"
                if (-not(Test-Path $GitBinPath))
                {
                    Throw "Git bin folder was not found - check that git client is actualy installed"
                }
                $currentPath = ([System.Environment]::GetEnvironmentVariable("Path","Machine")).Split(";")
                if (-not($currentPath.Contains($GitBinPath)))
                {
                    $env:Path = $env:Path + ";$GitBinPath"
                    [Environment]::SetEnvironmentVariable( "Path", $env:Path, [System.EnvironmentVariableTarget]::Machine )
                }
                else
                {
                    Write-Verbose "Global path variable already contains $GitBinPath"
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
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                
                Write-Verbose "Configuring git client user name and e-mail settings"
                Start-Process -Wait 'git.exe' -ArgumentList "config --system user.email $env:COMPUTERNAME@localhost.local"
                Start-Process -Wait 'git.exe' -ArgumentList "config --system user.name $env:COMPUTERNAME"
            }
            TestScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $GitConfig = & git config --list

                if( [bool]($GitConfig -match "user.email=$env:COMPUTERNAME") -and [bool]($GitConfig -match "user.name=$env:COMPUTERNAME") )
                {
                    return $true
                }
                else
                {
                    Write-Verbose "Git client user email and name are not set as required"
                    return $false
                }
            }
            GetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                $GitConfig = & git config --list
                @{"Result" = $($GitConfig -match $env:COMPUTERNAME)}
            }
            DependsOn = '[Script]SetGitPath'
        }
        Script Clone_rsConfigs 
        {
            SetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                # doing this only to help code readability
                $BootParams = $using:BootParameters
                $gitArguments = "clone --branch $($BootParams.branch_rsConfigs) https://$($BootParams.git_Oauthtoken)@github.com/$($BootParams.git_username)/$($BootParams.mR).git"
                
                Set-Location $using:PullConfigInstallPath -Verbose
                $RepoPath = Join-Path -Path $using:PullConfigInstallPath -ChildPath $BootParams.mR
                if (Test-Path $RepoPath)
                {
                    Write-Verbose "Existing config folder found - deleting..."
                    Remove-Item $RepoPath -Force -Recurse
                }

                Write-Verbose "Cloning DSC configuration repository"
                Start-Process -Wait 'git.exe' -ArgumentList $gitArguments
            }
            TestScript = {
                # We will always return false to make sure that we run the Set script in all cases
                return $false
            }
            GetScript = {
                $BootParams = $using:BootParameters
                return @{'Result' = (Test-Path -Path $(Join-Path $using:PullConfigInstallPath $BootParams.mR) -PathType Container)}
            }
            DependsOn = '[Script]UpdateGitConfig'
        }
        File rsPlatformDir 
        {
            SourcePath      = (Join-Path $PullConfigInstallPath "$($BootParameters.mR)\rsPlatform")
            DestinationPath = 'C:\Program Files\WindowsPowerShell\Modules\rsPlatform'
            Type            = 'Directory'
            Recurse         = $true
            MatchSource     = $true
            Ensure          = 'Present'
            DependsOn       = '[Script]Clone_rsConfigs'
        }
        Script ClonersPackageSourceManager 
        {
            SetScript = {
                # Ensure that current path variable is up-to-date
                $env:path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
                # doing this only to help code readability
                $BootParams = $using:BootParameters
                Set-Location 'C:\Program Files\WindowsPowerShell\Modules\'
                Write-Verbose "Cloning the rsPackageSourceManager module"
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
                $PullServerAddress = $using:BootParameters.PullServerAddress
                Import-Module -Name rsBoot -Force

                Get-ChildItem -Path Cert:\LocalMachine\My\ |
                Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"} | 
                Remove-Item
                
                $EndDate = (Get-Date).AddYears(25) | Get-Date -Format MM/dd/yyyy
                New-SelfSignedCertificateEx -Subject "CN=$PullServerAddress" `
                                            -NotAfter $EndDate `
                                            -StoreLocation LocalMachine `
                                            -StoreName My `
                                            -Exportable `
                                            -KeyLength 2048
            }
            TestScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                if( Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                    Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"} ) 
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }
            GetScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                                Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}).Thumbprint
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
        # Copy the self-signed certificate from 'My' to the root store for system to trust it
        Script InstallRootCertificate 
        {
            SetScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                
                # Remove any existing certificates that may cause a conflict
                Get-ChildItem -Path Cert:\LocalMachine\Root\ |
                Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"} |
                Remove-Item
                
                # Open the root store and add our self-signed cert to it
                $store = Get-Item Cert:\LocalMachine\Root
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                $CertificateObject = $(New-Object System.Security.Cryptography.X509Certificates.X509Certificate `
                                        -ArgumentList @(,(Get-ChildItem Cert:\LocalMachine\My | 
                                                          Where-Object Subject -eq "CN=$PullServerAddress").RawData))
                $store.Add($CertificateObject)
                $store.Close()
            }
            TestScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress

                Write-Verbose "Comparing certificatates in System personal store and in 'Root'"
                $SystemCert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | 
                               Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}).Thumbprint
                $RootCert = (Get-ChildItem -Path Cert:\LocalMachine\Root\ | 
                             Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}).Thumbprint

                if($RootCert -eq $SystemCert) 
                {
                    return $true
                }
                else 
                {
                    Write-Verbose "Certificates do not match"
                    return $false
                }
            }
            GetScript = {
                $PullServerAddress = $using:BootParameters.PullServerAddress
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\Root\ | 
                                Where-Object -FilterScript {$_.Subject -eq "CN=$PullServerAddress"}).Thumbprint
                }
            }
            DependsOn = '[Script]CreateServerCertificate'
        }
        LocalConfigurationManager
        {
            AllowModuleOverwrite           = 'True'
            ConfigurationModeFrequencyMins = 30
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded             = 'True'
            RefreshMode                    = 'PUSH'
            RefreshFrequencyMins           = 30
        }
    } 
}

Configuration ClientBoot 
{  
    param 
    (
        [string] $PullServerAddress,
        [string] $PullServerName,
        [int] $PullServerPort,
        [string] $InstallPath,
        [string] $NodeInfoPath
    )
    node $env:COMPUTERNAME 
    {
        File DevOpsDir
        {
            DestinationPath = $InstallPath
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
        Script CreateEncryptionCertificate 
        {
            SetScript = {
                Import-Module -Name rsBoot
                $EndDate = (Get-Date).AddYears(25) | Get-Date -Format MM/dd/yyyy
                $CertificateSubject = "CN=$($env:COMPUTERNAME)_enc"

                Get-ChildItem -Path Cert:\LocalMachine\My\ |
                Where-Object -FilterScript {$_.Subject -eq $CertificateSubject} | 
                Remove-Item -Force -Verbose -ErrorAction SilentlyContinue

                New-SelfSignedCertificateEx -Subject $CertificateSubject `
                                            -NotAfter $EndDate `
                                            -StoreLocation LocalMachine `
                                            -StoreName My `
                                            -Exportable `
                                            -KeyLength 2048 `
                                            -EnhancedKeyUsage 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2
            }
            TestScript = {
                $CertificateSubject = "CN=$($env:COMPUTERNAME)_enc"
                $ClientCert = [bool](Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $CertificateSubject})
                if($ClientCert)
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }
            GetScript = {
                $CertificateSubject = "CN=$($env:COMPUTERNAME)_enc"
                return @{
                    'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $CertificateSubject}).Thumbprint
                }
            }
        }
        # If PullServerAddress was an IP, set a HOSTS entry to resolve PullServer hostname
        Script SetHostFile 
        {
            SetScript = {
                if($using:PullServerAddress -as [ipaddress])
                {
                    $HostFilePath = Join-Path -Path $($env:windir) -ChildPath "system32\drivers\etc\hosts"
                    $HostFileContents = (Get-Content -Path $HostFilePath).where({$_ -notmatch $($using:PullServerAddress) -AND $_ -notmatch $($using:PullServerName)})
                    $HostFileContents += "$using:PullServerAddress    $using:PullServerName"
                    Set-Content -Value $HostFileContents -Path $HostFilePath -Force -Encoding ASCII
                }
            }
            TestScript = {
                if($using:PullServerAddress -as [ipaddress])
                {
                    $HostFilePath = Join-Path -Path $($env:windir) -ChildPath "system32\drivers\etc\hosts"
                    $HostEntryExists = [bool](Get-Content -Path $HostFilePath).where{$_ -match "$using:PullServerAddress    $using:PullServerName"}
                    return $HostEntryExists
                }
                else
                {
                    return $true
                }
            }
            GetScript = {
                $HostFilePath = Join-Path -Path $($env:windir) -ChildPath "system32\drivers\etc\hosts"
                $HostEntry = (Get-Content -Path $HostFilePath).where{$_ -match "$using:PullServerAddress    $using:PullServerName"}
                return @{
                    'Result' = $HostEntry
                }
            }
        }
        # MSMQ is required due to us requiring System.Messaging 
        WindowsFeature MSMQ 
        {
            Name = 'MSMQ'
            Ensure = 'Present'
        }
        # Retrieve the public key of pull server cert and store in root store
        Script GetPullPublicCert 
        {
            SetScript = {
                $Uri = "https://",$using:PullServerAddress,":",$using:PullServerPort -join ''
                Write-Verbose "Trying to connect to $Uri"
                do 
                {
                    $rerun = $true
                    try 
                    {
                        Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue -UseBasicParsing
                    }
                    catch 
                    {
                        if($($_.Exception.message) -like '*SSL/TLS*')
                        {
                            Write-Verbose "Sucessfully connected to Pull server"
                            $rerun = $false 
                        }
                        else 
                        {
                            Write-Verbose "Failed to connect to the Pull server - sleeping for 10 seconds..."
                            Start-Sleep -Seconds 10
                        }
                    }
                }
                while($rerun)
                
                $webRequest = [Net.WebRequest]::Create($Uri)
                try 
                {
                    $webRequest.GetResponse() 
                }
                catch
                {
                }
                $cert = $webRequest.ServicePoint.Certificate
                
                # Remove existing Pull server certificates that may cause a conflict
                Get-ChildItem -Path Cert:\LocalMachine\Root\ |
                Where-Object -FilterScript {$_.Subject -eq $cert.Issuer} |
                Remove-Item
                
                Write-Verbose "Adding PullServer Root Certificate to Cert:\LocalMachine\Root"
                $store = Get-Item Cert:\LocalMachine\Root
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                $store.Add($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                $store.Close()
            }
            TestScript = {
                $Uri = "https://",$using:PullServerAddress,":",$using:PullServerPort -join ''
                Write-Verbose "Contacting $Uri"
                do 
                {
                    $rerun = $true
                    try 
                    {
                        Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue -UseBasicParsing
                    }
                    catch 
                    {
                        Write-Verbose "Error retrieving configuration: $($_.Exception.message)"
                        if($($_.Exception.message) -like '*SSL/TLS*') 
                        {
                            $rerun = $false 
                        }
                        else
                        {
                            Start-Sleep -Seconds 10 
                        }
                    }
                }
                while($rerun)
                $webRequest = [Net.WebRequest]::Create($Uri)
                try 
                {
                $webRequest.GetResponse() 
                }
                catch
                {
                }
                $cert = $webRequest.ServicePoint.Certificate
                $CertMatch = (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq ($cert.GetCertHashString()) ).count
                if($CertMatch -eq 0)
                {
                    return $false
                }
                else
                {
                    return $true
                }
            }
            GetScript = {
                $Uri = "https://",$using:PullServerAddress,":",$using:PullServerPort -join ''
                $webRequest = [Net.WebRequest]::Create($uri)
                try 
                {
                    $webRequest.GetResponse() 
                }
                catch
                {
                }
                $cert = $webRequest.ServicePoint.Certificate
                return @{
                    'Result' = (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq ($cert.GetCertHashString()))
                }
            }
            DependsOn = @('[Script]SetHostFile')
        }
        # Retreieve all key local client variable and push them to Pull server via MSMQ to register
        Script SendClientPublicCert
        {
            SetScript = {
                $nodeinfo = Get-Content $using:NodeInfoPath -Raw | ConvertFrom-Json
                $ClientPublicCert = ((Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=$env:COMPUTERNAME`_enc").RawData)
                $MessageBody = @{'Name' = "$env:COMPUTERNAME"
                                'uuid' = $($nodeinfo.uuid)
                                'dsc_config' = $($nodeinfo.dsc_config)
                                'shared_key' = $($nodeinfo.shared_key)
                                'PublicCert' = "$([System.Convert]::ToBase64String($ClientPublicCert))"
                                'NetworkAdapters' = $($nodeinfo.NetworkAdapters)
                } | ConvertTo-Json

                [Reflection.Assembly]::LoadWithPartialName('System.Messaging') | Out-Null
                do 
                {
                    try 
                    {
                        $msg = New-Object System.Messaging.Message
                        $msg.Label = 'execute'
                        $msg.Body = $MessageBody
                        $queueName = "FormatName:DIRECT=HTTPS://$($using:PullServerName)/msmq/private$/rsdsc"
                        $queue = New-Object System.Messaging.MessageQueue ($queueName, $False, $False)                        
                        Write-Verbose "Trying to register with pull server: $queueName"
                        $queue.Send($msg)
                        Write-Verbose "Waiting 60 seconds for pull server to generate mof file..."
                        Start-Sleep -Seconds 60
                        $Uri = "https://$($using:PullServerName):$($using:PullServerPort)/PSDSCPullServer.svc/Action(ConfigurationId=`'$($nodeinfo.uuid)`')/ConfigurationContent"
                        Write-Verbose "Checking if client configuration has been generated..."
                        Write-Verbose "Using the following URI: $Uri"
                        $statusCode = (Invoke-WebRequest -Uri $Uri -ErrorAction SilentlyContinue -UseBasicParsing).statuscode
                    }
                    catch 
                    {
                        Write-Verbose "Error retrieving configuration: $($_.Exception.message)"
                    }
                }
                while($statusCode -ne 200)
                Write-Verbose "Looks like client mof file has been generated on the pull server!"
            }
            TestScript = {
                # We really want to run this every time
                Return $false
                }
            GetScript = {
                # Not terribly relevant in this instance
                return @{
                    'Result' = $true
                }
            }
            DependsOn = @('[WindowsFeature]MSMQ','[Script]GetPullPublicCert','[Script]CreateEncryptionCertificate','[Script]SetHostFile')
        }

        LocalConfigurationManager
        {
            AllowModuleOverwrite = 'True'
            ConfigurationID = "$($nodeinfo.uuid)"
            CertificateID = (Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -EQ "CN=$($env:COMPUTERNAME)_enc").Thumbprint
            ConfigurationModeFrequencyMins = 30
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = 'True'
            RefreshMode = 'Pull'
            RefreshFrequencyMins = 30
            DownloadManagerName = 'WebDownloadManager'
            DownloadManagerCustomData = (@{ServerUrl = "https://$($PullServerName):$($PullServerPort)/PSDSCPullServer.svc"; AllowUnsecureConnection = "false"})
        }
    } 
}

function Install-PlatformModules 
{
# We cannot run this code directly until the rsPlatform module is installed, 
# so we'll create it as string for now
@'
    Configuration InstallPlatformModules 
    {
        Import-DscResource -ModuleName rsPlatform
        Node $env:COMPUTERNAME
        {
            rsPlatform Modules
            {
                Ensure = 'Present'
            }
        }
    }
    InstallPlatformModules -OutputPath 'C:\Windows\Temp' -Verbose
    Start-DscConfiguration -Path 'C:\Windows\Temp' -Wait -Verbose -Force
'@ | Invoke-Expression -Verbose
}

#endregion

#########################################################################################################
# Local environment configuration
#region##################################################################################################

# Bootstrap log configuration
$TimeDate = (Get-Date -Format ddMMMyyyy_hh-mm-ss).ToString()
$LogPath = (Join-Path $env:SystemRoot -ChildPath "Temp\DSCBootstrap_$TimeDate.log")
$WinTemp = "$env:windir\Temp"
Start-Transcript -Path $LogPath -Force

Write-Verbose "Configuring local environment..."
Write-Verbose "Setting LocalMachine execurtion policy to RemoteSigned"
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force

Write-Verbose "Setting environment variables"
[Environment]::SetEnvironmentVariable('defaultPath',$DefaultInstallPath,'Machine')
[Environment]::SetEnvironmentVariable('nodeInfoPath',$NodeInfoPath,'Machine')

Write-Verbose " - Install path: $DefaultInstallPath"
Write-Verbose " - NodeInfoPath location: $NodeInfoPath"

if (-not(Test-Path $DefaultInstallPath))
{
    Write-Verbose "Creating configuration directory: $DefaultInstallPath"
    New-Item -Path $DefaultInstallPath -ItemType Directory
}
else
{
    Write-Verbose "Configuration directory already exists"
}

Write-Verbose "Setting folder permissions for $DefaultInstallPath"
#Disable persmission inheritance on $DefaultInstallPath
$objACL = Get-ACL -Path $DefaultInstallPath
$objACL.SetAccessRuleProtection($True, $True)
Set-ACL $DefaultInstallPath $objACL

# Remove BUILTIN\Users access to $DefaultInstallPath
$colRights = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute" 
$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None 
$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None 
$objType =[System.Security.AccessControl.AccessControlType]::Allow 
$objUser = New-Object System.Security.Principal.NTAccount("BUILTIN\Users") 
$objACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
    ($objUser, $colRights, $InheritanceFlag, $PropagationFlag, $objType) 
$objACL = Get-ACL -Path $DefaultInstallPath
$objACL.RemoveAccessRuleAll($objACE) 
Set-ACL $DefaultInstallPath $objACL

if (($BootParameters -eq $null) -or ($BootParameters -eq ''))
{
    Write-Verbose "BootParameters were not provided, checking local secrets.."
    if (Test-Path "$DefaultInstallPath\BootParameters.xml")
    {
        Write-Verbose "Reading contents of $DefaultInstallPath\BootParameters.xml"
        $BootParameters = Import-Clixml "$DefaultInstallPath\BootParameters.xml"
    }
    else
    {
        Throw "BootParameters were not provided and BootParameters.xml not found!"
        exit
    }
}
else
{
    Write-Verbose "Saving boot parameters to $DefaultInstallPath\BootParameters.xml"
    $BootParameters | Export-Clixml -Path "$DefaultInstallPath\BootParameters.xml" -Force
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
    Write-Verbose "Removing existing 'DSCBoot' task..."
    Unregister-ScheduledTask -TaskName DSCBoot -Confirm:$false
}
$Action = New-ScheduledTaskAction �Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -file $PSCommandPath $arguments"
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
# Set folder for DSC boot mof files
$DSCbootMofFolder = (Join-Path $WinTemp -ChildPath DSCBootMof)

# Determine if we're building a Pull server or a client
if ($PullServerConfig)
{
    ##############################################################
    Write-Verbose "Initiating DSC Pull Server bootstrap..."
    ##############################################################
    if(!($PullServerAddress))
    {
        $PullServerAddress = $env:COMPUTERNAME
    }
    # Need $pullserver_config parameter/variable
    Write-Secrets -PullServerAddress $PullServerAddress `
                  -PullServer_config $PullServerConfig `
                  -BootParameters $BootParameters `
                  -Path $DefaultInstallPath
    
    Write-Verbose "Configuring WinRM"
    Enable-WinRM

    Write-Verbose "Starting Pull Server Boot DSC configuration run"
    PullBoot -BootParameters $BootParameters `
             -PullConfigInstallPath $DefaultInstallPath `
             -OutputPath $DSCbootMofFolder

    Start-DscConfiguration -Path $DSCbootMofFolder -Wait -Verbose -Force
    
    Write-Verbose "Set Pull Server LCM"
    Set-DscLocalConfigurationManager -Path $DSCbootMofFolder -Verbose

    Write-Verbose "Running DSC config to install extra DSC modules as defined in rsPlatform configuration"
    Install-PlatformModules

    $PullServerDSCConfigPath = "$DefaultInstallPath\$($BootParameters.mR)\$PullServerConfig"
    Write-Verbose "Executing final Pull server DSC script from configuration repository"
    Write-Verbose "Configuration file: $PullServerDSCConfigPath"
    try
    {
        & "$PullServerDSCConfigPath" -Verbose
    }
    catch
    {
        Write-Verbose "Error in Pull Server DSC configuration: $($_.Exception)"
    }
}
else
{
    ##############################################################
    Write-Verbose "Initiating DSC Client bootstrap..."
    ##############################################################

    # Will hold Client configuration values to store in $NodeInfoPath
    $NodeInfo = @{}

    # Check that all client boot parameters have been provided
    $MandatoryClientKeys = @('shared_key','dsc_config')
    ForEach($key in $MandatoryClientKeys)
    {
        if($BootParameters.keys -notcontains $key)
        { 
            Write-Verbose "$key key is missing from BootParameters"
            exit
        }
    }
    $NodeInfo.Add('dsc_config',$BootParameters.dsc_config)
    $NodeInfo.Add('shared_key',$BootParameters.shared_key)

    Write-Verbose "Configuring WinRM"
    Enable-WinRM

    if($PullServerAddress -as [ipaddress])
    {
        # Legacy compatibility - really needs to go once all platform modules no longer depends on secrets.json
        $PullServerIP = $PullServerAddress
        
        Write-Verbose "Pull Server Address provided seems to be an IP - trying to resovle hostname..."
        
        # Attempt to resolve Pull server hostname by checking Common Name property
        # from the public certificate of DSC web endpoint
        $PullUrl = ("https://",$PullServerAddress,":",$PullServerPort -join '')
        do 
        {
            $webRequest = [Net.WebRequest]::Create($PullUrl)
            try 
            {
                $webRequest.GetResponse()
            }
            catch
            {
            }
            $PullServerName = $webRequest.ServicePoint.Certificate.Subject -replace '^CN\=','' -replace ',.*$',''
            if( !($PullServerName))
            {
                Write-Verbose "Failed to resolve Pull server Name - sleeping for 10 seconds..."
                Start-Sleep -Seconds 10 
            }
        }
        while(!($PullServerName))
        Write-Verbose "Resolve Pull server Name: $PullServerName"
    }
    # If Pull Server address is a FQDN, then use it for future connections
    else
    {
        $PullServerName = $PullServerAddress
    }

    $NodeInfo.Add('PullServerName',$PullServerName)
    $NodeInfo.Add('PullServerIP',$PullServerIP)
    $NodeInfo.Add('PullServerAddress',$PullServerAddress)
    $NodeInfo.Add('PullServerPort',$PullServerPort)
    $NodeInfo.Add('uuid',[Guid]::NewGuid().Guid)
    Set-Content -Path $NodeInfoPath -Value $($NodeInfo | ConvertTo-Json -Depth 2) -Force

    Write-Verbose "Executing client DSC boot configuration..."
    ClientBoot  -PullServerAddress $PullServerAddress `
                -PullServerName $PullServerName `
                -PullServerPort $PullServerPort `
                -NodeInfoPath $NodeInfoPath `
                -InstallPath $DefaultInstallPath `
                -OutputPath $DSCbootMofFolder -Verbose
                

    Start-DscConfiguration -Force -Path $DSCbootMofFolder -Wait -Verbose
    
    Write-Verbose "Configure Client LCM"
    Set-DscLocalConfigurationManager -Path $DSCbootMofFolder -Verbose

    Write-Verbose "Applying final Client DSC Configuration from Pull server - $PullServerName"
    Update-DscConfiguration -Wait -Verbose
}
#endregion

if (Get-ScheduledTask -TaskName 'DSCBoot' -ErrorAction SilentlyContinue)
{
    Write-Verbose "Removing the 'DSCBoot' task..."
    Unregister-ScheduledTask -TaskName DSCBoot -Confirm:$false
}

Stop-Transcript

Write-Verbose "The bootstrap process has completed"
Write-Verbose "Full bootstrap log file at: $LogPath"