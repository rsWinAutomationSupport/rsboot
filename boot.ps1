﻿param (
    [String] $defaultPath  = 'C:\DevOps',
    [string] $PullServerIP = $null,
    [string] $PullServerName = 'PullServer',
    [int] $PullServerPort = 8080,
    [Hashtable] $secrets
)
$VerbosePreference = 'Continue' 
[Environment]::SetEnvironmentVariable('defaultPath',$defaultPath,'Machine')
foreach( $key in ($PSBoundParameters.Keys -notmatch 'secrets') ){$arguments += "-$key $($PSBoundParameters[$key]) "}
function Create-Secrets {
    if(!($PullServerIP)){
        if(Test-Path (Join-Path $defaultPath 'secrets.json') ) {$d = Get-Content $(Join-Path $defaultPath 'secrets.json') | ConvertFrom-Json}
        else {
            $keys = @('branch_rsConfigs', 'mR', 'git_username', 'gitBr', 'git_oAuthtoken')
            foreach($key in $keys){
                if($secrets.keys -notcontains $key){ 
                    Write-Verbose "$key key is missing from secrets parameter"
                    exit
                }
                if((Test-Path -Path $defaultPath ) -eq $false) {New-Item -Path $defaultPath -ItemType Directory -Force}
                Set-Content -Path (Join-Path $defaultPath 'secrets.json') -Value $($secrets | ConvertTo-Json -Depth 2) -Verbose
            }
        }
    }
    else{
        $bootstrapinfo = @{
            'IP' = $PullServerIP
            'Name' = $PullServerName
            'Port' = $PullServerPort
            'MyGuid' = [Guid]::NewGuid().Guid
        }
        Set-Content -Path (Join-Path 'C:\Windows\Temp\' 'bootstrapinfo.json') -Value $($bootstrapinfo | ConvertTo-Json) -Verbose
    }
}
function Create-BootTask {
    if(!(Get-ScheduledTask -TaskName 'Boot' -ErrorAction SilentlyContinue)) {Start-Process -Wait schtasks.exe -ArgumentList "/create /sc Onstart /tn Boot /ru System /tr ""PowerShell.exe -ExecutionPolicy Bypass -file $PSCommandPath $arguments"""}
}
function Set-rsPlatform {
    @'
    Configuration initDSC {
        Import-DscResource -ModuleName rsPlatform
        Node $env:COMPUTERNAME
        {
            rsPlatform Modules
            {
                Ensure = "Present"
            }
        }
    }
    initDSC -OutputPath 'C:\Windows\Temp' -Verbose
    Start-DscConfiguration -Path 'C:\Windows\Temp' -Wait -Verbose -Force
'@ | Invoke-Expression -Verbose
}
function Set-LCM {
    param(
        [String] $PullServerIP
    )
    @"
    [DSCLocalConfigurationManager()]
    Configuration LCM
    {
        Node $env:COMPUTERNAME
        {
            if( !($PullServerIP) ){
                Settings
                {
                    ActionAfterReboot = 'ContinueConfiguration'
                    RebootNodeIfNeeded = 1
                    ConfigurationMode = 'ApplyAndAutoCorrect'
                    RefreshMode = 'Push'
                    ConfigurationModeFrequencyMins = 30
                    AllowModuleOverwrite = 1
                }
            }
            else {
                Settings {
                    AllowModuleOverwrite = 1
                    ConfigurationMode = 'ApplyAndAutoCorrect'
                    RefreshMode = 'Pull'
                    ConfigurationID = [Guid]::NewGuid()
                }

                ConfigurationRepositoryWeb DSCHTTPS {
                    Name= 'DSCHTTPS'
                    ServerURL = "https://$($bootstrapinfo.IP):$($bootstrapinfo.Port)/PSDSCPullServer.svc"
                    #CertificateID = (Get-ChildItem Cert:\LocalMachine\Root | ? Subject -EQ "CN=$($bootstrapinfo.Name)").Thumbprint
                    AllowUnsecureConnection = $False
                }
            }
        }
    }
    LCM -PullServerIP $PullServerIP -OutputPath 'C:\Windows\Temp' -Verbose
    Set-DscLocalConfigurationManager -Path 'C:\Windows\Temp' -Verbose
"@ | Invoke-Expression -Verbose
}
function Set-Pull {Invoke-Expression $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'rsConfigs\rsPullServer.ps1') -Verbose}

Configuration Boot {
    param(
        [String] $PullServerIP
    )
    node $env:COMPUTERNAME {
        script DevOpsDir {
            SetScript = {New-Item -Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) -ItemType Directory -Verbose}
            TestScript = {
                if(Test-Path -Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')))
                {return $true}
                else 
                {return $false}
            }

            GetScript = {
                return @{
                    'Result' = (Test-Path -Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) -PathType Container)
                }
            }
        }
        Script GetWMF5 {
            SetScript = {(New-Object -TypeName System.Net.webclient).DownloadFile('http://download.microsoft.com/download/B/5/1/B5130F9A-6F07-481A-B4A6-CEDED7C96AE2/WindowsBlue-KB3037315-x64.msu', $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine'))  'WindowsBlue-KB3037315-x64.msu'))}

            TestScript = {Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'WindowsBlue-KB3037315-x64.msu')}

            GetScript = {
                return @{
                    'Result' = $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'WindowsBlue-KB3037315-x64.msu')
                }
            }
            DependsOn = '[Script]DevOpsDir'
        }
        Script InstallWmf5 {
            SetScript = {
                Start-Process -Wait -FilePath $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'WindowsBlue-KB3037315-x64.msu') -ArgumentList '/quiet' -Verbose
                $global:DSCMachineStatus = 1 
            }
            TestScript = {
                if($PSVersionTable.PSVersion.Major -ge 5) 
                {return $true}
                else 
                {return $false}
            }
            GetScript = {
                return @{
                    'Result' = $PSVersionTable.PSVersion.Major
                }
            }
            DependsOn = @('[Script]GetWMF5', '[Script]DevOpsDir')
        }
        Script GetMakeCert {
            SetScript = {(New-Object -TypeName System.Net.webclient).DownloadFile('http://76112b97f58772cd1bdd-6e9d6876b769e06639f2cd7b465695c5.r57.cf1.rackcdn.com/makecert.exe', 'C:\Windows\system32\makecert.exe')}

            TestScript = {Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'makecert.exe')}

            GetScript = {
                return @{
                    'Result' = $(Test-Path  -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'makecert.exe'))
                }
            }
        }
        if(!($PullServerIP)){
            Script GetGit {
                SetScript = {(New-Object -TypeName System.Net.webclient).DownloadFile('https://raw.githubusercontent.com/rsWinAutomationSupport/Git/universal/Git-Windows-Latest.exe',$(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine'))  'Git-Windows-Latest.exe') )}

                TestScript = {if(Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'Git-Windows-Latest.exe')) {return $true} else {return $false}}

                GetScript = {
                    return @{
                        'Result' = $(Test-Path  -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'Git-Windows-Latest.exe'))
                    }
                }
                DependsOn = '[Script]Installwmf5'
            }
            Package InstallGit {
                Name = 'Git version 1.9.5-preview20150319'
                Path = $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'Git-Windows-Latest.exe')
                ProductId = ''
                Arguments = '/verysilent'
                Ensure = 'Present'
                DependsOn = '[Script]GetGit'
            }
            Registry SetGitPath {       
                Ensure = 'Present'
                Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
                ValueName = 'Path'
                ValueData = $( ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path), "${env:ProgramFiles(x86)}\Git\bin\" -join ';' )
                ValueType = 'ExpandString'
                DependsOn = '[Package]InstallGit'
            }  
            script UpdateGitConfig {
                SetScript = {
                    Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "config $('--', 'system' -join '') user.email $env:COMPUTERNAME@localhost.local"
                    Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "config $('--', 'system' -join '') user.name $env:COMPUTERNAME"
                }

                TestScript = {
                    if( (Get-Content 'C:\Program Files (x86)\Git\etc\gitconfig') -match $env:COMPUTERNAME )
                    { return $true }
                    else
                    { return $false }
                }

                GetScript = {
                    return @{
                        'Result' = $((Get-Content 'C:\Program Files (x86)\Git\etc\gitconfig') -contains $env:COMPUTERNAME)
                    }
                }
                DependsOn = '[Registry]SetGitPath'
            }
            script Clone_rsConfigs {
                SetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') | ConvertFrom-Json
                    Set-Location ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) -Verbose
                    Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "clone --branch $($d.branch_rsConfigs) $((('https://', $($d.git_Oauthtoken), '@github.com' -join ''), $($d.git_username), $($d.mR , '.git' -join '')) -join '/') rsConfigs"
                }

                TestScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') | ConvertFrom-Json
                    if(Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'rsConfigs')) 
                    {return $true}
                    else 
                    {return $false}
                }

                GetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') | ConvertFrom-Json
                    return @{
                        'Result' = (Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) $($d.mR)) -PathType Container)
                    }
                }
                DependsOn = '[Script]UpdateGitConfig'
            }
            File rsPlatformDir {
                SourcePath = Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'rsConfigs\rsPlatform'
                DestinationPath = 'C:\Program Files\WindowsPowerShell\Modules\rsPlatform'
                Type = 'Directory'
                Recurse = $true
                MatchSource = $true
                Ensure = 'Present'
                DependsOn = '[Script]Clone_rsConfigs'
            }
            script ClonersPackageSourceManager {
                SetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') | ConvertFrom-Json
                    Set-Location 'C:\Program Files\WindowsPowerShell\Modules\'
                    Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "clone --branch $($d.gitBr) https://github.com/rsWinAutomationSupport/rsPackageSourceManager.git"
                }

                TestScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') | ConvertFrom-Json
                    if(Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\rsPackageSourceManager\DSCResources') 
                    {return $true}
                    else 
                    {return $false}
                }

                GetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') | ConvertFrom-Json
                    return @{
                        'Result' = (Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\rsPackageSourceManager\DSCResources' -PathType Container)
                    }
                }
                DependsOn = '[File]rsPlatformDir'
            }
            Script CreateServerCertificate {
                SetScript = {
                    $yesterday = (Get-Date).AddDays(-1) | Get-Date -Format MM/dd/yyyy
                    Get-ChildItem -Path Cert:\LocalMachine\My\ |
                    Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')} |
                    Remove-Item
                    & makecert.exe -b $yesterday -r -pe -n $('CN=', $env:COMPUTERNAME -join ''), -ss my $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath', 'Machine'))  'pullserver.crt'), -sr localmachine, -len 2048
                }
                TestScript = {
                    if((Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}) -and (Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'pullserver.crt'))) 
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    return @{
                        'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}
                        ).Thumbprint
                    }
                }
                DependsOn = '[Script]GetMakeCert'
            }
            WindowsFeature IIS {
                Ensure = 'Present'
                Name = 'Web-Server'
                DependsOn = '[File]PublicPullServerCert'
            }
            WindowsFeature DSCServiceFeature {
                Ensure = 'Present'
                Name = 'DSC-Service'
                DependsOn = '[WindowsFeature]IIS'
            }
            Script InstallRootCertificate {
                SetScript = {
                    Get-ChildItem -Path Cert:\LocalMachine\Root\ |
                    Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')} |
                    Remove-Item
                    & certutil.exe -addstore -f Root $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'pullserver.crt')
                }
                TestScript = {
                    if((Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}).Thumbprint -eq (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}
                    ).Thumbprint) 
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    return @{
                        'Result' = (Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}
                        ).Thumbprint
                    }
                }
                DependsOn = '[Script]CreateServerCertificate'
            }
            File PublicPullServerCert {
                Ensure = 'Present'
                SourcePath = $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'pullserver.crt')
                DestinationPath = 'C:\inetpub\wwwroot'
                MatchSource = $true
                Type = 'File'
                Checksum = 'SHA-256'
                DependsOn = '[Script]CreateServerCertificate'
            }
        }
        else{
            Script CreateEncryptionCertificate {
                SetScript = {
                    $yesterday = (Get-Date).AddDays(-1) | Get-Date -Format MM/dd/yyyy
                    $cN = "CN=" + $env:COMPUTERNAME + "_enc"
                    Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $cN} | Remove-Item -Force -Verbose -ErrorAction SilentlyContinue
                    & makecert.exe -b $yesterday -r -pe -n $cN -sky exchange, -ss root, -sr localmachine, -len 2048, -eku 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2
                }
                TestScript = {
                    if( (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=' + $env:COMPUTERNAME + '_enc')} ))
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    return @{
                        'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=' + $env:COMPUTERNAME + '_enc')}
                        ).Thumbprint
                    }
                }
                DependsOn = '[Script]GetMakeCert'
            }
            WindowsFeature MSMQ {
                Name = "MSMQ"
                Ensure = "Present"
            }
            Script GetPullPublicCert {
                SetScript = {
                    $bootstrapinfo = Get-Content $(Join-Path 'C:\Windows\Temp\' 'bootstrapinfo.json') | ConvertFrom-Json
                    $uri = "https://$($bootstrapinfo.IP):$($bootstrapinfo.Port)"
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    $store = Get-Item Cert:\LocalMachine\Root
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]"ReadWrite")
                    $store.Add($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                    $store.Close()
                }
                TestScript = {
                    $bootstrapinfo = Get-Content $(Join-Path 'C:\Windows\Temp\' 'bootstrapinfo.json') | ConvertFrom-Json
                    $uri = "https://$($bootstrapinfo.IP):$($bootstrapinfo.Port)"
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    if( (Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq ($cert.GetCertHashString()) ).count -eq 0 ){return $false}
                    else {return $true}
                }
                GetScript = {
                    $bootstrapinfo = Get-Content $(Join-Path 'C:\Windows\Temp\' 'bootstrapinfo.json') | ConvertFrom-Json
                    $uri = "https://$($bootstrapinfo.IP):$($bootstrapinfo.Port)"
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    return @{
                        'Result' = (Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq ($cert.GetCertHashString()))
                    }
                }
            }
            Script SendClientPublicCert {
                SetScript = {
                    $bootstrapinfo = Get-Content $(Join-Path 'C:\Windows\Temp\' 'bootstrapinfo.json') | ConvertFrom-Json
                    [Reflection.Assembly]::LoadWithPartialName("System.Messaging") | Out-Null
                    $publicCert = ((Get-ChildItem Cert:\LocalMachine\Root | ? Subject -eq "CN=$env:COMPUTERNAME`_enc").RawData)
                    $msgbody = @{'Name' = "$env:COMPUTERNAME"
                        'GUID' = $($bootstrapinfo.MyGuid)
                        'PublicCert' = "$([System.Convert]::ToBase64String($publicCert))"
                    } | ConvertTo-Json
                    $msg = New-Object System.Messaging.Message
                    $msg.Label = 'execute'
                    $msg.Body = $msgbody
                    $queueName = "FormatName:DIRECT=HTTP://$($bootstrapinfo.IP)/msmq/private$/rsdsc"
                    $queue = New-Object System.Messaging.MessageQueue ($queueName, $False, $False)
                    $queue.Send($msg)
                }
                TestScript = { Return $false }
                GetScript = {
                    return @{
                        'Result' = $true
                    }
                }
            }                
        }
    } 
}
  
Create-BootTask
Create-Secrets
Boot -PullServerIP $PullServerIP -OutputPath 'C:\Windows\Temp' -Verbose
Start-DscConfiguration -Wait -Force -Verbose -Path 'C:\Windows\Temp'
Set-LCM -PullServerIP $PullServerIP
if( !($PullServerIP) ){
    Set-rsPlatform
    Set-Pull
}
