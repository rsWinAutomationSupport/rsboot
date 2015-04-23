param (
    [String] $defaultPath  = 'C:\DevOps',
    [string] $PullServerIP = $null,
    [string] $PullServerName = 'PullServer',
    [string] $dsc_Config,
    [string] $shared_key,
    [int] $PullServerPort = 8080,
    [Hashtable] $secrets)
[Environment]::SetEnvironmentVariable('defaultPath',$defaultPath,'Machine')
$global:PSBoundParameters = $PSBoundParameters
function Create-Secrets {
    if($global:PSBoundParameters.ContainsKey('shared_key')){
        $global:PSBoundParameters.Remove('secrets')
        $global:PSBoundParameters.Add('uuid',[Guid]::NewGuid().Guid)
        $global:PSBoundParameters.Add('PullServerPort',$PullServerPort)
        Set-Content -Path 'C:\Windows\Temp\nodeinfo.json' -Value $($global:PSBoundParameters | ConvertTo-Json -Depth 2)
    }
    if($global:PSBoundParameters.ContainsKey('secrets')){
        $keys = @('branch_rsConfigs', 'mR', 'git_username', 'gitBr', 'git_oAuthtoken','shared_key')
        foreach($key in $keys){
            if($secrets.keys -notcontains $key){ 
                Write-Verbose "$key key is missing from secrets parameter"
                exit
            }
            if((Test-Path -Path $defaultPath ) -eq $false) {New-Item -Path $defaultPath -ItemType Directory -Force}
            Set-Content -Path (Join-Path $defaultPath 'secrets.json') -Value $($secrets | ConvertTo-Json -Depth 2)
        }
    }
    if( Test-Path 'C:\Windows\Temp\nodeinfo.json' ) {
        Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json | Set-Variable -Name nodeinfo -Scope Global
    }
    if(Test-Path (Join-Path $defaultPath 'secrets.json') ) {
        Get-Content $(Join-Path $defaultPath 'secrets.json') -Raw | ConvertFrom-Json | Set-Variable -Name d -Scope Global
    }
}
function Create-BootTask {
    foreach( $key in ($global:PSBoundParameters.Keys -notmatch 'secrets') ){$arguments += "-$key $($global:PSBoundParameters[$key]) "}
    if(!(Get-ScheduledTask -TaskName 'rsBoot' -ErrorAction SilentlyContinue)) {Start-Process -Wait schtasks.exe -ArgumentList "/create /sc Onstart /tn rsBoot /ru System /tr ""PowerShell.exe -ExecutionPolicy Bypass -file $PSCommandPath $arguments"""}
}
function Set-rsPlatform {
@'
    Configuration initDSC {
        Import-DscResource -ModuleName rsPlatform
        Node $env:COMPUTERNAME
        {
            rsPlatform Modules
            {
                Ensure = 'Present'
            }
        }
    }
    initDSC -OutputPath 'C:\Windows\Temp' -Verbose
    Start-DscConfiguration -Path 'C:\Windows\Temp' -Wait -Verbose -Force
'@ | Invoke-Expression -Verbose
}
function Set-LCM {
@"
    [DSCLocalConfigurationManager()]
    Configuration LCM
    {
        Node $env:COMPUTERNAME
        {
            if( Test-Path 'C:\Windows\Temp\nodeinfo.json' ){
                Settings {
                    AllowModuleOverwrite = 1
                    ConfigurationMode = 'ApplyAndAutoCorrect'
                    RefreshMode = 'Pull'
                    RebootNodeIfNeeded = 1
                    ConfigurationID = "$($nodeinfo.uuid)"
                }
                ConfigurationRepositoryWeb DSCHTTPS {
                    Name= 'DSCHTTPS'
                    ServerURL = "https://$($nodeinfo.PullServerName):$($nodeinfo.PullServerPort)/PSDSCPullServer.svc"
                    CertificateID = (Get-ChildItem Cert:\LocalMachine\Root | ? Subject -EQ "CN=$($nodeinfo.PullServerName)").Thumbprint
                    AllowUnsecureConnection = 0
                } 
            }
            else {
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
        }
    }
    if( Test-Path 'C:\Windows\Temp\nodeinfo.json' ) {
        Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json | Set-Variable -Name nodeinfo -Scope Global
    }
    LCM -OutputPath 'C:\Windows\Temp' -Verbose
    Set-DscLocalConfigurationManager -Path 'C:\Windows\Temp' -Verbose
"@ | Invoke-Expression -Verbose
}
function Set-Pull {
    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
    Invoke-Expression $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) $($d.mR, 'rsPullServer.ps1' -join '\')) -Verbose
}

Configuration Boot {
    param(
        [String] $PullServerIP
    )
    node $env:COMPUTERNAME {
        Script DevOpsDir {
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
            SetScript = {(New-Object -TypeName System.Net.webclient).DownloadFile('http://download.microsoft.com/download/B/5/1/B5130F9A-6F07-481A-B4A6-CEDED7C96AE2/WindowsBlue-KB3037315-x64.msu', 'C:\Windows\Temp\WindowsBlue-KB3037315-x64.msu')}

            TestScript = {Test-Path -Path 'C:\Windows\Temp\WindowsBlue-KB3037315-x64.msu'}

            GetScript = {
                return @{
                    'Result' = 'C:\Windows\Temp\WindowsBlue-KB3037315-x64.msu'
                }
            }
            DependsOn = @('[Script]DevOpsDir','[Script]GetMakeCert')
        }
        Script InstallWmf5 {
            SetScript = {
                Start-Process -Wait -FilePath 'C:\Windows\Temp\WindowsBlue-KB3037315-x64.msu' -ArgumentList '/quiet' -Verbose
                Start-Sleep -Seconds 30
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

            TestScript = {Test-Path -Path 'C:\Windows\system32\makecert.exe'}

            GetScript = {
                return @{
                    'Result' = $(Test-Path  -Path 'C:\Windows\system32\makecert.exe')
                }
            }
        }
        script DSCBootTask {

            GetScript = {
                $result = Get-ScheduledTask -TaskName '\Microsoft\Windows\Desired State Configuration\DSCRestartBootTask' -ErrorAction SilentlyContinue
                if(!($result)) {
                    $result = 'No Boot Task'
                }
                return @{
                    'Result' = $result
                }
            }
            TestScript = {
                $test = Get-ScheduledTask -TaskName '\Microsoft\Windows\Desired State Configuration\DSCRestartBootTask' -ErrorAction SilentlyContinue
                if($test) {
                    return $true
                }
                else {
                    return $false
                }
            }
            SetScript = {
                $test = Get-ScheduledTask -TaskName '\Microsoft\Windows\Desired State Configuration\DSCRestartBootTask' -ErrorAction SilentlyContinue
                if($test) {
                    return $true
                }
                else {
                    schtasks.exe /Create /SC ONSTART /TN '\Microsoft\Windows\Desired State Configuration\DSCRestartBootTask' /RU System /F /TR "PowerShell.exe -NonInt -Window Hidden -Command 'Invoke-CimMethod -Namespace root/Microsoft/Windows/DesiredStateConfiguration –ClassName MSFT_DSCLocalConfigurationManager -MethodName PerformRequiredConfigurationChecks -Arg @{Flags = [System.UInt32]2 }'"
                }
            }
        }
        script DSCConsistencyTask {

            GetScript = {
                $result = Get-ScheduledTask -TaskName '\Microsoft\Windows\Desired State Configuration\Consistency' -ErrorAction SilentlyContinue
                if(!($result)) {
                    $result = 'No Consistency Task'
                }
                return @{
                    'Result' = $result
                }
            }
            TestScript = {
                $test = Get-ScheduledTask -TaskName '\Microsoft\Windows\Desired State Configuration\Consistency' -ErrorAction SilentlyContinue
                if($test) {
                    return $true
                }
                else {
                    return $false
                }
            }
            SetScript = {
                $test = Get-ScheduledTask -TaskName '\Microsoft\Windows\Desired State Configuration\Consistency' -ErrorAction SilentlyContinue
                if($test) {
                    return $true
                }
                else {
                    schtasks.exe /Create /sc Minute /mo 15 /TN '\Microsoft\Windows\Desired State Configuration\Consistency' /RU System /F /TR "PowerShell.exe -NonInt -Window Hidden -Command 'Invoke-CimMethod -Namespace root/Microsoft/Windows/DesiredStateConfiguration -Cl MSFT_DSCLocalConfigurationManager -Method PerformRequiredConfigurationChecks -Arguments @{Flags = [System.UInt32]2}'"
                }
            }

        }
        if(!($PullServerIP)){
            Script GetGit {
                SetScript = {(New-Object -TypeName System.Net.webclient).DownloadFile('https://raw.githubusercontent.com/rsWinAutomationSupport/Git/universal/Git-Windows-Latest.exe','C:\Windows\Temp\Git-Windows-Latest.exe' )}

                TestScript = {if(Test-Path -Path 'C:\Windows\Temp\Git-Windows-Latest.exe') {return $true} else {return $false}}

                GetScript = {
                    return @{
                        'Result' = 'C:\Windows\Temp\Git-Windows-Latest.exe'
                    }
                }
                DependsOn = '[Script]Installwmf5'
            }
            Package InstallGit {
                Name = 'Git version 1.9.5-preview20150319'
                Path = 'C:\Windows\Temp\Git-Windows-Latest.exe'
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
            Script UpdateGitConfig {
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
            Script Clone_rsConfigs {
                SetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
                    Set-Location ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) -Verbose
                    Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "clone --branch $($d.branch_rsConfigs) $((('https://', $($d.git_Oauthtoken), '@github.com' -join ''), $($d.git_username), $($d.mR , '.git' -join '')) -join '/')"
                }
                TestScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
                    if(Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) $d.mR)) 
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
                    return @{
                        'Result' = (Test-Path -Path $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) $($d.mR)) -PathType Container)
                    }
                }
                DependsOn = '[Script]UpdateGitConfig'
            }
            File rsPlatformDir {
                SourcePath = Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) $($d.mR, 'rsPlatform' -join '\')
                DestinationPath = 'C:\Program Files\WindowsPowerShell\Modules\rsPlatform'
                Type = 'Directory'
                Recurse = $true
                MatchSource = $true
                Ensure = 'Present'
                DependsOn = '[Script]Clone_rsConfigs'
            }
            Script ClonersPackageSourceManager {
                SetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
                    Set-Location 'C:\Program Files\WindowsPowerShell\Modules\'
                    Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "clone --branch $($d.gitBr) https://github.com/rsWinAutomationSupport/rsPackageSourceManager.git"
                }
                TestScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
                    if(Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\rsPackageSourceManager\DSCResources') 
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    $d = Get-Content $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) 'secrets.json') -Raw | ConvertFrom-Json
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
                    & makecert.exe -b $yesterday -r -pe -n $('CN=', $env:COMPUTERNAME -join ''), -ss my, -sr localmachine, -len 2048
                }
                TestScript = {
                    if( Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')} ) 
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    return @{
                        'Result' = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}).Thumbprint
                    }
                }
                DependsOn = '[Script]GetMakeCert'
            }
            WindowsFeature IIS {
                Ensure = 'Present'
                Name = 'Web-Server'
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
                    $publicCert = [System.Convert]::ToBase64String((Get-ChildItem Cert:\LocalMachine\My | ? Subject -eq "CN=$env:COMPUTERNAME").RawData)
                    $store = Get-Item Cert:\LocalMachine\Root
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                    $store.Add( $(New-Object System.Security.Cryptography.X509Certificates.X509Certificate -ArgumentList @(,[System.Convert]::fromBase64String($publicCert))) )
                    $store.Close()
                }
                TestScript = {
                    if((Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}).Thumbprint -eq (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}).Thumbprint) 
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    return @{
                        'Result' = (Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $('CN=', $env:COMPUTERNAME -join '')}).Thumbprint
                    }
                }
                DependsOn = '[Script]CreateServerCertificate'
            }
        }
        else{
            Script CreateEncryptionCertificate {
                SetScript = {
                    $yesterday = (Get-Date).AddDays(-1) | Get-Date -Format MM/dd/yyyy
                    $cN = 'CN=' + $env:COMPUTERNAME + '_enc'
                    Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $cN} | Remove-Item -Force -Verbose -ErrorAction SilentlyContinue
                    & makecert.exe -b $yesterday -r -pe -n $cN -sky exchange, -ss root, -sr localmachine, -len 2048, -eku 1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2
                }
                TestScript = {
                    if( (Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $('CN=' + $env:COMPUTERNAME + '_enc')} ))
                    {return $true}
                    else 
                    {return $false}
                }
                GetScript = {
                    return @{
                        'Result' = (Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object -FilterScript {$_.Subject -eq $('CN=' + $env:COMPUTERNAME + '_enc')}
                        ).Thumbprint
                    }
                }
                DependsOn = '[Script]GetMakeCert'
            }
            WindowsFeature MSMQ {
                Name = 'MSMQ'
                Ensure = 'Present'
            }
            Script GetPullPublicCert {
                SetScript = {
                    $nodeinfo = Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json
                    $uri = "https://$($nodeinfo.PullServerIP):$($nodeinfo.PullServerPort)"
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    $store = Get-Item Cert:\LocalMachine\Root
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                    $store.Add($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                    $store.Close()
                }
                TestScript = {
                    $nodeinfo = Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json
                    $uri = "https://$($nodeinfo.PullServerIP):$($nodeinfo.PullServerPort)"
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    if( (Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq ($cert.GetCertHashString()) ).count -eq 0 ){return $false}
                    else {return $true}
                }
                GetScript = {
                    $nodeinfo = Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json
                    $uri = "https://$($nodeinfo.PullServerIP):$($nodeinfo.PullServerPort)"
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    return @{
                        'Result' = (Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq ($cert.GetCertHashString()))
                    }
                }
                DependsOn = '[WindowsFeature]MSMQ'
            }
            Script SetHostFile {
                SetScript = {
                    $nodeinfo = Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json
                    $hostfile = (Get-Content -Path 'C:\Windows\system32\drivers\etc\hosts').where({$_ -notmatch $($nodeinfo.PullServerIP) -AND $_ -notmatch $($nodeinfo.PullServerName)})
                    $hostfile += $( $($nodeinfo.PullServerIP)+ "`t`t" + $($nodeinfo.PullServerName))
                    Set-Content -Path 'C:\Windows\System32\Drivers\etc\hosts' -Value $hostfile -Force
                }
                TestScript = {
                    return $false
                }
                GetScript = {
                    return @{
                        'Result' = $true
                    }
                }
                DependsOn = '[WindowsFeature]MSMQ'
            }
            Script SendClientPublicCert {
                SetScript = {
                    $nodeinfo = Get-Content 'C:\Windows\Temp\nodeinfo.json' -Raw | ConvertFrom-Json
                    [Reflection.Assembly]::LoadWithPartialName('System.Messaging') | Out-Null
                    $publicCert = ((Get-ChildItem Cert:\LocalMachine\Root | ? Subject -eq "CN=$env:COMPUTERNAME`_enc").RawData)
                    $msgbody = @{'Name' = "$env:COMPUTERNAME"
                        'uuid' = $($nodeinfo.uuid)
                        'dsc_config' = $($nodeinfo.dsc_config)
                        'shared_key' = $($nodeinfo.shared_key)
                        'PublicCert' = "$([System.Convert]::ToBase64String($publicCert))"
                    } | ConvertTo-Json
                    do {
                        try {
                            $msg = New-Object System.Messaging.Message
                            $msg.Label = 'execute'
                            $msg.Body = $msgbody
                            $queueName = "FormatName:DIRECT=HTTPS://$($nodeinfo.PullServerName)/msmq/private$/rsdsc"
                            $queue = New-Object System.Messaging.MessageQueue ($queueName, $False, $False)
                            $queue.Send($msg)
                            Start-Sleep -Seconds 30
                            $statusCode = (Invoke-WebRequest -Uri "https://$($nodeinfo.PullServerName):$($nodeinfo.PullServerPort)/PSDSCPullServer.svc/Action(ConfigurationId=`'$($nodeinfo.uuid)`')/ConfigurationContent" -ErrorAction SilentlyContinue -UseBasicParsing).statuscode
                        }
                        catch {
                            Write-Verbose "Error retrieving configuration $($_.Exceptions.message)"
                        }
                    }
                    while($statusCode -ne 200)
                }
                TestScript = { Return $false }
                GetScript = {
                    return @{
                        'Result' = $true
                    }
                }
                DependsOn = @('[WindowsFeature]MSMQ','[Script]SetHostFile')
            }                
        }
    } 
}

Create-BootTask
Create-Secrets
Boot -PullServerIP $PullServerIP -OutputPath 'C:\Windows\Temp' -Verbose
Start-DscConfiguration -Wait -Force -Verbose -Path 'C:\Windows\Temp'
Set-LCM
if( !($PullServerIP) ){
    Set-rsPlatform
    Set-Pull
}
else {
    Update-DscConfiguration -Wait -Verbose
}
Unregister-ScheduledTask -TaskName rsBoot -Confirm:$false