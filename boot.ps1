param (
    [String] $defaultPath  = 'C:\DevOps',
    [string] $NodeInfoPath = 'C:\Windows\Temp\nodeinfo.json',
    [String] $PullServerAddress,
    [String] $dsc_config,
    [String] $shared_key,
    [int] $PullServerPort = '8080',
    [Hashtable] $secrets
    )

[Environment]::SetEnvironmentVariable('defaultPath',$defaultPath,'Machine')
[Environment]::SetEnvironmentVariable('nodeInfoPath',$NodeInfoPath,'Machine')
$global:PSBoundParameters = $PSBoundParameters

function Get-PullServerInfo{

Add-Content -Path "C:\log.txt" -Value "$(Get-Date) - Begin Get-PullServerInfo"

    $PullServerPossibleIP = Resolve-DnsName -Name $global:PSBoundParameters.PullServerAddress | Where {$_.IP4Address} | Select-Object -ExpandProperty IP4Address


    $PullServerValidIPs = @()

    foreach($IP in $PullServerPossibleIP){

        $check =  Test-NetConnection $IP -RemotePort $PullServerPort

        if($check.TcpTestSucceeded){$PullServerValidIPs += @{$IP = $check.NetworkIsolationContext}}
    }


    if($PullServerValidIPs.values -contains 'Private Network'){
        $PullServerIP = ($PullServerValidIPs | Where {$_.values -contains 'Private Network'}).keys | Get-Random
    }
    else{
        $PullServerIP = $PullServerValidIPs.keys | Get-Random
    }

    $PullServerIP | Set-Variable -Name PullServerIP -Scope Global

    $uri = "https://google.com"
    $webRequest = [Net.WebRequest]::Create($uri)
    try { $webRequest.GetResponse() } catch {}
    $PullServerName = $webRequest.ServicePoint.Certificate.Subject -replace '^CN\=','' -replace ',.*$',''

    $PullServerName | Set-Variable -Name PullServerName -Scope Global

Add-Content -Path "C:\log.txt" -Value "$(Get-Date) - End Get-PullServerInfo"    
}






function Create-Secrets {
Add-Content -Path "C:\log.txt" -Value "Begin Create Secrets"
    if($global:PSBoundParameters.ContainsKey('shared_key')){
        $global:PSBoundParameters.Remove('secrets')
        $global:PSBoundParameters.Add('uuid',[Guid]::NewGuid().Guid)
        $global:PSBoundParameters.Add('PullServerPort',$PullServerPort)
        Set-Content -Path ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').toString()) -Value $($global:PSBoundParameters | ConvertTo-Json -Depth 2)
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
    if( Test-Path ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) ) {
        Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json | Set-Variable -Name nodeinfo -Scope Global
    }
    if(Test-Path (Join-Path $defaultPath 'secrets.json') ) {
        Get-Content $(Join-Path $defaultPath 'secrets.json') -Raw | ConvertFrom-Json | Set-Variable -Name d -Scope Global
    }
Add-Content -Path "C:\log.txt" -Value "End Create-Secrets"
}


function Create-BootTask {
Add-Content -Path "C:\log.txt" -Value "$(Get-Date) - Begin Create-BootTask"

    foreach( $key in ($global:PSBoundParameters.Keys -notmatch 'secrets') ){$arguments += "-$key $($global:PSBoundParameters[$key]) "}
    if(!(Get-ScheduledTask -TaskName 'rsBoot' -ErrorAction SilentlyContinue)) {
        $A = New-ScheduledTaskAction –Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -file $PSCommandPath $arguments"
        $T = New-ScheduledTaskTrigger -AtStartup
        $P = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
        $S = New-ScheduledTaskSettingsSet
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
        Register-ScheduledTask rsBoot -InputObject $D
    }
Add-Content -Path "C:\log.txt" -Value "$(Get-Date) - End Create-BootTask"
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
    Configuration LCM
    {
        Node $env:COMPUTERNAME
        {
                if( Test-Path ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) ){
                    LocalConfigurationManager
                    {
                        AllowModuleOverwrite = 'True'
                        ConfigurationID = "$($nodeinfo.uuid)"
                        CertificateID = (Get-ChildItem Cert:\LocalMachine\Root | ? Subject -EQ "CN=$($nodeinfo.PullServerName)").Thumbprint
                        ConfigurationModeFrequencyMins = 30
                        ConfigurationMode = 'ApplyAndAutoCorrect'
                        RebootNodeIfNeeded = 'True'
                        RefreshMode = 'Pull'
                        RefreshFrequencyMins = 30
                        DownloadManagerName = 'WebDownloadManager'
                        DownloadManagerCustomData = (@{ServerUrl = "https://$($nodeinfo.PullServerName):$($nodeinfo.PullServerPort)/PSDSCPullServer.svc"; AllowUnsecureConnection = "false"})
                    }
                }
                else {
                    LocalConfigurationManager
                    {
                        AllowModuleOverwrite = 'True'
                        ConfigurationModeFrequencyMins = 30
                        ConfigurationMode = 'ApplyAndAutoCorrect'
                        RebootNodeIfNeeded = 'True'
                        RefreshMode = 'PUSH'
                        RefreshFrequencyMins = 30
                    }
                }
        }
    }


    if( Test-Path ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) ) {
        Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json | Set-Variable -Name nodeinfo
    }
    LCM -OutputPath 'C:\Windows\Temp' -Verbose
    Set-DscLocalConfigurationManager -Path 'C:\Windows\Temp' -Verbose
"@ | Invoke-Expression -Verbose
}


function Set-Pull {
    try{
        Invoke-Expression $(Join-Path ([Environment]::GetEnvironmentVariable('defaultPath','Machine')) $($global:d.mR, 'rsPullServer.ps1' -join '\')) -Verbose
    }
    catch {
        Write-Verbose "Error in rsPullServer $($_.Exception.message)"
    }
}


Configuration Boot {
    param(
        [String] $PullServerIP
    )
    node $env:COMPUTERNAME {
        File DevOpsDir{
            DestinationPath = [Environment]::GetEnvironmentVariable('defaultPath','Machine')
            Ensure = 'Present'
            Type = 'Directory'
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
        Script GetWMF4 {
            SetScript = {Invoke-WebRequest -Uri 'http://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu' -OutFile 'C:\Windows\temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -UseBasicParsing}

            TestScript = {
                if( $PSVersionTable.PSVersion.Major -ge 4 ) { return $true }
                if( -not (Test-Path -Path 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu') ) { return $false }
                else{ return $true }
            }

            GetScript = {
                return @{
                    'Result' = 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu'
                }
            }
            DependsOn = @('[File]DevOpsDir','[Script]GetMakeCert')
        }
        Script InstallWMF4 {
            SetScript = {
                Start-Process -Wait -FilePath 'C:\Windows\Temp\Windows6.1-KB2819745-x64-MultiPkg.msu' -ArgumentList '/quiet' -Verbose
                Start-Sleep -Seconds 30
                $global:DSCMachineStatus = 1 
            }
            TestScript = {
                if($PSVersionTable.PSVersion.Major -ge 4) 
                {return $true}
                else 
                {return $false}
            }
            GetScript = {
                return @{
                    'Result' = $PSVersionTable.PSVersion.Major
                }
            }
            DependsOn = '[Script]GetWMF4'
        }

        if(!($PullServerIP)){

            Package InstallGit {
                Name = 'Git version 1.9.5-preview20150319'
                Path = 'http://raw.githubusercontent.com/rsWinAutomationSupport/Git/universal/Git-Windows-Latest.exe'
                ProductId = ''
                Arguments = '/verysilent'
                Ensure = 'Present'
            }
            Registry SetGitPath {       
                Ensure = 'Present'
                Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
                ValueName = 'Path'
                ValueType = 'ExpandString'
                ValueData = $(
                    if( (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path -like "*${env:ProgramFiles(x86)}\Git\bin\*" ){
                        (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path
                    }
                    else{
                        ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path), "${env:ProgramFiles(x86)}\Git\bin\" -join ';' 
                    }
                )
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
                    & makecert.exe -b $yesterday -r -pe -n $('CN=', $env:COMPUTERNAME -join ''), -sky exchange, -ss my, -sr localmachine, -len 2048
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
                    $store = Get-Item Cert:\LocalMachine\Root
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                    $store.Add( $(New-Object System.Security.Cryptography.X509Certificates.X509Certificate -ArgumentList @(,(Get-ChildItem Cert:\LocalMachine\My | ? Subject -eq "CN=$env:COMPUTERNAME").RawData)) )
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
                    $nodeinfo = Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json
                    $uri = "https://$($nodeinfo.PullServerIP):$($nodeinfo.PullServerPort)"
                    do {
                        $rerun = $true
                        try {
                            Invoke-WebRequest -Uri $uri -ErrorAction SilentlyContinue -UseBasicParsing
                        }
                        catch {
                            Write-Verbose "Error retrieving configuration: $($_.Exception.message)"
                            if($($_.Exception.message) -like '*SSL/TLS*') { $rerun = $false }
                            else { Start-Sleep -Seconds 10 }
                        }
                    }
                    while($rerun)
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    Write-Verbose "Adding PullServer Root Certificate to Cert:\LocalMachine\Root"
                    $store = Get-Item Cert:\LocalMachine\Root
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadWrite')
                    $store.Add($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                    $store.Close()
                }
                TestScript = {
                    $nodeinfo = Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json
                    $uri = "https://$($nodeinfo.PullServerIP):$($nodeinfo.PullServerPort)"
                    do {
                        $rerun = $true
                        try {
                            Invoke-WebRequest -Uri $uri -ErrorAction SilentlyContinue -UseBasicParsing
                        }
                        catch {
                            Write-Verbose "Error retrieving configuration: $($_.Exception.message)"
                            if($($_.Exception.message) -like '*SSL/TLS*') { $rerun = $false }
                            else{ Start-Sleep -Seconds 10 }
                        }
                    }
                    while($rerun)
                    $webRequest = [Net.WebRequest]::Create($uri)
                    try { $webRequest.GetResponse() } catch {}
                    $cert = $webRequest.ServicePoint.Certificate
                    if( (Get-ChildItem Cert:\LocalMachine\Root | ? Thumbprint -eq ($cert.GetCertHashString()) ).count -eq 0 ){return $false}
                    else {return $true}
                }
                GetScript = {
                    $nodeinfo = Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json
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
                    $nodeinfo = Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json
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
                    $nodeinfo = Get-Content ([Environment]::GetEnvironmentVariable('nodeInfoPath','Machine').ToString()) -Raw | ConvertFrom-Json
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
                            Write-Verbose "Error retrieving configuration $($_.Exception.message)"
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


Add-Content -Path "C:\log.txt" -Value "$(Get-Date) - Starting"
Create-BootTask
Get-PullServerInfo
Create-Secrets
if( (Get-ChildItem WSMan:\localhost\Listener | ? Keys -eq "Transport=HTTP").count -eq 0 ){
    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}
}
Add-Content -Path "C:\log.txt" -Value "Post-WinRM"
Boot -PullServerIP $PullServerIP -OutputPath 'C:\Windows\Temp' -Verbose
Start-DscConfiguration -Wait -Force -Verbose -Path 'C:\Windows\Temp'
Set-LCM
if( !($PullServerAddress) ){
    Set-rsPlatform
    Set-Pull
}
else {
    Get-ScheduledTask -TaskName "Consistency" | Start-ScheduledTask
}
Unregister-ScheduledTask -TaskName rsBoot -Confirm:$false
