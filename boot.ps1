param (
    [String] $DefaultPath = 'C:\DevOps',
    [string] $PullServerIP,
    [Parameter(Mandatory=$true)]
    [Hashtable] $secrets
)
$VerbosePreference = 'Continue'

function Create-Secrets {
    if((Test-Path -Path 'C:\DevOps') -eq $false) {New-Item -Path 'C:\DevOps' -ItemType Directory -Force}
    Set-Content -Path 'C:\DevOps\secrets.ps1' -Value $($secrets | ConvertTo-Json -Depth 2)
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
    initDSC -OutputPath 'C:\Windows\Temp'
    Start-DscConfiguration -Path 'C:\Windows\Temp' -Wait -Verbose -Force
'@ | Invoke-Expression -Verbose
}



function Set-PullLCM {
  @'
    [DSCLocalConfigurationManager()]
    Configuration PullServerLCM
    {
   
       Node $env:COMPUTERNAME
       {
          Settings
          {
             ActionAfterReboot = 'ContinueConfiguration'
             RebootNodeIfNeeded = $true
             ConfigurationMode = 'ApplyAndAutoCorrect'
             RefreshMode = 'Push'
             ConfigurationModeFrequencyMins = 30
             AllowModuleOverwrite = $true
          }
       }
    }
    PullServerLCM -OutputPath 'C:\Windows\Temp' -Verbose
    Set-DscLocalConfigurationManager -Path 'C:\Windows\Temp' -Verbose
'@ | Invoke-Expression -Verbose
}

Configuration Boot0 {
  node $env:COMPUTERNAME {
    script DevOpsDir {
      SetScript = {
        New-Item -Path 'C:\DevOps' -ItemType Directory
      }

      TestScript = {
        if(Test-Path -Path 'C:\DevOps') 
        {
          return $true
        }
        else 
        {
          return $false
        }
      }

      GetScript = {
        return @{
          'Result' = (Test-Path -Path 'C:\DevOps' -PathType Container)
        }
      }
    }
    
    Script GetWMF5 {
      SetScript = {
        (New-Object -TypeName System.Net.webclient).DownloadFile('http://download.microsoft.com/download/B/5/1/B5130F9A-6F07-481A-B4A6-CEDED7C96AE2/WindowsBlue-KB3037315-x64.msu', 'C:\DevOps\WindowsBlue-KB3037315-x64.msu')
      }

      TestScript = {
        Test-Path -Path 'C:\DevOps\WindowsBlue-KB3037315-x64.msu'
      }

      GetScript = {
        return @{
          'Result' = $(Test-Path  -Path 'C:\DevOps\WindowsBlue-KB3037315-x64.msu')
        }
      }
      DependsOn = '[Script]DevOpsDir'
    }
   
    Script InstallWmf5 {
      SetScript = {
        Start-Process -Wait -FilePath 'C:\DevOps\WindowsBlue-KB3037315-x64.msu' -ArgumentList '/quiet'
        $global:DSCMachineStatus = 1 
      }
      TestScript = {
        if($PSVersionTable.PSVersion.Major -ge 5) 
        {
          return $true
        }
        else 
        {
          return $false
        }
      }
      GetScript = {
        return @{
          'Result' = $PSVersionTable.PSVersion.Major
        }
      }
      DependsOn = @('[Script]GetWMF5', '[Script]DevOpsDir', '[Script]CreateBootTask')
    }
    Script GetGit {
      SetScript = {
        (New-Object -TypeName System.Net.webclient).DownloadFile('https://raw.githubusercontent.com/rsWinAutomationSupport/Git/v1.9.4/Git-Windows-Latest.exe','C:\DevOps\Git-Windows-Latest.exe')
      }

      TestScript = {
        Test-Path -Path 'C:\DevOps\Git-Windows-Latest.exe' 
      }

      GetScript = {
        return @{
          'Result' = $(Test-Path  -Path 'C:\DevOps\Git-Windows-Latest.exe')
        }
      }
      DependsOn = '[Script]Installwmf5'
    }

    Script InstallGit {
      SetScript = {
        Start-Process -Wait -FilePath 'C:\DevOps\Git-Windows-Latest.exe' -ArgumentList '/verysilent'
      }

      TestScript = {
        if(Test-Path -Path 'C:\Program Files (x86)\Git\bin\git.exe') 
        {
          return $true 
        }
        else 
        {
          return $false 
        }
      }

      GetScript = {
        return @{
          'Result' = $(Test-Path -Path 'C:\Program Files (x86)\Git\bin\git.exe')
        }
      }
      DependsOn = '[Script]GetGit'
    }

    Script CreateBootTask {
      SetScript = {
        & schtasks.exe /create /sc Onstart /tn Boot /ru System /tr 'PowerShell.exe -ExecutionPolicy Bypass -file C:\DevOps\boot.ps1'
      }
      TestScript = {
        if(Get-ScheduledTask -TaskName 'Boot' -ErrorAction SilentlyContinue) 
        {
          return $true 
        }
        else 
        {
          return $false 
        }
      }
      GetScript = {
        return @{
          'Result' = $((Get-ScheduledTask -TaskName 'Boot' -ErrorAction SilentlyContinue).State)
        }
      }
      DependsOn = '[Script]DevOpsDir'
    }
    Registry SetGitPath
    {       
      Ensure = 'Present'
      Key = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
      ValueName = 'Path'
      ValueData = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\;${env:ProgramFiles(x86)}\Git\bin\"
      ValueType = 'ExpandString'
      DependsOn = '[Script]InstallGit'
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
    script clonersConfigs {
      SetScript = {
        $d = Get-Content 'C:\DevOps\secrets.ps1' | ConvertFrom-Json
        Set-Location 'C:\DevOps'
        Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "clone --branch $($d.branch_rsConfigs) $((('https://', $($d.git_Oauthtoken), '@github.com' -join ''), $($d.git_username), $($d.mR , '.git' -join '')) -join '/') rsConfigs"
      }

      TestScript = {
        $d = Get-Content 'C:\DevOps\secrets.ps1' | ConvertFrom-Json
        if(Test-Path -Path 'C:\DevOps\rsConfigs') 
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }

            GetScript = {
                $d = Get-Content 'C:\DevOps\secrets.ps1' | ConvertFrom-Json
                return @{
                    'Result' = (Test-Path -Path "C:\DevOps\$($d.mR)" -PathType Container)
                }
            }
            DependsOn = '[Script]UpdateGitConfig'
        }
        File rsPlatformDir
        {
            SourcePath = 'C:\DevOps\rsConfigs\rsPlatform'
            DestinationPath = 'C:\Program Files\WindowsPowerShell\Modules\rsPlatform'
            Type = 'Directory'
            Recurse = $true
            MatchSource = $true
            Ensure = 'Present'
            DependsOn = '[Script]clonersConfigs'
        }
        script clonersGit {
            SetScript = {
                $d = Get-Content 'C:\DevOps\secrets.ps1' | ConvertFrom-Json
                Set-Location 'C:\Program Files\WindowsPowerShell\Modules\'
                Start-Process -Wait 'C:\Program Files (x86)\Git\bin\git.exe' -ArgumentList "clone --branch $($d.gitBr) https://github.com/rsWinAutomationSupport/rsGit.git"
            }

            TestScript = {
                $d = Get-Content 'C:\DevOps\secrets.ps1' | ConvertFrom-Json
                if(Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\rsGit\DSCResources') 
                {
                    return $true
                }
                else 
                {
                    return $false
                }
            }

            GetScript = {
                $d = Get-Content 'C:\DevOps\secrets.ps1' | ConvertFrom-Json
                return @{
                    'Result' = (Test-Path -Path 'C:\Program Files\WindowsPowerShell\Modules\rsGit\DSCResources' -PathType Container)
                }
            }
            DependsOn = '[File]rsPlatformDir'
        }
   
    } 
    }
    
   

        Create-Secrets
        Boot0 -OutputPath 'C:\Windows\Temp' -Verbose
        Start-DscConfiguration -Wait -Force -Verbose -Path 'C:\Windows\Temp'
        Set-PullLCM
        Set-rsPlatform 