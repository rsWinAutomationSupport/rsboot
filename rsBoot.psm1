# Import all local functions dependencies
Get-Item (Join-Path -Path $PSScriptRoot -ChildPath 'functions\*.ps1') | 
    ForEach-Object {
        Write-Verbose ("Importing sub-module {0}." -f $_.FullName)
        . $_.FullName
    }

# Executes pre-DSCbootstrap scripts from module scripts folder
function Invoke-PreBootScript
{
    [CmdletBinding()]
    Param
    (
        # Hashtable that contains filename of the script to run and any parameters it requires: @{"script.ps1" = "-param test"}
        [hashtable] $Scripts
    )

    $ScriptPath = $(Join-Path -Path $PSScriptRoot -ChildPath "scripts")
    ForEach ($item in $scripts.GetEnumerator())
    {
        $Script = $item.Name
        $Parameters = $item.Value
        $FullScriptPath = $(Join-Path -Path $ScriptPath -ChildPath $Script)
        if (Test-Path $FullScriptPath)
        {
            Write-Verbose "Executing script: $script"
            & $FullScriptPath @Parameters
        }
        else
        {
            Write-Verbose "Script '$Script' was not found at $ScriptPath"
        }
    }
}

# For DSC Clients, takes $PullServerAddress and sets PullServerIP and PullServerName variables
# If PullServerAddress is an IP, PullServerName is derived from the CN on the PullServer endpoint certificate
function Get-PullServerInfo
{
    param
    (
        [string] $PullServerAddress,
        [int] $PullPort,
        [int] $SleepSeconds = 10
    )

    # Check if PullServeraddress is a hostname or IP
    if($PullServerAddress -match '[a-zA-Z]')
    {
        $PullServerName = $PullServerAddress
    }
    else
    {
        $PullServerAddress | Set-Variable -Name PullServerIP -Scope Global
        # Attempt to get the PullServer's hostname from the certificate attached to the endpoint. 
        # Will not proceed unless a CN name is found.
        $uri = "https://$PullServerAddress`:$PullServerPort"
        do
        {
            $webRequest = [Net.WebRequest]::Create($uri)
            try 
            {
                Write-Verbose "Attempting to connect to Pull server and retrieve its public certificate..."
                $webRequest.GetResponse()
            }
            catch 
            {
            }
            Write-Verbose "Retrieveing Pull Server Name from its certificate"
            $PullServerName = $webRequest.ServicePoint.Certificate.Subject -replace '^CN\=','' -replace ',.*$',''
            if( -not($PullServerName) )
            {
                Write-Verbose "Could not retrieved server name from certificate - sleeping for $SleepSeconds seconds..."
                Start-Sleep -Seconds $SleepSeconds
            }
        } while ( -not($PullServerName) )
    }
    return $PullServerName
}

# Executes main Boot configuration of the DSC Bootstraping process
function Enable-WinRM
{
    if( (Get-ChildItem WSMan:\localhost\Listener | Where-Object Keys -eq "Transport=HTTP").count -eq 0 )
    {
        New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="http"}
    }
}

#Creates secrets.json on a pullserver
function Write-Secrets 
{
    param
    (
        # Pull server address
        [string] $PullServerAddress,

        # Name of the DSC script file that contains main Pull server config
        [string] $pullserver_config,

        # Contents of the secrets file
        [hashtable] $BootParameters,
        
        # Path where to store the secrets
        [string] $Path
    )

    Write-Verbose "Checking that  all compulsory secrets keys are present..."
    $keys = @('branch_rsConfigs', 'mR', 'git_username', 'gitBr', 'git_oAuthtoken','shared_key')
    ForEach($key in $keys)
    {
        if($BootParameters.keys -notcontains $key)
        { 
            Write-Verbose "$key key is missing from BootParameters"
            exit
        }
    }

    Write-Verbose "Preparing secrets and exporting as json file"
    # Add additional keys to the boot parameters, which were passed directly to the boot.ps1 script
    $BootParameters.Add("PullServerAddress","$PullServerAddress")
    $BootParameters.Add("pullserver_config","$pullserver_config")
    # Remove redundant keys
    $BootParameters.Remove("PreBoot")
    
    $SecretsPath = (Join-Path $Path 'secrets.json')
    # Make a backup in case of there being an existing secrets file
    if (Test-Path $SecretsPath)
    {
        Write-Verbose "Existing secrets.json found - making a backup..."
        $TimeDate = (Get-Date -Format ddMMMyyyy_hhmmss).ToString()
        Move-Item $SecretsPath -Destination (Join-Path $Path "secrets.json.$TimeDate.bak") -Force
    }
    Write-Verbose "Writing secrets.json"
    Set-Content -Path $SecretsPath -Value $($BootParameters | ConvertTo-Json -Depth 4)
}

