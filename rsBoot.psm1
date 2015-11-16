﻿# Import all local functions dependencies
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

function Write-DSCAutomationSettings 
{
    [CmdletBinding()]
    param
    (
        # Destination path for DSC Automation secure settings file
        [string]
        $Path = (Join-Path $env:defaultPath "DSCAutomationSettings.xml"),

        # Certificate hash with which to ecrypt the settigns
        [Parameter(Mandatory=$true)]
        [string]
        $CertThumbprint,

        # Contents of the settings file
        [Parameter(Mandatory=$true)]
        [hashtable]
        $Settings
    )

    # Create the certificate object whith which to secure the data
    $CertObject = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -like $CertThumbprint}

    # Process the provided hashtable and encrypt just the value string for each KV pair
    $DSCAutomationSettings = @{}
    $Settings.GetEnumerator() | Foreach {
        $EncodedValue = [system.text.encoding]::UTF8.GetBytes($_.Value)
        $EncryptedBytes = $CertObject.PublicKey.Key.Encrypt($EncodedValue, $true)
        $EncryptedValue = [System.Convert]::ToBase64String($EncryptedBytes)
        $DSCAutomationSettings.Add($($_.Key),$EncryptedValue)
    }

    # Adding cert hash value to databag to make it easier to decrypt the data later
    $DSCAutomationSettings.Add("CertThumbprint",$CertThumbprint)
    
    # Make a backup in case of there being an existing settings file
    if (Test-Path $Path)
    {
        Write-Verbose "Existing settings file found - making a backup..."
        $TimeDate = (Get-Date -Format ddMMMyyyy_hhmmss).ToString()
        Move-Item $Path -Destination ("$Path`-$TimeDate.bak") -Force
    }
    
    # Save the encrypted databag as a native PS hashtable object
    $DSCAutomationSettings | Export-Clixml -Path $Path -Force
}

function Read-DSCAutomationSettings 
{
    [CmdletBinding()]
    param
    (
        # Source path for the secure settings file
        [string]
        $Path = (Join-Path $env:defaultPath "DSCAutomationSettings.xml"),

        # Certificate hash with which to decrypt the settigns
        [string]
        $CertThumbprint
    )

    Write-Verbose "Importing the settings databag"
    $EncrytedSettings = Import-Clixml -Path $Path

    # Try to locate the the original cert using the hash in databag if one is not provided
    if (-not $CertThumbprint)
    {
        $CertThumbprint = $EncrytedSettings.CertThumbprint
    }
    # We will not need the thumbprint as part the returned settings
    $EncrytedSettings.Remove("CertThumbprint")

    # Create the certificate object whith which to decrypt the data
    $CertObject = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -like $CertThumbprint}

    # Process the provided hashtable and decrypt just the value string for each KV pair
    $DecryptedSettings = @{}
    $EncrytedSettings.GetEnumerator() | Foreach {
        $EncryptedBytes = [System.Convert]::FromBase64String($_.Value)
        $DecryptedBytes = $CertObject.PrivateKey.Decrypt($EncryptedBytes, $true)
        $DecryptedValue = [system.text.encoding]::UTF8.GetString($DecryptedBytes)
        $DecryptedSettings.Add($($_.Key),$DecryptedValue)
    }
    $DecryptedSettings
}
