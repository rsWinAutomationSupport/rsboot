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
        
        Write-Verbose "Executing script: $script"
        & $(Join-Path -Path $ScriptPath -ChildPath $Script) @Parameters
    }
}

# Executes main Boot configuration of the DSC Bootstraping process
function Invoke-DSCBoot
{

}