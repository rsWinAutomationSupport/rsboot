# Import all local dependencies
Get-Item (Join-Path -Path $PSScriptRoot -ChildPath 'Scripts\*.ps1') | 
    ForEach-Object {
        Write-Verbose ("Importing sub-module {0}." -f $_.FullName)
        . $_.FullName
    }
