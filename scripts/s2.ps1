[CmdletBinding()]
Param
(
    [string] $Param1,
    [string] $Param2
)

$MyInvocation.MyCommand.Name
Write-Verbose " "
Write-Verbose "Param1 is $Param1"
Write-Verbose "Param2 is $Param2"
Write-Verbose " "