# Pure protocol validation only; no process, WFP, registry or network operations.
function Get-WfpRecoveryArguments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$Plan,
        [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$Run,
        [Parameter(Mandatory=$true)][ValidateSet('inspect','cleanup','block-proxy')][string]$Action,
        [switch]$LegacyCleanup
    )
    if($Run -cnotmatch '^[a-f0-9]{32}$'){throw 'Run must be lowercase hexadecimal, matching the native protocol'}
    $layer=[guid]::Empty
    if(-not [guid]::TryParse([string]$Plan.SublayerKey,[ref]$layer) -or $layer -eq [guid]::Empty){throw 'Invalid WFP sublayer GUID'}
    if($LegacyCleanup){
        if($Action -cne 'cleanup' -or $null -ne $Plan.SchemaVersion -or $null -ne $Plan.Filters){throw 'Legacy IDs are only accepted for explicit unversioned historical cleanup'}
        $ids=@($Plan.FilterIds)
        if($ids.Count -notin @(4,5)){throw 'Invalid legacy filter count'}
        $seen=New-Object 'System.Collections.Generic.HashSet[UInt64]'
        $result=@('cleanup-legacy-ids',$Run,$layer.ToString('B'))
        foreach($value in $ids){
            $id=[UInt64]0
            if([string]$value -cnotmatch '^[0-9]+$' -or -not [UInt64]::TryParse([string]$value,[ref]$id) -or $id -eq 0 -or -not $seen.Add($id)){throw 'Invalid or duplicate legacy filter ID'}
            $result += $id.ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        return $result
    }
    if(($Plan.SchemaVersion -isnot [int] -and $Plan.SchemaVersion -isnot [long]) -or $Plan.SchemaVersion -ne 2 -or $Plan.Run -cne $Run -or $null -ne $Plan.FilterIds){throw 'WFP schema/run mismatch; numeric fallback is forbidden'}
    if($Plan.Persistent -isnot [bool] -or -not $Plan.Persistent -or $Plan.Dynamic -isnot [bool] -or $Plan.Dynamic){throw 'Recovery requires an explicit persistent probe plan'}
    $filters=@($Plan.Filters)
    if($filters.Count -notin @(4,5) -or ($Action -cne 'cleanup' -and $filters.Count -ne 4)){throw 'Invalid filter role count'}
    $roles=@('ipv4-address','ipv4-port','ipv4-protocol','ipv6-deny','proxy-failure')
    $keys=New-Object 'System.Collections.Generic.HashSet[Guid]'
    $null=$keys.Add($layer)
    $result=@($Action,$Run,$layer.ToString('B'))
    for($i=0;$i -lt $filters.Count;$i++){
        $key=[guid]::Empty
        if($filters[$i].Role -cne $roles[$i] -or -not [guid]::TryParse([string]$filters[$i].Key,[ref]$key) -or $key -eq [guid]::Empty -or -not $keys.Add($key)){throw 'Invalid, duplicate or reordered WFP role/key'}
        # ObservedId is evidence only. Never use it to recover a v2 object.
        $result += $key.ToString('B')
    }
    return $result
}
