# Pure recovery-protocol fixtures. No compiled code, process control, network,
# administrator token, registry, firewall, build or protected configuration access.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\WfpRecoveryProtocol.ps1')
$run='0123456789abcdef0123456789abcdef'
$roles=@('ipv4-address','ipv4-port','ipv4-protocol','ipv6-deny','proxy-failure')
function New-Plan([int]$Count=4){
    return [pscustomobject]@{
        SchemaVersion=2;Run=$run;Persistent=$true;Dynamic=$false
        SublayerKey='11111111-1111-1111-1111-111111111111'
        Filters=@(for($i=0;$i -lt $Count;$i++){
            [pscustomobject]@{Role=$roles[$i];Key=([guid]::Parse(('22222222-2222-2222-2222-22222222222'+[string]$i))).ToString('B');ObservedId=900+$i}
        })
    }
}
$results=New-Object System.Collections.Generic.List[object]
function Test([string]$Name,[scriptblock]$Body){
    try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Status='PASS'})}
    catch{$results.Add([pscustomobject]@{Name=$Name;Status='FAIL';Detail=$_.Exception.Message})}
}
function Reject([scriptblock]$Body){
    $rejected=$false
    try{$null=& $Body}catch{$rejected=$true}
    if(-not $rejected){throw 'Unsafe protocol input was accepted'}
}
Test 'four-role inspect emits GUIDs and ignores numeric observations' {
    $p=New-Plan
    $p.Filters[0].ObservedId='DO_NOT_USE'
    $a=@(Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect)
    if($a.Count -ne 7 -or $a[0] -cne 'inspect' -or $a[3] -cne $p.Filters[0].Key -or $a -contains 'DO_NOT_USE'){throw 'GUID dispatch mismatch'}
}
Test 'fifth role is cleanup-only' {
    $p=New-Plan 5
    $a=@(Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup)
    if($a.Count -ne 8){throw 'Fifth key lost'}
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect}
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action block-proxy}
}
Test 'all supported actions reject a duplicate key' {
    foreach($action in @('inspect','cleanup','block-proxy')){
        $p=New-Plan;$p.Filters[1].Key=$p.Filters[0].Key
        Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action $action}
    }
}
Test 'wrong run cannot select another probe' {
    $p=New-Plan;$p.Run='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup}
}
Test 'JSON journal roundtrip and lowercase run match native protocol' {
    $p=(New-Plan)|ConvertTo-Json -Depth 6|ConvertFrom-Json
    $a=@(Get-WfpRecoveryArguments -Plan $p -Run $run -Action block-proxy)
    if($a[0] -cne 'block-proxy' -or $a.Count -ne 7){throw 'Serialized journal lost protocol identity'}
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run.ToUpperInvariant() -Action cleanup}
}
Test 'missing/reordered/extra roles are rejected' {
    $p=New-Plan;$p.Filters=@($p.Filters[0..2])
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect}
    $p=New-Plan;$p.Filters[1].Role='ipv6-deny'
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect}
    $p=New-Plan 5;$p.Filters+=@($p.Filters[0])
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup}
}
Test 'bad/empty/sublayer filter GUIDs are rejected' {
    foreach($key in @('bad','00000000-0000-0000-0000-000000000000','11111111-1111-1111-1111-111111111111')){
        $p=New-Plan;$p.Filters[0].Key=$key
        Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup}
    }
}
Test 'dynamic/mistyped persistence cannot be healthy persistent recovery' {
    $p=New-Plan;$p.Persistent='true'
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect}
    $p=New-Plan;$p.Dynamic=$true
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect}
}
Test 'unknown/mistyped schema never falls back to IDs' {
    foreach($version in @(1,3,'2',$null)){
        $p=New-Plan;$p.SchemaVersion=$version
        $p|Add-Member NoteProperty FilterIds @(1,2,3,4)
        Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup}
    }
}
Test 'mixed identities in v2 are rejected' {
    $p=New-Plan;$p|Add-Member NoteProperty FilterIds @(1,2,3,4)
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup}
}
Test 'legacy cleanup requires explicit opt-in; cannot inspect or block' {
    $p=[pscustomobject]@{SublayerKey='11111111-1111-1111-1111-111111111111';FilterIds=@(1,2,3,4)}
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup}
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action inspect -LegacyCleanup}
    Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action block-proxy -LegacyCleanup}
    $a=@(Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup -LegacyCleanup)
    if($a[0] -cne 'cleanup-legacy-ids' -or $a.Count -ne 7){throw 'Legacy cleanup protocol mismatch'}
}
Test 'legacy duplicate/zero/signed/overflow IDs rejected' {
    foreach($bad in @(@(1,1,3,4),@(0,2,3,4),@('-1',2,3,4),@('18446744073709551616',2,3,4))){
        $p=[pscustomobject]@{SublayerKey='11111111-1111-1111-1111-111111111111';FilterIds=$bad}
        Reject {Get-WfpRecoveryArguments -Plan $p -Run $run -Action cleanup -LegacyCleanup}
    }
}
[pscustomobject]@{Scope='PURE_POWERSHELL_PROTOCOL_ONLY';PowerShell=$PSVersionTable.PSVersion.ToString();Results=@($results.ToArray());Compiled=$false;ProjectProcessesStarted=$false;WfpAccessed=$false}|ConvertTo-Json -Depth 6
if(@($results|Where-Object {$_.Status -ne 'PASS'}).Count){exit 2}
