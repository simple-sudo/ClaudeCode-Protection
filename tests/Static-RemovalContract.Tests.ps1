# Embedded removal decision data only. No C# load, administrator state, native
# deletion, network change or actual uninstall/restart is performed.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$policy=Get-Content -LiteralPath (Join-Path $root 'src\ProtectionLifecycle\RemovalProtocol.json') -Raw|ConvertFrom-Json
function Assert([bool]$Value,[string]$Text){if(-not $Value){throw $Text}}
function Validate($p){
    Assert ($p.SchemaVersion -eq 1 -and $p.DefaultAction -ceq 'REFUSE') 'Unsafe default'
    Assert ($p.RecursiveDelete -is [bool] -and -not $p.RecursiveDelete) 'Recursive removal is forbidden'
    foreach($flag in @('PreserveUserConfig','PreserveEvidence')){Assert ($p.$flag -is [bool] -and $p.$flag) 'Preservation requirement missing'}
    Assert ($p.MaximumVersions -is [int] -or $p.MaximumVersions -is [long]) 'Capacity must be an integer'
    Assert ($p.MaximumVersions -ge 1 -and $p.MaximumVersions -le 512) 'Unbounded inventory'
    foreach($kind in @('Files','Directories')){
        $seen=New-Object 'System.Collections.Generic.HashSet[string]'
        foreach($r in $p.$kind){
            Assert ($seen.Add(($r.Presence+'|'+$r.Identity+'|'+$r.Content))) 'Ambiguous decision'
            if($r.Action -ceq 'DELETE'){
                Assert ($r.Presence -ceq 'present' -and $r.Identity -ceq 'same') 'Deletion requires exact present identity'
                if($kind -ceq 'Files'){Assert ($r.Content -ceq 'same') 'Changed file bytes must be retained'}else{Assert ($r.Content -ceq 'empty') 'Nonempty directories must be retained'}
            }elseif($r.Action -ceq 'SKIP'){
                Assert ($r.Presence -ceq 'absent' -and $r.Identity -ceq 'not-applicable' -and $r.Content -ceq 'not-applicable') 'Unreadability is not absence'
            }else{throw 'Unreviewed action'}
        }
    }
}
function Decide($p,$kind,$presence,$identity,$content){
    $rules=@($p.$kind|Where-Object {$_.Presence -ceq $presence -and $_.Identity -ceq $identity -and $_.Content -ceq $content})
    if($rules.Count -gt 1){throw 'Ambiguous data'}
    if($rules.Count -eq 0){return $p.DefaultAction}
    return $rules[0].Action
}
function Clone($p){return ($p|ConvertTo-Json -Depth 8|ConvertFrom-Json)}
function Reject([scriptblock]$Body){$refused=$false;try{& $Body}catch{$refused=$true};Assert $refused 'Unsafe policy accepted'}
$results=New-Object 'System.Collections.Generic.List[object]'
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Status='PASS'})}catch{$results.Add([pscustomobject]@{Name=$Name;Status='FAIL';Detail=$_.Exception.Message})}}
Test 'actual embedded decisions preserve user data and require exact identity' {Validate $policy}
Test '96 observation cells expose four bounded decisions and92 refusals' {
    $allowed=0;$refused=0
    foreach($kind in @('Files','Directories')){
        $contents=if($kind -ceq 'Files'){@('same','changed','unreadable','not-applicable')}else{@('empty','not-empty','unreadable','not-applicable')}
        foreach($presence in @('present','absent','unreadable')){foreach($identity in @('same','changed','unreadable','not-applicable')){foreach($content in $contents){
            $action=Decide $policy $kind $presence $identity $content
            if($action -ceq 'REFUSE'){$refused++}else{$allowed++}
        }}}
    }
    Assert ($allowed -eq 4 -and $refused -eq 92) 'Decision coverage differs'
}
Test 'same bytes at a replaced file identity are refused' {$p=Clone $policy;$p.Files+=@([pscustomobject]@{Presence='present';Identity='changed';Content='same';Action='DELETE'});Reject {Validate $p}}
Test 'same identity with changed bytes is refused' {$p=Clone $policy;$p.Files+=@([pscustomobject]@{Presence='present';Identity='same';Content='changed';Action='DELETE'});Reject {Validate $p}}
Test 'unreadable file cannot be skipped as absent' {$p=Clone $policy;$p.Files+=@([pscustomobject]@{Presence='unreadable';Identity='not-applicable';Content='not-applicable';Action='SKIP'});Reject {Validate $p}}
Test 'nonempty directory cannot be removed' {$p=Clone $policy;$p.Directories+=@([pscustomobject]@{Presence='present';Identity='same';Content='not-empty';Action='DELETE'});Reject {Validate $p}}
Test 'recursive deletion is rejected' {$p=Clone $policy;$p.RecursiveDelete=$true;Reject {Validate $p}}
Test 'user config and evidence preservation cannot be disabled' {foreach($flag in @('PreserveUserConfig','PreserveEvidence')){$p=Clone $policy;$p.$flag=$false;Reject {Validate $p}}}
Test 'unbounded or mistyped inventory capacity rejected' {foreach($size in @(0,513,'512')){$p=Clone $policy;$p.MaximumVersions=$size;Reject {Validate $p}}}
Test 'duplicate decision rejected' {$p=Clone $policy;$p.Files+=@($p.Files[0]);Reject {Validate $p}}
Test 'arbitrary execution action rejected' {$p=Clone $policy;$p.Files[0].Action='EXECUTE';Reject {Validate $p}}
[pscustomobject]@{Scope='EMBEDDED_REMOVAL_MATRIX_ONLY';PowerShell=$PSVersionTable.PSVersion.ToString();Results=@($results.ToArray());Cells=96;CSharpExecuted=$false;AdministratorStateAccessed=$false;NativeDeletionCalled=$false;UninstallExecuted=$false}|ConvertTo-Json -Depth 6
if(@($results|Where-Object {$_.Status -ne 'PASS'}).Count){exit 2}
