# Checks actual embedded reconciliation data. Does not load C#, open administrator
# state, observe processes, alter files/network or claim actual recovery behavior.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$policy=Get-Content -LiteralPath (Join-Path $root 'src\ProtectionLifecycle\RecoveryProtocol.json') -Raw|ConvertFrom-Json
function Assert([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
function Validate($p){
    Assert ($p.SchemaVersion -eq 1 -and $p.DefaultAction -ceq 'REFUSE') 'Unsafe default'
    Assert (($p.AllowedOperations -join ',') -ceq 'install,update,rollback') 'Unreviewed recovery owner'
    foreach($flag in @('RequireRuntimeQuiescence','RetainOriginalLedger')){Assert ($p.$flag -is [bool] -and $p.$flag) 'Missing runtime/evidence prerequisite'}
    foreach($flag in @('MutatePointer','MutateNetwork')){Assert ($p.$flag -is [bool] -and -not $p.$flag) 'Reconciliation must not rewrite live state'}
    $seen=New-Object 'System.Collections.Generic.HashSet[string]'
    foreach($rule in $p.Rules){
        Assert ($seen.Add(($rule.Ledger+'|'+$rule.Pointer+'|'+$rule.Payload))) 'Ambiguous rule'
        Assert ($rule.Pointer -cne 'foreign' -and $rule.Payload -cne 'not-verified') 'Foreign/drifted observations cannot resolve an operation'
        switch -CaseSensitive ($rule.Action){
            'RECONCILE_TARGET_INACTIVE' {Assert ($rule.Ledger -ceq 'incomplete' -and $rule.Pointer -ceq 'target' -and $rule.Payload -ceq 'verified') 'Unsafe target reconciliation'}
            'VERIFY_COMPLETED_CURRENT_INACTIVE' {Assert ($rule.Ledger -ceq 'completed' -and $rule.Pointer -ceq 'target' -and $rule.Payload -ceq 'verified') 'Historical completion cannot replace current verification'}
            'ABORT_PRIOR_UNCHANGED_RETAIN_PAYLOAD' {Assert ($rule.Ledger -ceq 'incomplete' -and $rule.Pointer -ceq 'prior' -and $rule.Payload -ceq 'verified') 'Abort must retain verified old state'}
            'ABORT_UNCOMMITTED_RETAIN_PAYLOAD' {Assert ($rule.Ledger -ceq 'incomplete' -and $rule.Pointer -ceq 'absent' -and $rule.Payload -ceq 'not-applicable') 'Invalid uncommitted disposition'}
            default {throw 'Unreviewed recovery action'}
        }
    }
}
function Decide($p,[string]$Operation,[string]$Ledger,[string]$Pointer,[string]$Payload){
    if($p.AllowedOperations -cnotcontains $Operation){return $p.DefaultAction}
    $matches=@($p.Rules|Where-Object {$_.Ledger -ceq $Ledger -and $_.Pointer -ceq $Pointer -and $_.Payload -ceq $Payload})
    if($matches.Count -gt 1){throw 'Ambiguous policy'}
    if($matches.Count -eq 0){return $p.DefaultAction}
    return $matches[0].Action
}
function Clone($p){return ($p|ConvertTo-Json -Depth 8|ConvertFrom-Json)}
function Reject([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};Assert $failed 'Unsafe mutation accepted'}
$results=New-Object 'System.Collections.Generic.List[object]'
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Status='PASS'})}catch{$results.Add([pscustomobject]@{Name=$Name;Status='FAIL';Detail=$_.Exception.Message})}}
Test 'actual embedded matrix preserves runtime and evidence prerequisites' {Validate $policy}
Test 'all120 observation cells have 12 bounded dispositions and108 refusals' {
    $accepted=0;$refused=0
    foreach($op in @('install','update','rollback','uninstall','activate')){foreach($ledger in @('incomplete','completed')){foreach($pointer in @('prior','target','absent','foreign')){foreach($payload in @('verified','not-verified','not-applicable')){
        $action=Decide $policy $op $ledger $pointer $payload
        if($action -ceq 'REFUSE'){$refused++}else{$accepted++;Assert ($op -cin @('install','update','rollback')) 'Wrong owner';Assert ($pointer -cne 'foreign' -and $payload -cne 'not-verified') 'Unsafe observation accepted'}
    }}}}
    Assert ($accepted -eq 12 -and $refused -eq 108) 'Policy coverage differs'
}
Test 'payload drift never becomes a recovery success' {foreach($p in @('prior','target','absent','foreign')){Assert ((Decide $policy 'update' 'incomplete' $p 'not-verified') -ceq 'REFUSE') 'Drift was accepted'}}
Test 'foreign operation pointer cannot be reused as target' {foreach($l in @('incomplete','completed')){foreach($p in @('verified','not-verified','not-applicable')){Assert ((Decide $policy 'rollback' $l 'foreign' $p) -ceq 'REFUSE') 'Foreign pointer accepted'}}}
Test 'completed ledger with prior or missing current pointer is refused' {foreach($p in @('prior','absent')){foreach($v in @('verified','not-applicable')){Assert ((Decide $policy 'install' 'completed' $p $v) -ceq 'REFUSE') 'Stale completion upgraded'}}}
Test 'changed-pointer and network-mutation policies rejected' {foreach($flag in @('MutatePointer','MutateNetwork')){$p=Clone $policy;$p.$flag=$true;Reject {Validate $p}}}
Test 'uninstall cannot borrow version-reconciliation authority' {$p=Clone $policy;$p.AllowedOperations+=@('uninstall');Reject {Validate $p}}
Test 'duplicate tuple rejected' {$p=Clone $policy;$p.Rules+=@($p.Rules[0]);Reject {Validate $p}}
Test 'new rule accepting a drifted target rejected' {$p=Clone $policy;$p.Rules+=@([pscustomobject]@{Ledger='incomplete';Pointer='target';Payload='not-verified';Action='RECONCILE_TARGET_INACTIVE'});Reject {Validate $p}}
Test 'loss of original ledger retention rejected' {$p=Clone $policy;$p.RetainOriginalLedger=$false;Reject {Validate $p}}
Test 'missing runtime quiescence rejected' {$p=Clone $policy;$p.RequireRuntimeQuiescence=$false;Reject {Validate $p}}
[pscustomobject]@{Scope='EMBEDDED_RECOVERY_MATRIX_ONLY';PowerShell=$PSVersionTable.PSVersion.ToString();Results=@($results.ToArray());Cells=120;CSharpExecuted=$false;AdministratorStateAccessed=$false;RuntimeObserved=$false;RecoveryExecuted=$false}|ConvertTo-Json -Depth 6
if(@($results|Where-Object {$_.Status -ne 'PASS'}).Count){exit 2}
