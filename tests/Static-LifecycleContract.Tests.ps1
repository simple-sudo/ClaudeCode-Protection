# Inspects actual embedded protocol data; never loads/executes the C# library.
# These are graph/surface checks, NOT installer, ACL, broker or recovery tests.
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$lifecycle=Get-Content -LiteralPath (Join-Path $root 'src\ProtectionLifecycle\LifecycleProtocol.json') -Raw|ConvertFrom-Json
$broker=Get-Content -LiteralPath (Join-Path $root 'src\ProtectionLifecycle\BrokerProtocol.json') -Raw|ConvertFrom-Json
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Assert-Lifecycle($Protocol){
    Assert ($Protocol.SchemaVersion -eq 1 -and $Protocol.DefaultActivation -ceq 'INACTIVE' -and $Protocol.PreserveUserConfig -eq $true -and $Protocol.PreserveEvidence -eq $true) 'Activation or preservation invariant changed'
    Assert (($Protocol.AllowedOperations -join ',') -ceq 'install,update,rollback,uninstall') 'Operation scope changed'
    $keys=New-Object 'System.Collections.Generic.HashSet[string]'
    foreach($edge in $Protocol.Transitions){
        Assert ($edge.Operation -cin $Protocol.AllowedOperations) 'Unknown operation'
        Assert ($keys.Add(($edge.Operation+'|'+$edge.From+'|'+$edge.Event))) 'Ambiguous transition'
        Assert (-not [string]::IsNullOrWhiteSpace($edge.Proof)) 'Unproven transition'
    }
    foreach($operation in $Protocol.AllowedOperations){
        $edges=@($Protocol.Transitions|Where-Object {$_.Operation -ceq $operation})
        $pending=New-Object 'System.Collections.Generic.Queue[object]'
        $pending.Enqueue([pscustomobject]@{State='planned';States=@('planned');Proofs=@();Events=@()})
        $reached=New-Object 'System.Collections.Generic.HashSet[string]'
        $completed=0;$visited=0
        while($pending.Count -gt 0){
            $path=$pending.Dequeue();$visited++
            Assert ($visited -le 128) 'Graph is unbounded'
            $null=$reached.Add($path.State)
            $next=@($edges|Where-Object {$_.From -ceq $path.State})
            if($path.State -clike 'completed-*'){
                $completed++
                Assert ($next.Count -eq 0) 'Completed state can mutate again'
                $required=switch($operation){
                    'install' {@('reviewed-package','verified-payload','quiescent-pointer','pointer-readback')}
                    'update' {@('reviewed-package','verified-payload','quiescent-pointer','pointer-readback')}
                    'rollback' {@('owned-prior-payload','quiescent-pointer','pointer-readback')}
                    'uninstall' {@('owned-processes-zero','owned-resources-absent','pointer-absent','exact-owned-files-absent','removal-readback')}
                }
                Assert (($path.Proofs -join ',') -ceq ($required -join ',')) 'A completion path bypasses required verification/order'
                $expected=if($operation -ceq 'uninstall'){'completed-removed'}else{'completed-inactive'}
                Assert ($path.State -ceq $expected) 'Unsafe terminal state'
                continue
            }
            Assert ($next.Count -gt 0) 'Undeclared dead end'
            foreach($edge in $next){
                Assert ($path.States -cnotcontains $edge.To) 'Cycle permits repeated mutation'
                $pending.Enqueue([pscustomobject]@{State=$edge.To;States=@($path.States)+@($edge.To);Proofs=@($path.Proofs)+@($edge.Proof);Events=@($path.Events)+@($edge.Event)})
            }
        }
        Assert ($completed -gt 0) 'No completion path'
        foreach($edge in $edges){Assert ($reached.Contains($edge.From) -and $reached.Contains($edge.To)) 'Unreachable hidden transition'}
    }
}
function Assert-Broker($Protocol){
    Assert ($Protocol.SchemaVersion -eq 1 -and $Protocol.MaximumBytes -eq 2048) 'Broker size/schema changed'
    Assert (($Protocol.Fields -join ',') -ceq 'SchemaVersion,InstallationId,RequestId,Operation,Target') 'Unrestricted broker field'
    $expected=@('inspect|none','quarantine|none','recover|operation-id','update|staged-release-id','rollback|owned-release-id','uninstall|none')
    $actual=@($Protocol.Operations|ForEach-Object {$_.Name+'|'+$_.Target})
    Assert (($actual -join ',') -ceq ($expected -join ',')) 'Broker permits an unreviewed capability'
}
$results=New-Object 'System.Collections.Generic.List[object]'
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Name=$Name;Status='PASS'})}catch{$results.Add([pscustomobject]@{Name=$Name;Status='FAIL';Detail=$_.Exception.Message})}}
function Reject([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};Assert $failed 'Unsafe contract mutation was accepted'}
function Clone($Value){return ($Value|ConvertTo-Json -Depth 12|ConvertFrom-Json)}
Test 'all actual lifecycle paths require complete ordered evidence' {Assert-Lifecycle $lifecycle}
Test 'actual broker surface is bounded and data-only' {Assert-Broker $broker}
Test 'quarantine cannot acquire a caller-selected process/path target' {foreach($target in @('pid','path','sid','operation-id')){$p=Clone $broker;($p.Operations|Where-Object Name -ceq 'quarantine').Target=$target;Reject {Assert-Broker $p}}}
Test 'install shortcut without staging/verification rejected' {$p=Clone $lifecycle;$p.Transitions+=@([pscustomobject]@{Operation='install';From='planned';Event='shortcut';To='completed-inactive';Proof='pointer-readback'});Reject {Assert-Lifecycle $p}}
Test 'uninstall shortcut before resource cleanup rejected' {$p=Clone $lifecycle;$p.Transitions+=@([pscustomobject]@{Operation='uninstall';From='quiescent';Event='shortcut';To='completed-removed';Proof='removal-readback'});Reject {Assert-Lifecycle $p}}
Test 'activation terminal rejected' {$p=Clone $lifecycle;($p.Transitions|Where-Object {$_.Operation -ceq 'update' -and $_.Event -ceq 'finish'}).To='completed-active';Reject {Assert-Lifecycle $p}}
Test 'duplicate edge rejected' {$p=Clone $lifecycle;$p.Transitions+=@($p.Transitions[0]);Reject {Assert-Lifecycle $p}}
Test 'cycle rejected' {$p=Clone $lifecycle;$p.Transitions+=@([pscustomobject]@{Operation='rollback';From='verified';Event='again';To='planned';Proof='owned-prior-payload'});Reject {Assert-Lifecycle $p}}
Test 'missing proof rejected' {$p=Clone $lifecycle;$p.Transitions[0].Proof='';Reject {Assert-Lifecycle $p}}
Test 'loss of config or evidence preservation rejected' {foreach($field in @('PreserveUserConfig','PreserveEvidence')){$p=Clone $lifecycle;$p.$field=$false;Reject {Assert-Lifecycle $p}}}
Test 'arbitrary script/path/SID or activation capability rejected' {foreach($field in @('Command','Script','Path','Sid','FilterIds','Url')){$p=Clone $broker;$p.Fields+=@($field);Reject {Assert-Broker $p}};$p=Clone $broker;$p.Operations+=@([pscustomobject]@{Name='activate';Target='path'});Reject {Assert-Broker $p}}
[pscustomobject]@{Scope='EMBEDDED_DATA_CONTRACT_ONLY';PowerShell=$PSVersionTable.PSVersion.ToString();Results=@($results.ToArray());CSharpExecuted=$false;WindowsSecurityAPIsCalled=$false;InstallerExecuted=$false}|ConvertTo-Json -Depth 6
if(@($results|Where-Object {$_.Status -ne 'PASS'}).Count){exit 2}
