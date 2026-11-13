[CmdletBinding()]
param([switch]$Apply,[switch]$FenceLoopback,[switch]$UseWfpFence,[switch]$PersistentFence)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage IsolationProbe
$hostExe=Join-Path $root 'bin\engineering\ClaudeProtection.exe'
if(-not $Apply) {& $hostExe isolation-plan;exit $LASTEXITCODE}
if($PersistentFence){$UseWfpFence=$true}
if($UseWfpFence){$FenceLoopback=$true}
# Apply requires separate explicit user authorization. The firewall-only probe
# authorization is not authorization to create profiles, ACLs or exemptions.
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Start this probe as the ordinary user; only its narrowly scoped lease broker is elevated'}
$run=[guid]::NewGuid().ToString('N')
$directory=Join-Path $root ('state\isolation-probe\'+$run)
$invocationDirectory=Join-Path $root ('state\isolation-invocations\'+$run)
New-Item -ItemType Directory -Path $invocationDirectory -Force | Out-Null
$created=$false
$brokerStarted=$false
$profileCleanup='NOT_CREATED'
$errorType=$null
$baselineHash=$null
$systemProxyUnchanged='UNKNOWN'
$checks=New-Object System.Collections.Generic.List[object]
function Invoke-OwnedHost([ValidateSet('isolation-create','isolation-run','isolation-remove','isolation-guard-failure','system-proxy-baseline')][string]$Command,[string]$Phase) {
    $stdout=Join-Path $invocationDirectory ($Phase+'.stdout.log')
    $stderr=Join-Path $invocationDirectory ($Phase+'.stderr.log')
    $process=Start-Process -FilePath $hostExe -ArgumentList @($Command,$run) -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    return [pscustomobject]@{Code=$process.ExitCode;Text=(Get-Content -LiteralPath $stdout -Raw -Encoding UTF8);ErrorLog=$stderr}
}
function Assert-SystemProxy([string]$Phase) {
    $operation=Invoke-OwnedHost 'system-proxy-baseline' ('safety-'+$Phase)
    if($operation.Code -ne 0){throw 'System proxy APIs unreadable; probe refused'}
    $snapshot=$operation.Text|ConvertFrom-Json
    if(-not $snapshot.APIsAgree -or -not $snapshot.ExpectedFlClashProxy){throw 'System proxy APIs disagree or differ from validated FlClash; probe refused'}
    if($null -ne $baselineHash -and $snapshot.Fingerprint -cne $baselineHash){throw 'Global proxy drift detected between experiment phases; probe refused'}
    return $snapshot.Fingerprint
}
function Invoke-Worker([string]$Phase) {
    $null=Assert-SystemProxy $Phase
    $operation=Invoke-OwnedHost 'isolation-run' $Phase
    $workerExit=$operation.Code
    $text=$operation.Text
    $text | Set-Content -LiteralPath (Join-Path $directory ($Phase+'.json')) -Encoding UTF8
    if($workerExit -ne 0) {throw 'Sandbox worker failed; no qualification granted'}
    return ($text | ConvertFrom-Json)
}
try {
    $baselineHash=Assert-SystemProxy 'before-create'
    $creation=Invoke-OwnedHost 'isolation-create' 'create'
    if($creation.Code -ne 0) {throw 'Temporary profile creation failed'}
    $created=$true
    $manifest=$creation.Text | ConvertFrom-Json
    $baseline=Invoke-Worker 'before-loopback-exemption'
    $brokerScript=Join-Path $PSScriptRoot 'Use-ProbeLoopbackLease.ps1'
    $brokerArguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$brokerScript+'"'),'-Run',$run,'-LeaseSeconds','180')
    if($FenceLoopback){$brokerArguments+='-FenceLoopback'}
    if($UseWfpFence){$brokerArguments+='-UseWfpFence'}
    if($PersistentFence){$brokerArguments+='-PersistentFence'}
    $broker=Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList $brokerArguments -PassThru
    $brokerStarted=$true
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath (Join-Path $directory 'lease-ready.json'))) {
        if((Test-Path -LiteralPath (Join-Path $directory 'lease-cleaned.json')) -or $broker.HasExited -or $watch.Elapsed.TotalSeconds -gt 45) {throw 'Loopback lease was not established'}
        Start-Sleep -Milliseconds 200
    }
    $after=Invoke-Worker 'with-loopback-exemption'
    $unfenced=$after
    if($FenceLoopback) {
        'fence' | Set-Content -LiteralPath (Join-Path $directory 'fence.request') -Encoding ASCII
        $watch=[Diagnostics.Stopwatch]::StartNew()
        while(-not (Test-Path -LiteralPath (Join-Path $directory 'lease-fenced.json'))) {
            if((Test-Path -LiteralPath (Join-Path $directory 'lease-cleaned.json')) -or $broker.HasExited -or $watch.Elapsed.TotalSeconds -gt 45){throw 'Temporary probe loopback fence was not established'}
            Start-Sleep -Milliseconds 200
        }
        $phase=if($UseWfpFence){'with-wfp-fence'}else{'with-package-fence'}
        $after=Invoke-Worker $phase
        if($PersistentFence){
            $wfpReady=Get-Content -LiteralPath (Join-Path $directory 'wfp-ready.json') -Raw -Encoding UTF8|ConvertFrom-Json
            if(-not $wfpReady.Persistent -or $wfpReady.Dynamic){throw 'Persistent probe policy was not established'}
            'crash'|Set-Content -LiteralPath (Join-Path $directory 'crash-controller.request') -Encoding ASCII
            $watch=[Diagnostics.Stopwatch]::StartNew()
            while(-not (Test-Path -LiteralPath (Join-Path $directory 'controller-crashed.json'))){
                if((Test-Path -LiteralPath (Join-Path $directory 'lease-cleaned.json')) -or $broker.HasExited -or $watch.Elapsed.TotalSeconds -gt 45){throw 'Controller crash and surviving-policy verification failed'}
                Start-Sleep -Milliseconds 200
            }
            $kernel=Get-Content -LiteralPath (Join-Path $directory 'wfp-after-controller-exit.json') -Raw -Encoding UTF8|ConvertFrom-Json
            $controller=Get-Content -LiteralPath (Join-Path $directory 'controller-crashed.json') -Raw -Encoding UTF8|ConvertFrom-Json
            $verified=$controller.Terminated -and $kernel.SchemaVersion -eq 2 -and $kernel.Verified -and $kernel.PolicySemanticsVerified -and $kernel.HealthyRoles -eq 4 -and $kernel.Present -eq 4 -and $kernel.Persistent -eq 4
            $checks.Add([pscustomobject]@{Name='owned-controller-exited-four-persistent-filters-survive';Status=$(if($verified){'PASS'}else{'FAIL'})})
            $after=Invoke-Worker 'after-controller-crash'
            'block'|Set-Content -LiteralPath (Join-Path $directory 'proxy-failure.request') -Encoding ASCII
            $watch=[Diagnostics.Stopwatch]::StartNew()
            while(-not (Test-Path -LiteralPath (Join-Path $directory 'isolated-proxy-failed.json'))){
                if((Test-Path -LiteralPath (Join-Path $directory 'lease-cleaned.json')) -or $broker.HasExited -or $watch.Elapsed.TotalSeconds -gt 45){throw 'Isolated proxy failure was not established'}
                Start-Sleep -Milliseconds 200
            }
            $guard=Invoke-OwnedHost 'isolation-guard-failure' 'guard-failure-proof'
            if($guard.Code -ne 0){throw 'Owned-session guard-failure verification failed'}
            $guardResult=$guard.Text|ConvertFrom-Json
            $guardPassed=$guardResult.hostProxyStillWorks -and $guardResult.scopedProxyStatus -ceq 'FAIL' -and $guardResult.guardExitCode -eq 125 -and $guardResult.reportedParentAndChild -and $guardResult.activeOwnedProcessesAfterStop -eq 0 -and $guardResult.systemProxyUnchanged
            $checks.Add([pscustomobject]@{Name='isolated-proxy-failure-stops-owned-session-host-proxy-works';Status=$(if($guardPassed){'PASS'}else{'FAIL'})})
        }
        foreach($entry in @(@{Name='parent';Data=$after},@{Name='child';Data=$after.child})) {
            $checks.Add([pscustomobject]@{Name=($entry.Name+'-proxy-port-exclusive-ipv4');Status=$(if($entry.Data.checks.'alternate-loopback' -ceq 'DENIED'){'PASS'}else{'FAIL'})})
            if($UseWfpFence){$checks.Add([pscustomobject]@{Name=($entry.Name+'-proxy-port-exclusive-ipv6');Status=$(if($entry.Data.checks.'alternate-loopback-ipv6' -ceq 'DENIED'){'PASS'}else{'FAIL'})})}
        }
        if($UseWfpFence){
            foreach($family in @('ipv4ReceiptRoles','ipv6ReceiptRoles')){
                $positive=@($unfenced.controlledLoopback.$family)
                $negative=@($after.controlledLoopback.$family)
                $valid=$positive -contains 'parent' -and $positive -contains 'child' -and $negative.Count -eq 0
                $checks.Add([pscustomobject]@{Name=('controlled-udp-'+$family);Status=$(if($valid){'PASS_LOCAL_DELIVERY_SCOPE'}else{'UNKNOWN_OR_FAIL'});Before=$positive;Fenced=$negative})
            }
        }
    }
    foreach($entry in @(@{Name='parent';Data=$after},@{Name='child';Data=$after.child})) {
        $data=$entry.Data
        $valid=$null -ne $data -and $data.identity.IsAppContainer -eq $true -and $data.identity.Sid -ceq $manifest.Sid -and $data.identity.CapabilityCount -eq 0 -and $data.checks.ipv4 -ceq 'DENIED' -and $data.checks.ipv6 -ceq 'DENIED' -and $data.proxy.Status -ceq 'PASS'
        $checks.Add([pscustomobject]@{Name=($entry.Name+'-denied-direct-and-proxy-works');Status=$(if($valid){'PASS'}else{'UNKNOWN_OR_FAIL'})})
    }
} catch {$errorType=$_.Exception.GetType().Name;if(Test-Path -LiteralPath $directory){[pscustomobject]@{ErrorType=$errorType;Message=$_.Exception.Message}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'experiment-error.json') -Encoding UTF8}}
finally {
    if($created) {
        if($brokerStarted) {
            'finish' | Set-Content -LiteralPath (Join-Path $directory 'finish.signal') -Encoding ASCII
            $watch=[Diagnostics.Stopwatch]::StartNew()
            while(-not (Test-Path -LiteralPath (Join-Path $directory 'lease-cleaned.json')) -and $watch.Elapsed.TotalSeconds -lt 195) {Start-Sleep -Milliseconds 250}
        }
        $leaseCanClean=$true
        if($brokerStarted){
            $leaseRecord=Join-Path $directory 'lease-cleaned.json'
            $leaseCanClean=(Test-Path -LiteralPath $leaseRecord) -and (Get-Content -LiteralPath $leaseRecord -Raw -Encoding UTF8 | ConvertFrom-Json).Cleanup -eq 'PASS'
        }
        if($leaseCanClean){
            $removed=Invoke-OwnedHost 'isolation-remove' 'remove'
            $profileCleanup=if($removed.Code -eq 0){'PASS'}else{'FAIL_PRESERVED_FOR_EXACT_RECOVERY'}
        } else {$profileCleanup='PRESERVED_LEASE_CLEANUP_UNVERIFIED'}
    }
    try {$null=Assert-SystemProxy 'after-cleanup';$systemProxyUnchanged='PASS'}catch{$systemProxyUnchanged='FAIL_OR_UNKNOWN'}
    $report=[pscustomobject]@{Run=$run;AtUtc=[DateTime]::UtcNow.ToString('o');ErrorType=$errorType;Checks=@($checks.ToArray());ProfileCleanup=$profileCleanup;SystemProxyUnchanged=$systemProxyUnchanged;Scope='Disposable AppContainer probes only; no actual Claude, credentials, project tools, DNS attribution or production qualification'}
    if(Test-Path -LiteralPath $directory) {$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'experiment-results.json') -Encoding UTF8}
    $report | ConvertTo-Json -Depth 8
}
$expectedChecks=if($PersistentFence){10}elseif($UseWfpFence){8}elseif($FenceLoopback){4}else{2}
if($errorType -or $profileCleanup -ne 'PASS' -or $systemProxyUnchanged -ne 'PASS' -or $checks.Count -ne $expectedChecks -or @($checks | Where-Object {$_.Status -notin @('PASS','PASS_LOCAL_DELIVERY_SCOPE')}).Count) {exit 2}
exit 0
