[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$Run,[ValidateRange(30,180)][int]$LeaseSeconds=120,[switch]$FenceLoopback,[switch]$UseWfpFence,[switch]$PersistentFence)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1')
$hostExe=Join-Path $root 'bin\engineering\ClaudeProtection.exe'
. (Join-Path $PSScriptRoot 'WfpRecoveryProtocol.ps1')
$directory=Join-Path $root ('state\isolation-probe\'+$Run)
$profile='ClaudeProtectionProbe.'+$Run
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required; no exemptions changed' }
$manifest=Get-Content -LiteralPath (Join-Path $directory 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if($manifest.Run -cne $Run -or $manifest.Profile -cne $profile -or $manifest.Directory -ine $directory) {throw 'Probe manifest scope mismatch'}
$sid=((& $hostExe isolation-derive $profile) -join '').Trim()
if($LASTEXITCODE -ne 0 -or $sid -cne $manifest.Sid -or $sid -notmatch '^S-1-15-2-(\d+-)*\d+$') {throw 'Probe SID mismatch'}
$attempted=$false
$cleanup='NOT_NEEDED'
$failure=$null
$createdRules=New-Object System.Collections.Generic.List[string]
$fenced=$false
$wfpProcess=$null
$controllerStopped=$false
$proxyBlocked=$false
function Invoke-ExactWfpOperation([ValidateSet('inspect','cleanup','block-proxy')][string]$Action) {
    $plan=Get-Content -LiteralPath (Join-Path $directory 'wfp-plan.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $arguments=@(Get-WfpRecoveryArguments -Plan $plan -Run $Run -Action $Action)
    $operation=Start-Process -FilePath (Join-Path $root 'bin\engineering\ClaudeProtectionFence.exe') -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $directory ('wfp-'+$Action+'.stdout.log')) -RedirectStandardError (Join-Path $directory ('wfp-'+$Action+'.stderr.log'))
    if($operation.ExitCode -ne 0){throw ('Scoped WFP '+$Action+' failed')}
}
try {
    $artifactDirectory=Join-Path $directory 'artifacts'
    [IO.Directory]::CreateDirectory($artifactDirectory)|Out-Null
    $artifactFiles=@((Join-Path $root 'bin\engineering\ClaudeProtectionFence.exe'),(Join-Path $root 'src\NativeFence\ProbeFence.cpp'),(Join-Path $root 'src\NativeFence\FenceOwnership.h'),(Join-Path $PSScriptRoot 'WfpRecoveryProtocol.ps1'),$PSCommandPath)
    $artifactHashes=@(foreach($artifact in $artifactFiles){if(Test-Path -LiteralPath $artifact){Copy-Item -LiteralPath $artifact -Destination (Join-Path $artifactDirectory (Split-Path -Leaf $artifact));[pscustomobject]@{Name=(Split-Path -Leaf $artifact);SHA256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash}}})
    $artifactHashes|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'artifacts-before-execution.json') -Encoding UTF8
    try {
        $listener=Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 7890 -State Listen|Select-Object -First 1
        $core=Get-CimInstance Win32_Process -Filter ('ProcessId='+$listener.OwningProcess)
        $identityStatus=if($core.ExecutablePath -ieq 'E:\program\FlClash\FlClashCore.exe'){'PASS'}else{'UNKNOWN_OR_FAIL'}
        [pscustomobject]@{Status=$identityStatus;Pid=$core.ProcessId;ExpectedPathMatched=($core.ExecutablePath -ieq 'E:\program\FlClash\FlClashCore.exe');CreatedUtc=$core.CreationDate.ToUniversalTime().ToString('o');Scope='Read-only identity at this batch startup, not a future-process admission'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'proxy-owner-admin-observation.json') -Encoding UTF8
    } catch {[pscustomobject]@{Status='UNKNOWN';ErrorType=$_.Exception.GetType().Name}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'proxy-owner-admin-observation.json') -Encoding UTF8}
    $before=((& $hostExe isolation-loopback-check $sid) -join '').Trim()
    if($LASTEXITCODE -ne 0 -or $before -cne 'ABSENT') {throw 'Exemption must be absent before this lease; refusing to modify preexisting state'}
    [pscustomobject]@{Run=$Run;Profile=$profile;Sid=$sid;AtUtc=[DateTime]::UtcNow.ToString('o');LeaseSeconds=$LeaseSeconds;State='BEFORE_ADD'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'lease-plan.json') -Encoding UTF8
    $attempted=$true
    & "$env:SystemRoot\System32\CheckNetIsolation.exe" LoopbackExempt -a ('-p='+$sid) *> (Join-Path $directory 'lease-add.log')
    if($LASTEXITCODE -ne 0) {throw 'Exact probe loopback exemption add failed'}
    $after=((& $hostExe isolation-loopback-check $sid) -join '').Trim()
    if($LASTEXITCODE -ne 0 -or $after -cne 'PRESENT') {throw 'Added exemption could not be verified'}
    [pscustomobject]@{Run=$Run;State='READY';AtUtc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'lease-ready.json') -Encoding UTF8
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while(-not (Test-Path -LiteralPath (Join-Path $directory 'finish.signal')) -and $watch.Elapsed.TotalSeconds -lt $LeaseSeconds) {
        if($FenceLoopback -and -not $fenced -and (Test-Path -LiteralPath (Join-Path $directory 'fence.request'))) {
            if($UseWfpFence) {
                $fenceExecutable=Join-Path $root 'bin\engineering\ClaudeProtectionFence.exe'
                $leaseMode=if($PersistentFence){'lease-persistent'}else{'lease'}
                $wfpProcess=Start-Process -FilePath $fenceExecutable -ArgumentList @($leaseMode,$Run,'150') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $directory 'wfp.stdout.log') -RedirectStandardError (Join-Path $directory 'wfp.stderr.log')
                $startup=[Diagnostics.Stopwatch]::StartNew()
                while(-not (Test-Path -LiteralPath (Join-Path $directory 'wfp-ready.json'))) {
                    if($wfpProcess.HasExited -or $startup.Elapsed.TotalSeconds -gt 15){throw 'WFP probe fence failed to start'}
                    Start-Sleep -Milliseconds 100
                }
                $fenced=$true
                [pscustomobject]@{Run=$Run;State=$(if($PersistentFence){'PERSISTENT_WFP_PROBE_ONLY'}else{'DYNAMIC_WFP_PROBE_ONLY'});Scope='Exact disposable package SID; IPv4 only TCP to 127.0.0.1:7890, IPv6 denied';ProductionQualification='NOT_GRANTED'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'lease-fenced.json') -Encoding UTF8
            } else {
            $planned=@(('ClaudeProtection-Isolation-'+$Run+'-OtherTcpLoopback'),('ClaudeProtection-Isolation-'+$Run+'-Udp'))
            [pscustomobject]@{Run=$Run;PackageSid=$sid;Names=$planned;State='BEFORE_ADD'} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'fence-plan.json') -Encoding UTF8
            New-NetFirewallRule -Name $planned[0] -DisplayName $planned[0] -Direction Outbound -Action Block -Profile Any -Package $sid -Protocol TCP -RemoteAddress '127.0.0.0/8' -RemotePort @('0-7889','7891-65535') -Enabled True | Out-Null
            $createdRules.Add($planned[0])
            New-NetFirewallRule -Name $planned[1] -DisplayName $planned[1] -Direction Outbound -Action Block -Profile Any -Package $sid -Protocol UDP -Enabled True | Out-Null
            $createdRules.Add($planned[1])
            $fenced=$true
            [pscustomobject]@{Run=$Run;State='FENCED_IPV4_LOOPBACK_AND_UDP_ONLY';Unqualified='IPv6 loopback address filters rejected by NetSecurity in prior isolated attempts';Names=@($createdRules.ToArray())} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'lease-fenced.json') -Encoding UTF8
            }
        }
        if($PersistentFence -and $fenced -and -not $controllerStopped -and (Test-Path -LiteralPath (Join-Path $directory 'crash-controller.request'))){
            if($null -eq $wfpProcess -or $wfpProcess.HasExited){throw 'Expected live owned WFP controller before crash test'}
            $observedPid=$wfpProcess.Id
            Stop-Process -Id $observedPid -Force -ErrorAction Stop
            if(-not $wfpProcess.WaitForExit(10000)){throw 'Owned controller did not terminate'}
            Invoke-ExactWfpOperation 'inspect'
            $controllerStopped=$true
            [pscustomobject]@{Run=$Run;State='OWNED_CONTROLLER_TERMINATED_FILTERS_VERIFIED';ProcessId=$observedPid;Terminated=$wfpProcess.HasExited}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'controller-crashed.json') -Encoding UTF8
        }
        if($PersistentFence -and $controllerStopped -and -not $proxyBlocked -and (Test-Path -LiteralPath (Join-Path $directory 'proxy-failure.request'))){
            Invoke-ExactWfpOperation 'block-proxy'
            $proxyBlocked=$true
            [pscustomobject]@{Run=$Run;State='ONLY_PROBE_PROXY_PATH_BLOCKED';HostProxyConfigurationChanged=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $directory 'isolated-proxy-failed.json') -Encoding UTF8
        }
        Start-Sleep -Milliseconds 250
    }
} catch { $failure=$_.Exception.GetType().Name; [pscustomobject]@{ErrorType=$failure;Message=$_.Exception.Message;ErrorId=$_.FullyQualifiedErrorId} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'lease-error.json') -Encoding UTF8 }
finally {
    $ruleCleanupErrors=@()
    if($null -ne $wfpProcess) {
        'finish' | Set-Content -LiteralPath (Join-Path $directory 'wfp-finish.signal') -Encoding ASCII
        if(-not $wfpProcess.WaitForExit(15000)) {$ruleCleanupErrors+='WFP_PROBE_SESSION_STILL_RUNNING'}
        if($PersistentFence -and (Test-Path -LiteralPath (Join-Path $directory 'wfp-plan.json'))){
            try{Invoke-ExactWfpOperation 'cleanup'}catch{$ruleCleanupErrors+='PERSISTENT_WFP_EXACT_RECOVERY_FAILED'}
        }
        $wfpRecord=Join-Path $directory $(if($PersistentFence){'wfp-recovered.json'}else{'wfp-cleaned.json'})
        if(Test-Path -LiteralPath $wfpRecord) {
            $wfpCleanup=Get-Content -LiteralPath $wfpRecord -Raw -Encoding UTF8 | ConvertFrom-Json
            if($wfpCleanup.Cleanup -ne 'PASS'){$ruleCleanupErrors+='WFP_PROBE_FILTERS_NOT_VERIFIED_ABSENT'}
        } else {$ruleCleanupErrors+='WFP_PROBE_CLEANUP_RECORD_MISSING'}
    }
    foreach($name in $createdRules) {
        try {Remove-NetFirewallRule -Name $name -ErrorAction Stop} catch {$ruleCleanupErrors+=$name}
    }
    foreach($name in $createdRules) {if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){$ruleCleanupErrors+=$name}}
    if($attempted) {
        try {
            & "$env:SystemRoot\System32\CheckNetIsolation.exe" LoopbackExempt -d ('-p='+$sid) *> (Join-Path $directory 'lease-remove.log')
            $exitCode=$LASTEXITCODE
            $remaining=((& $hostExe isolation-loopback-check $sid) -join '').Trim()
            if($LASTEXITCODE -ne 0 -or $remaining -cne 'ABSENT') {throw 'Exact temporary exemption still present or unreadable'}
            $cleanup='PASS'
        } catch {$cleanup='FAIL';$failure=$_.Exception.GetType().Name}
    }
    if($ruleCleanupErrors.Count){$cleanup='FAIL'}
    [pscustomobject]@{Run=$Run;AtUtc=[DateTime]::UtcNow.ToString('o');Cleanup=$cleanup;ErrorType=$failure;RulesCreated=@($createdRules.ToArray());RuleCleanupFailures=@($ruleCleanupErrors|Select-Object -Unique);PersistentProbe=[bool]$PersistentFence;ControllerStopped=$controllerStopped;Scope='Only this uniquely derived probe SID'} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'lease-cleaned.json') -Encoding UTF8
}
if($cleanup -eq 'FAIL' -or $failure) {exit 2}
exit 0
