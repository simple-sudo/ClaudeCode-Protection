[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($Apply) { . (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage WfpMutation }
$program = Join-Path $root 'bin\engineering\ClaudeProtectionProbe.exe'
$source = Join-Path $root 'bin\engineering\ClaudeProtection.exe'
$ranges = @{
    IPv4 = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255')
    IPv6 = @('::/128','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
}
if (-not $Apply) {
    [pscustomobject]@{
        Mode='INSPECT_ONLY'; Program=$program
        Effects=@('Copy the locally built host to a dedicated probe executable', 'Create two temporary outbound block rules scoped ONLY to that probe', 'Compare direct TCP baselines and denied sockets for IPv4/IPv6', 'Verify explicit loopback-proxy TLS transport still works', 'Remove ONLY this invocation''s temporary rules in finally')
        Unchanged=@('Existing Claude rules', 'Firewall profile settings', 'FlClash processes, TUN, nodes and configuration', 'Authentication and account files')
        Qualification='Probe executable and current TUN path only; does NOT qualify actual Claude, children, DNS, UDP or proxy outage'
    } | ConvertTo-Json -Depth 5
    exit 0
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required. No rules changed.' }
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Build missing' }
Copy-Item -LiteralPath $source -Destination $program -Force
if ((Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $program).Hash) { throw 'Probe copy hash mismatch' }
$run = [guid]::NewGuid().ToString('N')
$directory = Join-Path $root ('state\firewall-probe\' + $run)
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$plannedNames = @(('ClaudeProtection-Probe-' + $run + '-IPv4'), ('ClaudeProtection-Probe-' + $run + '-IPv6'))
[pscustomobject]@{SchemaVersion=1;State='PLANNED';Program=$program;Rules=$plannedNames;AtUtc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'plan.json') -Encoding UTF8
$created = New-Object System.Collections.Generic.List[string]
$results = New-Object System.Collections.Generic.List[object]
$cleanup = 'NOT_RUN'
function Probe([string]$Address, [int]$Port) {
    $output = @(& $program probe-tcp $Address $Port 2>$null)
    return [pscustomobject]@{ Code=$LASTEXITCODE; Result=($output -join '').Trim() }
}
try {
    # These unauthenticated TCP handshakes send no application payload.
    # TUN remains on, so a successful baseline does not prove physical-NIC direct access.
    $targets = @(@{Family='IPv4';Address='1.1.1.1'}, @{Family='IPv6';Address='2606:4700:4700::1111'})
    $before = @{}
    foreach ($target in $targets) { $before[$target.Family] = Probe $target.Address 443 }
    foreach ($family in @('IPv4','IPv6')) {
        $name = 'ClaudeProtection-Probe-' + $run + '-' + $family
        New-NetFirewallRule -Name $name -DisplayName $name -Direction Outbound -Action Block -Profile Any -Protocol Any -Program $program -RemoteAddress $ranges[$family] -Enabled True | Out-Null
        $created.Add($name)
    }
    foreach ($target in $targets) {
        $after = Probe $target.Address 443
        $status = if ($before[$target.Family].Code -eq 0 -and $after.Code -eq 10 -and $after.Result -eq 'SOCKET=AccessDenied') { 'PASS' } else { 'UNKNOWN' }
        $results.Add([pscustomobject]@{Name=($target.Family + '-probe-block');Status=$status;Before=$before[$target.Family];Blocked=$after})
    }
    $loopback = Probe '127.0.0.1' 7890
    $results.Add([pscustomobject]@{Name='probe-loopback';Status=$(if ($loopback.Code -eq 0) {'PASS'} else {'FAIL'});Result=$loopback})
    $transportRaw = @(& $program transport 2>$null)
    $transportCode = $LASTEXITCODE
    $transport = ($transportRaw -join "`n") | ConvertFrom-Json
    $results.Add([pscustomobject]@{Name='probe-proxy-tls';Status=$(if ($transportCode -eq 0 -and $transport.Status -eq 'PASS') {'PASS'} else {'FAIL'});Result=$transport})
} finally {
    $cleanupErrors = @()
    foreach ($name in $created) {
        try { Remove-NetFirewallRule -Name $name -ErrorAction Stop }
        catch { $cleanupErrors += $name }
    }
    foreach ($name in $created) {
        if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { $cleanupErrors += $name }
    }
    $cleanup = if ($cleanupErrors.Count) { 'FAIL' } else { 'PASS' }
    $report = [pscustomobject]@{SchemaVersion=1;AtUtc=[DateTime]::UtcNow.ToString('o');Scope='Probe executable ONLY; actual Claude and process-tree isolation remain UNKNOWN';RulesCreated=@($created.ToArray());Cleanup=$cleanup;CleanupFailures=@($cleanupErrors | Select-Object -Unique);Results=@($results.ToArray())}
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $directory 'results.json') -Encoding UTF8
    $report | ConvertTo-Json -Depth 10
    if ($cleanup -eq 'FAIL') { Write-Warning 'Temporary probe rule cleanup failed. Exact remaining names are in the report. Claude/other software rules were not changed.' }
}
if ($cleanup -ne 'PASS' -or $results.Count -ne 4 -or @($results | Where-Object Status -ne 'PASS').Count) { exit 2 }
exit 0
