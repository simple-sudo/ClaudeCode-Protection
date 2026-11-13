[CmdletBinding()]
param([ValidateSet('Inspect','Enable','Restore')][string]$Mode='Inspect', [string]$Snapshot)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($Mode -in @('Enable','Restore')) { . (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage WfpMutation }
$exe = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
$names = @('ClaudeCodeFailClosed-BlockDirect-IPv4','ClaudeCodeFailClosed-BlockDirect-IPv6')
$original = @()
foreach ($name in $names) {
    $rule = Get-NetFirewallRule -Name $name -PolicyStore PersistentStore
    $app = $rule | Get-NetFirewallApplicationFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $port = $rule | Get-NetFirewallPortFilter
    $expected = if ($name.EndsWith('IPv4')) { @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255') } else { @('::','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') }
    $actual = @($address.RemoteAddress | ForEach-Object { if ($_ -eq '::/128') {'::'} else {$_} })
    if ($rule.Action -ne 'Block' -or $rule.Direction -ne 'Outbound' -or $rule.Profile -ne 'Any' -or $app.Program -ine $exe -or $port.Protocol -ne 'Any' -or @(Compare-Object ($expected | Sort-Object) ($actual | Sort-Object)).Count) { throw 'Rule/filter differs from reviewed scope; refusing mutation' }
    $original += [pscustomobject]@{Name=$name;Enabled=[string]$rule.Enabled}
}
if ($Mode -eq 'Inspect') { [pscustomobject]@{Mode='INSPECT_ONLY';Rules=$original;Effects='Enable changes only these two Enabled flags; Restore uses their saved flags. No global import.'} | ConvertTo-Json -Depth 5; exit 0 }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required. No rules changed.' }
if ($Mode -eq 'Restore') {
    if (-not $Snapshot) { throw 'An exact snapshot file is required' }
    $saved = Get-Content -LiteralPath $Snapshot -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($saved.SchemaVersion -ne 1 -or $saved.Program -ine $exe -or @($saved.Rules).Count -ne 2 -or @($saved.Rules.Name | Select-Object -Unique).Count -ne 2) { throw 'Snapshot schema/scope mismatch' }
    foreach ($item in $saved.Rules) {
        if ($item.Name -notin $names -or $item.Enabled -notin @('True','False')) { throw 'Invalid snapshot item' }
    }
    # During the security hold, exact restoration may disable owned rules but
    # must not provide an alternate route to enable protection rules.
    if (@($saved.Rules | Where-Object { $_.Enabled -eq 'True' }).Count) {
        . (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage WfpMutation
    }
    foreach ($item in $saved.Rules) { Set-NetFirewallRule -PolicyStore PersistentStore -Name $item.Name -Enabled $item.Enabled | Out-Null }
    foreach ($item in $saved.Rules) { if ([string](Get-NetFirewallRule -PolicyStore ActiveStore -Name $item.Name).Enabled -ne $item.Enabled) { throw 'Restored rule not reflected in ActiveStore' } }
    Write-Output 'Restored only the two saved Enabled flags. No other settings changed.'
    exit 0
}
if (Get-Process -Name claude -ErrorAction SilentlyContinue) { throw 'Close existing Claude sessions before enabling; no processes will be killed by this script' }
$directory = Join-Path $root 'state\firewall-changes'
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$snapshotFile = Join-Path $directory ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N') + '.json')
[pscustomobject]@{SchemaVersion=1;Program=$exe;Rules=$original} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $snapshotFile -Encoding UTF8
$roundTrip = Get-Content -LiteralPath $snapshotFile -Raw -Encoding UTF8 | ConvertFrom-Json
if (@($roundTrip.Rules).Count -ne 2 -or $roundTrip.Program -ine $exe) { throw 'Snapshot verification failed; no rules changed' }
try {
    foreach ($name in $names) { Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled True | Out-Null }
    foreach ($name in $names) { if ((Get-NetFirewallRule -PolicyStore ActiveStore -Name $name).Enabled -ne 'True') { throw 'Enabled rule not reflected in ActiveStore' } }
    Write-Output ('Enabled the two reviewed rules. Snapshot=' + $snapshotFile)
    Write-Output 'Rule activation is NOT functional Claude, DNS, UDP or child-process qualification. Strict launcher remains blocked.'
} catch {
    $failure = $_
    $restoreErrors = @()
    foreach ($item in $original) {
        try { Set-NetFirewallRule -PolicyStore PersistentStore -Name $item.Name -Enabled $item.Enabled -ErrorAction Stop | Out-Null }
        catch { $restoreErrors += $item.Name }
    }
    if ($restoreErrors.Count) { throw ('Activation failed and rollback is incomplete. Exact rules: ' + ($restoreErrors -join ', ') + '; Snapshot=' + $snapshotFile) }
    throw $failure
}
