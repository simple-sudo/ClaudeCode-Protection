param([string]$WorkingDirectory)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$checks = New-Object System.Collections.Generic.List[object]
$proxyListenerPid = $null
function Add-Check([string]$Name, [string]$Status, [string]$Detail, [bool]$Required = $true) {
    $checks.Add([pscustomobject]@{ Name=$Name; Status=$Status; Detail=$Detail; Required=$Required })
}
function Read-Check([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { Add-Check $Name 'UNKNOWN' $_.Exception.GetType().Name }
}
$exe = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
$settings = Join-Path $env:USERPROFILE '.claude\settings.json'
$expectedProxy = 'http://127.0.0.1:7890'
Read-Check 'claude-executable' {
    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        Add-Check 'claude-executable' 'PASS' ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O="?Anthropic, PBC') {
            Add-Check 'claude-signature' 'PASS' 'Valid Anthropic signature'
        } else { Add-Check 'claude-signature' 'FAIL' 'Expected a valid Anthropic signature' }
    } else { Add-Check 'claude-executable' 'FAIL' 'Executable missing' }
}
Read-Check 'user-proxy-settings' {
    $cfg = Get-Content -LiteralPath $settings -Raw -Encoding UTF8 | ConvertFrom-Json
    $ok = $cfg.env.HTTP_PROXY -ceq $expectedProxy -and $cfg.env.HTTPS_PROXY -ceq $expectedProxy -and $cfg.env.NO_PROXY -ceq 'localhost,127.0.0.1,::1'
    if ($ok) { Add-Check 'user-proxy-settings' 'PASS' 'Expected explicit proxy and loopback bypass only' }
    else { Add-Check 'user-proxy-settings' 'FAIL' 'Proxy configuration differs; values withheld' }
}
Read-Check 'environment-overrides' {
    $names = @('ANTHROPIC_BASE_URL','CLAUDE_CONFIG_DIR','ALL_PROXY','NODE_TLS_REJECT_UNAUTHORIZED','CLAUDE_CODE_SKIP_BEDROCK_AUTH','NODE_OPTIONS','BUN_OPTIONS')
    $found = @($names | Where-Object { [Environment]::GetEnvironmentVariable($_, 'Process') })
    if ($found.Count) { Add-Check 'environment-overrides' 'FAIL' ('Review environment keys: ' + ($found -join ', ')) }
    else { Add-Check 'environment-overrides' 'PASS' 'No unsupported endpoint/config/runtime overrides' }
}
Read-Check 'additional-settings' {
    $candidates = New-Object System.Collections.Generic.List[string]
    $candidates.Add((Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.json'))
    $candidates.Add((Join-Path $env:USERPROFILE '.claude\managed-settings.json'))
    if ($WorkingDirectory) {
        $current = Get-Item -LiteralPath $WorkingDirectory
        while ($current) {
            $candidates.Add((Join-Path $current.FullName '.claude\settings.json'))
            $candidates.Add((Join-Path $current.FullName '.claude\settings.local.json'))
            $candidates.Add((Join-Path $current.FullName '.mcp.json'))
            $current = $current.Parent
        }
    }
    # User-level MCP and hooks may launch unfiltered children. Read key names only.
    $userCfg = Get-Content -LiteralPath $settings -Raw -Encoding UTF8 | ConvertFrom-Json
    $hasHooks = $null -ne $userCfg.hooks -or $null -ne $userCfg.mcpServers
    $extra = @($candidates | Where-Object { $_ -ine $settings -and (Test-Path -LiteralPath $_) })
    if ($extra.Count -or $hasHooks) { Add-Check 'additional-settings' 'UNKNOWN' 'Additional project/managed/MCP/hook configuration requires scope review; contents withheld' }
    else { Add-Check 'additional-settings' 'PASS' 'No additional files detected in inspected locations; not a complete managed-policy audit' }
}
Read-Check 'proxy-listener' {
    $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 7890 -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -ne 1) { Add-Check 'proxy-listener' 'FAIL' 'Expected exactly one IPv4 loopback listener'; return }
    $owner = Get-Process -Id $listeners[0].OwningProcess
    if ($owner.ProcessName -ne 'FlClashCore') { Add-Check 'proxy-listener' 'FAIL' 'Listener is not FlClashCore'; return }
    Add-Check 'proxy-listener' 'PASS' ('FlClashCore PID=' + $owner.Id)
    # Return an observation to the already-running managed caller, never launch
    # a second backend from a guessed installation or development path.
    $script:proxyListenerPid = [uint32]$owner.Id
}
Add-Check 'proxy-owner-path' 'UNKNOWN' 'Requires managed limited-information identity query; name alone is insufficient'
Read-Check 'flclash-tun' {
    $tun = @(Get-NetAdapter -Name 'FlClash' -ErrorAction SilentlyContinue)
    if ($tun.Count -eq 1 -and $tun[0].Status -eq 'Up') { Add-Check 'flclash-tun' 'PASS' 'Exact FlClash adapter is Up' }
    else { Add-Check 'flclash-tun' 'FAIL' 'FlClash adapter is not Up' }
}
Read-Check 'windows-region' {
    $ok = (Get-TimeZone).Id -eq 'Eastern Standard Time' -and (Get-Culture).Name -eq 'en-US' -and (Get-WinSystemLocale).Name -eq 'en-US'
    if ($ok) { Add-Check 'windows-region' 'PASS' 'Eastern Standard Time / en-US / en-US; not network isolation evidence' }
    else { Add-Check 'windows-region' 'FAIL' 'Timezone or culture drift detected; no automatic system change' }
}
Read-Check 'firewall-service' {
    if ((Get-Service -Name MpsSvc).Status -eq 'Running') { Add-Check 'firewall-service' 'PASS' 'MpsSvc running' }
    else { Add-Check 'firewall-service' 'FAIL' 'MpsSvc is not running' }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -eq 3 -and @($profiles | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.AllowLocalFirewallRules -eq 'False' }).Count -eq 0) {
        Add-Check 'firewall-profiles' 'PASS' 'All profiles enabled; local rules not explicitly suppressed'
    } else { Add-Check 'firewall-profiles' 'FAIL' 'Firewall profile/merge policy requires review' }
}
foreach ($family in @('IPv4','IPv6')) {
    $name = 'ClaudeCodeFailClosed-BlockDirect-' + $family
    try {
        $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name
        $app = $rule | Get-NetFirewallApplicationFilter
        $addr = $rule | Get-NetFirewallAddressFilter
        $port = $rule | Get-NetFirewallPortFilter
        $expected = if ($family -eq 'IPv4') { @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255') } else { @('::','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') }
        $actual = @($addr.RemoteAddress | ForEach-Object { if ($_ -eq '::/128') { '::' } else { $_ } })
        $exact = @((Compare-Object ($expected | Sort-Object) ($actual | Sort-Object))).Count -eq 0
        $valid = $rule.Action -eq 'Block' -and $rule.Direction -eq 'Outbound' -and $rule.Profile -eq 'Any' -and $app.Program -ieq $exe -and $port.Protocol -eq 'Any' -and $exact
        if (-not $valid) { Add-Check $name 'FAIL' 'Rule/filter differs from reviewed baseline' }
        elseif ($rule.Enabled -ne 'True') { Add-Check $name 'FAIL' 'Reviewed rule exists but remains DISABLED' }
        else { Add-Check $name 'PASS' 'Enabled effective rule matches reviewed baseline; functional coverage still unqualified' }
    } catch { Add-Check $name 'UNKNOWN' $_.Exception.GetType().Name }
}
Add-Check 'dns-isolation' 'UNKNOWN' 'OS resolver/service traffic has not been captured and attributed'
Add-Check 'stun-webrtc' 'UNKNOWN' 'No live direct UDP probe sent; timeout must never mean safe'
Add-Check 'ipv6-functional' 'UNKNOWN' 'IPv6 direct-block behavior has not been functionally verified'
Add-Check 'child-network-isolation' 'UNKNOWN' 'Executable firewall rules do not establish child/MCP/browser isolation'
[pscustomobject]@{ SchemaVersion=1; AtUtc=[DateTime]::UtcNow.ToString('o'); Checks=@($checks.ToArray()); ProxyListenerPid=$proxyListenerPid } | ConvertTo-Json -Depth 6 -Compress
