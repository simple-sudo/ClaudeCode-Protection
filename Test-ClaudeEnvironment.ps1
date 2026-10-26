$ErrorActionPreference = 'Stop'

$exe = "$env:USERPROFILE\.local\bin\claude.exe"
$settings = "$env:USERPROFILE\.claude\settings.json"
$proxy = 'http://127.0.0.1:7890'

function Assert-Check($condition, $message) {
    if (-not $condition) {
        throw "FAIL: $message"
    }
    Write-Host "PASS: $message" -ForegroundColor Green
}

Write-Host "`n========== 1. Claude Code =========="

Assert-Check (Test-Path $exe) 'CLI 可执行文件存在'
Assert-Check (Test-Path $settings) '配置文件存在'

$cfg = Get-Content $settings -Raw -Encoding UTF8 |
    ConvertFrom-Json

Assert-Check (
    $cfg.env.HTTP_PROXY -eq $proxy -and
    $cfg.env.HTTPS_PROXY -eq $proxy
) 'HTTP/HTTPS 代理配置正确'

Write-Host "`n========== 2. FlClash =========="

$listener = Get-NetTCPConnection `
    -LocalAddress '127.0.0.1' `
    -LocalPort 7890 `
    -State Listen `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

Assert-Check ($null -ne $listener) '代理端口在线'

$ownerName = if ($listener) {
    (Get-Process -Id $listener.OwningProcess).ProcessName
} else { '' }

Assert-Check (
    $ownerName -eq 'FlClashCore'
) '端口归属 FlClashCore'

$tun = Get-NetAdapter -Name 'FlClash' `
    -ErrorAction SilentlyContinue

Assert-Check (
    $null -ne $tun -and $tun.Status -eq 'Up'
) 'FlClash TUN 在线'

Write-Host "`n========== 3. 代理传输 =========="

$curlArgs = @(
    '-q'
    '--proxy', $proxy
    '--connect-timeout', '8'
    '--max-time', '15'
    '--silent'
    '--output', 'NUL'
    '--write-out', 'HTTP=%{http_code};CONNECT=%{http_connect};SSL=%{ssl_verify_result}'
    'https://api.anthropic.com/v1/models'
)

$result = & curl.exe @curlArgs 2>$null
$exitCode = $LASTEXITCODE

Assert-Check (
    $exitCode -eq 0 -and
    $result -match '^HTTP=(200|401|403);CONNECT=200;SSL=0$'
) 'Claude API 代理传输成功且 TLS 验证通过'

Write-Host "`n========== 4. 系统区域 =========="

Assert-Check (
    (Get-TimeZone).Id -eq 'Eastern Standard Time'
) '美国东部时区'

Assert-Check (
    (Get-WinSystemLocale).Name -eq 'en-US'
) '系统区域 en-US'

Assert-Check (
    (Get-Culture).Name -eq 'en-US'
) '地区格式 en-US'

Write-Host "`n========== 5. 防火墙规则 =========="

$names = @(
    'ClaudeCodeFailClosed-BlockDirect-IPv4'
    'ClaudeCodeFailClosed-BlockDirect-IPv6'
)

foreach ($name in $names) {
    $rule = Get-NetFirewallRule -Name $name `
        -ErrorAction Stop

    Assert-Check (
        $rule.Action -eq 'Block'
    ) "$name 为阻断规则"

    Write-Host "启用状态: $($rule.Enabled)"
}

Write-Host "`n========== 审计结束 =========="
Write-Host "注意：审计通过不代表网络隔离已生效"