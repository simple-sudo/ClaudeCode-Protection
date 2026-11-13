#requires -Version 7.4
param([string]$OutputRoot, [switch]$Win32kControl, [switch]$BuildBranchWitness, [switch]$PrivateDesktopControl, [switch]$BuildPrivateTraceWitness)

$ErrorActionPreference = 'Stop'
$repoRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'scripts\Assert-ProjectSecurityClearance.ps1') -Stage IsolationProbe
if ($PrivateDesktopControl -and ($Win32kControl -or $BuildBranchWitness -or $BuildPrivateTraceWitness) -or
    $BuildPrivateTraceWitness -and $BuildBranchWitness) { throw 'Private desktop control requires its own witness' }

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or !$installation) { throw 'Microsoft x64 C++ Build Tools required' }
$compilerRoot = Get-ChildItem -LiteralPath (Join-Path $installation 'VC\Tools\MSVC') -Directory |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$tools = Join-Path $compilerRoot.FullName 'bin\Hostx64\x64'
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$version = '10.0.26100.0'
$includes = @(
    (Join-Path $compilerRoot.FullName 'include')
    (Join-Path $sdk "Include\$version\um")
    (Join-Path $sdk "Include\$version\shared")
    (Join-Path $sdk "Include\$version\ucrt")
) | ForEach-Object { "/I$_" }

if (!$OutputRoot) { $OutputRoot = Join-Path $repo 'work' }
$output = Join-Path $OutputRoot ('session-zero-startup-witness-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $output)
$exe = Join-Path $output 'SessionZeroStartupWitness.exe'
$object = Join-Path $output 'StartupWitness.obj'
$source = Join-Path $PSScriptRoot 'StartupWitness.c'
$savedPath = $env:PATH
try {
    $env:PATH = "$tools;$savedPath"
    # Keep CRT and pre-entry user32/shell32 initialization out of the witness.
    $defines = @()
    if ($Win32kControl) { $defines += '/DORDINARY_WIN32K_CONTROL' }
    if ($BuildBranchWitness) { $defines += '/DSTARTUP_BRANCH_WITNESS' }
    if ($PrivateDesktopControl) { $defines += '/DSTARTUP_PRIVATE_DESKTOP_WITNESS' }
    if ($BuildPrivateTraceWitness) { $defines += @('/DSTARTUP_PRIVATE_DESKTOP_WITNESS','/DSTARTUP_PRIVATE_TRACE_WITNESS') }
    $arguments = @('/nologo','/TC','/std:c17','/W4','/WX','/O2','/GS-','/Zl') + $defines + $includes + @(
        "/Fo$object", "/Fe$exe", $source, '/link', '/NODEFAULTLIB', '/ENTRY:StartupWitness', '/SUBSYSTEM:CONSOLE',
        '/DYNAMICBASE', '/NXCOMPAT', '/Brepro', "/LIBPATH:$sdk\Lib\$version\um\x64", 'kernel32.lib'
    )
    & (Join-Path $tools 'cl.exe') @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Startup witness build failed' }
    $dependencies = & (Join-Path $tools 'dumpbin.exe') /dependents $exe
    if ($LASTEXITCODE -ne 0) { throw 'Startup witness import inspection failed' }
    $imports = @($dependencies | Select-String '^[ \t]+[a-z0-9_.-]+\.dll$' | ForEach-Object { $_.Line.Trim() })
    if ($imports.Count -ne 1 -or $imports[0] -ne 'KERNEL32.dll') { throw 'Unexpected startup witness imports' }
} finally {
    $env:PATH = $savedPath
}

if ($BuildBranchWitness -or $BuildPrivateTraceWitness) {
    [pscustomobject]@{
        Result = if ($BuildPrivateTraceWitness) { 'PRIVATE_TRACE_WITNESS_BUILT' } else { 'BRANCH_WITNESS_BUILT' }
        Win32kControl = [bool]$Win32kControl
        StaticImport = $imports[0]
        Length = (Get-Item -LiteralPath $exe).Length
        SHA256 = (Get-FileHash -LiteralPath $exe).Hash
        Image = $exe
    }
    return
}

$info = [Diagnostics.ProcessStartInfo]::new($exe)
$info.WorkingDirectory = $output
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$process = [Diagnostics.Process]::Start($info)
try {
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(10000)) { throw 'Startup witness terminal state unavailable' }
    $checkpoints = @('ENTRY','BEFORE_USER32','AFTER_USER32','BEFORE_DESKTOP','AFTER_DESKTOP',
        'BEFORE_SHELL32','AFTER_SHELL32','BEFORE_UCRT','AFTER_UCRT')
    $diagnostics = @('WIN32K_QUERY','WIN32K_BLOCKED','USER32_FILE','USER32_MAP',
        'WIN32U_LOAD','GDI32_LOAD','GDI32FULL_LOAD') | ForEach-Object { "$_=0x00000000" }
    $expectedExit = 0
    if ($Win32kControl) {
        $checkpoints = @('ENTRY','BEFORE_USER32','WIN32=0x0000045A')
        $diagnostics[1] = 'WIN32K_BLOCKED=0x00000001'
        $diagnostics[5] = 'GDI32_LOAD=0x00000008'
        $diagnostics[6] = 'GDI32FULL_LOAD=0x00000008'
        $expectedExit = 65
    }
    if ($PrivateDesktopControl) {
        $checkpoints = @('ENTRY','BEFORE_USER32','AFTER_USER32','BEFORE_DESKTOP','WIN32=0x0000000D')
        $diagnostics = @()
        $expectedExit = 72
    }
    $observed = $stdout.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $output 'ordinary-stdout.txt'), $observed)
    $errorOutput = $stderr.GetAwaiter().GetResult()
    [IO.File]::WriteAllText((Join-Path $output 'ordinary-stderr.txt'), $errorOutput)
    $expected = (($checkpoints + $diagnostics) -join [char]10) + [char]10
    if ($process.ExitCode -ne $expectedExit -or $observed -cne $expected -or $errorOutput) {
        throw 'Ordinary startup witness checkpoints differ'
    }
} finally {
    $process.Dispose()
}
[pscustomobject]@{
    Result = if ($PrivateDesktopControl) { 'ORDINARY_PRIVATE_DESKTOP_REFUSED' } elseif ($Win32kControl) { 'ORDINARY_WIN32K_CONTROL_PASSED' } else { 'ORDINARY_STARTUP_WITNESS_PASSED' }
    StaticImport = $imports[0]
    Checkpoints = $checkpoints.Count
    Diagnostics = $diagnostics.Count
    ExitCode = $expectedExit
    Length = (Get-Item -LiteralPath $exe).Length
    SHA256 = (Get-FileHash -LiteralPath $exe).Hash
    Image = $exe
    SessionZeroLpacVerified = $false
}
