#requires -Version 7.4
param([Parameter(Mandatory)][string]$EvidenceDirectory)

$ErrorActionPreference = 'Stop'
$repoRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'scripts\Assert-ProjectSecurityClearance.ps1') -Stage IsolationProbe
$out = (New-Item -ItemType Directory -Path $EvidenceDirectory).FullName
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -or !$vs) { throw 'MSVC x64 required' }
$compiler = Get-ChildItem -LiteralPath (Join-Path $vs 'VC/Tools/MSVC') -Directory |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$tools = Join-Path $compiler.FullName 'bin/Hostx64/x64'
$sdk = 'C:\Program Files (x86)\Windows Kits\10'
$ver = '10.0.26100.0'
$includes = @((Join-Path $compiler.FullName 'include'),(Join-Path $sdk "Include/$ver/um"),
    (Join-Path $sdk "Include/$ver/shared"),(Join-Path $sdk "Include/$ver/ucrt")) | ForEach-Object { "/I$_" }
$savedPath = $env:PATH
try {
    $env:PATH = "$tools;$savedPath"
    $rows = @(foreach ($variant in 'native-default','native-disabled') {
        $exe = Join-Path $out "$variant.exe"
        $obj = Join-Path $out "$variant.obj"
        $defines = if ($variant -ceq 'native-disabled') { @('/DTEST_WIN32K_DISABLED') } else { @() }
        $arguments = @('/nologo','/TC','/std:c17','/W4','/WX','/O2','/GS-','/Zl') + $includes + $defines + @(
            "/Fo$obj","/Fe$exe",(Join-Path $PSScriptRoot 'GpuWin32kNative.c'),
            '/link','/NODEFAULTLIB','/ENTRY:GpuWin32kNative','/SUBSYSTEM:CONSOLE','/DYNAMICBASE','/NXCOMPAT','/Brepro',
            "/LIBPATH:$sdk/Lib/$ver/um/x64",'kernel32.lib')
        & (Join-Path $tools 'cl.exe') @arguments | Tee-Object -FilePath (Join-Path $out "$variant-build.log") | Out-Host
        if ($LASTEXITCODE) { throw 'Native witness build failed' }
        $imports = @(& (Join-Path $tools 'dumpbin.exe') /dependents $exe | Select-String '^[ \t]+[a-z0-9_.-]+\.dll$' |
            ForEach-Object { $_.Line.Trim() })
        if ($LASTEXITCODE -or $imports.Count -ne 1 -or $imports[0] -cne 'KERNEL32.dll') { throw 'Native witness import differs' }
        $start = [Diagnostics.ProcessStartInfo]::new($exe)
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['CUDA_FORCE_PRELOAD_LIBRARIES'] = '0'
        $process = [Diagnostics.Process]::Start($start)
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (!$process.WaitForExit(20000)) { throw 'Owned native test process remains live' }
            $body = $stdout.GetAwaiter().GetResult()
            $path = Join-Path $out "$variant-private.log"
            [IO.File]::WriteAllText($path,$body,[Text.UTF8Encoding]::new($false))
            $safe = [ordered]@{}
            foreach ($line in $body -split '\r?\n') {
                if ($line -match '^(WIN32K|USER32_LOAD|DESKTOP_PRESENT|WIN32U_LOAD|WDDM_SIZE|WDDM_READ|WDDM_COUNT|WDDM_CLOSE|PNP_LOAD|PNP_SIZE|PNP_LIST|CUDA_LOAD|CUDA_INIT|CUDA_DEVICE|CUDA_UUID_STATUS|NVML_LOAD|NVML_INIT|NVML_HANDLE|NVML_UUID_STATUS|NVML_SHUTDOWN|SET_FAILED)=([0-9A-F]{8})$') {
                    $key = $Matches[1]
                    $number = [BitConverter]::ToUInt32([Convert]::FromHexString($Matches[2]))
                    if ($key -eq 'WDDM_CLOSE') { $safe[$key] = @($safe[$key] | Where-Object { $null -ne $_ }) + @($number) }
                    else { $safe[$key] = $number }
                }
            }
            [ordered]@{Variant=$variant; ExitCode=$process.ExitCode; Imports=$imports; ErrorLength=$stderr.GetAwaiter().GetResult().Length;
                Checkpoints=$safe; WddmLuidCount=@($body -split '\r?\n' | Where-Object {$_ -match '^WDDM_LUID='}).Count;
                PnpContentPresent=$body -match '(?m)^PNP_CONTENT=[0-9A-F]'; CudaUuidPresent=$body -match '(?m)^CUDA_UUID=[0-9A-F]';
                NvmlUuidPresent=$body -match '(?m)^NVML_UUID=[0-9A-F]';
                RawSHA256=(Get-FileHash -LiteralPath $path).Hash}
        } finally { $process.Dispose() }
    })
    $rows | ConvertTo-Json -Depth 6 | Tee-Object -FilePath (Join-Path $out 'native-summary.json')
} finally { $env:PATH = $savedPath }
