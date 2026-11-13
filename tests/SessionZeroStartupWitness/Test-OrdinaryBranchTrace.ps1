#requires -Version 7.4
param(
    [Parameter(Mandatory)][string]$Library,
    [Parameter(Mandatory)][string]$BuildReceipt,
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$repoRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot 'scripts\Assert-ProjectSecurityClearance.ps1') -Stage IsolationProbe
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Ordinary branch trace test required'
    }
} finally { $identity.Dispose() }
if (Test-Path -LiteralPath $OutputPath) { throw 'Fresh branch trace result required' }
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $Library).Path)
$observerType = $assembly.GetType('ProtectionLifecycle.SessionZeroStartupBranchTrace', $true)
$instance = [Reflection.BindingFlags]'NonPublic, Instance'
$capture = $observerType.GetMethod('Observe',$instance)
$snapshot = $observerType.GetMethod('Snapshot',$instance)
$inputs = @(Get-Content -LiteralPath $BuildReceipt -Raw | ConvertFrom-Json)
if ($inputs.Count -ne 2 -or @($inputs | Where-Object Win32kControl).Count -ne 1) { throw 'Both witness controls required' }
$privateTrace = $inputs[0].Result -ceq 'PRIVATE_TRACE_WITNESS_BUILT'
$buildResult = if ($privateTrace) { 'PRIVATE_TRACE_WITNESS_BUILT' } else { 'BRANCH_WITNESS_BUILT' }
$positiveExit = if ($privateTrace) { 72 } else { 0 }
$positiveTail = "BEFORE_USER32`nAFTER_USER32`n"
$negativeTail = "BEFORE_USER32`nWIN32=0x0000045A`n"
if ($privateTrace) {
    $holdWindowQueryImage = $observerType.GetMethod('HoldWindowQueryImage', [Reflection.BindingFlags]'NonPublic, Static')
    $windowQueryImage = $holdWindowQueryImage.Invoke($null, $null)
    $positiveTail += "BEFORE_DESKTOP`nWIN32=0x0000000D`n"
    $negativeTail += "WINDOW_QUERY=0x00000000`nWINDOW_STATION_PRESENT=0x00000000`nWINDOW_DESKTOP_PRESENT=0x00000000`n"
    $negativeTail += "WINDOW_STATION_MATCH=0xFFFFFFFF`nWINDOW_DESKTOP_MATCH=0xFFFFFFFF`n"
}

Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class OrdinaryStartupTraceProcess
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint pid);
}
'@

$default = $inputs | Where-Object { !$_.Win32kControl }
$cases = @($inputs | ForEach-Object { @{Input=$_;Mode='Observe'} }) +
    @(@{Input=$default;Mode='AbortAfterUser32Map'}, @{Input=$default;Mode='NoAttachment'})
$results = @(foreach ($case in $cases) {
    $item = $case.Input
    if ($item.Result -cne $buildResult -or $item.StaticImport -cne 'KERNEL32.dll' -or
        (Get-FileHash -LiteralPath $item.Image).Hash -cne $item.SHA256) { throw 'Branch witness pin differs' }
    $observer = [Activator]::CreateInstance($observerType, $true)
    $info = [Diagnostics.ProcessStartInfo]::new($item.Image)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        $null = $process.SafeHandle
        $entry = $process.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(3)).GetAwaiter().GetResult()
        $threads = @($process.Threads)
        if ($entry -cne 'ENTRY' -or $threads.Count -ne 1 -or $process.MainModule.FileName -cne $item.Image) {
            throw 'Ordinary witness process binding differs'
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($case.Mode -ne 'NoAttachment') {
            $check = [Action]{}
            if ($case.Mode -eq 'AbortAfterUser32Map') {
                $check = [Action]({
                    if ($snapshot.Invoke($observer,$null).User32Mapped) { throw 'Ordinary injected health loss' }
                }.GetNewClosure())
            }
            $query = [OrdinaryStartupTraceProcess]::OpenProcess(0x121000, $false, [uint32]$process.Id)
            try {
                if ($query.IsInvalid) { throw 'Could not hold limited process handle' }
                $observedAbort = $false
                try { $null = $capture.Invoke($observer,@($query,[uint32]$process.Id,[uint32]$threads[0].Id,$check)) }
                catch {
                    $errorCause = $_.Exception.GetBaseException()
                    if ($case.Mode -ne 'AbortAfterUser32Map' -or $errorCause.Message -ne 'Ordinary injected health loss') {
                        throw "Branch trace failed at $($errorCause.Data['Stage']) with $($errorCause.GetType().Name) $($errorCause.NativeErrorCode)"
                    }
                    $observedAbort = $true
                }
                if ($case.Mode -eq 'AbortAfterUser32Map' -and !$observedAbort) { throw 'Injected loss not observed' }
            } finally { $query.Dispose() }
        }
        if (!$process.WaitForExit(6000)) { throw 'Ordinary witness terminal state unavailable' }
        $evidence = $snapshot.Invoke($observer,$null)
        $tail = $stdout.GetAwaiter().GetResult()
        if ($case.Mode -eq 'AbortAfterUser32Map') {
            if (!$evidence.Attached -or !$evidence.User32Mapped -or !$evidence.Detached -or $evidence.ExitEventContinued -or
                $evidence.Gdi32FullMapped -or $process.ExitCode -ne $positiveExit -or $tail -cne $positiveTail -or
                $stderr.GetAwaiter().GetResult()) { throw 'Ordinary branch trace detach evidence differs' }
            [pscustomobject]@{Mode=$case.Mode;Win32kControl=$false;ImageSHA256=$item.SHA256;Exit=$process.ExitCode;Evidence=$evidence}
            continue
        }
        if ($case.Mode -eq 'NoAttachment') {
            if ($evidence.Attached -or $process.ExitCode -ne 71 -or $tail -or $stderr.GetAwaiter().GetResult()) {
                throw 'Unobserved witness did not stop before USER32'
            }
            [pscustomobject]@{Mode=$case.Mode;Win32kControl=$false;ImageSHA256=$item.SHA256;Exit=$process.ExitCode;Evidence=$evidence}
            continue
        }
        if (!$evidence.Attached -or !$evidence.ExitEventContinued -or !$evidence.User32Mapped -or !$evidence.Gdi32FullMapped -or
            $evidence.CsrStatus -ne 0 -or $stderr.GetAwaiter().GetResult()) { throw 'Ordinary branch trace evidence incomplete' }
        if ($item.Win32kControl) {
            if ($process.ExitCode -ne 65 -or $tail -cne $negativeTail -or
                !$evidence.GdiInit2ReturnedNull -or $evidence.GdiStatus -ne [uint32]3221225473 -or
                $evidence.FailureValue -ne [uint32]3221225473) { throw 'Ordinary Win32k control branch differs' }
        } elseif ($process.ExitCode -ne $positiveExit -or $tail -cne $positiveTail -or
            $evidence.GdiInit2ReturnedNull -ne $false -or $evidence.GdiStatus -ne 0 -or $null -ne $evidence.FailureValue) {
            throw 'Ordinary positive control branch differs'
        }
        [pscustomobject]@{Mode=$case.Mode;Win32kControl=$item.Win32kControl;ImageSHA256=$item.SHA256;Exit=$process.ExitCode;Evidence=$evidence}
    } finally {
        $process.Dispose()
        $observer.Dispose()
    }
})
if ($privateTrace) { $windowQueryImage.Dispose() }
$results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding utf8
$results | ConvertTo-Json -Depth 6
