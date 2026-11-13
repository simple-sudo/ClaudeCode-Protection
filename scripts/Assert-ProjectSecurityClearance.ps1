[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('DailyBuild','EngineeringBuild','CenterBuild','NativeBuild','IsolationProbe','WfpMutation')]
    [string]$Stage
)
$ErrorActionPreference='Stop'
$script:ProjectSecurityStage=$Stage
$script:ProjectSecurityStartedAt=Get-Date
if($Stage -cne 'DailyBuild'){
    throw "SECURITY_STAGE_BLOCKED: '$Stage' has not been opened. Only DailyBuild is currently eligible."
}
function Get-ProjectSecuritySnapshot {
    [CmdletBinding()]
    param([switch]$IncludeEvents)
    $service=Get-Service -Name 'AVP21.26' -ErrorAction Stop
    if($service.Status -ne 'Running'){throw 'SECURITY_MONITOR_FAILED: pinned Kaspersky service AVP21.26 is not running.'}
    $products=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop | Where-Object { $_.displayName -eq 'Kaspersky' })
    if($products.Count -ne 1 -or [uint32]$products[0].productState -ne 266240){
        throw 'SECURITY_MONITOR_FAILED: Kaspersky Security Center registration/state differs from the qualified baseline.'
    }
    $events=@()
    if($IncludeEvents){
        try{
            $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$script:ProjectSecurityStartedAt} -ErrorAction Stop | Where-Object { $_.ProviderName -match '(?i)avp|kaspersky' })
        }catch{
            if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){
                throw "SECURITY_MONITOR_FAILED: Application event log could not be inspected: $($_.Exception.Message)"
            }
        }
        if($events.Count -gt 0){
            $ids=(@($events | Select-Object -First 8 | ForEach-Object { "$($_.ProviderName)/$($_.Id)/$($_.RecordId)" }) -join ', ')
            throw "KASPERSKY_NEW_EVENT: new Kaspersky-related Application event(s) detected since stage start: $ids"
        }
    }
    [pscustomobject]@{
        ObservedAtUtc=[DateTime]::UtcNow.ToString('o')
        Stage=$script:ProjectSecurityStage
        KasperskyService=$service.Name
        KasperskyServiceStatus=[string]$service.Status
        KasperskyProductState=[uint32]$products[0].productState
        ApplicationKasperskyEventsSinceStageStart=$events.Count
        FullVendorAlertVisibility='UNKNOWN'
    }
}
$script:ProjectSecurityInitialSnapshot=Get-ProjectSecuritySnapshot -IncludeEvents
function Invoke-ProjectSecurityMonitoredProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$ArgumentList,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][string]$StandardOutputPath,
        [Parameter(Mandatory=$true)][string]$StandardErrorPath
    )
    if($script:ProjectSecurityStage -cne 'DailyBuild'){throw 'SECURITY_STAGE_BLOCKED: monitored process invocation is not enabled for this stage.'}
    if(-not (Test-Path -LiteralPath $FilePath -PathType Leaf)){throw 'Monitored executable is missing.'}
    if(-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)){throw 'Monitored working directory is missing.'}
    [void](Get-ProjectSecuritySnapshot -IncludeEvents)
    $process=Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -PassThru -NoNewWindow -RedirectStandardOutput $StandardOutputPath -RedirectStandardError $StandardErrorPath
    $lastFullCheck=[DateTime]::UtcNow
    try{
        while(-not $process.HasExited){
            Start-Sleep -Milliseconds 750
            $process.Refresh()
            if($process.HasExited){break}
            $full=([DateTime]::UtcNow-$lastFullCheck).TotalSeconds -ge 3
            if($full){
                [void](Get-ProjectSecuritySnapshot -IncludeEvents)
                $lastFullCheck=[DateTime]::UtcNow
            }else{
                $events=@()
                try{
                    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$script:ProjectSecurityStartedAt} -ErrorAction Stop | Where-Object { $_.ProviderName -match '(?i)avp|kaspersky' })
                }catch{
                    if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){throw "SECURITY_MONITOR_FAILED: event monitoring failed: $($_.Exception.Message)"}
                }
                if($events.Count -gt 0){throw 'KASPERSKY_NEW_EVENT: a new Kaspersky-related Application event was detected during the build.'}
            }
        }
        $process.Refresh()
        [void](Get-ProjectSecuritySnapshot -IncludeEvents)
        return [int]$process.ExitCode
    }catch{
        $reason=$_.Exception.Message
        try{$process.Refresh();if(-not $process.HasExited){$process.Kill($true);[void]$process.WaitForExit(10000)}}catch{}
        throw "SECURITY_MONITORED_BUILD_STOPPED: $reason"
    }
}
Write-Output ("SECURITY_STAGE_READY: {0}; Kaspersky service and SecurityCenter2 state verified; event monitoring active." -f $Stage)
