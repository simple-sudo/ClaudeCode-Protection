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
if([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)){
    throw 'SECURITY_MONITOR_FAILED: LOCALAPPDATA is unavailable; refusing to run without a durable local evidence path.'
}
$script:ProjectSecurityLogRoot=Join-Path $env:LOCALAPPDATA 'ClaudeCode-Protection\security-stage'
[void][IO.Directory]::CreateDirectory($script:ProjectSecurityLogRoot)
$script:ProjectSecurityRunId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+$PID
$script:ProjectSecurityEvidencePath=Join-Path $script:ProjectSecurityLogRoot ($script:ProjectSecurityRunId+'-'+$Stage+'-kaspersky-monitor.jsonl')

function Write-ProjectSecurityEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RecordType,
        [Parameter(Mandatory=$true)][object]$Data
    )
    $record=[ordered]@{
        ObservedAtUtc=[DateTime]::UtcNow.ToString('o')
        Stage=$script:ProjectSecurityStage
        RecordType=$RecordType
        Data=$Data
    }
    $line=$record | ConvertTo-Json -Depth 9 -Compress
    Add-Content -LiteralPath $script:ProjectSecurityEvidencePath -Value $line -Encoding utf8 -ErrorAction Stop
}

function Get-ProjectSecurityEvents {
    [CmdletBinding()]
    param()
    try{
        return ,@(
            Get-WinEvent -FilterHashtable @{
                LogName='Application'
                StartTime=$script:ProjectSecurityStartedAt
            } -ErrorAction Stop | Where-Object { $_.ProviderName -match '(?i)avp|kaspersky' }
        )
    }catch{
        if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound'){return ,@()}
        Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{
            Check='ApplicationEventLog'
            Error=$_.Exception.Message
            FullyQualifiedErrorId=$_.FullyQualifiedErrorId
        }
        throw "SECURITY_MONITOR_FAILED: Application event log could not be inspected: $($_.Exception.Message)"
    }
}

function Get-ProjectSecuritySnapshot {
    [CmdletBinding()]
    param()

    try{
        $service=Get-Service -Name 'AVP21.26' -ErrorAction Stop
    }catch{
        Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{
            Check='KasperskyService'
            Service='AVP21.26'
            Error=$_.Exception.Message
        }
        throw 'SECURITY_MONITOR_FAILED: pinned Kaspersky service AVP21.26 is unavailable.'
    }
    if($service.Status -ne 'Running'){
        Write-ProjectSecurityEvidence -RecordType 'KasperskyStateChange' -Data @{
            Check='KasperskyService'
            Service=$service.Name
            Status=[string]$service.Status
        }
        throw 'SECURITY_MONITOR_FAILED: pinned Kaspersky service AVP21.26 is not running.'
    }

    try{
        $products=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop |
            Where-Object { $_.displayName -eq 'Kaspersky' })
    }catch{
        Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{
            Check='SecurityCenter2'
            Error=$_.Exception.Message
        }
        throw "SECURITY_MONITOR_FAILED: Security Center product state could not be read: $($_.Exception.Message)"
    }
    if($products.Count -ne 1 -or [uint32]$products[0].productState -ne 266240){
        Write-ProjectSecurityEvidence -RecordType 'KasperskyStateChange' -Data @{
            Check='SecurityCenter2'
            MatchingKasperskyProducts=$products.Count
            ProductStates=@($products | ForEach-Object { [uint32]$_.productState })
        }
        throw 'SECURITY_MONITOR_FAILED: Kaspersky Security Center registration/state differs from the qualified baseline.'
    }

    $events=@(Get-ProjectSecurityEvents)
    if($events.Count -gt 0){
        $details=@($events | Select-Object -First 16 | ForEach-Object {
            [pscustomobject]@{
                ProviderName=$_.ProviderName
                EventId=$_.Id
                RecordId=$_.RecordId
                TimeCreatedUtc=if($_.TimeCreated){$_.TimeCreated.ToUniversalTime().ToString('o')}else{$null}
            }
        })
        Write-ProjectSecurityEvidence -RecordType 'KASPERSKY_NEW_EVENT' -Data $details
        throw ("KASPERSKY_NEW_EVENT: new Kaspersky-related Application event(s) detected since stage start: "+(($details | ForEach-Object {"$($_.ProviderName)/$($_.EventId)/$($_.RecordId)"}) -join ', '))
    }

    $snapshot=[pscustomobject]@{
        ObservedAtUtc=[DateTime]::UtcNow.ToString('o')
        Stage=$script:ProjectSecurityStage
        KasperskyService=$service.Name
        KasperskyServiceStatus=[string]$service.Status
        KasperskyProductState=[uint32]$products[0].productState
        ApplicationKasperskyEventsSinceStageStart=0
        FullVendorAlertVisibility='UNKNOWN'
    }
    Write-ProjectSecurityEvidence -RecordType 'KasperskyHealthSnapshot' -Data $snapshot
    return $snapshot
}

try{
    $script:ProjectSecurityInitialSnapshot=Get-ProjectSecuritySnapshot
}catch{
    try{Write-ProjectSecurityEvidence -RecordType 'PreflightFailure' -Data @{Error=$_.Exception.Message}}catch{}
    throw
}

function Invoke-ProjectSecurityMonitoredProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$ArgumentList,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][string]$StandardOutputPath,
        [Parameter(Mandatory=$true)][string]$StandardErrorPath
    )
    if($script:ProjectSecurityStage -cne 'DailyBuild'){
        throw 'SECURITY_STAGE_BLOCKED: monitored process invocation is not enabled for this stage.'
    }
    if(-not (Test-Path -LiteralPath $FilePath -PathType Leaf)){throw 'Monitored executable is missing.'}
    if(-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)){throw 'Monitored working directory is missing.'}

    [void](Get-ProjectSecuritySnapshot)
    Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStarting' -Data @{
        FilePath=$FilePath
        ArgumentList=$ArgumentList
        WorkingDirectory=$WorkingDirectory
        StandardOutputPath=$StandardOutputPath
        StandardErrorPath=$StandardErrorPath
    }
    try{
        $process=Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -PassThru -NoNewWindow -RedirectStandardOutput $StandardOutputPath -RedirectStandardError $StandardErrorPath
    }catch{
        Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStartFailure' -Data @{Error=$_.Exception.Message}
        throw
    }
    Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStarted' -Data @{
        ProcessId=$process.Id
        FilePath=$FilePath
    }

    $lastFullCheck=[DateTime]::UtcNow
    try{
        while(-not $process.HasExited){
            Start-Sleep -Milliseconds 750
            $process.Refresh()
            if($process.HasExited){break}
            $full=([DateTime]::UtcNow-$lastFullCheck).TotalSeconds -ge 3
            if($full){
                [void](Get-ProjectSecuritySnapshot)
                $lastFullCheck=[DateTime]::UtcNow
            }else{
                $events=@(Get-ProjectSecurityEvents)
                if($events.Count -gt 0){
                    $details=@($events | Select-Object -First 16 | ForEach-Object {
                        [pscustomobject]@{
                            ProviderName=$_.ProviderName
                            EventId=$_.Id
                            RecordId=$_.RecordId
                            TimeCreatedUtc=if($_.TimeCreated){$_.TimeCreated.ToUniversalTime().ToString('o')}else{$null}
                        }
                    })
                    Write-ProjectSecurityEvidence -RecordType 'KASPERSKY_NEW_EVENT' -Data $details
                    throw 'KASPERSKY_NEW_EVENT: a new Kaspersky-related Application event was detected during the build.'
                }
            }
        }
        $process.Refresh()
        [void](Get-ProjectSecuritySnapshot)
        Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessExited' -Data @{
            ProcessId=$process.Id
            ExitCode=[int]$process.ExitCode
        }
        return [int]$process.ExitCode
    }catch{
        $reason=$_.Exception.Message
        try{Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStopped' -Data @{
            ProcessId=$process.Id
            Reason=$reason
        }}catch{}
        try{
            $process.Refresh()
            if(-not $process.HasExited){
                $process.Kill($true)
                [void]$process.WaitForExit(10000)
                Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessTreeTerminated' -Data @{
                    ProcessId=$process.Id
                    HasExited=$process.HasExited
                }
            }
        }catch{
            try{Write-ProjectSecurityEvidence -RecordType 'ProcessTerminationFailure' -Data @{ProcessId=$process.Id;Error=$_.Exception.Message}}catch{}
        }
        throw "SECURITY_MONITORED_BUILD_STOPPED: $reason"
    }
}

Write-Output ("SECURITY_STAGE_READY: {0}; Kaspersky service and SecurityCenter2 state verified; event monitoring active; evidence={1}" -f $Stage,$script:ProjectSecurityEvidencePath)
