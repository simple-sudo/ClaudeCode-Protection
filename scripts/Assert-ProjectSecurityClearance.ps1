[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)]
 [ValidateSet('DailyBuild','EngineeringBuild','CenterBuild','NativeBuild','IsolationProbe','WfpMutation','LegacyOfflineBuild')]
 [string]$Stage
)
$ErrorActionPreference='Stop'
$script:ProjectSecurityStage=$Stage
$script:ProjectSecurityStartedAt=Get-Date
$script:ProjectSecurityRoot=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if($Stage -cne 'DailyBuild'){throw "SECURITY_STAGE_BLOCKED: '$Stage' has not been opened. Only DailyBuild is currently eligible."}
if([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)){throw 'SECURITY_MONITOR_FAILED: LOCALAPPDATA is unavailable.'}
$script:ProjectSecurityLogRoot=Join-Path $env:LOCALAPPDATA 'ClaudeCode-Protection\security-stage'
[void][IO.Directory]::CreateDirectory($script:ProjectSecurityLogRoot)
$script:ProjectSecurityRunId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+$PID+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
$script:ProjectSecurityEvidencePath=Join-Path $script:ProjectSecurityLogRoot ($script:ProjectSecurityRunId+'-DailyBuild-kaspersky-monitor.jsonl')
$script:ProjectSecurityDotNetPath='C:\Program Files\dotnet\dotnet.exe'
$script:ProjectSecurityBuildProperties=@(
 '-p:ImportDirectoryBuildProps=false','-p:ImportDirectoryBuildTargets=false','-p:ImportDirectoryPackagesProps=false',
 '-p:EnableNETAnalyzers=false','-p:RunAnalyzers=false','-p:RunAnalyzersDuringBuild=false',
 '-p:UseSharedCompilation=false','-p:BuildProjectReferences=false',
 '-p:CustomBeforeMicrosoftCommonTargets=','-p:CustomAfterMicrosoftCommonTargets=',
 '-p:CustomBeforeMicrosoftCSharpTargets=','-p:CustomAfterMicrosoftCSharpTargets=',
 '-p:CustomBeforeMicrosoftNETCoreCompile=','-p:CustomAfterMicrosoftNETCoreCompile='
)
foreach($part in @('Props','Targets')){
 foreach($position in @('Before','After')){
  $script:ProjectSecurityBuildProperties+='-p:ImportUserLocationsByWildcard'+$position+'MicrosoftCommon'+$part+'=false'
  $script:ProjectSecurityBuildProperties+='-p:ImportByWildcard'+$position+'MicrosoftCommon'+$part+'=false'
 }
}

function Write-ProjectSecurityEvidence {
 [CmdletBinding()]
 param([Parameter(Mandatory=$true)][string]$RecordType,[Parameter(Mandatory=$true)][object]$Data)
 $record=[ordered]@{
  ObservedAtUtc=[DateTime]::UtcNow.ToString('o')
  RunId=$script:ProjectSecurityRunId
  Stage=$script:ProjectSecurityStage
  RecordType=$RecordType
  Data=$Data
 }
 Add-Content -LiteralPath $script:ProjectSecurityEvidencePath -Value ($record | ConvertTo-Json -Depth 12 -Compress) -Encoding utf8 -ErrorAction Stop
}

function Get-ProjectSecurityEventChannelInventory {
 [CmdletBinding()]
 param()
 try{
  $logs=@(Get-WinEvent -ListLog * -ErrorAction Stop | Where-Object {$_.LogName -match '(?i)(kaspersky|avp)'} | Sort-Object LogName)
  return @($logs | ForEach-Object {[pscustomobject]@{LogName=[string]$_.LogName;IsEnabled=[bool]$_.IsEnabled}})
 }catch{
  try{Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='KasperskyEventChannelInventory';Error=$_.Exception.Message;FullyQualifiedErrorId=$_.FullyQualifiedErrorId}}catch{}
  throw "SECURITY_MONITOR_FAILED: Kaspersky event-channel inventory could not be read: $($_.Exception.Message)"
 }
}

function Get-ProjectSecurityEvents {
 [CmdletBinding()]
 param()
 $events=[Collections.Generic.List[object]]::new()
 try{
  $application=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$script:ProjectSecurityStartedAt} -ErrorAction Stop |
   Where-Object {$_.ProviderName -match '(?i)avp|kaspersky'})
  foreach($event in $application){$events.Add($event)}
 }catch{
  if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){
   try{Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='ApplicationEventLog';Error=$_.Exception.Message;FullyQualifiedErrorId=$_.FullyQualifiedErrorId}}catch{}
   throw "SECURITY_MONITOR_FAILED: Application event log could not be inspected: $($_.Exception.Message)"
  }
 }
 foreach($channel in @($script:ProjectSecurityVendorEventChannels | Where-Object IsEnabled)){
  try{
   $channelEvents=@(Get-WinEvent -FilterHashtable @{LogName=$channel.LogName;StartTime=$script:ProjectSecurityStartedAt} -ErrorAction Stop)
   foreach($event in $channelEvents){$events.Add($event)}
  }catch{
   if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){
    try{Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='KasperskyNamedEventLog';LogName=$channel.LogName;Error=$_.Exception.Message;FullyQualifiedErrorId=$_.FullyQualifiedErrorId}}catch{}
    throw "SECURITY_MONITOR_FAILED: Kaspersky event channel '$($channel.LogName)' could not be inspected: $($_.Exception.Message)"
   }
  }
 }
 $unique=@($events | Group-Object -Property {'{0}|{1}|{2}' -f $_.LogName,$_.ProviderName,$_.RecordId} | ForEach-Object {$_.Group[0]})
 return $unique
}

function ConvertTo-ProjectSecurityEventDetails {
 [CmdletBinding()]
 param([Parameter(Mandatory=$true)][object[]]$Events)
 try{
  return @($Events | Sort-Object TimeCreated | ForEach-Object {
   [pscustomobject]@{
    LogName=$_.LogName;ProviderName=$_.ProviderName;EventId=$_.Id;RecordId=$_.RecordId
    Level=$_.Level;LevelDisplayName=$_.LevelDisplayName
    TimeCreatedUtc=if($_.TimeCreated){$_.TimeCreated.ToUniversalTime().ToString('o')}else{$null}
    MachineName=$_.MachineName;Message=$_.Message;EventXml=$_.ToXml()
   }
  })
 }catch{
  try{Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='KasperskyEventMaterialization';Error=$_.Exception.Message}}catch{}
  throw "SECURITY_MONITOR_FAILED: a Kaspersky event could not be preserved completely: $($_.Exception.Message)"
 }
}

function Get-ProjectSecuritySnapshot {
 [CmdletBinding()]
 param()
 try{$service=Get-Service -Name 'AVP21.26' -ErrorAction Stop}
 catch{
  Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='KasperskyService';Service='AVP21.26';Error=$_.Exception.Message}
  throw 'SECURITY_MONITOR_FAILED: pinned Kaspersky service AVP21.26 is unavailable.'
 }
 if($service.Status -ne 'Running'){
  Write-ProjectSecurityEvidence -RecordType 'KasperskyStateChange' -Data @{Check='KasperskyService';Service=$service.Name;Status=[string]$service.Status}
  throw 'SECURITY_MONITOR_FAILED: pinned Kaspersky service AVP21.26 is not running.'
 }
 try{
  $products=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop | Where-Object {$_.displayName -eq 'Kaspersky'})
 }catch{
  Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='SecurityCenter2';Error=$_.Exception.Message}
  throw "SECURITY_MONITOR_FAILED: Security Center product state could not be read: $($_.Exception.Message)"
 }
 if($products.Count -ne 1 -or [uint32]$products[0].productState -ne 266240){
  Write-ProjectSecurityEvidence -RecordType 'KasperskyStateChange' -Data @{
   Check='SecurityCenter2';MatchingKasperskyProducts=$products.Count
   ProductStates=@($products | ForEach-Object {[uint32]$_.productState})
  }
  throw 'SECURITY_MONITOR_FAILED: Kaspersky Security Center registration/state differs from the qualified baseline.'
 }
 $currentChannels=@(Get-ProjectSecurityEventChannelInventory)
 $disabledChannels=@($currentChannels | Where-Object {-not $_.IsEnabled})
 if($disabledChannels.Count -gt 0){
  Write-ProjectSecurityEvidence -RecordType 'KasperskyEventChannelDisabled' -Data @{DisabledChannels=$disabledChannels}
  throw ('SECURITY_MONITOR_FAILED: Kaspersky/AVP event channel(s) are disabled: '+(($disabledChannels | ForEach-Object {$_.LogName}) -join ', '))
 }
 $initialKeys=@($script:ProjectSecurityVendorEventChannels | ForEach-Object {'{0}|{1}' -f $_.LogName,$_.IsEnabled})
 $currentKeys=@($currentChannels | ForEach-Object {'{0}|{1}' -f $_.LogName,$_.IsEnabled})
 $channelChanges=@(Compare-Object -ReferenceObject $initialKeys -DifferenceObject $currentKeys)
 if($channelChanges.Count -gt 0){
  Write-ProjectSecurityEvidence -RecordType 'KasperskyEventChannelSetChanged' -Data @{Initial=$script:ProjectSecurityVendorEventChannels;Current=$currentChannels;Differences=$channelChanges}
  throw 'SECURITY_MONITOR_FAILED: Kaspersky event-channel inventory changed during the monitored operation.'
 }
 $events=@(Get-ProjectSecurityEvents)
 if($events.Count -gt 0){
  $details=@(ConvertTo-ProjectSecurityEventDetails -Events $events)
  Write-ProjectSecurityEvidence -RecordType 'KASPERSKY_NEW_EVENT' -Data @{TotalEvents=$details.Count;Events=$details}
  throw ("KASPERSKY_NEW_EVENT: new Kaspersky-related Windows event(s) detected: "+(($details | ForEach-Object {"$($_.LogName)/$($_.ProviderName)/$($_.EventId)/$($_.RecordId)"}) -join ', '))
 }
 $snapshot=[pscustomobject]@{
  ObservedAtUtc=[DateTime]::UtcNow.ToString('o');RunId=$script:ProjectSecurityRunId;Stage=$script:ProjectSecurityStage
  KasperskyService=$service.Name;KasperskyServiceStatus=[string]$service.Status
  KasperskyProductState=[uint32]$products[0].productState
  ApplicationKasperskyEventsSinceStageStart=0
  MonitoredKasperskyEventChannels=@($currentChannels | Where-Object IsEnabled | ForEach-Object {$_.LogName})
  DisabledKasperskyEventChannels=@($currentChannels | Where-Object {-not $_.IsEnabled} | ForEach-Object {$_.LogName})
  FullVendorAlertVisibility='UNKNOWN'
 }
 Write-ProjectSecurityEvidence -RecordType 'KasperskyHealthSnapshot' -Data $snapshot
 return $snapshot
}

function Get-ProjectSecurityProcessTree {
 [CmdletBinding()]
 param([Parameter(Mandatory=$true)][int]$RootProcessId)
 try{$all=@(Get-CimInstance -ClassName Win32_Process -Property ProcessId,ParentProcessId,CreationDate,Name -ErrorAction Stop)}
 catch{
  try{Write-ProjectSecurityEvidence -RecordType 'MonitorFailure' -Data @{Check='ProcessTreeInspection';RootProcessId=$RootProcessId;Error=$_.Exception.Message}}catch{}
  throw "SECURITY_MONITOR_FAILED: process-tree inspection failed: $($_.Exception.Message)"
 }
 $rootRows=@($all | Where-Object {[int]$_.ProcessId -eq $RootProcessId})
 if($rootRows.Count -gt 1){throw 'SECURITY_MONITOR_FAILED: process ID is not unique in Win32_Process inventory.'}
 $children=@{}
 foreach($item in $all){
  $parentId=[int]$item.ParentProcessId
  if(-not $children.ContainsKey($parentId)){$children[$parentId]=[Collections.Generic.List[object]]::new()}
  $children[$parentId].Add($item)
 }
 $descendants=[Collections.Generic.List[object]]::new()
 $seen=[Collections.Generic.HashSet[int]]::new()
 $stack=[Collections.Generic.Stack[int]]::new()
 $stack.Push($RootProcessId)
 while($stack.Count -gt 0){
  $parentId=$stack.Pop()
  if(-not $children.ContainsKey($parentId)){continue}
  foreach($child in $children[$parentId]){
   $childId=[int]$child.ProcessId
   if($childId -eq $RootProcessId -or -not $seen.Add($childId)){continue}
   $creation=if($child.CreationDate -is [datetime]){$child.CreationDate.ToUniversalTime().ToString('o')}else{[string]$child.CreationDate}
   if([string]::IsNullOrWhiteSpace($creation)){throw 'SECURITY_MONITOR_FAILED: process creation identity is unavailable.'}
   $descendants.Add([pscustomobject]@{ProcessId=$childId;ParentProcessId=[int]$child.ParentProcessId;Name=[string]$child.Name;CreationDate=$creation})
   $stack.Push($childId)
  }
 }
 $rows=[Collections.Generic.List[object]]::new()
 if($rootRows.Count -eq 1){
  $root=$rootRows[0]
  $creation=if($root.CreationDate -is [datetime]){$root.CreationDate.ToUniversalTime().ToString('o')}else{[string]$root.CreationDate}
  if([string]::IsNullOrWhiteSpace($creation)){throw 'SECURITY_MONITOR_FAILED: root process creation identity is unavailable.'}
  $rows.Add([pscustomobject]@{ProcessId=$RootProcessId;ParentProcessId=[int]$root.ParentProcessId;Name=[string]$root.Name;CreationDate=$creation})
 }
 foreach($descendant in $descendants){$rows.Add($descendant)}
 return [pscustomobject]@{RootPresent=($rootRows.Count -eq 1);Rows=@($rows.ToArray())}
}

$script:ProjectSecurityVendorEventChannels=Get-ProjectSecurityEventChannelInventory
try{$script:ProjectSecurityInitialSnapshot=Get-ProjectSecuritySnapshot}
catch{try{Write-ProjectSecurityEvidence -RecordType 'PreflightFailure' -Data @{Error=$_.Exception.Message}}catch{};throw}

function Invoke-ProjectSecurityMonitoredProcess {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory=$true)][ValidateSet('SdkVersion','Preprocess','DailyBuild')][string]$Purpose,
  [Parameter(Mandatory=$true)][string]$FilePath,
  [Parameter(Mandatory=$true)][string[]]$ArgumentList,
  [Parameter(Mandatory=$true)][string]$WorkingDirectory,
  [Parameter(Mandatory=$true)][string]$StandardOutputPath,
  [Parameter(Mandatory=$true)][string]$StandardErrorPath,
  [string]$OperationOutputPath,
  [string]$OutputDirectory
 )
 if($script:ProjectSecurityStage -cne 'DailyBuild'){throw 'SECURITY_STAGE_BLOCKED: monitored process invocation is not enabled for this stage.'}
 if([IO.Path]::GetFullPath($FilePath) -ine $script:ProjectSecurityDotNetPath){throw 'SECURITY_STAGE_BLOCKED: DailyBuild may invoke only the pinned dotnet host.'}
 if([IO.Path]::GetFullPath($WorkingDirectory) -ine [IO.Path]::GetFullPath($script:ProjectSecurityWorkingDirectory)){throw 'SECURITY_STAGE_BLOCKED: monitored process working directory differs from the run workspace.'}
 $project=Join-Path $script:ProjectSecurityRoot 'src\ClaudeProtection\ClaudeProtection.csproj'
 switch($Purpose){
  'SdkVersion' {$expectedArguments=@('--version')}
  'Preprocess' {
   if([string]::IsNullOrWhiteSpace($OperationOutputPath) -or -not ([IO.Path]::GetFullPath($OperationOutputPath).StartsWith([IO.Path]::GetFullPath($script:ProjectSecurityWorkingDirectory)+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'SECURITY_STAGE_BLOCKED: MSBuild preprocess output must remain in the isolated run workspace.'}
   $expectedArguments=@('msbuild',$project,'-nologo','-noAutoResponse',('-preprocess:'+$OperationOutputPath))+$script:ProjectSecurityBuildProperties
  }
  'DailyBuild' {
   $expectedOutput=Join-Path $script:ProjectSecurityRoot ('bin\security-stage\'+$script:ProjectSecurityRunId)
   if([string]::IsNullOrWhiteSpace($OutputDirectory) -or [IO.Path]::GetFullPath($OutputDirectory) -ine [IO.Path]::GetFullPath($expectedOutput)){throw 'SECURITY_STAGE_BLOCKED: DailyBuild output must use this run''s isolated artifact directory.'}
   $expectedArguments=@('build',$project,'--configuration','Release','--output',$OutputDirectory,'--nologo','--verbosity','normal','--no-restore','--no-dependencies','--disable-build-servers','-m:1','-nr:false','-noAutoResponse')+$script:ProjectSecurityBuildProperties
  }
 }
 if($ArgumentList.Count -ne $expectedArguments.Count){throw 'SECURITY_STAGE_BLOCKED: monitored process argument count differs from the reviewed operation.'}
 for($index=0;$index -lt $expectedArguments.Count;$index++){
  if($ArgumentList[$index] -cne $expectedArguments[$index]){throw 'SECURITY_STAGE_BLOCKED: monitored process arguments differ from the reviewed operation.'}
 }
 $logPrefix=$script:ProjectSecurityLogRoot+'\'+$script:ProjectSecurityRunId+'-'
 foreach($logPath in @($StandardOutputPath,$StandardErrorPath)){
  if(-not [IO.Path]::GetFullPath($logPath).StartsWith($logPrefix,[StringComparison]::OrdinalIgnoreCase)){throw 'SECURITY_STAGE_BLOCKED: monitored process logs must be correlated under the security-stage run ID.'}
 }
 if(-not (Test-Path -LiteralPath $FilePath -PathType Leaf)){throw 'Monitored executable is missing.'}
 if(-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)){throw 'Monitored working directory is missing.'}
 [void](Get-ProjectSecuritySnapshot)
 Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStarting' -Data @{
  Purpose=$Purpose;FilePath=$FilePath;ArgumentList=$ArgumentList;WorkingDirectory=$WorkingDirectory
  StandardOutputPath=$StandardOutputPath;StandardErrorPath=$StandardErrorPath
  OperationOutputPath=$OperationOutputPath;OutputDirectory=$OutputDirectory
 }
 try{$process=Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -PassThru -NoNewWindow -RedirectStandardOutput $StandardOutputPath -RedirectStandardError $StandardErrorPath}
 catch{Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStartFailure' -Data @{Purpose=$Purpose;Error=$_.Exception.Message};throw}
 $lastFullCheck=[DateTime]::UtcNow
 try{
  Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStarted' -Data @{Purpose=$Purpose;ProcessId=$process.Id;FilePath=$FilePath}
  $initialTree=Get-ProjectSecurityProcessTree -RootProcessId $process.Id
  Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessTreeSnapshot' -Data @{Purpose=$Purpose;RootProcessId=$process.Id;RootPresent=$initialTree.RootPresent;Processes=$initialTree.Rows}
  if(-not $initialTree.RootPresent -and -not $process.HasExited){throw 'SECURITY_MONITOR_FAILED: monitored root process is absent from the process inventory.'}
  while(-not $process.HasExited){
   Start-Sleep -Milliseconds 750
   $process.Refresh()
   if($process.HasExited){break}
   $full=([DateTime]::UtcNow-$lastFullCheck).TotalSeconds -ge 3
   if($full){
    [void](Get-ProjectSecuritySnapshot)
    $tree=Get-ProjectSecurityProcessTree -RootProcessId $process.Id
    Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessTreeSnapshot' -Data @{Purpose=$Purpose;RootProcessId=$process.Id;RootPresent=$tree.RootPresent;Processes=$tree.Rows}
    if(-not $tree.RootPresent){throw 'SECURITY_MONITOR_FAILED: monitored root process disappeared while its operation was active.'}
    $lastFullCheck=[DateTime]::UtcNow
   }else{
    $events=@(Get-ProjectSecurityEvents)
    if($events.Count -gt 0){
     $details=@(ConvertTo-ProjectSecurityEventDetails -Events $events)
     Write-ProjectSecurityEvidence -RecordType 'KASPERSKY_NEW_EVENT' -Data @{TotalEvents=$details.Count;Events=$details}
     throw 'KASPERSKY_NEW_EVENT: a new Kaspersky-related Windows event was detected during the monitored operation.'
    }
   }
  }
  $process.Refresh()
  $finalTree=Get-ProjectSecurityProcessTree -RootProcessId $process.Id
  if($finalTree.Rows.Count -gt 0){
   Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessExitedWithDescendants' -Data @{Purpose=$Purpose;RootProcessId=$process.Id;Processes=$finalTree.Rows}
   throw 'SECURITY_MONITOR_FAILED: monitored root exited while one or more descendants remained.'
  }
  [void](Get-ProjectSecuritySnapshot)
  Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessExited' -Data @{Purpose=$Purpose;ProcessId=$process.Id;ExitCode=[int]$process.ExitCode;DescendantVerification='PASS'}
  return [int]$process.ExitCode
 }catch{
   $reason=$_.Exception.Message
   $terminationErrors=[Collections.Generic.List[string]]::new()
   $terminationEvidencePersisted=$true
   try{Write-ProjectSecurityEvidence -RecordType 'MonitoredProcessStopped' -Data @{Purpose=$Purpose;ProcessId=$process.Id;Reason=$reason}}
   catch{$terminationEvidencePersisted=$false;$terminationErrors.Add('MonitoredProcessStopped evidence write failed: '+$_.Exception.Message)}
   $terminationConfirmed=$false
   try{$process.Refresh();if(-not $process.HasExited){$process.Kill($true)}}catch{$terminationErrors.Add('Root Kill(true): '+$_.Exception.Message)}
   $deadline=[DateTime]::UtcNow.AddSeconds(10)
   $lastTree=@()
   while([DateTime]::UtcNow -lt $deadline){
    try{
     $tree=Get-ProjectSecurityProcessTree -RootProcessId $process.Id
     $lastTree=@($tree.Rows)
     if($lastTree.Count -eq 0){$terminationConfirmed=$true;break}
     foreach($child in @($tree.Rows | Where-Object {$_.ParentProcessId -eq $process.Id -and $_.ProcessId -ne $process.Id})){
      try{$childProcess=[Diagnostics.Process]::GetProcessById([int]$child.ProcessId);try{$childProcess.Kill($true)}finally{$childProcess.Dispose()}}
      catch [ArgumentException]{}catch [InvalidOperationException]{}catch{$terminationErrors.Add(('Descendant PID {0}: {1}' -f $child.ProcessId,$_.Exception.Message))}
     }
     $process.Refresh()
     if(-not $process.HasExited){try{$process.Kill($true)}catch{$terminationErrors.Add('Retry root Kill(true): '+$_.Exception.Message)};[void]$process.WaitForExit(250)}
    }catch{$terminationErrors.Add('Process-tree verification: '+$_.Exception.Message);break}
    Start-Sleep -Milliseconds 250
   }
   if($terminationConfirmed){
    try{Write-ProjectSecurityEvidence -RecordType 'ProcessTreeTerminationVerified' -Data @{
     Purpose=$Purpose;RootProcessId=$process.Id;DescendantsRemaining=0
     Verification='Win32_Process root/descendant inventory; WaitForExit alone is not treated as proof'
     VerificationWindowSeconds=10;PriorErrors=@($terminationErrors.ToArray())
    }}catch{$terminationEvidencePersisted=$false;$terminationErrors.Add('ProcessTreeTerminationVerified evidence write failed: '+$_.Exception.Message)}
   }else{
    try{Write-ProjectSecurityEvidence -RecordType 'ProcessTerminationFailure' -Data @{
     Purpose=$Purpose;RootProcessId=$process.Id;Error='Process tree did not become empty and verifiable within 10 seconds.'
     RemainingProcesses=$lastTree;Errors=@($terminationErrors.ToArray())
    }}catch{$terminationEvidencePersisted=$false;$terminationErrors.Add('ProcessTerminationFailure evidence write failed: '+$_.Exception.Message)}
   }
   $finalReason=$reason
   if(-not $terminationConfirmed){$finalReason+='; PROCESS_TREE_TERMINATION_UNCONFIRMED'}
   if(-not $terminationEvidencePersisted){$finalReason+='; PROCESS_TERMINATION_EVIDENCE_PERSISTENCE_FAILED'}
   throw "SECURITY_MONITORED_BUILD_STOPPED: $finalReason"
 }
}
Write-Output ("SECURITY_STAGE_READY: {0}; Kaspersky service, SecurityCenter2 and discovered Windows event channels verified; process-tree verification active; FullVendorAlertVisibility=UNKNOWN; evidence={1}" -f $Stage,$script:ProjectSecurityEvidencePath)
