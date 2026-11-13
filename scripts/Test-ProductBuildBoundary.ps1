#requires -Version 7.4
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Require([bool]$condition,[string]$message)
{
    if(-not $condition){throw "PRODUCT_BUILD_BOUNDARY_REVIEW_FAILED: $message"}
}
function Read-Text([string]$relative)
{
    $path=Join-Path $root $relative
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw "Missing reviewed input: $relative"}
    [IO.File]::ReadAllText($path)
}
function Get-CompileInventory([string]$relative)
{
    $path=Join-Path $root $relative
    [xml]$project=Read-Text $relative
    Require ([string]$project.Project.PropertyGroup.EnableDefaultCompileItems -eq 'false') "$relative must use an explicit Compile inventory"
    $base=Split-Path -Parent $path
    $items=[Collections.Generic.List[string]]::new()
    foreach($node in $project.SelectNodes('//Compile[@Include]'))
    {
        foreach($entry in ([string]$node.Include).Split(';',[StringSplitOptions]::RemoveEmptyEntries))
        {
            $resolved=[IO.Path]::GetFullPath((Join-Path $base $entry.Trim()))
            $items.Add([IO.Path]::GetRelativePath($root,$resolved).Replace('\','/'))
        }
    }
    return ,$items.ToArray()
}

# The daily product must not absorb historical aggregate selftests or the
# engineering-only process/job/sandbox implementation.
$daily='src/ClaudeProtection/ClaudeProtection.csproj'
$engineering='src/ClaudeProtection.Engineering/ClaudeProtection.Engineering.csproj'
$dailyItems=Get-CompileInventory $daily
$engineeringItems=Get-CompileInventory $engineering
Require ($dailyItems -contains 'src/ClaudeProtection/Program.cs') 'daily entrypoint is absent from the explicit inventory'
$forbiddenDaily=@(
    'src/ClaudeProtection/SelfTests.cs',
    'src/ClaudeProtection/NativeJob.cs',
    'src/ClaudeProtection/SandboxToken.cs',
    'src/ClaudeProtection/ControlledLoopback.cs',
    'src/ClaudeProtection/ExperimentMonitor.cs',
    'src/ClaudeProtection/IsolationExperiment.cs',
    'src/ClaudeProtection.Engineering/Program.cs'
)
$includedForbidden=@($dailyItems | Where-Object {$_ -in $forbiddenDaily})
Require ($includedForbidden.Count -eq 0) ('daily product includes engineering/test source: '+($includedForbidden -join ', '))
$dailyXml=[xml](Read-Text $daily)
Require ($dailyXml.SelectNodes('//ProjectReference').Count -eq 0) 'daily product unexpectedly references another project'
$dailyProgram=Read-Text 'src/ClaudeProtection/Program.cs'
Require ($dailyProgram -notmatch '(?im)^\s*case\s+"selftest"\s*:|SelfTests\.Run\s*\(') 'daily dispatcher exposes aggregate selftest'

$engineeringRequired=@(
    'src/ClaudeProtection.Engineering/Program.cs',
    'src/ClaudeProtection/NativeJob.cs',
    'src/ClaudeProtection/SandboxToken.cs',
    'src/ClaudeProtection/ControlledLoopback.cs',
    'src/ClaudeProtection/ExperimentMonitor.cs',
    'src/ClaudeProtection/IsolationExperiment.cs'
)
foreach($item in $engineeringRequired)
{
    Require ($engineeringItems -contains $item) "engineering-only source was moved or omitted: $item"
}
Require ($engineeringItems -notcontains 'src/ClaudeProtection/SelfTests.cs') 'historical aggregate SelfTests.cs was reintroduced into engineering build'
$engineeringXml=[xml](Read-Text $engineering)
Require ($engineeringXml.SelectNodes('//ProjectReference').Count -eq 0) 'engineering project unexpectedly references the daily product'

# The checked-in package approval must not ship the engineering/test split.
$approved=Read-Text 'src/ProtectionBootstrap/ApprovedPackage.json' | ConvertFrom-Json
$assetNames=@($approved.Files | ForEach-Object {[string]$_.Asset})
Require ($assetNames.Count -gt 0) 'approved package asset inventory is empty'
$forbiddenAssets=@($assetNames | Where-Object {$_ -match '(?i)engineering|selftest|native-fence|sandbox'})
Require ($forbiddenAssets.Count -eq 0) ('approved package contains non-product engineering assets: '+($forbiddenAssets -join ', '))

# The staged security gate must be explicit, fail closed outside the first
# daily-build stage, and continuously monitor the Kaspersky service/event state.
$gateText=Read-Text 'scripts/Assert-ProjectSecurityClearance.ps1'
$tokens=$null;$parseErrors=$null
$gateAst=[System.Management.Automation.Language.Parser]::ParseInput($gateText,[ref]$tokens,[ref]$parseErrors)
Require ($parseErrors.Count -eq 0) 'security gate has PowerShell parse errors'
Require ($null -ne $gateAst.ParamBlock) 'security gate must require an explicit stage'
Require ($gateText -match "ValidateSet\('DailyBuild','EngineeringBuild','CenterBuild','NativeBuild','IsolationProbe','WfpMutation','LegacyOfflineBuild'\)") 'security stage allowlist changed'
Require ($gateText -match '\$Stage -cne ''DailyBuild''') 'all stages except DailyBuild must remain closed'
Require ($gateText -match "Get-Service -Name 'AVP21\.26'") 'pinned Kaspersky service health check missing'
Require ($gateText -match "root/SecurityCenter2") 'Windows Security Center Kaspersky registration check missing'
Require ($gateText -match "Get-WinEvent") 'Kaspersky event monitoring missing'
Require ($gateText -match "KASPERSKY_NEW_EVENT") 'new Kaspersky events must stop the monitored operation'
Require ($gateText -match "ProjectSecurityEvidencePath") 'durable Kaspersky monitor evidence path missing'
Require ($gateText -match "Add-Content -LiteralPath") 'Kaspersky monitor evidence is not persisted'
Require ($gateText -match "Start-Sleep -Milliseconds 750") 'Kaspersky event poll interval changed'
Require ($gateText -match "TotalSeconds -ge 3") 'Kaspersky service/product recheck interval changed'
Require ($gateText -match '\$process\.Kill\(\$true\)') 'monitor must terminate the complete child process tree on failure'
Require ($gateText -match 'Get-ProjectSecurityProcessTree') 'monitor must inspect the actual Win32 process tree'
Require ($gateText -match 'Win32_Process') 'monitor must use Windows process ancestry for descendant verification'
Require ($gateText -match 'ProcessTreeTerminationVerified') 'monitor must persist positive process-tree verification evidence'
Require ($gateText -match 'WaitForExit\(250\)') 'monitor must use bounded root waits while independently checking descendants'
Require ($gateText -match 'PROCESS_TREE_TERMINATION_UNCONFIRMED') 'unconfirmed process-tree termination must be a distinct failure'
Require ($gateText -match 'Get-WinEvent -ListLog \*') 'monitor must discover Kaspersky-named Windows event channels'
Require ($gateText -match 'KasperskyEventChannelSetChanged') 'monitor must stop if the Kaspersky event-channel inventory changes'
Require ($gateText -match 'EventXml=\$_.ToXml\(\)') 'monitor must preserve raw Windows event XML'
Require ($gateText -match 'RunId=\$script:ProjectSecurityRunId') 'every monitor record must carry the shared run ID'
Require ($gateText -match 'return \$unique') 'an empty event query must return an empty array, not a nested empty array'
Require ($gateText -match "FullVendorAlertVisibility='UNKNOWN'") 'limited event coverage must remain explicitly UNKNOWN'

$dailyBuild=Read-Text 'scripts/Build.ps1'
Require ($dailyBuild -match "Assert-ProjectSecurityClearance\.ps1'\) -Stage DailyBuild") 'daily build does not request the explicit DailyBuild stage'
Require ($dailyBuild -match 'Invoke-ProjectSecurityMonitoredProcess') 'daily build is not continuously AV-monitored'
Require ($dailyBuild -match "'--no-restore'") 'daily build must not fetch or restore dependencies during the first stage'
Require ($dailyBuild -match 'ExpectedCommit') 'daily build must require a fixed expected Git SHA'
Require ($dailyBuild -match 'project.assets.json') 'daily build must inspect the existing no-restore assets graph'
Require ($dailyBuild -match 'RunAnalyzers=false') 'daily build must disable analyzer/source-generator execution'
Require ($dailyBuild -match 'preprocess') 'daily build must inventory the evaluated MSBuild import graph'
Require ($dailyBuild -match 'noAutoResponse') 'daily build must refuse implicit MSBuild response-file injection'
Require ($dailyBuild -match 'daily-build-inputs.json') 'daily build must persist input SHA-256 evidence'
Require ($dailyBuild -match 'daily-build-artifacts.json') 'daily build must persist output SHA-256 evidence'
Require ($dailyBuild -match '--disable-build-servers') 'daily build must disable persistent SDK build servers'
Require ($dailyBuild -match '\$script:ProjectSecurityRunId') 'build logs are not correlated with the AV monitor evidence run ID'

$expectedStages=@{
    'Build.ps1'='DailyBuild'
    'Build-Engineering.ps1'='EngineeringBuild'
    'Build-Center.ps1'='CenterBuild'
    'Build-NativeFence.ps1'='NativeBuild'
}
$buildEntrypoints=@(Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter 'Build*.ps1' -File | ForEach-Object { $_.Name } | Sort-Object)
$expectedBuildEntrypoints=@($expectedStages.Keys | Sort-Object)
$entrypointDrift=@(Compare-Object -ReferenceObject $expectedBuildEntrypoints -DifferenceObject $buildEntrypoints)
Require ($entrypointDrift.Count -eq 0) ('conventional Build entrypoint inventory changed: '+($entrypointDrift | Out-String))
foreach($name in $expectedStages.Keys){
    $text=Read-Text ('scripts/'+$name)
    Require ($text.Contains("Assert-ProjectSecurityClearance.ps1') -Stage "+$expectedStages[$name])) "$name does not request its explicit stage"
}
$probe=Read-Text 'scripts/Invoke-IsolationProbe.ps1'
Require ($probe.Contains("Assert-ProjectSecurityClearance.ps1') -Stage IsolationProbe")) 'isolation probe does not remain behind its own closed stage'
$wfpScripts=@('scripts/Set-MainProtection.ps1','scripts/Test-ScopedFirewall.ps1','scripts/Use-ProbeLoopbackLease.ps1')
foreach($relative in $wfpScripts){
    $text=Read-Text $relative
    Require ($text.Contains("Assert-ProjectSecurityClearance.ps1') -Stage WfpMutation")) "$relative does not remain behind the WFP mutation stage"
}


foreach($relative in @('scripts/Build.ps1','scripts/Invoke-S1DailyBuild.ps1','scripts/Invoke-BrokerOfflineBuild.ps1','scripts/Set-MainProtection.ps1','tests/SessionZeroStartupWitness/Test-OrdinaryStartupWitness.ps1','tests/SessionZeroStartupWitness/Test-OrdinaryBranchTrace.ps1','tests/GpuCallProgress/Test-NativeWin32k.ps1')){
    $source=Read-Text $relative
    $tokens=$null;$parseErrors=$null
    [void][System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
    Require ($parseErrors.Count -eq 0) "$relative has PowerShell parse errors"
}
$legacyStages=@{
    'scripts/Invoke-S1DailyBuild.ps1'='LegacyOfflineBuild'
    'scripts/Invoke-BrokerOfflineBuild.ps1'='EngineeringBuild'
}
foreach($relative in $legacyStages.Keys){
    $source=Read-Text $relative
    $gatePosition=$source.IndexOf("Assert-ProjectSecurityClearance.ps1') -Stage "+$legacyStages[$relative],[StringComparison]::Ordinal)
    $buildPosition=$source.IndexOf('dotnet',[StringComparison]::OrdinalIgnoreCase)
    Require ($gatePosition -ge 0 -and ($buildPosition -lt 0 -or $gatePosition -lt $buildPosition)) "$relative does not fail closed before its legacy build action"
}
$mainProtection=Read-Text 'scripts/Set-MainProtection.ps1'
Require ($mainProtection -match 'if \(\$Mode -in @\(''Enable'',''Restore''\)\)') 'WFP enable and restore mutations must both require the closed WfpMutation stage'
Require ($dailyXml.SelectNodes('//Target|//UsingTask|//Exec|//PackageReference|//ProjectReference|//Analyzer|//SourceGenerator|//Import').Count -eq 0) 'daily project contains custom build execution, external packages, analyzers, generators or imports'

Write-Output 'PASS daily explicit source inventory excludes historical SelfTests and engineering-only Job/sandbox code'
Write-Output 'PASS engineering-only process/job/sandbox source remains separately compiled and unshipped'
Write-Output 'PASS approved package inventory excludes engineering, selftest, sandbox and native-fence assets'
Write-Output 'PASS staged gate opens only the monitored daily build and keeps engineering, legacy offline builds, probes and WFP mutation closed'
Write-Output 'PASS legacy offline build scripts and both WFP mutation modes fail closed before side effects'

$probeEntryPoints=@(
    'tests/SessionZeroStartupWitness/Test-OrdinaryStartupWitness.ps1',
    'tests/SessionZeroStartupWitness/Test-OrdinaryBranchTrace.ps1',
    'tests/GpuCallProgress/Test-NativeWin32k.ps1'
)
foreach($relative in $probeEntryPoints){
    $source=Read-Text $relative
    $gatePosition=$source.IndexOf("Assert-ProjectSecurityClearance.ps1') -Stage IsolationProbe",[StringComparison]::Ordinal)
    Require ($gatePosition -ge 0) "$relative is not behind the closed IsolationProbe stage"
}

Write-Output 'PASS DailyBuild source project contains no custom Target, UsingTask, Exec, package, analyzer, generator or explicit import nodes'
Write-Output 'PASS native Win32k and SessionZero executable witness tests are behind the closed IsolationProbe stage'
Write-Output ("PASS {0} conventional Build entrypoints require explicit staged qualification before build actions" -f $buildEntrypoints.Count)
Write-Output 'STATIC SOURCE REVIEW ONLY: no product build, assembly load, product execution, AV query, install or host mutation'
