#requires -Version 7.4
#requires -PSEdition Core
# One authorized attempt, not a replacement for any normal build/launch gate.
# Human authorization: 2026-10-26, source chat 01a175d2-12fc-77f2-8bd5-2f9be137bcba.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if($root -cne 'C:\Users\simple\ClaudeCode-Protection'){throw 'Wrong checkout'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary user required'}
$freeze='C:\Users\simple\Documents\Codex\2026-10-25\claude-protection-continuation\outputs\s1-decision\s1-input-freeze.json'
if((Get-FileHash -LiteralPath $freeze).Hash -cne '841B3B911A52BD300B424FF83E0B405FE37F9AF519117F4938CC626AFF0DECAE'){throw 'Freeze changed'}
$manifest=Get-Content -LiteralPath $freeze -Raw|ConvertFrom-Json
foreach($entry in @($manifest.Inputs)+@($manifest.Toolchain)+@($manifest.ReferenceAssemblies)+@($manifest.Preserved)){
    if((Get-FileHash -LiteralPath $entry.Path).Hash -cne $entry.SHA256){throw ('Input changed: '+$entry.Path)}
}
if(@(Get-ChildItem Env: | Where-Object Name -match '^(MSBUILD|DOTNET|NUGET|COMPLUS|CORECLR)').Count){throw 'Unexpected toolchain environment'}
for($directory=Get-Item -LiteralPath (Join-Path $root 'src\ClaudeProtection');$null -ne $directory;$directory=$directory.Parent){
    foreach($leaf in 'Directory.Build.props','Directory.Build.targets','Directory.Packages.props','global.json'){
        if(Test-Path -LiteralPath (Join-Path $directory.FullName $leaf)){throw 'Unexpected parent build input'}
    }
    if(($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected checkout'}
}
function Read-Safety {
    $rules=@(Get-NetFirewallRule -Name ClaudeCodeFailClosed-BlockDirect-IPv4,ClaudeCodeFailClosed-BlockDirect-IPv6)
    if($rules.Count -ne 2 -or @($rules|Where-Object Enabled -ne 'False').Count){throw 'Real Claude rule state changed'}
    if((Get-Service AVP21.26).Status -ne 'Running' -or (Get-Service BFE).Status -ne 'Running'){throw 'Safety service unavailable'}
    $av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct|Where-Object displayName -eq 'Kaspersky')
    if($av.Count -ne 1 -or $av[0].productState -ne 266240){throw 'Kaspersky registration changed; review required'}
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$script:started} -ErrorAction SilentlyContinue | Where-Object ProviderName -match 'avp|kaspersky')
    if($events.Count){throw 'New AV event; stop for review'}
    [pscustomobject]@{AtUtc=[DateTime]::UtcNow.ToString('o');AvService='Running';KasperskyProductState=$av[0].productState;ApplicationAvEventsSinceStart=$events.Count;FullAvAlertCoverage='UNKNOWN';BFE='Running';Rules=@($rules|Select-Object Name,@{n='Enabled';e={[string]$_.Enabled}})}
}
$started=Get-Date
if(@(Get-Process ClaudeProtection,ProtectionCenter,ClaudeProtectionFence -ErrorAction SilentlyContinue).Count){throw 'Related process active'}
if(@(Get-ChildItem -LiteralPath (Join-Path $root 'src') -Recurse -File -Include *.exe,*.dll,*.obj,*.pdb).Count){throw 'Unexpected source-tree artifacts'}
$before=Read-Safety
$work=Join-Path $root 'work\s1-daily-c419'
if(Test-Path -LiteralPath $work){throw 'S1 attempt already exists; no automatic retry'}
[void][IO.Directory]::CreateDirectory($work)
# CreateNew also prevents a second concurrent invocation from consuming the grant.
$claim=[IO.File]::Open((Join-Path $work 'attempt.claim'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$claim.Dispose()
$before|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $work 'safety-before.json') -Encoding utf8
[IO.File]::WriteAllText((Join-Path $work 'global.json'),'{"sdk":{"version":"8.0.422","rollForward":"disable","allowPrerelease":false}}')
[void][IO.Directory]::CreateDirectory((Join-Path $work 'empty-source'))
[IO.File]::WriteAllText((Join-Path $work 'NuGet.Config'),'<configuration><packageSources><clear/><add key="local-empty" value="empty-source"/></packageSources><fallbackPackageFolders><clear/></fallbackPackageFolders><packageSourceMapping><clear/></packageSourceMapping></configuration>')
$dotnet='C:\Program Files\dotnet\dotnet.exe'
$project=Join-Path $root 'src\ClaudeProtection\ClaudeProtection.csproj'
$properties=@(('-p:BaseIntermediateOutputPath='+$work+'\obj\'),('-p:MSBuildProjectExtensionsPath='+$work+'\obj\'),('-p:OutputPath='+$work+'\bin\'))
$properties+=@('-p:UseSharedCompilation=false','-p:BuildProjectReferences=false','-p:EnableNETAnalyzers=false','-p:RunAnalyzers=false','-p:ImportDirectoryBuildProps=false','-p:ImportDirectoryBuildTargets=false','-p:ImportDirectoryPackagesProps=false','-p:NuGetAudit=false','-p:RestoreIgnoreFailedSources=false','-p:DisableImplicitNuGetFallbackFolder=true')
foreach($part in 'Props','Targets'){
    foreach($position in 'Before','After'){
        $properties+='-p:ImportUserLocationsByWildcard'+$position+'MicrosoftCommon'+$part+'=false'
        $properties+='-p:ImportByWildcard'+$position+'MicrosoftCommon'+$part+'=false'
    }
}
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
$env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true'
$env:MSBuildEnableWorkloadResolver='false'
$env:MSBUILDDISABLENODEREUSE='1'
$receipt=[ordered]@{StartedUtc=$started.ToUniversalTime().ToString('o');SourceCommit=$manifest.SourceCommit;FreezeSHA256=(Get-FileHash $freeze).Hash;Sdk='8.0.422';Properties=$properties;PreprocessExit=$null;RestoreExit=$null;BuildExit=$null;ProductExecuted=$false;Status='STARTED'}
Push-Location $work
try {
    & $dotnet msbuild $project -nologo @properties ('-preprocess:'+(Join-Path $work 'expanded.xml')) *> (Join-Path $work 'preprocess.log')
    $receipt.PreprocessExit=$LASTEXITCODE
    if($LASTEXITCODE -ne 0){throw 'Preprocess failed'}
    # Preprocessing evaluates imports but does not execute project targets/tasks.
    # Every imported file must be in the installed SDK or be this exact project.
    $expanded=[IO.File]::ReadAllText((Join-Path $work 'expanded.xml'))
    $imports=@([regex]::Matches($expanded,'(?m)^\s*([A-Za-z]:\\[^\r\n<>]+\.(?:props|targets|csproj))\s*$')|ForEach-Object {$_.Groups[1].Value.Trim()}|Sort-Object -Unique)
    if($imports.Count -lt 5){throw 'Import inventory unavailable'}
    foreach($import in $imports){
        if($import -ine $project -and !$import.StartsWith('C:\Program Files\dotnet\sdk\8.0.422\',[StringComparison]::OrdinalIgnoreCase)){throw ('External import refused: '+$import)}
    }
    @($imports|ForEach-Object {Get-FileHash -LiteralPath $_|Select-Object Path,Hash})|ConvertTo-Json|Set-Content (Join-Path $work 'imports.json') -Encoding utf8
    & $dotnet restore $project --configfile (Join-Path $work 'NuGet.Config') --packages (Join-Path $work 'packages') --disable-parallel --no-dependencies --verbosity diagnostic @properties *> (Join-Path $work 'restore.log')
    $receipt.RestoreExit=$LASTEXITCODE
    if($LASTEXITCODE -ne 0){throw 'Offline restore failed'}
    $null=Read-Safety
    & $dotnet build $project --configuration Release --no-restore --no-dependencies --nologo --verbosity diagnostic @properties *> (Join-Path $work 'build.log')
    $receipt.BuildExit=$LASTEXITCODE
    if($LASTEXITCODE -ne 0){throw 'S1 build failed'}
    $receipt.Status='BUILD_SUCCEEDED_NO_PRODUCT_EXECUTION'
}
catch { $receipt.Status='STOPPED';$receipt.Failure=$_.Exception.Message;throw }
finally {
    Pop-Location
    $receipt.CompletedUtc=[DateTime]::UtcNow.ToString('o')
    $receipt|ConvertTo-Json -Depth 5|Set-Content (Join-Path $work 'receipt.json') -Encoding utf8
    @(Get-ChildItem -LiteralPath $work -Recurse -File|Where-Object Extension -in '.exe','.dll','.pdb','.json','.ps1'|ForEach-Object {Get-FileHash -LiteralPath $_.FullName|Select-Object Path,Hash})|ConvertTo-Json|Set-Content (Join-Path $work 'artifacts.json') -Encoding utf8
    Read-Safety|ConvertTo-Json -Depth 5|Set-Content (Join-Path $work 'safety-after.json') -Encoding utf8
}
$receipt|ConvertTo-Json -Depth 5
