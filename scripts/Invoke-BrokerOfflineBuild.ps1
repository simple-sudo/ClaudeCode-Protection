#requires -Version 7.4
#requires -PSEdition Core
# Human authorization in this chat, 2026-10-26: one ordinary-user offline build
# of ProtectionBroker + ProtectionLifecycle only. No product execution.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$commit='8a9c4b13711598187cde8845794f24d455ea0004'
if($root -cne 'C:\Users\simple\ClaudeCode-Protection' -or (git -C $root rev-parse HEAD) -ne $commit){throw 'Wrong checkout or source revision'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary user required'}
if(@(Get-ChildItem Env:|Where-Object Name -match '^(MSBUILD|DOTNET|NUGET|CORECLR|COMPLUS|COR_)').Count){throw 'Unexpected toolchain environment'}
$toolFreeze='C:\Users\simple\Documents\Codex\2026-10-25\claude-protection-continuation\outputs\s1-decision\s1-input-freeze.json'
if((Get-FileHash -LiteralPath $toolFreeze).Hash -ne '841B3B911A52BD300B424FF83E0B405FE37F9AF519117F4938CC626AFF0DECAE'){throw 'Tool baseline changed'}
$baseline=Get-Content -LiteralPath $toolFreeze -Raw|ConvertFrom-Json
foreach($entry in @($baseline.Toolchain)+@($baseline.ReferenceAssemblies)+@($baseline.Preserved)){
    if((Get-FileHash -LiteralPath $entry.Path).Hash -ne $entry.SHA256){throw ('Baseline changed: '+$entry.Path)}
}
$projects=@((Join-Path $root 'src\ProtectionLifecycle\ProtectionLifecycle.csproj'),(Join-Path $root 'src\ProtectionBroker\ProtectionBroker.csproj'))
$inputs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($project in $projects){
    [xml]$xml=[IO.File]::ReadAllText($project)
    if($xml.Project.Sdk -ne 'Microsoft.NET.Sdk' -or [string]$xml.Project.PropertyGroup.TargetFramework -ne 'net8.0-windows' -or
        [string]$xml.Project.PropertyGroup.EnableDefaultCompileItems -ne 'false' -or
        $xml.SelectNodes('//*[@Condition or @Remove or @Update or @Exclude]|//Import|//Target|//UsingTask|//PackageReference|//Analyzer|//Reference').Count){throw 'Unexpected project declaration'}
    $null=$inputs.Add($project)
    foreach($node in $xml.SelectNodes('//Compile|//EmbeddedResource')){
        foreach($relative in $node.Include.Split(';')){
            $path=[IO.Path]::GetFullPath((Join-Path (Split-Path $project) $relative))
            if(!$path.StartsWith((Split-Path $project)+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Source outside approved project'}
            $null=$inputs.Add($path)
        }
    }
    $references=@($xml.SelectNodes('//ProjectReference'))
    if($project -eq $projects[0]){if($references.Count){throw 'Library is not a leaf'}}
    elseif($references.Count -ne 1 -or $references[0].Include -ne '../ProtectionLifecycle/ProtectionLifecycle.csproj' -or $references[0].Attributes.Count -ne 1){throw 'Unexpected project graph'}
    for($directory=Get-Item -LiteralPath (Split-Path $project);$null -ne $directory;$directory=$directory.Parent){
        if(($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected checkout'}
        foreach($leaf in 'Directory.Build.props','Directory.Build.targets','Directory.Packages.props','global.json'){
            if(Test-Path -LiteralPath (Join-Path $directory.FullName $leaf)){throw 'Unexpected parent build input'}
        }
    }
}
if($inputs.Count -ne 27){throw 'Expected exactly 21 sources, 2 projects and 4 resources'}
$inputHashes=@(foreach($path in ($inputs|Sort-Object)){
    if(((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected build input'}
    $relative=[IO.Path]::GetRelativePath($root,$path).Replace('\','/')
    $expected=git -C $root rev-parse ($commit+':'+$relative)
    $actual=git -C $root hash-object --no-filters -- $path
    if(!$expected -or $actual -ne $expected){throw 'Tracked source differs from authorized commit'}
    Get-FileHash -LiteralPath $path|Select-Object Path,Hash
})
if(@(Get-Process ProtectionBroker,ClaudeProtection,ProtectionCenter,ClaudeProtectionFence -ErrorAction SilentlyContinue).Count){throw 'Related product process active'}
$started=Get-Date
function Read-Safety {
    if((Get-Service AVP21.26).Status -ne 'Running' -or (Get-Service BFE).Status -ne 'Running'){throw 'Safety service unavailable'}
    $av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct|Where-Object displayName -eq 'Kaspersky')
    if($av.Count -ne 1 -or $av[0].productState -ne 266240){throw 'Kaspersky registration changed'}
    $rules=@(Get-NetFirewallRule -Name ClaudeCodeFailClosed-BlockDirect-IPv4,ClaudeCodeFailClosed-BlockDirect-IPv6)
    if($rules.Count -ne 2 -or @($rules|Where-Object Enabled -ne 'False').Count){throw 'Real Claude rule state changed'}
    $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$script:started} -ErrorAction SilentlyContinue|Where-Object ProviderName -match 'avp|kaspersky')
    if($events.Count){throw 'New AV event; stop for review'}
    [pscustomobject]@{AtUtc=[DateTime]::UtcNow.ToString('o');KasperskyService='Running';KasperskyProductState=$av[0].productState;BFE='Running';ClaudeRulesDisabled=$true;ObservedApplicationAvEvents=$events.Count;FullAvAlertCoverage='UNKNOWN';FlClashPid=@(Get-Process FlClash|Select-Object -ExpandProperty Id);CorePid=@(Get-Process FlClashCore|Select-Object -ExpandProperty Id)}
}
$before=Read-Safety
$work=Join-Path $root 'work\broker-offline-build'
if(Test-Path -LiteralPath $work){throw 'Attempt already exists; no automatic retry'}
if(((Get-Item -LiteralPath (Split-Path $work)).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Redirected work folder'}
[void][IO.Directory]::CreateDirectory($work)
$claim=[IO.File]::Open((Join-Path $work 'attempt.claim'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$claim.Dispose()
$inputHashes|ConvertTo-Json|Set-Content (Join-Path $work 'inputs.json') -Encoding utf8
$before|ConvertTo-Json -Depth 5|Set-Content (Join-Path $work 'safety-before.json') -Encoding utf8
[IO.File]::WriteAllText((Join-Path $work 'global.json'),'{"sdk":{"version":"8.0.422","rollForward":"disable","allowPrerelease":false}}')
[void][IO.Directory]::CreateDirectory((Join-Path $work 'empty-source'))
[IO.File]::WriteAllText((Join-Path $work 'NuGet.Config'),'<configuration><packageSources><clear/><add key="local-empty" value="empty-source"/></packageSources><fallbackPackageFolders><clear/></fallbackPackageFolders><packageSourceMapping><clear/></packageSourceMapping></configuration>')
$properties=@(('-p:ArtifactsPath='+$work+'\artifacts'),'-p:UseArtifactsOutput=true','-p:UseArtifactsIntermediateOutput=true','-p:IncludeProjectNameInArtifactsPaths=true','-p:Configuration=Release','-p:UseSharedCompilation=false','-p:EnableNETAnalyzers=false','-p:RunAnalyzers=false','-p:ImportDirectoryBuildProps=false','-p:ImportDirectoryBuildTargets=false','-p:ImportDirectoryPackagesProps=false','-p:NuGetAudit=false','-p:RestoreIgnoreFailedSources=false','-p:DisableImplicitNuGetFallbackFolder=true')
foreach($part in 'Props','Targets'){foreach($position in 'Before','After'){
    $properties+='-p:ImportUserLocationsByWildcard'+$position+'MicrosoftCommon'+$part+'=false'
    $properties+='-p:ImportByWildcard'+$position+'MicrosoftCommon'+$part+'=false'
}}
function Invoke-Sdk([string]$Log,[string[]]$SdkArguments){
    $start=[Diagnostics.ProcessStartInfo]::new('C:\Program Files\dotnet\dotnet.exe')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WorkingDirectory=$work
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    # SDK diagnostics must not capture the caller's tokens/provider settings.
    $start.Environment.Clear()
    foreach($name in 'SystemRoot','windir','ComSpec','SystemDrive','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA','ProgramFiles','ProgramFiles(x86)','ProgramW6432','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS'){
        $value=[Environment]::GetEnvironmentVariable($name);if($value){$start.Environment[$name]=$value}
    }
    $start.Environment['PATH']='C:\Program Files\dotnet;C:\Windows\System32;C:\Windows'
    $start.Environment['DOTNET_CLI_HOME']=Join-Path $work 'cli-home'
    $start.Environment['DOTNET_CLI_TELEMETRY_OPTOUT']='1'
    $start.Environment['DOTNET_SKIP_FIRST_TIME_EXPERIENCE']='1'
    $start.Environment['DOTNET_GENERATE_ASPNET_CERTIFICATE']='false'
    $start.Environment['DOTNET_ADD_GLOBAL_TOOLS_TO_PATH']='false'
    $start.Environment['DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE']='true'
    $start.Environment['MSBuildEnableWorkloadResolver']='false'
    $start.Environment['MSBUILDDISABLENODEREUSE']='1'
    foreach($argument in $SdkArguments){$start.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::Start($start)
    try{
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [IO.File]::WriteAllText((Join-Path $work ($Log+'.stdout.log')),$stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $work ($Log+'.stderr.log')),$stderr.GetAwaiter().GetResult())
        return $process.ExitCode
    }finally{$process.Dispose()}
}
function Check-Imports([string]$Phase){
    foreach($project in $projects){
        $name=[IO.Path]::GetFileNameWithoutExtension($project)
        $expanded=Join-Path $work ($Phase+'-'+$name+'.xml')
        $code=Invoke-Sdk ($Phase+'-'+$name) (@('msbuild',$project,'-nologo',('-preprocess:'+$expanded))+$properties)
        if($code -ne 0){throw ('Preprocess failed: '+$name)}
        $imports=@([regex]::Matches([IO.File]::ReadAllText($expanded),'(?m)^\s*([A-Za-z]:\\[^\r\n<>]+\.(?:props|targets|csproj))\s*$')|ForEach-Object {$_.Groups[1].Value.Trim()}|Sort-Object -Unique)
        if($imports.Count -lt 5){throw 'Import inventory unavailable'}
        $generated=Join-Path $work ('artifacts\obj\'+$name+'\'+$name+'.csproj.nuget.g')
        foreach($import in $imports){
            if($import -ine $project -and !$import.StartsWith('C:\Program Files\dotnet\sdk\8.0.422\',[StringComparison]::OrdinalIgnoreCase) -and
                $import -ine ($generated+'.props') -and $import -ine ($generated+'.targets')){throw ('External import refused: '+$import)}
        }
        @($imports|ForEach-Object {Get-FileHash -LiteralPath $_|Select-Object Path,Hash})|ConvertTo-Json|Set-Content (Join-Path $work ($Phase+'-'+$name+'-imports.json')) -Encoding utf8
    }
}
$receipt=[ordered]@{StartedUtc=$started.ToUniversalTime().ToString('o');SourceCommit=$commit;InputCount=$inputs.Count;Properties=$properties;RestoreExit=$null;BuildExit=$null;ProductExecuted=$false;Installed=$false;Elevated=$false;Status='STARTED'}
$leases=[Collections.Generic.List[IO.FileStream]]::new()
$operationFailure=$null
try{
    foreach($path in $inputs){$leases.Add([IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read))}
    Check-Imports 'before-restore'
    foreach($project in $projects){
        $name=[IO.Path]::GetFileNameWithoutExtension($project)
        $code=Invoke-Sdk ('paths-'+$name) (@('msbuild',$project,'-nologo','-getProperty:MSBuildProjectExtensionsPath,TargetPath')+$properties)
        if($code -ne 0){throw 'Path evaluation failed'}
        $paths=Get-Content (Join-Path $work ('paths-'+$name+'.stdout.log')) -Raw|ConvertFrom-Json
        if($paths.Properties.MSBuildProjectExtensionsPath -ine (Join-Path $work ('artifacts\obj\'+$name+'\')) -or
            !$paths.Properties.TargetPath.StartsWith((Join-Path $work ('artifacts\bin\'+$name+'\')),[StringComparison]::OrdinalIgnoreCase)){throw 'Build paths escaped per-project artifact directories'}
    }
    $null=Read-Safety
    $receipt.RestoreExit=Invoke-Sdk 'restore' (@('restore',$projects[1],'--configfile',(Join-Path $work 'NuGet.Config'),'--packages',(Join-Path $work 'packages'),'--disable-parallel','--verbosity','diagnostic')+$properties)
    if($receipt.RestoreExit -ne 0){throw 'Offline restore failed'}
    foreach($name in 'ProtectionBroker','ProtectionLifecycle'){
        $assets=Get-Content (Join-Path $work ('artifacts\obj\'+$name+'\project.assets.json')) -Raw|ConvertFrom-Json
        if(@($assets.libraries.PSObject.Properties|Where-Object {$_.Value.type -ne 'project'}).Count){throw 'Non-project package in offline graph'}
    }
    Check-Imports 'after-restore'
    $null=Read-Safety
    $receipt.BuildExit=Invoke-Sdk 'build' (@('build',$projects[1],'--configuration','Release','--no-restore','--nologo','--verbosity','diagnostic','-m:1','-nr:false')+$properties)
    if($receipt.BuildExit -ne 0){throw 'Management component build failed'}
    $receipt.Status='BUILD_SUCCEEDED_NO_PRODUCT_EXECUTION'
}catch{$operationFailure=$_.Exception;$receipt.Status='STOPPED';$receipt.FailureType=$_.Exception.GetType().Name;$receipt.Failure=$_.Exception.Message}
finally{
    foreach($lease in $leases){$lease.Dispose()}
    try{
        Read-Safety|ConvertTo-Json -Depth 5|Set-Content (Join-Path $work 'safety-after.json') -Encoding utf8
        foreach($entry in @($inputHashes)+@($baseline.Preserved)){
            $expected=if($entry.Hash){$entry.Hash}else{$entry.SHA256}
            if((Get-FileHash -LiteralPath $entry.Path).Hash -ne $expected){throw 'Input or preserved original changed'}
        }
    }catch{
        $receipt.Status='STOPPED_SAFETY_OR_INPUT_RECHECK';$receipt.RecheckFailureType=$_.Exception.GetType().Name
        $operationFailure=if($operationFailure){[AggregateException]::new('Build operation and post-check failed',$operationFailure,$_.Exception)}else{$_.Exception}
    }
    $receipt.CompletedUtc=[DateTime]::UtcNow.ToString('o')
    $receipt|ConvertTo-Json -Depth 5|Set-Content (Join-Path $work 'receipt.json') -Encoding utf8
    @(Get-ChildItem -LiteralPath (Join-Path $work 'artifacts') -Recurse -File -ErrorAction SilentlyContinue|ForEach-Object {Get-FileHash -LiteralPath $_.FullName|Select-Object Path,Hash})|ConvertTo-Json|Set-Content (Join-Path $work 'artifacts.json') -Encoding utf8
}
if($operationFailure){throw $operationFailure}
$receipt|ConvertTo-Json -Depth 5
