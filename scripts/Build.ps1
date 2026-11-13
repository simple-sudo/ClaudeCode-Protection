#requires -Version 7.4
#requires -PSEdition Core
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedCommit
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage DailyBuild
$run=$script:ProjectSecurityRunId
$logRoot=$script:ProjectSecurityLogRoot
$project=Join-Path $root 'src\ClaudeProtection\ClaudeProtection.csproj'
$projectDirectory=Split-Path -Parent $project
$dotnet=$script:ProjectSecurityDotNetPath
$expectedSdk='8.0.422'
$dotnetRoot=Split-Path -Parent $dotnet
$sdkRoot=Join-Path $dotnetRoot ('sdk\'+$expectedSdk)
$runDirectory=Join-Path $logRoot $run
$outputDirectory=Join-Path $root ('bin\security-stage\'+$run)
$expanded=Join-Path $runDirectory 'expanded-project.xml'
$sdkStdout=Join-Path $logRoot ($run+'-sdk-version.stdout.log')
$sdkStderr=Join-Path $logRoot ($run+'-sdk-version.stderr.log')
$preprocessStdout=Join-Path $logRoot ($run+'-preprocess.stdout.log')
$preprocessStderr=Join-Path $logRoot ($run+'-preprocess.stderr.log')
$buildStdout=Join-Path $logRoot ($run+'-daily-build.stdout.log')
$buildStderr=Join-Path $logRoot ($run+'-daily-build.stderr.log')
$inputsPath=Join-Path $logRoot ($run+'-daily-build-inputs.json')
$artifactsPath=Join-Path $logRoot ($run+'-daily-build-artifacts.json')
$receiptPath=Join-Path $logRoot ($run+'-daily-build-receipt.json')
$receipt=[ordered]@{
    RunId=$run
    ExpectedCommit=$ExpectedCommit.ToLowerInvariant()
    ActualCommit=$null
    SDK=$expectedSdk
    StartedUtc=[DateTime]::UtcNow.ToString('o')
    SdkVersionExit=$null
    PreprocessExit=$null
    BuildExit=$null
    InputManifestSHA256=$null
    OutputArtifactCount=0
    ProductExecuted=$false
    Installed=$false
    Status='STARTED'
}
$operationFailure=$null
$oldPath=$env:PATH
$environmentNames=@('DOTNET_CLI_TELEMETRY_OPTOUT','DOTNET_SKIP_FIRST_TIME_EXPERIENCE',
    'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE','MSBuildEnableWorkloadResolver','MSBUILDDISABLENODEREUSE')
$environmentBackup=@{}
foreach($name in $environmentNames){$environmentBackup[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
$pathChanged=$false

function Assert-NoReparsePath([string]$Path){
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor -and (Test-Path -LiteralPath $cursor)){
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse point in build path: '+$item.FullName)}
        $cursor=$item.Parent.FullName
    }
}
function Add-UniquePath([Collections.Generic.HashSet[string]]$Set,[string]$Path){
    $full=[IO.Path]::GetFullPath($Path)
    if(-not (Test-Path -LiteralPath $full -PathType Leaf)){throw ('Required build input is missing: '+$full)}
    Assert-NoReparsePath $full
    [void]$Set.Add($full)
}
function Add-TaskAssemblyByLeaf([string]$Leaf,[switch]$Optional){
    if([string]::IsNullOrWhiteSpace($Leaf) -or $Leaf -match '\$\('){throw ('Unresolvable MSBuild task assembly leaf: '+$Leaf)}
    $resolvedTaskAssemblies=[Collections.Generic.List[string]]::new()
    foreach($searchRoot in @($sdkRoot,(Join-Path $dotnetRoot 'shared'))){
        if(Test-Path -LiteralPath $searchRoot -PathType Container){
            foreach($match in @(Get-ChildItem -LiteralPath $searchRoot -Filter $Leaf -Recurse -File -ErrorAction Stop)){
                $full=[IO.Path]::GetFullPath($match.FullName)
                if(-not $full.StartsWith($dotnetRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
                    throw ('Task assembly escapes .NET root: '+$full)
                }
                $resolvedTaskAssemblies.Add($full)
            }
        }
    }
    if($resolvedTaskAssemblies.Count -eq 0){
        if($Optional){return}
        throw ('MSBuild task assembly could not be resolved under the pinned .NET installation: '+$Leaf)
    }
    foreach($resolvedAssembly in $resolvedTaskAssemblies){[void]$taskAssemblyPaths.Add($resolvedAssembly)}
}

try{
    [void](Get-ProjectSecuritySnapshot)
    if(-not (Test-Path -LiteralPath $dotnet -PathType Leaf)){throw 'Pinned .NET SDK host is missing.'}
    if(-not (Test-Path -LiteralPath $sdkRoot -PathType Container)){throw ('Pinned .NET SDK directory is missing: '+$sdkRoot)}
    $unsafeEnvironment=@(Get-ChildItem Env: | Where-Object {$_.Name -match '^(?i:MSBUILD|DOTNET|NUGET|CORECLR|COMPLUS|COR_|GIT_)'})
    if($unsafeEnvironment.Count -gt 0){throw ('Unexpected build/toolchain environment overrides: '+(($unsafeEnvironment.Name | Sort-Object) -join ', '))}

    $git=(Get-Command git.exe -ErrorAction Stop).Source
    $actualCommit=(& $git -C $root rev-parse HEAD 2>$null)
    if($LASTEXITCODE -ne 0){throw 'Could not resolve the current Git HEAD.'}
    $actualCommit=([string]$actualCommit).Trim().ToLowerInvariant()
    $receipt.ActualCommit=$actualCommit
    if($actualCommit -cne $ExpectedCommit.ToLowerInvariant()){throw ('Fixed SHA mismatch. Expected '+$ExpectedCommit+'; actual '+$actualCommit)}

    for($directory=Get-Item -LiteralPath $projectDirectory;$null -ne $directory;$directory=$directory.Parent){
        if(($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Redirected build input directory: '+$directory.FullName)}
        foreach($leaf in @('Directory.Build.props','Directory.Build.targets','Directory.Packages.props',
            'Directory.Build.rsp','MSBuild.rsp','global.json')){
            if(Test-Path -LiteralPath (Join-Path $directory.FullName $leaf)){
                throw ('Unexpected parent MSBuild/SDK input: '+(Join-Path $directory.FullName $leaf))
            }
        }
    }

    [xml]$projectXml=[IO.File]::ReadAllText($project)
    if($projectXml.Project.Sdk -ne 'Microsoft.NET.Sdk'){throw 'Daily project SDK differs from the reviewed Microsoft.NET.Sdk baseline.'}
    $dangerousProjectNodes=$projectXml.SelectNodes('//Target|//UsingTask|//Exec|//PackageReference|//ProjectReference|//Analyzer|//SourceGenerator|//Import|//CustomBeforeMicrosoftCommonTargets|//CustomAfterMicrosoftCommonTargets|//CustomBeforeMicrosoftCSharpTargets|//CustomAfterMicrosoftCSharpTargets')
    if($dangerousProjectNodes.Count -gt 0){
        throw ('Daily project contains custom build execution, package, analyzer, generator, import or target-injection nodes: '+$dangerousProjectNodes.Count)
    }

    $assetsPath=Join-Path $projectDirectory 'obj\project.assets.json'
    if(-not (Test-Path -LiteralPath $assetsPath -PathType Leaf)){throw 'No existing project.assets.json. DailyBuild is --no-restore and will not restore packages.'}
    $assets=Get-Content -LiteralPath $assetsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach($framework in $assets.project.frameworks.PSObject.Properties){
        $dependencies=$framework.Value.dependencies
        if($null -ne $dependencies -and @($dependencies.PSObject.Properties).Count -gt 0){
            throw ('Package dependencies found in the no-restore assets graph: '+$framework.Name)
        }
    }
    foreach($target in $assets.targets.PSObject.Properties){
        foreach($library in $target.Value.PSObject.Properties){
            if($library.Name -notmatch '^(Microsoft\.NETCore\.App\.Ref|Microsoft\.WindowsDesktop\.App\.Ref)/'){
                throw ('Non-framework package in the daily build graph: '+$library.Name)
            }
            if($null -ne $library.Value.analyzers -and @($library.Value.analyzers.PSObject.Properties).Count -gt 0){
                throw ('Analyzer/source-generator assets are present: '+$library.Name)
            }
        }
    }

    $nugetGenerated=@(
        (Join-Path $projectDirectory 'obj\ClaudeProtection.csproj.nuget.g.props'),
        (Join-Path $projectDirectory 'obj\ClaudeProtection.csproj.nuget.g.targets')
    )
    foreach($generated in $nugetGenerated){
        if(-not (Test-Path -LiteralPath $generated -PathType Leaf)){continue}
        $generatedText=[IO.File]::ReadAllText($generated)
        if($generatedText -match '\$\(\['){throw ('MSBuild property-function expression in generated NuGet import: '+$generated)}
        [xml]$generatedXml=$generatedText
        $generatedCustomNodes=$generatedXml.SelectNodes('//Target|//UsingTask|//Exec|//PackageReference|//ProjectReference|//Analyzer|//SourceGenerator')
        if($generatedCustomNodes.Count -gt 0){throw ('Generated NuGet props/targets contain custom execution or package nodes: '+$generated)}
        foreach($import in $generatedXml.SelectNodes('//Import[@Project]')){
            $importPath=[string]$import.Project
            if($importPath -match '\$\('){throw ('Unresolved generated import is not permitted: '+$importPath)}
            $resolved=[IO.Path]::GetFullPath($importPath)
            if(-not $resolved.StartsWith($dotnetRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
                throw ('External generated NuGet import is not permitted: '+$resolved)
            }
        }
    }

    if(Test-Path -LiteralPath $runDirectory){throw 'This security-stage RunId workspace already exists; no automatic retry.'}
    [void][IO.Directory]::CreateDirectory($runDirectory)
    $script:ProjectSecurityWorkingDirectory=$runDirectory
    [IO.File]::WriteAllText((Join-Path $runDirectory 'global.json'),
        '{"sdk":{"version":"8.0.422","rollForward":"disable","allowPrerelease":false}}',
        [Text.UTF8Encoding]::new($false))
    $env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
    $env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true'
    $env:MSBuildEnableWorkloadResolver='false'
    $env:MSBUILDDISABLENODEREUSE='1'
    $env:PATH='C:\Windows\System32;C:\Windows;C:\Program Files\dotnet'
    $pathChanged=$true

    $sdkExit=Invoke-ProjectSecurityMonitoredProcess -Purpose SdkVersion -FilePath $dotnet -ArgumentList @('--version') -WorkingDirectory $runDirectory -StandardOutputPath $sdkStdout -StandardErrorPath $sdkStderr
    $receipt.SdkVersionExit=$sdkExit
    if($sdkExit -ne 0){throw ('Pinned SDK version query failed: '+$sdkExit)}
    $sdkVersion=(Get-Content -LiteralPath $sdkStdout -Raw -Encoding UTF8).Trim()
    if($sdkVersion -cne $expectedSdk){throw ('SDK version mismatch. Expected '+$expectedSdk+'; actual '+$sdkVersion)}

    $preprocessArguments=@('msbuild',$project,'-nologo','-noAutoResponse',('-preprocess:'+$expanded))+$script:ProjectSecurityBuildProperties
    $preprocessExit=Invoke-ProjectSecurityMonitoredProcess -Purpose Preprocess -FilePath $dotnet -ArgumentList $preprocessArguments -WorkingDirectory $runDirectory -StandardOutputPath $preprocessStdout -StandardErrorPath $preprocessStderr -OperationOutputPath $expanded
    $receipt.PreprocessExit=$preprocessExit
    if($preprocessExit -ne 0){throw ('MSBuild import preprocessing failed: '+$preprocessExit)}
    if(-not (Test-Path -LiteralPath $expanded -PathType Leaf)){throw 'MSBuild did not produce the expected preprocessed import inventory.'}

    $imports=@([regex]::Matches([IO.File]::ReadAllText($expanded),'(?m)^\s*([A-Za-z]:\\[^\r\n<>]+\.(?:props|targets|csproj))\s*$') |
        ForEach-Object {$_.Groups[1].Value.Trim()} | Sort-Object -Unique)
    if($imports.Count -lt 5){throw 'MSBuild import inventory is incomplete.'}
    foreach($import in $imports){
        $resolved=[IO.Path]::GetFullPath($import)
        if($resolved -ine [IO.Path]::GetFullPath($project) -and
            -not $resolved.StartsWith($dotnetRoot+'\',[StringComparison]::OrdinalIgnoreCase) -and
            $resolved -notin @($nugetGenerated | ForEach-Object {[IO.Path]::GetFullPath($_)})){
            throw ('External MSBuild import refused: '+$resolved)
        }
    }

    [xml]$expandedXml=[IO.File]::ReadAllText($expanded)
    $importedTargets=@($expandedXml.SelectNodes('//Target'))
    $importedUsingTasks=@($expandedXml.SelectNodes('//UsingTask'))
    $importedExecNodes=@($expandedXml.SelectNodes('//Exec'))
    $taskAssemblyPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $taskAssemblyNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $taskFactories=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach($task in $importedUsingTasks){
        $assemblyFile=[string]$task.AssemblyFile
        $assemblyName=[string]$task.AssemblyName
        $factory=[string]$task.TaskFactory
        if(-not [string]::IsNullOrWhiteSpace($factory)){
            if($factory -notmatch '(?i)(^|\.)(CodeTaskFactory|RoslynCodeTaskFactory)$'){
                throw ('Unreviewed MSBuild TaskFactory in imported SDK graph: '+$factory)
            }
            [void]$taskFactories.Add($factory)
        }
        if(-not [string]::IsNullOrWhiteSpace($assemblyFile)){
            if($assemblyFile -match '^[A-Za-z]:\\'){
                $taskPath=[IO.Path]::GetFullPath($assemblyFile)
                if(-not $taskPath.StartsWith($dotnetRoot+'\',[StringComparison]::OrdinalIgnoreCase)){
                    throw ('MSBuild task assembly escapes the pinned .NET installation: '+$taskPath)
                }
                [void]$taskAssemblyPaths.Add($taskPath)
            }else{
                Add-TaskAssemblyByLeaf ([IO.Path]::GetFileName($assemblyFile))
            }
        }elseif(-not [string]::IsNullOrWhiteSpace($assemblyName)){
            if($assemblyName -notmatch '^(Microsoft|System)\.'){
                throw ('Unreviewed MSBuild task assembly name: '+$assemblyName)
            }
            $simpleName=$assemblyName.Split(',')[0].Trim()
            Add-TaskAssemblyByLeaf ($simpleName+'.dll')
            [void]$taskAssemblyNames.Add($assemblyName)
        }elseif(-not [string]::IsNullOrWhiteSpace($factory)){
            Add-TaskAssemblyByLeaf 'Microsoft.Build.Tasks.Core.dll'
        }else{
            throw ('MSBuild UsingTask has no auditable assembly or task factory: '+[string]$task.TaskName)
        }
    }
    foreach($coreAssembly in @('MSBuild.dll','Microsoft.Build.dll','Microsoft.Build.Framework.dll',
        'Microsoft.Build.Utilities.Core.dll','Microsoft.Build.Tasks.Core.dll','Microsoft.NET.Build.Tasks.dll',
        'Microsoft.CodeAnalysis.dll','Microsoft.CodeAnalysis.CSharp.dll','csc.dll')){
        Add-TaskAssemblyByLeaf $coreAssembly -Optional
    }

    $receipt.ImportedTargetCount=$importedTargets.Count
    $receipt.ImportedUsingTaskCount=$importedUsingTasks.Count
    $receipt.ImportedExecNodeCount=$importedExecNodes.Count
    $receipt.ImportedTaskAssemblyFiles=@($taskAssemblyPaths)
    $receipt.ImportedTaskAssemblyNames=@($taskAssemblyNames)
    $receipt.ImportedTaskFactories=@($taskFactories)

    $inputPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Add-UniquePath $inputPaths $project
    Add-UniquePath $inputPaths $PSCommandPath
    Add-UniquePath $inputPaths (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1')
    Add-UniquePath $inputPaths $assetsPath
    Add-UniquePath $inputPaths $dotnet
    Add-UniquePath $inputPaths $git
    Add-UniquePath $inputPaths $expanded
    foreach($taskAssembly in $taskAssemblyPaths){Add-UniquePath $inputPaths $taskAssembly}
    Add-UniquePath $inputPaths (Join-Path $runDirectory 'global.json')
    foreach($generated in $nugetGenerated){
        if(Test-Path -LiteralPath $generated -PathType Leaf){Add-UniquePath $inputPaths $generated}
    }
    foreach($import in $imports){
        if(Test-Path -LiteralPath $import -PathType Leaf){Add-UniquePath $inputPaths $import}
    }
    foreach($node in $projectXml.SelectNodes('//Compile[@Include]|//EmbeddedResource[@Include]|//None[@Include]')){
        $include=[string]$node.Include
        if($include -match '[*?]|\$\('){throw ('Non-literal project input is not permitted: '+$include)}
        foreach($relative in $include.Split(';',[StringSplitOptions]::RemoveEmptyEntries)){
            $path=[IO.Path]::GetFullPath((Join-Path $projectDirectory $relative.Trim()))
            if(-not $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
                throw ('Daily project input escapes the repository: '+$path)
            }
            Add-UniquePath $inputPaths $path
        }
    }

    $inputRecords=[Collections.Generic.List[object]]::new()
    foreach($path in ($inputPaths | Sort-Object)){
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $relative=if($path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
            [IO.Path]::GetRelativePath($root,$path).Replace('\','/')
        }else{$path}
        if($path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -and
            $relative -notmatch '(^|/)(obj|bin|work|security-stage)/'){
            $expectedBlob=(& $git -C $root rev-parse ($ExpectedCommit+':'+$relative) 2>$null)
            if($LASTEXITCODE -ne 0){throw ('Build source is not tracked at the fixed SHA: '+$relative)}
            $actualBlob=(& $git -C $root hash-object --no-filters -- $path 2>$null)
            if($LASTEXITCODE -ne 0 -or ([string]$actualBlob).Trim() -cne ([string]$expectedBlob).Trim()){
                throw ('Build input differs from the fixed Git object: '+$relative)
            }
        }
        $inputRecords.Add([pscustomobject]@{Path=$path;GitPath=$relative;SHA256=$hash})
    }
    $inputManifest=[ordered]@{
        RunId=$run
        SourceCommit=$actualCommit
        SDK=$sdkVersion
        InputCount=$inputRecords.Count
        Inputs=@($inputRecords.ToArray())
    }
    [IO.File]::WriteAllText($inputsPath,($inputManifest | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    $receipt.InputManifestSHA256=(Get-FileHash -LiteralPath $inputsPath -Algorithm SHA256).Hash

    $outputParent=Join-Path $root 'bin\security-stage'
    if(Test-Path -LiteralPath $outputParent){Assert-NoReparsePath $outputParent}
    [void][IO.Directory]::CreateDirectory($outputParent)
    if(Test-Path -LiteralPath $outputDirectory){throw 'Run-specific build output already exists; no overwrite is permitted.'}
    [void][IO.Directory]::CreateDirectory($outputDirectory)
    Assert-NoReparsePath $outputDirectory

    $buildArguments=@('build',$project,'--configuration','Release','--output',$outputDirectory,'--nologo',
        '--verbosity','normal','--no-restore','--no-dependencies','--disable-build-servers','-m:1','-nr:false','-noAutoResponse')+
        $script:ProjectSecurityBuildProperties
    $buildExit=Invoke-ProjectSecurityMonitoredProcess -Purpose DailyBuild -FilePath $dotnet -ArgumentList $buildArguments -WorkingDirectory $runDirectory -StandardOutputPath $buildStdout -StandardErrorPath $buildStderr -OutputDirectory $outputDirectory
    $receipt.BuildExit=$buildExit
    $combinedBuildLog=''
    if(Test-Path -LiteralPath $buildStdout){$combinedBuildLog+=[IO.File]::ReadAllText($buildStdout)}
    if(Test-Path -LiteralPath $buildStderr){$combinedBuildLog+=[IO.File]::ReadAllText($buildStderr)}
    $executedTasks=[regex]::Matches($combinedBuildLog,'Task\s+"([^"]+)"')
    $receipt.ExecutedTaskNames=@($executedTasks | ForEach-Object {$_.Groups[1].Value} | Sort-Object -Unique)
    $execTaskMatches=[regex]::Matches($combinedBuildLog,'Task\s+"Exec"')
    $receipt.ExecutedExecTaskCount=$execTaskMatches.Count
    if($execTaskMatches.Count -gt 0){throw 'MSBuild executed an Exec task. DailyBuild refuses external command execution from imported targets.'}
    if($buildExit -ne 0){throw ('Daily build failed with exit code '+$buildExit)}
    $receipt.Status='BUILD_SUCCEEDED_NO_PRODUCT_EXECUTION'
}catch{
    $operationFailure=$_.Exception
    $receipt.Status='STOPPED'
    $receipt.FailureType=$_.Exception.GetType().FullName
    $receipt.Failure=$_.Exception.Message
}finally{
    if($pathChanged){$env:PATH=$oldPath}
    foreach($name in $environmentNames){
        if($null -eq $environmentBackup[$name]){Remove-Item -LiteralPath ('Env:\'+$name) -ErrorAction SilentlyContinue}
        else{Set-Item -Path ('Env:\'+$name) -Value $environmentBackup[$name]}
    }
    try{
        [void](Get-ProjectSecuritySnapshot)
        $receipt.FinalKasperskyState='HEALTHY'
    }catch{
        $receipt.FinalKasperskyState='UNKNOWN_OR_FAILED'
        $receipt.FinalKasperskyFailure=$_.Exception.Message
        if(-not $operationFailure){$operationFailure=$_.Exception}
        $receipt.Status='STOPPED_FINAL_KASPERSKY_RECHECK'
    }
    try{
        $artifactRecords=@()
        if(Test-Path -LiteralPath $outputDirectory -PathType Container){
            $artifactRecords=@(Get-ChildItem -LiteralPath $outputDirectory -Recurse -File |
                Sort-Object FullName | ForEach-Object {
                    [pscustomobject]@{
                        Path=$_.FullName
                        RelativePath=[IO.Path]::GetRelativePath($outputDirectory,$_.FullName).Replace('\','/')
                        Length=$_.Length
                        SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                    }
                })
        }
        $artifactManifest=[ordered]@{
            RunId=$run
            SourceCommit=$actualCommit
            OutputDirectory=$outputDirectory
            ArtifactCount=$artifactRecords.Count
            Artifacts=$artifactRecords
        }
        [IO.File]::WriteAllText($artifactsPath,($artifactManifest | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        $receipt.OutputArtifactCount=$artifactRecords.Count
        $receipt.ArtifactManifestSHA256=(Get-FileHash -LiteralPath $artifactsPath -Algorithm SHA256).Hash
        if(-not (Test-Path -LiteralPath $script:ProjectSecurityEvidencePath -PathType Leaf)){
            throw 'Kaspersky monitor JSONL evidence file is missing; refusing to issue a build receipt.'
        }
        $evidencePaths=@($script:ProjectSecurityEvidencePath,$sdkStdout,$sdkStderr,$preprocessStdout,$preprocessStderr,
            $buildStdout,$buildStderr,$inputsPath,$artifactsPath)
        $evidenceHashes=[Collections.Generic.List[object]]::new()
        foreach($evidencePath in $evidencePaths){
            if(Test-Path -LiteralPath $evidencePath -PathType Leaf){
                $evidenceItem=Get-Item -LiteralPath $evidencePath
                $evidenceHashes.Add([pscustomobject]@{
                    Path=$evidencePath
                    Length=$evidenceItem.Length
                    SHA256=(Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
                })
            }
        }
        $receipt.EvidenceFileHashes=@($evidenceHashes.ToArray())
    }catch{
        $receipt.ArtifactHashFailure=$_.Exception.Message
        if(-not $operationFailure){$operationFailure=$_.Exception}
        $receipt.Status='STOPPED_ARTIFACT_HASH_FAILURE'
    }
    $receipt.CompletedUtc=[DateTime]::UtcNow.ToString('o')
    try{[IO.File]::WriteAllText($receiptPath,($receipt | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}catch{
        if(-not $operationFailure){$operationFailure=$_.Exception}
    }
}
if($operationFailure){throw $operationFailure}
if($receipt.OutputArtifactCount -lt 1){throw 'DailyBuild produced no hashable output artifacts.'}
$receipt | ConvertTo-Json -Depth 8
Write-Output "DAILY_BUILD_PASS: $run; monitor=$($script:ProjectSecurityEvidencePath); stdout=$buildStdout; stderr=$buildStderr; inputs=$inputsPath; artifacts=$artifactsPath; receipt=$receiptPath"
