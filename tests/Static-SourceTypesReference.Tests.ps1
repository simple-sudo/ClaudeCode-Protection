# Exercises the real non-emitting checker against synthetic source declarations.
# No product project/source is copied, loaded or executed. Fixture evidence stays
# in work; there is no restore, MSBuild, Emit or native/product call.
#requires -Version 7.4
#requires -PSEdition Core
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$fixture=Join-Path $root ('work\source-reference-check-'+[Guid]::NewGuid().ToString('N'))
foreach($leaf in 'scripts','src\Library','src\Client','results'){[void][IO.Directory]::CreateDirectory((Join-Path $fixture $leaf))}
$checker=Join-Path $root 'scripts\Check-SourceTypes.ps1'
$copy=Join-Path $fixture 'scripts\Check-SourceTypes.ps1'
Copy-Item -LiteralPath $checker -Destination $copy
$hash=(Get-FileHash -LiteralPath $checker).Hash
if((Get-FileHash -LiteralPath $copy).Hash -ne $hash){throw 'Checker copy differs'}
$library=Join-Path $fixture 'src\Library\Library.csproj'
$client=Join-Path $fixture 'src\Client\Client.csproj'
$program=Join-Path $fixture 'src\Client\Program.cs'
$baseLibrary='<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Library</OutputType><AssemblyName>SourceReferenceLibrary</AssemblyName><TargetFramework>net8.0-windows</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include="Api.cs"/></ItemGroup></Project>'
$baseClient='<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><AssemblyName>SourceReferenceClient</AssemblyName><TargetFramework>net8.0-windows</TargetFramework><ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include="Program.cs"/><ProjectReference Include="../Library/Library.csproj"/></ItemGroup></Project>'
$baseProgram='Console.WriteLine(SourceReference.Api.Answer);'
[IO.File]::WriteAllText((Join-Path $fixture 'src\Library\Api.cs'),'namespace SourceReference; public static class Api { public static int Answer => 42; } internal static class Secret { internal static int Hidden => 7; }')
$results=[Collections.Generic.List[object]]::new()
function Run-Case([string]$Name,[int]$ExpectedExit,[string]$ExpectedDiagnostic,[scriptblock]$Mutate){
    [IO.File]::WriteAllText($library,$baseLibrary)
    [IO.File]::WriteAllText($client,$baseClient)
    [IO.File]::WriteAllText($program,$baseProgram)
    & $Mutate
    $report=Join-Path $fixture ('results\'+$Name+'.json')
    $log=Join-Path $fixture ('results\'+$Name+'.log')
    & (Join-Path $PSHOME 'pwsh.exe') -NoProfile -File $copy -ReportPath $report *> $log
    $exit=$LASTEXITCODE
    $content=[IO.File]::ReadAllText($log)
    if(Test-Path -LiteralPath $report){$content+=[IO.File]::ReadAllText($report)}
    $passed=$exit -eq $ExpectedExit -and (!$ExpectedDiagnostic -or $content.Contains($ExpectedDiagnostic))
    if($Name -eq 'public-reference'){
        $data=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
        $referencing=@($data.Projects|Where-Object {$_.Project.EndsWith('Client.csproj')})
        $passed=$passed -and $data.Projects.Count -eq 2 -and $referencing[0].ProjectReferences.Count -eq 1 -and
            !$data.EmitCalled -and !$data.ProjectAssemblyLoaded -and !$data.MSBuildCalled -and !$data.RestoreCalled
    }
    $results.Add([pscustomobject]@{Name=$Name;ExitCode=$exit;ExpectedExit=$ExpectedExit;Status=$(if($passed){'PASS'}else{'FAIL'})})
}
Run-Case 'public-reference' 0 '' {}
Run-Case 'internal-visibility' 2 'CS0122' {[IO.File]::WriteAllText($program,'Console.WriteLine(SourceReference.Secret.Hidden);')}
Run-Case 'reference-metadata' 1 'Unsupported ProjectReference metadata or wildcard' {
    [IO.File]::WriteAllText($client,$baseClient.Replace('Include="../Library/Library.csproj"','Include="../Library/Library.csproj" ReferenceOutputAssembly="false"'))
}
Run-Case 'missing-reference' 1 'Unknown/external/self project reference' {
    [IO.File]::WriteAllText($client,$baseClient.Replace('../Library/Library.csproj','../Missing/Missing.csproj'))
}
Run-Case 'non-leaf-reference' 1 'Only direct local net8.0-windows library leaf references are supported' {
    [IO.File]::WriteAllText($library,$baseLibrary.Replace('</ItemGroup>','<ProjectReference Include="../Client/Client.csproj"/></ItemGroup>'))
}
$summary=[pscustomobject]@{Scope='NON_EMITTING_CHECKER_SYNTHETIC_REFERENCE_INPUTS';CheckerSHA256=$hash;EvidenceDirectory=$fixture;Results=$results.ToArray();ProductSourceCopied=$false;ProductAssemblyExecuted=$false;EmitCalled=$false;MSBuildCalled=$false;NativeApisCalled=$false}
$summary|ConvertTo-Json -Depth 6|Set-Content (Join-Path $fixture 'summary.json') -Encoding utf8
$summary|ConvertTo-Json -Depth 6
if(@($results|Where-Object Status -ne 'PASS').Count){exit 2}
