#requires -Version 7.4
#requires -PSEdition Core
[CmdletBinding()]
param([string]$ReportPath)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$compiler=(Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'dotnet\sdk\8.0.422\Roslyn\bincore')
$core=(Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'dotnet\packs\Microsoft.NETCore.App.Ref\8.0.28\ref\net8.0')
$desktop=(Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'dotnet\packs\Microsoft.WindowsDesktop.App.Ref\8.0.28\ref\net8.0')
Add-Type -Path (Join-Path $compiler 'Microsoft.CodeAnalysis.dll')
Add-Type -Path (Join-Path $compiler 'Microsoft.CodeAnalysis.CSharp.dll')
$globalUsings='global using System; global using System.Collections.Generic; global using System.IO; global using System.Linq; global using System.Net.Http; global using System.Threading; global using System.Threading.Tasks;'
$parse=[Microsoft.CodeAnalysis.CSharp.CSharpParseOptions]::Default.WithLanguageVersion([Microsoft.CodeAnalysis.CSharp.LanguageVersion]::CSharp12)
$results=@(foreach($project in Get-ChildItem -LiteralPath (Join-Path $root 'src') -Recurse -File -Filter '*.csproj'){
    [xml]$xml=[IO.File]::ReadAllText($project.FullName)
    if($xml.SelectNodes('//*[@Condition or @Remove or @Update or @Exclude]').Count -or $xml.SelectNodes('//PackageReference|//Reference|//Analyzer|//AdditionalFiles|//Import|//Target|//UsingTask|//FrameworkReference|//DefineConstants').Count){throw 'Unsupported conditional/custom build input; use an appropriately cleared real build'}
    if([string]$xml.Project.PropertyGroup.TargetFramework -ne 'net8.0-windows'){throw 'Unsupported target framework in bounded checker'}
    if(@($xml.Project.ItemGroup.ProjectReference).Where({$null -ne $_}).Count){throw 'Project references require explicit metadata composition'}
    $paths=@(foreach($node in @($xml.Project.ItemGroup.Compile)){if($null -ne $node){foreach($relative in $node.Include.Split(';')){if($relative){[IO.Path]::GetFullPath((Join-Path $project.DirectoryName $relative))}}}})
    if([string]$xml.Project.PropertyGroup.EnableDefaultCompileItems -ne 'false'){$paths+=@(Get-ChildItem -LiteralPath $project.DirectoryName -Recurse -File -Filter '*.cs'|Where-Object {$_.FullName -notmatch '\\(obj|bin)\\'}|ForEach-Object FullName)}
    $paths=@($paths|Sort-Object -Unique)
    $trees=[Collections.Generic.List[Microsoft.CodeAnalysis.SyntaxTree]]::new()
    foreach($path in $paths){
        $text=[IO.File]::ReadAllText($path)
        if($text -match '(?m)^\s*#\s*(if|elif|define|undef)\b'){throw 'Conditional source needs explicit SDK preprocessor evaluation'}
        $trees.Add([Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($text,$parse,$path))
    }
    if([string]$xml.Project.PropertyGroup.ImplicitUsings -eq 'enable'){$trees.Add([Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($globalUsings,$parse,'(in-memory SDK implicit global usings)'))}
    $assemblyPaths=@{}
    foreach($reference in Get-ChildItem -LiteralPath $core -File -Filter '*.dll'){$assemblyPaths[$reference.Name]=$reference.FullName}
    if([string]$xml.Project.PropertyGroup.UseWPF -eq 'true'){foreach($reference in Get-ChildItem -LiteralPath $desktop -File -Filter '*.dll'){$assemblyPaths[$reference.Name]=$reference.FullName}}
    $references=[Collections.Generic.List[Microsoft.CodeAnalysis.MetadataReference]]::new()
    foreach($path in $assemblyPaths.Values){$references.Add([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($path))}
    $kind=switch([string]$xml.Project.PropertyGroup.OutputType){'Exe'{[Microsoft.CodeAnalysis.OutputKind]::ConsoleApplication};'WinExe'{[Microsoft.CodeAnalysis.OutputKind]::WindowsApplication};'Library'{[Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary};default{throw 'Unknown output kind'}}
    $options=[Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new($kind).WithPlatform([Microsoft.CodeAnalysis.Platform]::X64).WithNullableContextOptions([Microsoft.CodeAnalysis.NullableContextOptions]::Enable)
    if([string]$xml.Project.PropertyGroup.TreatWarningsAsErrors -eq 'true'){$options=$options.WithGeneralDiagnosticOption([Microsoft.CodeAnalysis.ReportDiagnostic]::Error)}
    $name=[string]$xml.Project.PropertyGroup.AssemblyName;if(-not $name){$name=$project.BaseName}
    $analysis=[Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create($name,$trees,$references,$options)
    $diagnostics=@($analysis.GetDiagnostics([Threading.CancellationToken]::None)|Where-Object {$_.Severity -eq [Microsoft.CodeAnalysis.DiagnosticSeverity]::Error -or $_.Severity -eq [Microsoft.CodeAnalysis.DiagnosticSeverity]::Warning}|ForEach-Object {[pscustomobject]@{Id=$_.Id;Severity=$_.Severity.ToString();Diagnostic=$_.ToString()}})
    [pscustomobject]@{Project=$project.FullName;SourceFiles=$paths.Count;ReferenceFiles=$references.Count;Errors=@($diagnostics|Where-Object {$_.Severity -eq 'Error'}).Count;Warnings=@($diagnostics|Where-Object {$_.Severity -eq 'Warning'}).Count;Diagnostics=$diagnostics}
})
$report=[pscustomobject]@{AtUtc=[DateTime]::UtcNow.ToString('o');Scope='NON_EMITTING_CSHARP_SEMANTIC_ANALYSIS';CompilerVersion='SDK8.0.422';ReferenceVersion='8.0.28';LanguageVersion='CSharp12';Projects=$results;EmitCalled=$false;ProjectAssemblyLoaded=$false;MSBuildCalled=$false;RestoreCalled=$false;AnalyzersOrGeneratorsExecuted=$false;NativeApisCalled=$false;BuildQualified=$false;RuntimeQualified=$false}
if($ReportPath){$report|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $ReportPath -Encoding utf8}
$results|Select-Object Project,SourceFiles,ReferenceFiles,Errors,Warnings|ConvertTo-Json
foreach($result in $results){$result.Diagnostics|Select-Object -First 15|ConvertTo-Json -Depth 3}
if(@($results|Where-Object {$_.Errors -or $_.Warnings}).Count){exit 2}
