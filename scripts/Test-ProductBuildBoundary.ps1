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

# The security stop itself must remain a single unconditional throw. No
# environment variable, command-line parameter, expiry or branch may bypass it.
$gateText=Read-Text 'scripts/Assert-ProjectSecurityClearance.ps1'
$tokens=$null;$parseErrors=$null
$gateAst=[System.Management.Automation.Language.Parser]::ParseInput($gateText,[ref]$tokens,[ref]$parseErrors)
Require ($parseErrors.Count -eq 0) 'security-stop script has PowerShell parse errors'
Require ($null -eq $gateAst.ParamBlock) 'security-stop script accepts caller parameters'
Require ($gateAst.EndBlock.Statements.Count -eq 1) 'security-stop script must contain exactly one executable statement'
$statement=$gateAst.EndBlock.Statements[0]
Require ($statement -is [System.Management.Automation.Language.ThrowStatementAst]) 'security-stop is not an unconditional throw'
Require ($statement.Extent.Text -match 'SECURITY_REVIEW_REQUIRED') 'security-stop reason marker changed'

# Every conventional Build*.ps1 entrypoint must source the hard stop before
# invoking a compiler, creating output directories or running build tools.
$scriptsRoot=Join-Path $root 'scripts'
$buildEntrypoints=@(Get-ChildItem -LiteralPath $scriptsRoot -File | Where-Object {$_.Name -match '^Build.*\.(ps1|cmd|bat)$'})
Require ($buildEntrypoints.Count -gt 0) 'no conventional Build entrypoints were discovered'
foreach($entry in $buildEntrypoints)
{
    $text=[IO.File]::ReadAllText($entry.FullName)
    $gateIndex=$text.IndexOf('Assert-ProjectSecurityClearance.ps1',[StringComparison]::Ordinal)
    Require ($gateIndex -ge 0) "$($entry.Name) does not source the security stop"
    $firstBuildAction=[regex]::Match($text,'(?im)^\s*(?:&\s*)?(?:dotnet(?:\.exe)?|New-Item|Get-ChildItem|cl\.exe|vswhere(?:\.exe)?)\b')
    Require ((-not $firstBuildAction.Success) -or $gateIndex -lt $firstBuildAction.Index) "$($entry.Name) performs a build action before the security stop"
}

Write-Output 'PASS daily explicit source inventory excludes historical SelfTests and engineering-only Job/sandbox code'
Write-Output 'PASS engineering-only process/job/sandbox source remains separately compiled and unshipped'
Write-Output 'PASS approved package inventory excludes engineering, selftest, sandbox and native-fence assets'
Write-Output 'PASS SECURITY_REVIEW_REQUIRED remains an unconditional, parameterless hard stop'
Write-Output ("PASS {0} conventional Build entrypoints source the hard stop before build actions" -f $buildEntrypoints.Count)
Write-Output 'STATIC SOURCE REVIEW ONLY: no product build, assembly load, product execution, AV query, install or host mutation'
