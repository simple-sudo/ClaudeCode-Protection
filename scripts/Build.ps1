$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1')
& dotnet.exe publish (Join-Path $root 'src\ClaudeProtection\ClaudeProtection.csproj') --configuration Release --output (Join-Path $root 'bin\current') --nologo -p:RestoreIgnoreFailedSources=true
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
