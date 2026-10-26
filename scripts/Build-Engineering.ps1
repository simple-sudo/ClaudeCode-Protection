$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1')
# Never invoked by the daily build or GUI. This source split does not clear AV review.
& dotnet.exe publish (Join-Path $root 'src\ClaudeProtection.Engineering\ClaudeProtection.Engineering.csproj') --configuration Release --output (Join-Path $root 'bin\engineering') --nologo -p:RestoreIgnoreFailedSources=true
if($LASTEXITCODE -ne 0){throw 'Engineering build failed'}
