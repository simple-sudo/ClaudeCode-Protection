$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1')
& dotnet.exe publish (Join-Path $root 'src\ProtectionCenter\ProtectionCenter.csproj') --configuration Release --output (Join-Path $root 'bin\center') --nologo -p:RestoreIgnoreFailedSources=true
if($LASTEXITCODE -ne 0){throw 'Protection Center build failed'}
