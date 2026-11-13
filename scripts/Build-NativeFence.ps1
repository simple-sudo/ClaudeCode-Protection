$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage NativeBuild
New-Item -ItemType Directory -Path (Join-Path $root 'bin\engineering') -Force | Out-Null
$vswhere='C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$installation=((& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -join '').Trim()
if(-not $installation){throw 'Microsoft C++ Build Tools required'}
$tools=Get-ChildItem -LiteralPath (Join-Path $installation 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
$sdk='C:\Program Files (x86)\Windows Kits\10'
$version='10.0.26100.0'
$compiler=Join-Path $tools.FullName 'bin\Hostx64\x64\cl.exe'
$oldPath=$env:PATH
try {
    $env:PATH=(Split-Path -Parent $compiler)+';'+$oldPath
    $arguments=@('/nologo','/std:c++20','/EHsc','/W4','/WX','/O2','/MT','/DUNICODE','/D_UNICODE')
    foreach($include in @((Join-Path $tools.FullName 'include'),(Join-Path $sdk ('Include\'+$version+'\um')),(Join-Path $sdk ('Include\'+$version+'\shared')),(Join-Path $sdk ('Include\'+$version+'\ucrt')))){ $arguments+=('/I'+$include) }
    $arguments+=@(('/Fo'+(Join-Path $root 'state\ProbeFence.obj')),('/Fe'+(Join-Path $root 'bin\engineering\ClaudeProtectionFence.exe')),(Join-Path $root 'src\NativeFence\ProbeFence.cpp'),'/link')
    foreach($library in @((Join-Path $tools.FullName 'lib\x64'),(Join-Path $sdk ('Lib\'+$version+'\um\x64')),(Join-Path $sdk ('Lib\'+$version+'\ucrt\x64')))){ $arguments+=('/LIBPATH:'+ $library) }
    $arguments+=@('Fwpuclnt.lib','Userenv.lib','Advapi32.lib','Ole32.lib','Rpcrt4.lib')
    & $compiler @arguments
    if($LASTEXITCODE -ne 0){throw 'Native probe fence build failed'}
} finally {$env:PATH=$oldPath}
