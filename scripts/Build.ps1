$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Assert-ProjectSecurityClearance.ps1') -Stage DailyBuild
$project=Join-Path $root 'src\ClaudeProtection\ClaudeProtection.csproj'
$dotnet=(Get-Command dotnet.exe -ErrorAction Stop).Source
$logRoot=Join-Path $env:LOCALAPPDATA 'ClaudeCode-Protection\security-stage'
[void][IO.Directory]::CreateDirectory($logRoot)
$run=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$stdout=Join-Path $logRoot ($run+'-daily-build.stdout.log')
$stderr=Join-Path $logRoot ($run+'-daily-build.stderr.log')
$arguments=@('build',$project,'--configuration','Release','--output',(Join-Path $root 'bin\current'),'--nologo','--no-restore')
$exitCode=Invoke-ProjectSecurityMonitoredProcess -FilePath $dotnet -ArgumentList $arguments -WorkingDirectory $root -StandardOutputPath $stdout -StandardErrorPath $stderr
if($exitCode -ne 0){throw "Daily build failed with exit code $exitCode. Logs: $stdout ; $stderr"}
Write-Output "DAILY_BUILD_PASS: $run; stdout=$stdout; stderr=$stderr"
