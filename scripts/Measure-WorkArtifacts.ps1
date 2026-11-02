#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateRange(1, 100)][int]$Top = 15,
    [switch]$IncludeFiles
)

# Metadata only. This report never grants deletion or execution authority.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$work = Join-Path $root 'work'
$ancestor = Get-Item -LiteralPath $work -Force
while ($null -ne $ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Inventory root or ancestor is a reparse point'
    }
    $ancestor = $ancestor.Parent
}
$pending = [Collections.Generic.Stack[string]]::new()
$pending.Push($work)
$files = [Collections.Generic.List[object]]::new()
$skipped = [Collections.Generic.List[object]]::new()
while ($pending.Count) {
    $directory = $pending.Pop()
    try {
        $item = Get-Item -LiteralPath $directory -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Directory changed to a reparse point'
        }
        $entries = @(Get-ChildItem -LiteralPath $directory -Force)
    } catch {
        $skipped.Add([pscustomobject]@{
            Path = [IO.Path]::GetRelativePath($root, $directory)
            Reason = 'EnumerationFailed'; ErrorType = $_.Exception.GetType().Name
        })
        continue
    }
    foreach ($entry in $entries) {
        $relative = [IO.Path]::GetRelativePath($root, $entry.FullName)
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $skipped.Add([pscustomobject]@{ Path = $relative; Reason = 'ReparsePoint' })
        } elseif ($entry.PSIsContainer) {
            $pending.Push($entry.FullName)
        } else {
            $files.Add([pscustomobject]@{
                Path = $relative; Bytes = $entry.Length
                LastWriteUtc = $entry.LastWriteTimeUtc.ToString('o')
            })
        }
    }
}
$groups = @($files | Group-Object { $_.Path.Split([IO.Path]::DirectorySeparatorChar)[1] } |
    ForEach-Object {
        [pscustomobject]@{
            Directory = $_.Name; Files = $_.Count
            Bytes = [long](($_.Group | Measure-Object Bytes -Sum).Sum)
        }
    } | Sort-Object Bytes -Descending | Select-Object -First $Top)
$report = [ordered]@{
    SchemaVersion = 1; AtUtc = [DateTime]::UtcNow.ToString('o'); Root = $work
    Status = $(if (@($skipped | Where-Object Reason -eq 'EnumerationFailed').Count) {
        'PARTIAL'
    } else { 'COMPLETE_EXCLUDING_REPARSE_POINTS' })
    Measurement = 'Logical file lengths; excludes filesystem allocation and linked targets'
    Files = $files.Count; Bytes = [long](($files | Measure-Object Bytes -Sum).Sum)
    LargestDirectories = $groups
    LargestFiles = @($files | Sort-Object Bytes -Descending | Select-Object -First $Top)
    Skipped = @($skipped.ToArray())
}
if ($IncludeFiles) { $report['FileInventory'] = @($files.ToArray() | Sort-Object Path) }
$report | ConvertTo-Json -Depth 6
