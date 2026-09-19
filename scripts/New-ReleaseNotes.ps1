param(
  [Parameter(Mandatory = $true)][string]$Tag,
  [string]$Changelog = (Join-Path (Split-Path -Parent $PSScriptRoot) 'CHANGELOG.md'),
  [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'

$version = ($Tag -replace '^v', '') -replace '-.*$', ''
$content = Get-Content -LiteralPath $Changelog -Raw
$escapedVersion = [regex]::Escape($version)
$pattern = "(?ms)^##\s+v?$escapedVersion(?:\s+-\s+\d{4}-\d{2}-\d{2})?\s*\r?\n(.*?)(?=^##\s+|\z)"
$match = [regex]::Match($content, $pattern)

if (-not $match.Success) {
  throw "Could not find CHANGELOG section for $Tag"
}

$body = $match.Groups[1].Value.Trim()
$header = @"
Windows x64 release of **Cheat Wizard $Tag**.

Download ``Cheat-Wizard-Builder-$Tag-win64.exe`` and verify it with the attached
``Cheat-Wizard-Builder-$Tag-win64.exe.sha256`` file.

The standalone builder contains the pinned source/toolchain payload and compiles
Cheat Wizard locally on the user's Windows x64 machine. No Visual Studio, CMake,
Git or network download is required during the build.

"@

($header.TrimEnd() + [Environment]::NewLine + [Environment]::NewLine + $body + [Environment]::NewLine) |
  Set-Content -LiteralPath $Output -Encoding utf8

Write-Host "Release notes: $Output"
