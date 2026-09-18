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

Download `Cheat-Wizard-$Tag-win64.zip` and verify it with the attached
`Cheat-Wizard-$Tag-win64.zip.sha256` file.

"@

($header.TrimEnd() + [Environment]::NewLine + [Environment]::NewLine + $body + [Environment]::NewLine) |
  Set-Content -LiteralPath $Output -Encoding utf8

Write-Host "Release notes: $Output"
