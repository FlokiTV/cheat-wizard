param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [Parameter(Mandatory = $true)][string]$OutputDir,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$BuildDir = [IO.Path]::GetFullPath((Join-Path $RepoRoot $BuildDir))
$OutputDir = [IO.Path]::GetFullPath((Join-Path $RepoRoot $OutputDir))
$ReleaseDir = Join-Path $BuildDir 'Release'
$ReleaseName = "Cheat-Wizard-$Version-win64"
$StageDir = Join-Path $OutputDir $ReleaseName
$ZipPath = Join-Path $OutputDir "$ReleaseName.zip"
$ZipChecksumPath = "$ZipPath.sha256"

$required = @(
  (Join-Path $ReleaseDir 'Cheat Wizard.exe'),
  (Join-Path $ReleaseDir 'cw-engine-builder.exe'),
  (Join-Path $ReleaseDir 'cw-trainer-builder.exe'),
  (Join-Path $RepoRoot 'bin\README.txt'),
  (Join-Path $RepoRoot 'LICENSE'),
  (Join-Path $RepoRoot 'NOTICE'),
  (Join-Path $RepoRoot 'locales\en-US.json'),
  (Join-Path $RepoRoot 'locales\pt-BR.json')
)

foreach ($path in $required) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Required release input is missing: $path"
  }
}

if (Test-Path -LiteralPath $StageDir) {
  Remove-Item -LiteralPath $StageDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir 'locales') | Out-Null

Copy-Item -LiteralPath (Join-Path $ReleaseDir 'Cheat Wizard.exe') -Destination $StageDir
Copy-Item -LiteralPath (Join-Path $ReleaseDir 'cw-engine-builder.exe') -Destination $StageDir
Copy-Item -LiteralPath (Join-Path $ReleaseDir 'cw-trainer-builder.exe') -Destination $StageDir
Copy-Item -LiteralPath (Join-Path $RepoRoot 'bin\README.txt') -Destination (Join-Path $StageDir 'README.txt')
Copy-Item -LiteralPath (Join-Path $RepoRoot 'LICENSE') -Destination $StageDir
Copy-Item -LiteralPath (Join-Path $RepoRoot 'NOTICE') -Destination $StageDir
Copy-Item -LiteralPath (Join-Path $RepoRoot 'locales\en-US.json') -Destination (Join-Path $StageDir 'locales\en-US.json')
Copy-Item -LiteralPath (Join-Path $RepoRoot 'locales\pt-BR.json') -Destination (Join-Path $StageDir 'locales\pt-BR.json')

$manifest = Get-ChildItem -LiteralPath $StageDir -Recurse -File |
  Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
  Sort-Object FullName |
  ForEach-Object {
    $relative = [IO.Path]::GetRelativePath($StageDir, $_.FullName).Replace('\', '/')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
    "$hash  $relative"
  }

$manifestPath = Join-Path $StageDir 'SHA256SUMS.txt'
$manifest | Set-Content -LiteralPath $manifestPath -Encoding ascii

if (Test-Path -LiteralPath $ZipPath) {
  Remove-Item -LiteralPath $ZipPath -Force
}
if (Test-Path -LiteralPath $ZipChecksumPath) {
  Remove-Item -LiteralPath $ZipChecksumPath -Force
}

Compress-Archive -Path (Join-Path $StageDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal

$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath).Hash.ToLowerInvariant()
"$zipHash  $([IO.Path]::GetFileName($ZipPath))" |
  Set-Content -LiteralPath $ZipChecksumPath -Encoding ascii

Write-Host "Release package: $ZipPath"
Write-Host "Release checksum: $ZipChecksumPath"
Write-Host "SHA256: $zipHash"
