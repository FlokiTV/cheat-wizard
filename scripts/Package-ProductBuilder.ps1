param(
    [Parameter(Mandatory = $true)]
    [string]$Builder,
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$builderPath = [IO.Path]::GetFullPath($Builder)
$outputRoot = [IO.Path]::GetFullPath($OutputDir)

if (-not (Test-Path -LiteralPath $builderPath -PathType Leaf)) {
    throw "Standalone builder not found: $builderPath"
}

[IO.Directory]::CreateDirectory($outputRoot) | Out-Null

$name = "Cheat-Wizard-Builder-$Version-win64.exe"
$destination = Join-Path $outputRoot $name
Copy-Item -LiteralPath $builderPath -Destination $destination -Force

$hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
$sidecar = "$destination.sha256"
"$hash  $name" | Set-Content -LiteralPath $sidecar -Encoding ASCII

Write-Host "Standalone builder package ready."
Write-Host "  Builder: $destination"
Write-Host "  SHA-256: $hash"
Write-Host "  Sidecar: $sidecar"
