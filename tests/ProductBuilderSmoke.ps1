param(
    [Parameter(Mandatory = $true)]
    [string]$Builder,
    [Parameter(Mandatory = $true)]
    [string]$WorkDir
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$builderPath = [IO.Path]::GetFullPath($Builder)
$workRoot = [IO.Path]::GetFullPath($WorkDir)
$outputDir = Join-Path $workRoot "Cheat-Wizard"

if (-not (Test-Path -LiteralPath $builderPath -PathType Leaf)) {
    throw "Product builder not found: $builderPath"
}

if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
[IO.Directory]::CreateDirectory($workRoot) | Out-Null

$builderProcess = Start-Process -FilePath $builderPath -ArgumentList @(
    "--headless",
    "--output-dir",
    $outputDir
) -Wait -PassThru
if ($builderProcess.ExitCode -ne 0) {
    $errorLog = Join-Path (Split-Path -Parent $builderPath) "Cheat-Wizard-Builder-error.txt"
    if (Test-Path -LiteralPath $errorLog) {
        Write-Host (Get-Content -LiteralPath $errorLog -Raw)
    }
    throw "Cheat-Wizard-Builder exited with code $($builderProcess.ExitCode)"
}

$required = @(
    "Cheat Wizard.exe",
    "cw-engine.exe",
    "cw-trainer-builder.exe",
    "cw-engine.build.json",
    "cw-build-manifest.json",
    "README.txt",
    "LICENSE",
    "NOTICE",
    "locales\en-US.json",
    "locales\pt-BR.json"
)
foreach ($relative in $required) {
    $path = Join-Path $outputDir $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Standalone builder output is missing: $relative"
    }
}

$version = & (Join-Path $outputDir "cw-engine.exe") --version
if ($LASTEXITCODE -ne 0 -or ($version -join [Environment]::NewLine) -notmatch "protocol 1\.1") {
    throw "Generated cw-engine.exe failed version/protocol self-check: $version"
}

$manifest = Get-Content -LiteralPath (Join-Path $outputDir "cw-build-manifest.json") -Raw | ConvertFrom-Json
if (-not $manifest.builtLocally -or $manifest.architecture -ne "x64") {
    throw "Product manifest does not identify a local x64 build."
}
foreach ($name in @("Cheat Wizard.exe", "cw-engine.exe", "cw-trainer-builder.exe")) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $outputDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = [string]$manifest.files.$name
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch for $name"
    }
}

Write-Host "Product builder smoke PASS."
Write-Host "  Output: $outputDir"
Write-Host "  Source revision: $($manifest.sourceRevision)"
Write-Host "  Toolchain: $($manifest.toolchain)"
