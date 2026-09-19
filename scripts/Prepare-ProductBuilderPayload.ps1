param(
    [Parameter(Mandatory = $true)]
    [string]$Output,
    [string]$CacheDir = (Join-Path $PSScriptRoot "..\build\product-builder-cache")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$nl = [Environment]::NewLine

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputPath = [IO.Path]::GetFullPath($Output)
$cacheRoot = [IO.Path]::GetFullPath($CacheDir)

$toolchainVersion = "20260908"
$toolchainArchive = "llvm-mingw-$toolchainVersion-ucrt-x86_64.zip"
$toolchainUrl = "https://github.com/mstorsjo/llvm-mingw/releases/download/$toolchainVersion/$toolchainArchive"
$toolchainSha256 = "1bcf74d06b724aeecaa6412ca85f5b26fb1da770e7cdcefa9263c9c5c3ad34b6"
$toolchainId = "llvm-mingw-$toolchainVersion-ucrt-x86_64-minimal"
$productVersion = "1.7.3"
$engineVersion = "1.7.3"
$protocolMajor = 1
$protocolMinor = 0

$sourceFiles = @(
    "src\Value.cpp",
    "src\AobPattern.cpp",
    "src\AobPersistence.cpp",
    "src\ScanPersistence.cpp",
    "src\RelativeAddress.cpp",
    "src\InstructionDecode.cpp",
    "src\PointerAlgorithms.cpp",
    "src\PointerPersistence.cpp",
    "src\PointerProfile.cpp",
    "src\PointerMap.cpp",
    "src\Win32Error.cpp",
    "src\EngineSession.cpp",
    "src\ProcessManager.cpp",
    "src\MemoryScanner.cpp",
    "src\AobScanner.cpp",
    "src\MemoryWriter.cpp",
    "src\FreezeManager.cpp",
    "src\PointerScanner.cpp",
    "src\EngineProtocol.cpp",
    "src\EnginePipe.cpp",
    "src\EngineClient.cpp",
    "src\EngineFrontend.cpp",
    "src\EngineMain.cpp",
    "portable_win\CW_GUI_NoCRT.cpp",
    "portable_win\GuiEngineBridge.cpp",
    "portable_win\StandardCRTEntry.cpp",
    "portable_win\TrainerRuntime_NoCRT.cpp",
    "portable_win\TrainerBuilder_NoCRT.cpp"
)

$portableHeaders = @(
    "portable_win\MdiIconMasks.hpp",
    "portable_win\GuiEngineBridge.hpp"
)

function Ensure-Directory([string]$Path) {
    [IO.Directory]::CreateDirectory($Path) | Out-Null
}

function Copy-RelativeFile([string]$SourceRoot, [string]$DestinationRoot, [string]$RelativePath) {
    $source = Join-Path $SourceRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required file not found: $source"
    }
    $destination = Join-Path $DestinationRoot $RelativePath
    Ensure-Directory (Split-Path -Parent $destination)
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

function Invoke-Checked([string]$Executable, [string[]]$Arguments, [string]$WorkingDirectory) {
    Push-Location $WorkingDirectory
    try {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Executable exited with code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Get-SourceDigest([string[]]$Files) {
    $lines = foreach ($file in ($Files | Sort-Object)) {
        $relative = [IO.Path]::GetRelativePath($repoRoot, $file).Replace("\", "/")
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        "$relative=$hash"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join $nl) + $nl)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        ([Convert]::ToHexString($sha.ComputeHash($bytes))).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function New-VersionRc(
    [string]$Path,
    [string]$Description,
    [string]$InternalName,
    [string]$OriginalFilename
) {
    $content = @"
1 VERSIONINFO
FILEVERSION 1,7,3,0
PRODUCTVERSION 1,7,3,0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Cheat Wizard"
      VALUE "FileDescription", "$Description"
      VALUE "FileVersion", "$productVersion"
      VALUE "InternalName", "$InternalName"
      VALUE "OriginalFilename", "$OriginalFilename"
      VALUE "ProductName", "Cheat Wizard"
      VALUE "ProductVersion", "$productVersion"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"@
    Set-Content -LiteralPath $Path -Value $content -Encoding ASCII
}

Ensure-Directory $cacheRoot
$archivePath = Join-Path $cacheRoot $toolchainArchive
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    Write-Host "Downloading pinned llvm-mingw $toolchainVersion..."
    Invoke-WebRequest -Uri $toolchainUrl -OutFile $archivePath
}

$actualSha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha -ne $toolchainSha256) {
    throw "llvm-mingw SHA-256 mismatch. Expected $toolchainSha256, got $actualSha"
}

$extractParent = Join-Path $cacheRoot "extracted"
$fullRoot = Join-Path $extractParent "llvm-mingw-$toolchainVersion-ucrt-x86_64"
if (-not (Test-Path -LiteralPath (Join-Path $fullRoot "bin\x86_64-w64-mingw32-clang++.exe") -PathType Leaf)) {
    if (Test-Path -LiteralPath $extractParent) {
        Remove-Item -LiteralPath $extractParent -Recurse -Force
    }
    Ensure-Directory $extractParent
    Write-Host "Extracting verified llvm-mingw archive..."
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractParent -Force
}

$workRoot = Join-Path $cacheRoot "work"
if (Test-Path -LiteralPath $workRoot) {
    Remove-Item -LiteralPath $workRoot -Recurse -Force
}
Ensure-Directory $workRoot
$depRoot = Join-Path $workRoot "deps"
$depGenerated = Join-Path $depRoot "generated"
Ensure-Directory $depGenerated

$stub = @"
#pragma once
static const unsigned char g_trainer_runtime_bytes[] = { 0 };
static const unsigned long long g_trainer_runtime_size = sizeof(g_trainer_runtime_bytes);
"@
Set-Content -LiteralPath (Join-Path $depGenerated "TrainerRuntimeBlob.hpp") -Value $stub -Encoding ASCII

$compiler = Join-Path $fullRoot "bin\x86_64-w64-mingw32-clang++.exe"
$commonCompileArgs = @(
    "-std=c++20", "-O2", "-DNDEBUG",
    "-DUNICODE", "-D_UNICODE", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX",
    "-I$repoRoot\include", "-I$repoRoot\portable_win", "-I$depGenerated",
    "-fstack-protector-strong", "-fcf-protection=full"
)

Write-Host "Collecting product header dependencies..."
foreach ($relative in $sourceFiles) {
    $source = Join-Path $repoRoot $relative
    $safeName = ($relative -replace "[\\/:]", "_") -replace "\.cpp$", ""
    $object = Join-Path $depRoot "$safeName.o"
    $dep = Join-Path $depRoot "$safeName.d"
    $extra = @()
    if ($relative -eq "portable_win\CW_GUI_NoCRT.cpp") {
        $extra += "-DCW_USE_STANDARD_CRT=1"
    }
    elseif ($relative -eq "portable_win\TrainerRuntime_NoCRT.cpp") {
        $extra += "-DCW_USE_STANDARD_CRT=1"
    }
    elseif ($relative -eq "portable_win\TrainerBuilder_NoCRT.cpp") {
        $extra += "-DCW_USE_STANDARD_CRT=1"
    }
    elseif ($relative -eq "portable_win\StandardCRTEntry.cpp") {
        $extra += "-DCW_CRT_ENTRY_GUI=1"
    }
    Invoke-Checked $compiler ($commonCompileArgs + $extra + @("-MD", "-MF", $dep, "-c", $source, "-o", $object)) $repoRoot
}

$payloadRoot = Join-Path $workRoot "payload"
$toolchainRoot = Join-Path $payloadRoot "toolchain"
$sourceRoot = Join-Path $payloadRoot "source"
Ensure-Directory $toolchainRoot
Ensure-Directory $sourceRoot

$fixedToolchainFiles = @(
    "LICENSE.TXT",
    "bin\x86_64-w64-mingw32-clang++.exe",
    "bin\clang-23.exe",
    "bin\ld.lld.exe",
    "bin\llvm-windres.exe",
    "bin\x86_64-w64-windows-gnu.cfg",
    "bin\mingw32-common.cfg",
    "bin\libLLVM-23.dll",
    "bin\libclang-cpp.dll",
    "bin\libc++.dll",
    "bin\libunwind.dll",
    "x86_64-w64-mingw32\lib\crt2.o",
    "x86_64-w64-mingw32\lib\crt2u.o",
    "x86_64-w64-mingw32\lib\crtbegin.o",
    "x86_64-w64-mingw32\lib\crtend.o",
    "x86_64-w64-mingw32\lib\libc++.a",
    "x86_64-w64-mingw32\lib\libunwind.a",
    "x86_64-w64-mingw32\lib\libmoldname.a",
    "x86_64-w64-mingw32\lib\libmingw32.a",
    "x86_64-w64-mingw32\lib\libmingwex.a",
    "x86_64-w64-mingw32\lib\libmsvcrt.a",
    "x86_64-w64-mingw32\lib\libadvapi32.a",
    "x86_64-w64-mingw32\lib\libbcrypt.a",
    "x86_64-w64-mingw32\lib\libshell32.a",
    "x86_64-w64-mingw32\lib\libuser32.a",
    "x86_64-w64-mingw32\lib\libgdi32.a",
    "x86_64-w64-mingw32\lib\libcomdlg32.a",
    "x86_64-w64-mingw32\lib\libmsimg32.a",
    "x86_64-w64-mingw32\lib\libkernel32.a",
    "lib\clang\23\lib\windows\libclang_rt.builtins-x86_64.a"
)
foreach ($relative in $fixedToolchainFiles) {
    Copy-RelativeFile $fullRoot $toolchainRoot $relative
}

$fullPrefix = $fullRoot.Replace("\", "/") + "/"
$distributionMarker = "/llvm-mingw-$toolchainVersion-ucrt-x86_64/"
$headerSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($depFile in Get-ChildItem -LiteralPath $depRoot -Filter "*.d") {
    $raw = Get-Content -LiteralPath $depFile.FullName -Raw
    foreach ($token in ($raw -split "\s+")) {
        $candidate = $token.Trim().Replace("\", "/")
        $relative = $null
        if ($candidate.StartsWith($fullPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $relative = $candidate.Substring($fullPrefix.Length)
        }
        else {
            $markerIndex = $candidate.LastIndexOf($distributionMarker, [StringComparison]::OrdinalIgnoreCase)
            if ($markerIndex -ge 0) {
                $relative = $candidate.Substring($markerIndex + $distributionMarker.Length)
            }
        }
        if ($relative) {
            [void]$headerSet.Add($relative.Replace("/", "\"))
        }
    }
}
foreach ($relative in $headerSet) {
    Copy-RelativeFile $fullRoot $toolchainRoot $relative
}

foreach ($relative in $sourceFiles) {
    Copy-RelativeFile $repoRoot $sourceRoot $relative
}
foreach ($relative in $portableHeaders) {
    Copy-RelativeFile $repoRoot $sourceRoot $relative
}

Ensure-Directory (Join-Path $sourceRoot "include\cw")
Copy-Item -Path (Join-Path $repoRoot "include\cw\*") -Destination (Join-Path $sourceRoot "include\cw") -Recurse -Force

Ensure-Directory (Join-Path $sourceRoot "locales")
Copy-Item -LiteralPath (Join-Path $repoRoot "locales\en-US.json") -Destination (Join-Path $sourceRoot "locales\en-US.json") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "locales\pt-BR.json") -Destination (Join-Path $sourceRoot "locales\pt-BR.json") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination (Join-Path $sourceRoot "LICENSE") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "NOTICE") -Destination (Join-Path $sourceRoot "NOTICE") -Force

$resourceRoot = Join-Path $sourceRoot "resources"
Ensure-Directory $resourceRoot
New-VersionRc (Join-Path $resourceRoot "engine-version.rc") "Cheat Wizard Engine" "cw-engine" "cw-engine.exe"
New-VersionRc (Join-Path $resourceRoot "gui-version.rc") "Cheat Wizard" "cw-gui" "cw-gui.exe"
New-VersionRc (Join-Path $resourceRoot "trainer-runtime-version.rc") "Cheat Wizard Trainer Runtime" "trainer-runtime-template" "trainer-runtime-template.exe"
New-VersionRc (Join-Path $resourceRoot "trainer-builder-version.rc") "Cheat Wizard Trainer Builder" "cw-trainer-builder" "cw-trainer-builder.exe"
Copy-Item -LiteralPath (Join-Path $resourceRoot "engine-version.rc") -Destination (Join-Path $sourceRoot "engine-version.rc") -Force

$digestFiles = @()
foreach ($relative in $sourceFiles) { $digestFiles += (Join-Path $repoRoot $relative) }
foreach ($relative in $portableHeaders) { $digestFiles += (Join-Path $repoRoot $relative) }
$digestFiles += Get-ChildItem -LiteralPath (Join-Path $repoRoot "include\cw") -Recurse -File | ForEach-Object FullName
$digestFiles += @(
    (Join-Path $repoRoot "locales\en-US.json"),
    (Join-Path $repoRoot "locales\pt-BR.json"),
    (Join-Path $repoRoot "LICENSE"),
    (Join-Path $repoRoot "NOTICE")
)
$sourceDigest = Get-SourceDigest $digestFiles

$sourceRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $sourceRevision) { $sourceRevision = "unknown" }
$dirty = & git -C $repoRoot status --porcelain -- src include/cw portable_win locales LICENSE NOTICE
if ($dirty) { $sourceRevision += "-dirty" }

$metadata = @(
    "schema=1",
    "productVersion=$productVersion",
    "engineVersion=$engineVersion",
    "protocolMajor=$protocolMajor",
    "protocolMinor=$protocolMinor",
    "architecture=x64",
    "sourceRevision=$sourceRevision",
    "sourceDigest=$sourceDigest",
    "toolchain=$toolchainId",
    "toolchainUpstreamSha256=$toolchainSha256"
) -join $nl
Set-Content -LiteralPath (Join-Path $payloadRoot "BUILD-METADATA.txt") -Value ($metadata + $nl) -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $fullRoot "LICENSE.TXT") -Destination (Join-Path $payloadRoot "TOOLCHAIN-LICENSE.txt") -Force
$headerSet | Sort-Object | Set-Content -LiteralPath (Join-Path $payloadRoot "TOOLCHAIN-FILES.txt") -Encoding UTF8

Ensure-Directory (Split-Path -Parent $outputPath)
if (Test-Path -LiteralPath $outputPath) {
    Remove-Item -LiteralPath $outputPath -Force
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory(
    $payloadRoot,
    $outputPath,
    [IO.Compression.CompressionLevel]::Optimal,
    $false
)

$payloadHash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant()
$payloadBytes = (Get-Item -LiteralPath $outputPath).Length
$toolchainBytes = (Get-ChildItem -LiteralPath $toolchainRoot -Recurse -File | Measure-Object Length -Sum).Sum

Write-Host "Product builder payload ready."
Write-Host "  Output: $outputPath"
Write-Host "  Payload bytes: $payloadBytes"
Write-Host "  Payload SHA-256: $payloadHash"
Write-Host "  Pruned toolchain bytes: $toolchainBytes"
Write-Host "  Toolchain headers copied: $($headerSet.Count)"
Write-Host "  Source digest: $sourceDigest"
Write-Host "  Source revision: $sourceRevision"
