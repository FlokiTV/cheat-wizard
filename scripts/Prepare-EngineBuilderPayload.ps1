param(
    [Parameter(Mandatory = $true)]
    [string]$Output,
    [string]$CacheDir = (Join-Path $PSScriptRoot "..\build\engine-builder-cache")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputPath = [IO.Path]::GetFullPath($Output)
$cacheRoot = [IO.Path]::GetFullPath($CacheDir)

$toolchainVersion = "20260908"
$toolchainArchive = "llvm-mingw-$toolchainVersion-ucrt-x86_64.zip"
$toolchainUrl = "https://github.com/mstorsjo/llvm-mingw/releases/download/$toolchainVersion/$toolchainArchive"
$toolchainSha256 = "1bcf74d06b724aeecaa6412ca85f5b26fb1da770e7cdcefa9263c9c5c3ad34b6"
$toolchainId = "llvm-mingw-$toolchainVersion-ucrt-x86_64-minimal"
$engineVersion = "1.7.3"
$protocolMajor = 1
$protocolMinor = 0

$sourceNames = @(
    "Value", "AobPattern", "AobPersistence", "ScanPersistence",
    "RelativeAddress", "InstructionDecode", "PointerAlgorithms",
    "PointerPersistence", "PointerProfile", "PointerMap", "Win32Error",
    "EngineSession", "ProcessManager", "MemoryScanner", "AobScanner",
    "MemoryWriter", "FreezeManager", "PointerScanner",
    "EngineProtocol", "EnginePipe", "EngineMain"
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
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        ([Convert]::ToHexString($sha.ComputeHash($bytes))).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
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
Ensure-Directory $depRoot

$compiler = Join-Path $fullRoot "bin\x86_64-w64-mingw32-clang++.exe"
$commonCompileArgs = @(
    "-std=c++20", "-O2", "-DNDEBUG",
    "-DUNICODE", "-D_UNICODE", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX",
    "-I$repoRoot\include", "-fstack-protector-strong", "-fcf-protection=full"
)

Write-Host "Collecting exact engine header dependencies..."
foreach ($name in $sourceNames) {
    $source = Join-Path $repoRoot "src\$name.cpp"
    $object = Join-Path $depRoot "$name.o"
    $dep = Join-Path $depRoot "$name.d"
    Invoke-Checked $compiler ($commonCompileArgs + @("-MD", "-MF", $dep, "-c", $source, "-o", $object)) $repoRoot
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
    "x86_64-w64-mingw32\lib\libshell32.a",
    "x86_64-w64-mingw32\lib\libuser32.a",
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

Ensure-Directory (Join-Path $sourceRoot "src")
Ensure-Directory (Join-Path $sourceRoot "include\cw")
foreach ($name in $sourceNames) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "src\$name.cpp") -Destination (Join-Path $sourceRoot "src\$name.cpp") -Force
}
Copy-Item -Path (Join-Path $repoRoot "include\cw\*") -Destination (Join-Path $sourceRoot "include\cw") -Recurse -Force

$rc = @"
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
      VALUE "FileDescription", "Cheat Wizard Engine"
      VALUE "FileVersion", "1.7.3"
      VALUE "InternalName", "cw-engine"
      VALUE "OriginalFilename", "cw-engine.exe"
      VALUE "ProductName", "Cheat Wizard"
      VALUE "ProductVersion", "1.7.3"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"@
Set-Content -LiteralPath (Join-Path $sourceRoot "engine-version.rc") -Value $rc -Encoding ASCII

$sourceFiles = @()
foreach ($name in $sourceNames) { $sourceFiles += (Join-Path $repoRoot "src\$name.cpp") }
$sourceFiles += Get-ChildItem -LiteralPath (Join-Path $repoRoot "include\cw") -Recurse -File | ForEach-Object FullName
$sourceDigest = Get-SourceDigest $sourceFiles
$sourceRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $sourceRevision) { $sourceRevision = "unknown" }
$dirty = & git -C $repoRoot status --porcelain -- src include/cw
if ($dirty) { $sourceRevision += "-dirty" }

$metadata = @(
    "schema=1",
    "engineVersion=$engineVersion",
    "protocolMajor=$protocolMajor",
    "protocolMinor=$protocolMinor",
    "architecture=x64",
    "sourceRevision=$sourceRevision",
    "sourceDigest=$sourceDigest",
    "toolchain=$toolchainId",
    "toolchainUpstreamSha256=$toolchainSha256"
) -join "`n"
Set-Content -LiteralPath (Join-Path $payloadRoot "BUILD-METADATA.txt") -Value ($metadata + "`n") -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $fullRoot "LICENSE.TXT") -Destination (Join-Path $payloadRoot "TOOLCHAIN-LICENSE.txt") -Force
$headerSet | Sort-Object | Set-Content -LiteralPath (Join-Path $payloadRoot "TOOLCHAIN-FILES.txt") -Encoding UTF8

Write-Host "Validating pruned toolchain with a clean source -> object -> link build..."
$proofRoot = Join-Path $workRoot "proof"
$objRoot = Join-Path $proofRoot "obj"
Ensure-Directory $objRoot
$minimalCompiler = Join-Path $toolchainRoot "bin\x86_64-w64-mingw32-clang++.exe"
$objects = @()
foreach ($name in $sourceNames) {
    $source = Join-Path $sourceRoot "src\$name.cpp"
    $object = Join-Path $objRoot "$name.o"
    Invoke-Checked $minimalCompiler @(
        "-std=c++20", "-O2", "-DNDEBUG",
        "-DUNICODE", "-D_UNICODE", "-DWIN32_LEAN_AND_MEAN", "-DNOMINMAX",
        "-I$sourceRoot\include", "-fstack-protector-strong", "-fcf-protection=full",
        "-c", $source, "-o", $object
    ) $proofRoot
    $objects += $object
}

$windres = Join-Path $toolchainRoot "bin\llvm-windres.exe"
$resourceObject = Join-Path $objRoot "engine-version.o"
Invoke-Checked $windres @("-i", (Join-Path $sourceRoot "engine-version.rc"), "-o", $resourceObject, "-O", "coff") $proofRoot
$objects += $resourceObject

$proofEngine = Join-Path $proofRoot "cw-engine.exe"
Invoke-Checked $minimalCompiler (@(
    "-municode", "-static", "-Wl,--dynamicbase,--high-entropy-va,--nxcompat"
) + $objects + @("-ladvapi32", "-o", $proofEngine)) $proofRoot

$versionOutput = & $proofEngine --version
if ($LASTEXITCODE -ne 0 -or ($versionOutput -join "`n") -notmatch "protocol 1\.0") {
    throw "Pruned toolchain produced an invalid engine: $versionOutput"
}

Ensure-Directory (Split-Path -Parent $outputPath)
if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Force }
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

Write-Host "Engine builder payload ready."
Write-Host "  Output: $outputPath"
Write-Host "  Payload bytes: $payloadBytes"
Write-Host "  Payload SHA-256: $payloadHash"
Write-Host "  Pruned toolchain bytes: $toolchainBytes"
Write-Host "  Toolchain headers copied: $($headerSet.Count)"
Write-Host "  Source digest: $sourceDigest"
