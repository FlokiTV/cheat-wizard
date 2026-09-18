param(
  [Parameter(Mandatory = $true)][string[]]$Path,
  [switch]$SkipSignatureUpdate
)

$ErrorActionPreference = 'Stop'

function Resolve-MpCmdRun {
  $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
  if (Test-Path -LiteralPath $platformRoot -PathType Container) {
    $candidate = Get-ChildItem -LiteralPath $platformRoot -Directory |
      Sort-Object Name -Descending |
      ForEach-Object { Join-Path $_.FullName 'MpCmdRun.exe' } |
      Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
      Select-Object -First 1

    if ($candidate) {
      return $candidate
    }
  }

  $fallback = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
  if (Test-Path -LiteralPath $fallback -PathType Leaf) {
    return $fallback
  }

  throw 'Microsoft Defender MpCmdRun.exe was not found. Refusing to pass the release security gate.'
}

$resolvedPaths = foreach ($item in $Path) {
  $resolved = Resolve-Path -LiteralPath $item -ErrorAction Stop
  $resolved.Path
}

$mpCmdRun = Resolve-MpCmdRun
Write-Host "Microsoft Defender CLI: $mpCmdRun"

if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  $status = Get-MpComputerStatus
  Write-Host "Defender engine: $($status.AMEngineVersion)"
  Write-Host "Defender platform: $($status.AMProductVersion)"
  Write-Host "Defender signatures: $($status.AntivirusSignatureVersion)"
  Write-Host "Defender antivirus enabled: $($status.AntivirusEnabled)"
}

if (-not $SkipSignatureUpdate) {
  $signatureUpdated = $false
  $lastSignatureExitCode = $null

  for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Host "Updating Microsoft Defender security intelligence (attempt $attempt/3)..."
    & $mpCmdRun -SignatureUpdate
    $lastSignatureExitCode = $LASTEXITCODE

    if ($lastSignatureExitCode -eq 0) {
      $signatureUpdated = $true
      break
    }

    if ($attempt -lt 3) {
      Write-Warning "Microsoft Defender signature update returned exit code $lastSignatureExitCode. Retrying after a transient failure."
      Start-Sleep -Seconds 10
    }
  }

  if (-not $signatureUpdated) {
    throw "Microsoft Defender signature update failed after 3 attempts; last exit code: $lastSignatureExitCode."
  }
}

foreach ($scanPath in $resolvedPaths) {
  Write-Host "Scanning with Microsoft Defender (no remediation): $scanPath"
  & $mpCmdRun -Scan -ScanType 3 -File $scanPath -DisableRemediation
  $scanExitCode = $LASTEXITCODE

  if ($scanExitCode -ne 0) {
    throw "Microsoft Defender rejected or could not scan '$scanPath' (exit code $scanExitCode). Release publication is blocked."
  }
}

Write-Host 'Microsoft Defender release gate: PASS'
