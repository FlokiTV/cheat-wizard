param(
  [Parameter(Mandatory=$true)][string]$Builder,
  [Parameter(Mandatory=$true)][string]$WorkDir
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
function Add-U16([System.Collections.Generic.List[byte]]$b,[UInt16]$v){ $b.Add([byte]($v -band 0xFF)); $b.Add([byte](($v -shr 8) -band 0xFF)) }
function Add-U32([System.Collections.Generic.List[byte]]$b,[UInt32]$v){ 0..3 | ForEach-Object { $b.Add([byte](($v -shr (8*$_)) -band 0xFF)) } }
function Add-U64([System.Collections.Generic.List[byte]]$b,[UInt64]$v){ 0..7 | ForEach-Object { $b.Add([byte](($v -shr (8*$_)) -band 0xFF)) } }
function Add-Ascii([System.Collections.Generic.List[byte]]$b,[string]$s){ [Text.Encoding]::ASCII.GetBytes($s) | ForEach-Object { $b.Add($_) } }
function Assert-Built([string]$manifest,[string]$output){
  & $Builder build $manifest -o $output
  if ($LASTEXITCODE -ne 0) { throw "trainer-builder exited $LASTEXITCODE for $manifest" }
  if (!(Test-Path $output)) { throw "builder did not create $output" }
  $bytes=[IO.File]::ReadAllBytes($output)
  if ($bytes.Length -lt 20000) { throw "generated trainer unexpectedly small: $($bytes.Length)" }
  $footerMagic=[Text.Encoding]::ASCII.GetString($bytes,$bytes.Length-40,8)
  if ($footerMagic -ne 'CWTRFTR1') { throw "generated trainer footer magic is $footerMagic, expected CWTRFTR1" }
  return $bytes.Length
}

$cw = [System.Collections.Generic.List[byte]]::new()
Add-Ascii $cw 'CWPROF01'; Add-U32 $cw 1; Add-U32 $cw 8; Add-U32 $cw 4
$proc='CwNeverRunning.exe'; Add-U16 $cw ([UInt16]$proc.Length); Add-U64 $cw 1; Add-Ascii $cw $proc
$mod='example.dll'; Add-U16 $cw ([UInt16]$mod.Length); Add-Ascii $cw $mod; Add-U64 $cw 0x1234; Add-U32 $cw 2; Add-U64 $cw 0x20; Add-U64 $cw 0x68
[IO.File]::WriteAllBytes((Join-Path $WorkDir 'value.cwptr'),$cw.ToArray())

$legacyBytes=$cw.ToArray()
[Text.Encoding]::ASCII.GetBytes('MCEPROF1').CopyTo($legacyBytes,0)
[IO.File]::WriteAllBytes((Join-Path $WorkDir 'value.mcptr'),$legacyBytes)

@"
{
  "format":"cheat-wizard-trainer",
  "version":1,
  "trainer":{"name":"Builder Smoke Trainer","process":"$proc"},
  "window":{"width":560,"height":420,"theme":"zinc"},
  "entries":[{"id":"value","label":"Value","profile":"value.cwptr","defaultValue":"100","showCurrent":true,"allowWrite":true,"allowFreeze":true}],
  "layout":[
    {"type":"title","text":"Gameplay"},
    {"type":"subtitle","text":"Primary value"},
    {"type":"field","entry":"value"}
  ]
}
"@ | Set-Content -Encoding ASCII (Join-Path $WorkDir 'trainer.cwtrainer')
$cwLen=Assert-Built (Join-Path $WorkDir 'trainer.cwtrainer') (Join-Path $WorkDir 'BuilderSmokeTrainer.exe')

@"
{
  "format":"minice-trainer",
  "version":1,
  "trainer":{"name":"Builder Legacy Smoke","process":"$proc"},
  "entries":[{"id":"value","label":"Value","profile":"value.mcptr","defaultValue":"100","showCurrent":true,"allowWrite":true,"allowFreeze":true}]
}
"@ | Set-Content -Encoding ASCII (Join-Path $WorkDir 'legacy.json')
$legacyLen=Assert-Built (Join-Path $WorkDir 'legacy.json') (Join-Path $WorkDir 'BuilderSmokeLegacy.exe')
Write-Host "Trainer builder smoke PASS (cw=$cwLen bytes, legacy=$legacyLen bytes)"
