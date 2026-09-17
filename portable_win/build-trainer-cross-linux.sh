#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bin"
TMP="${TMPDIR:-/tmp}/cw-trainer-nocrt-build"
CLANG_CL="${CLANG_CL:-/usr/local/swift/usr/bin/clang-cl}"
LLD_LINK="${LLD_LINK:-/usr/local/swift/usr/bin/lld-link}"
mkdir -p "$OUT" "$TMP/gen"
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/kernel32.def" /out:"$TMP/kernel32_stub.dll" /implib:"$TMP/kernel32.lib" /machine:x64
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/user32.def" /out:"$TMP/user32_stub.dll" /implib:"$TMP/user32.lib" /machine:x64
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/gdi32.def" /out:"$TMP/gdi32_stub.dll" /implib:"$TMP/gdi32.lib" /machine:x64
"$CLANG_CL" --target=x86_64-pc-windows-msvc /c /O2 /GS- /GR- /EHs-c- /W4 /Fo"$TMP/trainer-runtime.obj" "$ROOT/portable_win/TrainerRuntime_NoCRT.cpp"
"$LLD_LINK" /entry:trainerCRTStartup /subsystem:windows /nodefaultlib /machine:x64 /opt:ref /opt:icf /out:"$TMP/trainer-runtime.exe" "$TMP/trainer-runtime.obj" "$TMP/kernel32.lib" "$TMP/user32.lib" "$TMP/gdi32.lib"
cmake -DINPUT="$TMP/trainer-runtime.exe" -DOUTPUT="$TMP/gen/TrainerRuntimeBlob.hpp" -P "$ROOT/cmake/EmbedBinary.cmake"
"$CLANG_CL" --target=x86_64-pc-windows-msvc /c /O2 /Ob0 /GS- /GR- /EHs-c- /W4 /I"$TMP/gen" /Fo"$TMP/trainer-builder.obj" "$ROOT/portable_win/TrainerBuilder_NoCRT.cpp"
"$LLD_LINK" /entry:builderCRTStartup /subsystem:console /nodefaultlib /machine:x64 /opt:ref /opt:icf /out:"$OUT/cw-trainer-builder.exe" "$TMP/trainer-builder.obj" "$TMP/kernel32.lib"
file "$OUT/cw-trainer-builder.exe"
