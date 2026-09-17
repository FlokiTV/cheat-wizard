#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bin"
TMP="${TMPDIR:-/tmp}/cw-nocrt-build"
CLANG_CL="${CLANG_CL:-/usr/local/swift/usr/bin/clang-cl}"
LLD_LINK="${LLD_LINK:-/usr/local/swift/usr/bin/lld-link}"
mkdir -p "$OUT" "$TMP"
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/kernel32.def" /out:"$TMP/kernel32_stub.dll" /implib:"$TMP/kernel32.lib" /machine:x64
"$CLANG_CL" --target=x86_64-pc-windows-msvc /c /O2 /GS- /GR- /EHs-c- /W4 /Fo"$TMP/cw.obj" "$ROOT/portable_win/CW_NoCRT.cpp"
"$LLD_LINK" /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:x64 /opt:ref /opt:icf /out:"$OUT/cw.exe" "$TMP/cw.obj" "$TMP/kernel32.lib"
