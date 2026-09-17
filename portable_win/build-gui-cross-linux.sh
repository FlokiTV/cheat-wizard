#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/bin"
TMP="${TMPDIR:-/tmp}/cw-gui-nocrt-build"
CLANG_CL="${CLANG_CL:-/usr/local/swift/usr/bin/clang-cl}"
LLD_LINK="${LLD_LINK:-/usr/local/swift/usr/bin/lld-link}"
mkdir -p "$OUT" "$TMP"
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/kernel32.def" /out:"$TMP/kernel32_stub.dll" /implib:"$TMP/kernel32.lib" /machine:x64
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/user32.def" /out:"$TMP/user32_stub.dll" /implib:"$TMP/user32.lib" /machine:x64
"$LLD_LINK" /dll /noentry /def:"$ROOT/portable_win/gdi32.def" /out:"$TMP/gdi32_stub.dll" /implib:"$TMP/gdi32.lib" /machine:x64
"$CLANG_CL" --target=x86_64-pc-windows-msvc /c /O2 /GS- /GR- /EHs-c- /W4 /Fo"$TMP/cw-gui.obj" "$ROOT/portable_win/CW_GUI_NoCRT.cpp"
"$LLD_LINK" /entry:guiCRTStartup /subsystem:windows /nodefaultlib /machine:x64 /opt:ref /opt:icf /out:"$OUT/cw-gui.exe" "$TMP/cw-gui.obj" "$TMP/kernel32.lib" "$TMP/user32.lib" "$TMP/gdi32.lib"

"$ROOT/portable_win/audit-gui-imports.sh" "$OUT/cw-gui.exe"
