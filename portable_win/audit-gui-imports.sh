#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXE="${1:-$ROOT/bin/cw-gui.exe}"
OBJDUMP="${OBJDUMP:-/usr/local/swift/usr/bin/llvm-objdump}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
"$OBJDUMP" -p "$EXE" > "$TMP"
python3 - "$TMP" <<'PY'
import re,sys
text=open(sys.argv[1],encoding='utf-8',errors='replace').read().splitlines()
cur=None; imports={}
for line in text:
    m=re.search(r'DLL Name:\s*(\S+)',line)
    if m:
        cur=m.group(1).lower(); imports.setdefault(cur,set()); continue
    if cur:
        m=re.match(r'\s*\d+\s+([A-Za-z_][A-Za-z0-9_@?$]*)\s*$',line)
        if m: imports[cur].add(m.group(1))
expected={
 'user32.dll': {'DrawTextA','FillRect','CreateWindowExA','RegisterClassExA'},
 'gdi32.dll': {'CreateSolidBrush','CreateFontA','BitBlt','RoundRect'},
 'kernel32.dll': {'OpenProcess','ReadProcessMemory','WriteProcessMemory','VirtualQueryEx'},
}
errors=[]
for dll,syms in expected.items():
    missing=syms-imports.get(dll,set())
    if missing: errors.append(f'{dll}: missing {sorted(missing)}')
wrong={'DrawTextA':'gdi32.dll','FillRect':'gdi32.dll','FrameRect':'gdi32.dll'}
for sym,dll in wrong.items():
    if sym in imports.get(dll,set()): errors.append(f'{sym} incorrectly imported from {dll}')
if errors:
    print('GUI import audit FAILED')
    for e in errors: print(' -',e)
    sys.exit(1)
print('GUI import audit PASS')
for dll in ['kernel32.dll','user32.dll','gdi32.dll']:
    print(f' {dll}: {len(imports.get(dll,set()))} imports')
PY
