#!/usr/bin/env bash
# 在 Linux/macOS 上用 zig 交叉编译器验证 Windows 代码确实能编译并链接成 PE。
# 用法: python3 -m pip install ziglang && ./scripts/verify-windows.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v zig >/dev/null 2>&1; then
  ZIG=zig
else
  ZIG="$(python3 -c 'import ziglang,os;print(os.path.join(os.path.dirname(ziglang.__file__),"zig"))' 2>/dev/null || true)"
fi
if [ -z "${ZIG:-}" ] || [ ! -x "$ZIG" ]; then
  echo "找不到 zig。请先运行: python3 -m pip install ziglang" >&2
  exit 1
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
FLAGS=(-target x86_64-windows-gnu -std=c++17 -D_WIN32 -DUNICODE -D_UNICODE
       -DWOWMOD_WINDOWS -DWOWMOD_HOOK_DLL -Iinclude -Isrc -Wall -Wextra)

echo "==> 编译 (1/3): 可移植核心 + Windows 源 + CLI"
OBJS=()
for f in src/core/*.cpp src/windows/*.cpp src/cli/main.cpp; do
  obj="$OUT/$(echo "$f" | tr '/' '_').obj"
  "$ZIG" c++ "${FLAGS[@]}" -c "$f" -o "$obj"
  OBJS+=("$obj")
done
CORE=("$OUT"/src_core_*.obj)
DLL_SRC=("$OUT"/src_windows_runtime.cpp.obj "$OUT"/src_windows_overlay_dll.cpp.obj
         "$OUT"/src_windows_iat_hook.cpp.obj "$OUT"/src_windows_fs_hooks.cpp.obj
         "$OUT"/src_windows_fileid_hook.cpp.obj "$OUT"/src_windows_mem_scan.cpp.obj)

echo "==> 链接 (2/3): wowmod_hook.dll / wowmod.exe"
"$ZIG" c++ -target x86_64-windows-gnu -shared -o "$OUT/wowmod_hook.dll" \
  "${CORE[@]}" "${DLL_SRC[@]}" -lkernel32 -luser32
"$ZIG" c++ -target x86_64-windows-gnu -o "$OUT/wowmod.exe" \
  "${CORE[@]}" "$OUT/src_cli_main.cpp.obj" "$OUT/src_windows_launch.cpp.obj" "$OUT/src_windows_inject.cpp.obj" \
  -lkernel32 -luser32 -lshell32 -Wl,--subsystem,console

echo "==> 校验 (3/3): PE 头与导出符号"
python3 - "$OUT/wowmod.exe" "$OUT/wowmod_hook.dll" <<'PY'
import struct, sys
for p in sys.argv[1:]:
    d = open(p, 'rb').read(0x1000)
    assert d[:2] == b'MZ', p + ': 缺少 MZ'
    off = struct.unpack_from('<I', d, 0x3C)[0]
    assert d[off:off+4] == b'PE\0\0', p + ': 缺少 PE'
    machine = struct.unpack_from('<H', d, off + 4)[0]
    assert machine == 0x8664, p + ': 不是 x64'
    print('  OK', p.split('/')[-1], 'machine=0x%x' % machine)
dll = open(sys.argv[2], 'rb').read()
for sym in [b'wowmod_version', b'wowmod_overlay_count', b'wowmod_client_build', b'wowmod_hook_mode', b'wowmod_hook_proc']:
    assert sym in dll, 'DLL 缺少导出: ' + sym.decode()
    print('  OK export', sym.decode())
PY
echo "Windows 交叉编译验证通过 ✅"
