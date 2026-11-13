#!/usr/bin/env bash
# 在 Linux/macOS 上用 zig 交叉编译出「可直接拷到 Windows 运行」的 x64 二进制。
# 产物: dist/windows-x64/wowmod.exe + wowmod_hook.dll (+ 同名 zip)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
if command -v zig >/dev/null 2>&1; then ZIG=zig
else ZIG="$(python3 -c 'import ziglang,os;print(os.path.join(os.path.dirname(ziglang.__file__),"zig"))')"; fi
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
DIST="$ROOT/dist/windows-x64"; mkdir -p "$DIST"
FLAGS=(-target x86_64-windows-gnu -std=c++17 -O2 -D_WIN32 -DUNICODE -D_UNICODE
       -DWOWMOD_WINDOWS -DWOWMOD_HOOK_DLL -Iinclude -Isrc)
echo "==> 编译"
for f in src/core/*.cpp src/windows/*.cpp src/cli/main.cpp; do
  "$ZIG" c++ "${FLAGS[@]}" -c "$f" -o "$OUT/$(echo "$f" | tr '/' '_').obj"
done
CORE=("$OUT"/src_core_*.obj)
DLL_SRC=("$OUT"/src_windows_runtime.cpp.obj "$OUT"/src_windows_overlay_dll.cpp.obj
         "$OUT"/src_windows_iat_hook.cpp.obj "$OUT"/src_windows_fs_hooks.cpp.obj
         "$OUT"/src_windows_fileid_hook.cpp.obj "$OUT"/src_windows_mem_scan.cpp.obj)
echo "==> 链接"
"$ZIG" c++ -target x86_64-windows-gnu -shared -Wl,--strip-all -o "$DIST/wowmod_hook.dll" \
  "${CORE[@]}" "${DLL_SRC[@]}" -lkernel32 -luser32
"$ZIG" c++ -target x86_64-windows-gnu -Wl,--strip-all -o "$DIST/wowmod.exe" \
  "${CORE[@]}" "$OUT/src_cli_main.cpp.obj" "$OUT/src_windows_launch.cpp.obj" \
  "$OUT/src_windows_inject.cpp.obj" -lkernel32 -luser32 -lshell32 -Wl,--subsystem,console
chmod +x "$0"
rm -f "$DIST"/*.pdb "$DIST"/*.lib
(cd "$DIST" && zip -q -r ../wowmod-windows-x64.zip wowmod.exe wowmod_hook.dll)
echo "==> 产物"
ls -l "$DIST" ../wowmod-windows-x64.zip 2>/dev/null || ls -l "$DIST" "$ROOT/dist/wowmod-windows-x64.zip"
