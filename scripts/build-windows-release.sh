#!/usr/bin/env bash
# 在 Linux/macOS 上用 zig 交叉编译出「可直接拷到 Windows 运行」的 x64 二进制。
#
# 产物（dist/windows-x64/）:
#   wowmod_loader.exe   启动器：挂起创建客户端 -> 载入 wowmod_rt.dll -> 恢复运行
#   wowmod_rt.dll       运行时：在客户端内部做分析，并按模式安装 hook
#   wowmod.exe          CLI：analyze / xref / site / stub / stub-plan / arctium-plan ...
#   wowmod_hook.dll     旧版覆盖层（保留，供 VFS 路线使用）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
if command -v zig >/dev/null 2>&1; then ZIG=zig
else
  # ziglang 包在这个环境里会随快照丢失，缺了就自动装一次。
  # 之前每轮都要手动 pip install，忘了就会 BUILD=1 但报错很隐蔽。
  if ! python3 -c 'import ziglang' >/dev/null 2>&1; then
    echo "== 安装 ziglang（工具链缺失）==" >&2
    pip install -q --break-system-packages ziglang >&2 || { echo "ziglang 安装失败" >&2; exit 1; }
  fi
  ZIG="$(python3 -c 'import ziglang,os;print(os.path.join(os.path.dirname(ziglang.__file__),"zig"))')"
fi
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
DIST="$ROOT/dist/windows-x64"; mkdir -p "$DIST"
FLAGS=(-target x86_64-windows-gnu -std=c++17 -O2 -DNDEBUG -D_WIN32 -DUNICODE -D_UNICODE
       -DWOWMOD_WINDOWS -Iinclude -Isrc)
# 不链接静态 CRT（产物会从 1 MB 涨到 13 MB）。
# 动态 CRT 依赖 api-ms-win-crt-*.dll —— 在 Windows 10/11 上这些都是
# System32 里的 API set，通常存在。若目标进程加载失败（错误码 126），
# 启动器会自动退到「手工映射」，那条路不需要任何额外的 DLL。
LINK=(-target x86_64-windows-gnu -lkernel32 -luser32)

obj() { # obj <source> [extra-flags...]
  local src="$1"; shift
  local name; name="$(echo "$src" | tr '/' '_').obj"
  "$ZIG" c++ "${FLAGS[@]}" "$@" -c "$src" -o "$OUT/$name"
  echo "$OUT/$name"
}

echo "==> 编译核心"
CORE=()
for f in src/core/*.cpp; do CORE+=("$(obj "$f")"); done

echo "==> wowmod_rt.dll（运行时分析 + hook 安装）"
RT=()
for f in src/windows/rt_dll.cpp src/windows/rt_entry.cpp src/windows/detour.cpp src/windows/fd_hook.cpp src/windows/scan_images.cpp src/windows/probe_reader.cpp src/windows/crash_evidence.cpp; do
  RT+=("$(obj "$f")")
done
"$ZIG" c++ -target x86_64-windows-gnu -shared -Wl,--strip-all -o "$DIST/wowmod_rt.dll" \
  "${CORE[@]}" "${RT[@]}" "${LINK[@]}"

echo "==> wowmod_loader.exe（启动器）"
LM=("$(obj src/windows/launcher_main.cpp)" "$(obj src/windows/remote_load.cpp)" \
    "$(obj src/windows/inject_first.cpp)" "$(obj src/windows/agent_code.cpp)" \
    "$(obj src/windows/remote_analyze.cpp)" "$(obj src/windows/diagnose.cpp)" \
    "$(obj src/windows/detour.cpp)" "$(obj src/windows/fd_hook.cpp)" \
    "$(obj src/windows/scan_images.cpp)" "$(obj src/windows/arctium_sig.cpp)" \
    "$(obj src/windows/arctium_patch.cpp)" "$(obj src/windows/mod_loader.cpp)" \
    "$(obj src/core/arctium_clone.cpp)" "$(obj src/core/x64sim.cpp)" \
    "$(obj src/core/anticrash_plan.cpp)" \
    "$(obj src/windows/process_suspend.cpp)" "$(obj src/windows/anticrash.cpp)" \
    "$(obj src/windows/fs_scan.cpp)" "$(obj src/windows/probe_reader.cpp)" "$(obj src/windows/crash_evidence.cpp)" \
    )
"$ZIG" c++ -target x86_64-windows-gnu -Wl,--strip-all -o "$DIST/wowmod_loader.exe" \
  "${CORE[@]}" "${LM[@]}" "${LINK[@]}" -Wl,--subsystem,console

echo "==> wowmod.exe（正式应用，GUI，无控制台）"
APP=("$(obj src/app/main.cpp)" "$(obj src/windows/listfile_fetch.cpp)" \
     "$(obj src/windows/archive_extract.cpp)")
# 注意：不能用 ${LM[@]} —— 它包含 launcher_main.cpp，那个文件有 main()，
# 会和 GUI 的 main 冲突（duplicate symbol: main）。引擎侧只需要真正会写
# 内存 / 扫描映像的那些 TU。
ENGINE=("$(obj src/windows/remote_load.cpp)" "$(obj src/windows/inject_first.cpp)" \
        "$(obj src/windows/agent_code.cpp)" "$(obj src/windows/remote_analyze.cpp)" \
        "$(obj src/windows/diagnose.cpp)" "$(obj src/windows/detour.cpp)" \
        "$(obj src/windows/fd_hook.cpp)" "$(obj src/windows/scan_images.cpp)" \
        "$(obj src/windows/arctium_sig.cpp)" "$(obj src/windows/arctium_patch.cpp)" \
        "$(obj src/windows/mod_loader.cpp)" "$(obj src/core/arctium_clone.cpp)" \
        "$(obj src/core/x64sim.cpp)" "$(obj src/core/anticrash_plan.cpp)" \
        "$(obj src/windows/process_suspend.cpp)" "$(obj src/windows/anticrash.cpp)" \
        "$(obj src/windows/fs_scan.cpp)" "$(obj src/windows/probe_reader.cpp)" \
        "$(obj src/windows/crash_evidence.cpp)")
# 链接顺序：CORE 已经包含引擎（mod_loader 依赖的 core 部分），
# 这里再补 launcher 侧真正会写内存的那几个 TU。
# 清单必须编译进 exe（不是放个同名文件在旁边）：
#   DPI 感知 / Common Controls v6 / UTF-8 代码页 / 长路径
# 没有它，125% 缩放下整个界面是糊的，深目录直接打不开。
"$ZIG" rc /fo "$OUT/wowmod.res" src/app/wowmod.rc
"$ZIG" c++ -target x86_64-windows-gnu -Wl,--strip-all -o "$DIST/wowmod.exe" \
  "${CORE[@]}" "${ENGINE[@]}" "${APP[@]}" "$OUT/wowmod.res" "${LINK[@]}" \
  -Wl,--subsystem,windows -lwinhttp -lcomctl32 -lole32 -loleaut32 -lshlwapi -lshell32 -lgdi32 -lcomdlg32

# CLI 独立成 wowmod-cli.exe，不再占用 wowmod.exe —— 用户双击的那个
# 必须是应用，不能是一个"给你传参数的命令行工具"。
echo "==> wowmod-cli.exe（高级命令行工具，保留给排查用）"
CLI=("$(obj src/cli/main.cpp)")
LAUNCH=("$(obj src/windows/launch.cpp)")
INJECT=("$(obj src/windows/inject.cpp)")
"$ZIG" c++ -target x86_64-windows-gnu -Wl,--strip-all -o "$DIST/wowmod-cli.exe" \
  "${CORE[@]}" "${CLI[@]}" "${LAUNCH[@]}" "${INJECT[@]}" \
  "${LINK[@]}" -lshell32 -Wl,--subsystem,console

echo "==> wowmod_hook.dll（旧版覆盖层，可选）"
HOOK=()
for f in src/windows/runtime.cpp src/windows/overlay_dll.cpp src/windows/iat_hook.cpp \
         src/windows/fs_hooks.cpp src/windows/fileid_hook.cpp src/windows/mem_scan.cpp; do
  HOOK+=("$(obj "$f" -DWOWMOD_HOOK_DLL)")
done
"$ZIG" c++ -target x86_64-windows-gnu -shared -Wl,--strip-all -o "$DIST/wowmod_hook.dll" \
  "${CORE[@]}" "${HOOK[@]}" "${LINK[@]}" || echo "  （wowmod_hook.dll 编译失败，跳过；新流程不需要它）"

chmod +x "$0"
rm -f "$DIST"/*.pdb "$DIST"/*.lib

# 同步到仓库根目录。打包脚本只认根目录里的文件，
# 少了这一步 zip 里就会是上一次的旧二进制（曾经因此白跑两轮）。
echo "==> 同步到仓库根目录"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for f in wowmod.exe wowmod_loader.exe wowmod_rt.dll wowmod_hook.dll wowmod-cli.exe; do
  if [ -f "$DIST/$f" ]; then cp -f "$DIST/$f" "$ROOT/$f"; fi
done

# 自检：根目录的二进制必须真的含本轮新增的模式字符串，
# 否则打出来的 zip 是旧货——这个错误已经让用户白跑过两轮。
echo "==> 校验打包内容"
if ! grep -aq "sigscan" "$ROOT/wowmod_loader.exe"; then
  echo "  !! 错误: 根目录 wowmod_loader.exe 不含 sigscan，拒绝打包" >&2
  exit 1
fi
echo "  根目录 wowmod_loader.exe 含 sigscan 模式"

echo "==> 产物"
ls -l "$DIST"
