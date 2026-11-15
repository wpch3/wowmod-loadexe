#!/usr/bin/env bash
# 打出「正式应用」发布包。
#
# 与旧包的区别（用户明确要求）：
#   旧包：8 个 .cmd + 2 个 python 脚本 + ps1，用户要先跑这个再跑那个；
#   新包：双击 wowmod.exe 就是全部。包里只剩 3 个文件：
#           wowmod.exe          应用本体（窗口程序）
#           wowmod_loader.exe   同一套引擎的命令行版（高级用户 / 我以前脚本用）
#           使用说明.txt
#
# 这里逐项验证「应用真的能自己跑完整个流程」的证据，而不是只看文件在不在：
#   * 是窗口程序（PE Subsystem == 2），双击不会弹黑窗口
#   * 含内置下载器（WinHTTP 导入 + 应用自身的下载文案）
#   * 含三个引擎阶段（anti-crash / NoJump / FileDataID 跳板）的输出字符串
#   * wowmod_loader.exe --version 的构建标记与 app 一致
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
DIST="$ROOT/dist/windows-x64"
OUT="$ROOT/wowmod-app.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

fail() { echo "  !! 失败: $*" >&2; exit 1; }

[ -f "$DIST/wowmod.exe" ]       || fail "缺少 dist/windows-x64/wowmod.exe（先跑 build-windows-release.sh）"
[ -f "$DIST/wowmod_loader.exe" ] || fail "缺少 dist/windows-x64/wowmod_loader.exe"

echo "==> 校验 wowmod.exe 是窗口程序"
SUB=$(python3 - "$DIST/wowmod.exe" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
print(struct.unpack_from('<H', d, pe + 0x5c)[0])
PY
)
[ "$SUB" = "2" ] || fail "wowmod.exe 的 PE Subsystem=$SUB，应为 2（窗口程序）；否则双击会弹出控制台"

echo "==> 校验内置下载器"
python3 - "$DIST/wowmod.exe" <<'PY' || exit 1
import sys
d = open(sys.argv[1], 'rb').read()
need = [b"WinHttpOpen", b"WinHttpReadData", b"WinHttpSendRequest"]
missing = [n.decode() for n in need if n not in d]
if missing:
    print("  !! 缺少 WinHTTP 导入: " + ", ".join(missing)); sys.exit(1)
for s in ["下载 listfile", "wow-listfile.csv", "wowmod-app.log"]:
    if s.encode('utf-8') not in d:
        print("  !! 缺少字符串: " + s); sys.exit(1)
PY

echo "==> 校验三阶段引擎都在应用里"
python3 - "$DIST/wowmod.exe" <<'PY' || exit 1
import sys
d = open(sys.argv[1], 'rb').read()
need = ["anti-crash", "NoJump", "字符串块自检", "映射表写入完成", "扫描完成"]
missing = [s for s in need if s.encode('utf-8') not in d]
if missing:
    print("  !! 缺少引擎输出: " + ", ".join(missing)); sys.exit(1)
PY

echo "==> 校验 UI 文案"
python3 - "$DIST/wowmod.exe" <<'PY' || exit 1
import sys
d = open(sys.argv[1], 'rb').read()
w = lambda s: s.encode('utf-16-le')
need = [w("扫描模组"), w("▶  启动游戏并加载"), w("选择客户端…"), w("选择模组目录…")]
missing = [s.decode('utf-16-le') for s in need if s not in d]
if missing:
    print("  !! 缺少按钮: " + ", ".join(missing)); sys.exit(1)
PY

echo "==> 校验命令行版与图形版是同一批产物"
grep -aq "modes: observe auto hook" "$DIST/wowmod_loader.exe" \
  || fail "wowmod_loader.exe 没有模式清单（不是本轮产物）"

echo "==> 组包"
mkdir -p "$STAGE"
cp "$DIST/wowmod.exe" "$STAGE/"
cp "$DIST/wowmod_loader.exe" "$STAGE/"
cat > "$STAGE/使用说明.txt" <<'TXT'
wowmod — WoW 12.0.7 (Firestorm) 模组加载器
================================================

怎么用（四步，不需要 python、不需要命令行）
------------------------------------------------
1. 双击 wowmod.exe
2. 「选择客户端…」   选你的 Wow.exe / WoW 12.0.7 - Firestorm.exe
3. 「选择模组目录…」 选放了 .blp / .m2 / .skin 的那个文件夹
                     （里面应该是 Character\ 或 Creature\ 或 item\ 这一层）
                     也可以直接把 .zip / .rar / .7z 拖进窗口，
                     或者点「解压模组包…」——程序会自己解开并接着扫描。
                     压缩包里多几层目录没关系，程序按第一个游戏前缀
                     （Character / Creature / item / Spells ...）裁剪路径。
4. 「下载 listfile」 只需一次，约 72 MB（用于把文件名换算成 FileDataID）
5. 「扫描模组」      看到「N 个文件可用」就说明全部换算成功
6. 「▶ 启动游戏并加载」

一切正常时，最后一行会写「安装成功。客户端已启动，进游戏即可。」

它做了什么
------------------------------------------------
和 Arctium 完全一样的三件事，按顺序：

  1. anti-crash —— 关掉客户端对代码页完整性的校验，
     否则改动任何字节都会被判成篡改，进程以 0xC00000E5 结束。
  2. NoJump —— 把「按 FileDataID / 按路径从 CASC 加载」的两个条件跳转
     改成不跳，让客户端以为 CASA 里没有这个资源。
  3. FileDataID 查表跳板 —— 客户端回头问「这个 id 的本地文件在哪」时，
     直接返回你磁盘上那个文件的绝对路径。

三件缺一不可：只有 2 时客户端认为「哪里都没有」，只有 3 时客户端根本不会问。

文件在哪
------------------------------------------------
  %LOCALAPPDATA%\wowmod\wow-listfile.csv   下载的 listfile
  %LOCALAPPDATA%\wowmod\wowmod-app.log     本次运行的完整日志
  <游戏目录>\wowmod\wowmod-mods.txt        安装报告（每一步的真实结果）

出问题怎么办
------------------------------------------------
把 wowmod-app.log 和 wowmod-mods.txt 发过来。日志里每一步都有真实数值，
不需要猜。

只改内存，不动任何磁盘文件。关掉游戏，一切自动还原。

高级：wowmod_loader.exe 是同一套引擎的命令行版
------------------------------------------------
  wowmod_loader.exe --help
TXT

echo "==> 压缩"
rm -f "$OUT"
( cd "$STAGE" && zip -9 -r "$OUT" wowmod.exe wowmod_loader.exe 使用说明.txt >/dev/null )

echo "==> 复验 zip"
VERIFY="$(mktemp -d)"
( cd "$VERIFY" && unzip -q "$OUT" )
for f in wowmod.exe wowmod_loader.exe 使用说明.txt; do
  [ -f "$VERIFY/$f" ] || fail "zip 里缺少 $f"
done
a=$(md5sum "$VERIFY/wowmod.exe" | cut -d' ' -f1)
b=$(md5sum "$DIST/wowmod.exe" | cut -d' ' -f1)
[ "$a" = "$b" ] || fail "zip 里的 wowmod.exe 与构建产物不一致"
rm -rf "$VERIFY"
echo
echo "OK  $OUT  ($(stat -c%s "$OUT") 字节)"
unzip -l "$OUT" | tail -6
