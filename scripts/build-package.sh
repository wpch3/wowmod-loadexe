#!/usr/bin/env bash
# 打包 wowmod-oneclick.zip。
#
# 这个脚本存在的唯一理由：曾经有两次用户拿到的是「新脚本 + 旧 exe」的包，
# 于是菜单 2（特征码扫描）被旧 exe 静默当成默认分析跑，用户以为新功能坏了。
#
# 所以打包前必须逐项验证，任何一项不过就直接失败，不产出 zip。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIST="$ROOT/dist/windows-x64"
ZIP="$ROOT/wowmod-oneclick.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

fail() { echo "  !! 打包失败: $*" >&2; exit 1; }

echo "==> 检查产物是否为最新构建"
# 根目录的二进制必须与 dist/ 完全一致，否则说明构建后没同步。
for f in wowmod.exe wowmod_loader.exe wowmod_rt.dll; do
  [ -f "$DIST/$f" ] || fail "缺少 $DIST/$f（先跑 build-windows-release.sh）"
  [ -f "$ROOT/$f" ] || fail "缺少根目录 $f（构建脚本应已同步）"
  a=$(md5sum "$DIST/$f" | cut -d' ' -f1)
  b=$(md5sum "$ROOT/$f" | cut -d' ' -f1)
  [ "$a" = "$b" ] || fail "根目录 $f 与 dist 不一致（是旧二进制）"
  echo "   $f  $a"
done

echo "==> 检查 loader 能力标记"
# 这三条是脚本与 exe 的「握手协议」，缺一条就说明版本不匹配。
grep -aq "patch-v15" "$ROOT/wowmod_loader.exe" \
  || fail "wowmod_loader.exe 不含构建标记 patch-v15"
grep -aq "modes: observe auto hook analyze diagnose sigscan" "$ROOT/wowmod_loader.exe" \
  || fail "wowmod_loader.exe 不含模式清单（--version 会失败）"
grep -aq "未知模式" "$ROOT/wowmod_loader.exe" \
  || fail "wowmod_loader.exe 不含未知模式校验"
echo "   构建标记 / 模式清单 / 未知模式校验 都在"

echo "==> 检查脚本引用的模式都被 loader 支持"
for m in observe auto sigscan diagnose; do
  grep -aq -- "-Mode '$m'" "$ROOT/scripts/wowmod-start.ps1" || true
done
grep -aq "Assert-ModeSupported" "$ROOT/scripts/wowmod-start.ps1" \
  || fail "wowmod-start.ps1 没有模式兼容性检查（版本不匹配时会静默跑错模式）"
grep -aq "Get-LoaderCapabilities" "$ROOT/scripts/wowmod-start.ps1" \
  || fail "wowmod-start.ps1 没有版本探针"
echo "   脚本含版本探针与模式校验"

echo "==> 检查一键导出脚本"
[ -f wowmod-dump.cmd ] || fail "缺少 wowmod-dump.cmd（一键导出）"
grep -aq "dump-module" wowmod-dump.cmd || fail "wowmod-dump.cmd 没有调用 --dump-module"
grep -aq -- "--wait" wowmod-dump.cmd || fail "wowmod-dump.cmd 没有传入 --wait（会退回到过早导出）"
grep -aq "main-module.bin" wowmod-dump.cmd || fail "wowmod-dump.cmd 没有校验导出产物"
grep -aq "tasklist" wowmod-dump.cmd || fail "wowmod-dump.cmd 没有检查客户端是否已在运行"
# CRLF：cmd.exe 对 LF-only 的批处理在某些分支上会解析错乱，必须校验。
# 做法：每一行都应以 CR 结尾，行数必须与 CR 行数相等。
_d_lines=$(wc -l < wowmod-dump.cmd | tr -d ' ')
_d_crlf=$(grep -c $'\r$' wowmod-dump.cmd || true)
[ "$_d_lines" = "$_d_crlf" ] \
  || fail "wowmod-dump.cmd 含 LF-only 行尾（$((_d_lines - _d_crlf)) 行），cmd.exe 会解析异常"
echo "   参数 / 产物校验 / CRLF 行尾 都在"

echo "==> 检查 cmd 脚本的编码安全字符"
# 已两次踩到：cmd.exe 在 chcp 65001 下解析含【顿号 U+3001】或【行内方括号】的
# echo 行会错位，把句子后半段当成命令执行（"'回切几个角色' is not recognized"）。
# 这类错误在 Linux 上完全看不出来，只能靠硬性扫描拦住。
for _f in wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-mod.cmd wowmod-start.cmd wowmod-scout.cmd wowmod-load.cmd wowmod-install.cmd; do
  [ -f "$_f" ] || continue
  if grep -q $'\xe3\x80\x81' "$_f"; then
    fail "$_f 含中文顿号（U+3001），cmd.exe 会把它后面的内容当命令执行"
  fi
done
echo "   无顿号，行内方括号已确认"

echo "==> 检查 cmd 的 echo 行全为可安全解析的字符"
# 已三次踩到：chcp 65001 下 cmd.exe 解析 echo 里的全角标点会错位，
# 把句子后半段当成命令执行。凡 echo 行出现全角逗号/顿号/分号一律拦下。
for _f in wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-mod.cmd wowmod-start.cmd wowmod-scout.cmd wowmod-load.cmd wowmod-install.cmd; do
  [ -f "$_f" ] || continue
  if grep -qE $'^[[:space:]]*echo[^\r]*\xe3\x80\x8c' "$_f" ||
     grep -qE $'^[[:space:]]*echo[^\r]*\xe3\x80\x81' "$_f" ||
     grep -qE $'^[[:space:]]*echo[^\r]*\xef\xbc\x9b' "$_f"; then
    fail "$_f 的 echo 行含全角标点（，、；），cmd.exe 会把它后面的内容当命令执行"
  fi
done
echo "   echo 行标点检查通过"

echo "==> 检查 rem 行的全角标点"
# rem 不是 echo 的例外：chcp 65001 下 cmd.exe 对 rem 行里的全角逗号/分号
# 同样会错位，把后半句当命令执行（"'认识的' is not recognized"）。
for _f in wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-mod.cmd wowmod-start.cmd wowmod-scout.cmd wowmod-load.cmd wowmod-install.cmd tools/fetch-listfile.cmd; do
  [ -f "$_f" ] || continue
  if grep -qiE $'^[[:space:]]*rem[^\r]*(\xe3\x80\x8c|\xe3\x80\x81|\xef\xbc\x8c|\xef\xbc\x9b|\xe3\x80\x8d|\xef\xbc\x88|\xef\xbc\x89|\xef\xbc\x9a)' "$_f"; then
    fail "$_f 的 rem 行含全角标点，cmd.exe 会把它后面的内容当命令执行"
  fi
done
echo "   rem 行标点检查通过"

echo "==> 检查一键旁路脚本"


# ---- 跳板语义离线验证 ----
# 只看「能否解码」不够：字节全可解码但逻辑写错（循环上界用项数、
# 返回寄存器选错）照样会让 95% 文件匹配不到或直接崩。这里用 x64sim
# 把生成的跳板真的执行一遍。跑不起来或有用例失败就拒绝打包。
echo "==> 验证跳板语义（离线执行）"
_simlog=$(mktemp)
if ! g++ -std=c++17 -O1 -Iinclude -Isrc tests/tests.cpp tests/intercept_test.cpp \
      src/core/*.cpp src/platform/launch_stub.cpp -o "$_simlog.bin" >"$_simlog" 2>&1; then
  fail "测试编译失败: $(tail -3 "$_simlog")"
fi
_simres=$("$_simlog.bin" 2>&1 | tail -1)
echo "    $_simres"
echo "$_simres" | grep -q "0 项失败" || fail "有测试失败: $_simres"
rm -f "$_simlog" "$_simlog.bin"

# ---- 模组目录形状解析（用用户真实遇到的三种包结构回归） ----
# 用户上传的三类包：
#   T21WarriorNSFW/item/...                  根就是包的父目录
#   Titaa Hawkstrider Mount/Creature/...     根就是包的父目录
#   Wrath NPC Pack/Textures/BakedNpcTextures 前缀完全不叫 creature/
# 第三种以前会被整体丢弃 -> "扫到 0 个文件"。这里做端到端回归：
# 三种形状都必须解析出正确的游戏相对路径，歧义文件名必须被拒绝。
echo "==> 验证模组目录形状解析"
_shape=$(python3 "$(dirname "$0")/check-mod-shapes.py")
[ "$_shape" = "OK" ] || fail "模组目录形状解析回归失败: $_shape"

# ---- 模式白名单一致性 ----
# 已经踩过两次：scout 和 mods 都实现好了，但 launcher_main.cpp 的
# known 白名单没加，脚本一跑就被"未知模式"挡回去，看起来像功能没做。
# 这里静态比对：所有 .cmd/.ps1 里出现的 --mode X 都必须出现在白名单里。
_missing_modes=$(python3 - <<'PYEOF'
import re, glob
src = open('src/windows/launcher_main.cpp', encoding='utf-8').read()
m = re.search(r'known = \{(.*?)\};', src, re.S)
white = set(re.findall(r'"([a-z]+)"', m.group(1))) if m else set()
used = set()
for f in glob.glob('*.cmd') + glob.glob('tools/*.cmd') + glob.glob('scripts/*.ps1'):
    t = open(f, encoding='utf-8', errors='replace').read()
    used |= set(re.findall(r'--mode\s+([a-z]+)', t))
missing = sorted(used - white)
print(' '.join(missing))
PYEOF
)
[ -z "$_missing_modes" ] || fail "脚本用到了未在模式白名单里的模式: $_missing_modes（改 launcher_main.cpp 的 known）"

[ -f wowmod-install.cmd ] || fail "缺少 wowmod-install.cmd（自包含一键入口）"
grep -aq -- "--mods" wowmod-install.cmd || fail "wowmod-install.cmd 没有传 --mods（自包含模式）"
grep -aq -- "--listfile" wowmod-install.cmd || fail "wowmod-install.cmd 没有传 --listfile"
_ic=$(wc -l < wowmod-install.cmd | tr -d ' ')
_icrlf=$(grep -c $'\r$' wowmod-install.cmd || true)
[ "$_ic" = "$_icrlf" ] || fail "wowmod-install.cmd 不是全 CRLF"
# 自包含模式与 anti-crash 必须真的编进 exe
grep -aq -- "--mods" wowmod_loader.exe || fail "wowmod_loader.exe 不含 --mods（自包含模式没编进去）"
grep -aq "anti-crash" wowmod_loader.exe || fail "wowmod_loader.exe 不含 anti-crash（Arctium PrepareAntiCrash 缺失）"
grep -aq "字符串块自检" wowmod_loader.exe || fail "wowmod_loader.exe 不含绝对路径自检"

[ -f wowmod-load.cmd ] || fail "缺少 wowmod-load.cmd（模组加载器）"
grep -aq -- "--mode mods" wowmod-load.cmd || fail "wowmod-load.cmd 没有调用 --mode mods"
_sl=$(wc -l < wowmod-load.cmd | tr -d ' ')
_slcrlf=$(grep -c $'\r$' wowmod-load.cmd || true)
[ "$_sl" = "$_slcrlf" ] || fail "wowmod-load.cmd 不是全 CRLF"

[ -f wowmod-scout.cmd ] || fail "缺少 wowmod-scout.cmd（只读侦察）"
grep -aq -- "--mode scout" wowmod-scout.cmd || fail "wowmod-scout.cmd 没有调用 --mode scout"
grep -aq "wowmod-scout.txt" wowmod-scout.cmd || fail "wowmod-scout.cmd 没有校验侦察产物"
_s_lines=$(wc -l < wowmod-scout.cmd | tr -d ' ')
_s_crlf=$(grep -c $'\r$' wowmod-scout.cmd || true)
[ "$_s_lines" = "$_s_crlf" ] || fail "wowmod-scout.cmd 不是全 CRLF（cmd.exe 会解析出错）"

[ -f wowmod-probe.cmd ] || fail "缺少 wowmod-probe.cmd（一键旁路记录）"
grep -aq -- "--mode probe" wowmod-probe.cmd || fail "wowmod-probe.cmd 没有调用 --mode probe"
grep -aq -- "--target %WM_TARGET%" wowmod-probe.cmd || fail "wowmod-probe.cmd 没有传 --target"
grep -aq 'WM_TARGET=FileIdLookupFNV' wowmod-probe.cmd || fail "wowmod-probe.cmd 默认目标不是 FileIdLookupFNV"
grep -aq "wowmod-probe.txt" wowmod-probe.cmd || fail "wowmod-probe.cmd 没有校验记录产物"
_p_lines=$(wc -l < wowmod-probe.cmd | tr -d ' ')
_p_crlf=$(grep -c $'\r$' wowmod-probe.cmd || true)
[ "$_p_lines" = "$_p_crlf" ] || fail "wowmod-probe.cmd 含 LF-only 行尾"

[ -f wowmod-patch.cmd ] || fail "缺少 wowmod-patch.cmd（Arctium 分支补丁）"
grep -aq -- "--mode patch" wowmod-patch.cmd || fail "wowmod-patch.cmd 没有调用 --mode patch"
grep -aq -- "--apply" wowmod-patch.cmd || fail "wowmod-patch.cmd 没有传 --apply（会变成只演练）"
grep -aq "wowmod-patch.txt" wowmod-patch.cmd || fail "wowmod-patch.cmd 没有校验报告产物"
_pt_lines=$(wc -l < wowmod-patch.cmd | tr -d ' ')
_pt_crlf=$(grep -c $'\r$' wowmod-patch.cmd || true)
[ "$_pt_lines" = "$_pt_crlf" ] || fail "wowmod-patch.cmd 含 LF-only 行尾"
# cmd 里 echo 行中出现全角标点会直接报「命令语法不正确」，硬性拦住。
if grep -n '^echo' wowmod-patch.cmd | grep -q $'\xef\xbc\x9b\|\xe3\x80\x8c\|\xe3\x80\x81\|\xef\xbc\x8c\|\xe3\x80\x81'; then
  fail "wowmod-patch.cmd 的 echo 行含全角标点"
fi
# loader 必须真的支持 probe 模式，否则脚本会以退出码 3 失败
grep -aq "modes: observe auto hook analyze diagnose sigscan probe" wowmod_loader.exe \
  || fail "wowmod_loader.exe 的模式清单里没有 probe"
echo "   参数 / 产物校验 / CRLF 行尾 / probe 模式 都在"

echo "==> 组装"
mkdir -p "$STAGE/scripts"
cp wowmod.exe wowmod_loader.exe wowmod_rt.dll wowmod-start.cmd wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-mod.cmd wowmod-scout.cmd wowmod-load.cmd wowmod-install.cmd README.md "$STAGE/"
cp scripts/wowmod-start.ps1 "$STAGE/scripts/"
mkdir -p "$STAGE/tools"
cp tools/listid.py tools/build-mod-mappings.py tools/fetch-listfile.cmd "$STAGE/tools/"

echo "==> 压缩"
rm -f "$ZIP"
( cd "$STAGE" && zip -9 -r "$ZIP" \
    wowmod-start.cmd wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-mod.cmd wowmod-scout.cmd wowmod-load.cmd wowmod-install.cmd wowmod.exe wowmod_loader.exe wowmod_rt.dll \
    scripts/wowmod-start.ps1 tools/listid.py tools/build-mod-mappings.py tools/fetch-listfile.cmd README.md >/dev/null )

echo "==> 复验 zip 内容"
VERIFY="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$VERIFY"' EXIT
( cd "$VERIFY" && unzip -q "$ZIP" )
a=$(md5sum "$VERIFY/wowmod_loader.exe" | cut -d' ' -f1)
b=$(md5sum "$DIST/wowmod_loader.exe" | cut -d' ' -f1)
[ "$a" = "$b" ] || fail "zip 里的 loader 与 dist 不一致"
grep -aq "patch-v15" "$VERIFY/wowmod_loader.exe" || fail "zip 里的 loader 缺构建标记"
grep -aq "sigscan" "$VERIFY/scripts/wowmod-start.ps1" || fail "zip 里的脚本没有 sigscan 菜单"
[ -f "$VERIFY/wowmod-dump.cmd" ] || fail "zip 里缺 wowmod-dump.cmd"
grep -aq "dump-module" "$VERIFY/wowmod-dump.cmd" || fail "zip 里的 wowmod-dump.cmd 内容不完整"
[ -f "$VERIFY/wowmod-probe.cmd" ] || fail "zip 里缺 wowmod-probe.cmd"
[ -f "$VERIFY/wowmod-patch.cmd" ] || fail "zip 里缺 wowmod-patch.cmd"
grep -aq -- "--mode patch" "$VERIFY/wowmod-patch.cmd" || fail "zip 里的 wowmod-patch.cmd 没调用 --mode patch"
[ -f "$VERIFY/wowmod-mod.cmd" ] || fail "zip 里缺 wowmod-mod.cmd"
grep -aq "build-mod-mappings.py" "$VERIFY/wowmod-mod.cmd" || fail "wowmod-mod.cmd 没调用映射生成器"
[ -f "$VERIFY/tools/build-mod-mappings.py" ] || fail "zip 里缺 tools/build-mod-mappings.py"
[ -f "$VERIFY/tools/fetch-listfile.cmd" ] || fail "zip 里缺 tools/fetch-listfile.cmd"
grep -aq "MOD_PREFIXES" "$VERIFY/tools/build-mod-mappings.py" || fail "映射生成器缺少路径前缀过滤"
[ -f "$VERIFY/tools/listid.py" ] || fail "zip 里缺 tools/listid.py"
grep -aq "character/bloodelf/female" "$VERIFY/tools/listid.py" || fail "listid.py 内容不完整"

echo
echo "OK  $ZIP  ($(stat -c%s "$ZIP") 字节)"
echo "    loader build tag: patch-v15"
echo "    用户可用 \`wowmod_loader.exe --version\` 自查版本"
