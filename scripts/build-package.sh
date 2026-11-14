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
grep -aq "patch-v12" "$ROOT/wowmod_loader.exe" \
  || fail "wowmod_loader.exe 不含构建标记 patch-v12"
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
for _f in wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-start.cmd; do
  [ -f "$_f" ] || continue
  if grep -q $'\xe3\x80\x81' "$_f"; then
    fail "$_f 含中文顿号（U+3001），cmd.exe 会把它后面的内容当命令执行"
  fi
done
echo "   无顿号，行内方括号已确认"

echo "==> 检查 cmd 的 echo 行全为可安全解析的字符"
# 已三次踩到：chcp 65001 下 cmd.exe 解析 echo 里的全角标点会错位，
# 把句子后半段当成命令执行。凡 echo 行出现全角逗号/顿号/分号一律拦下。
for _f in wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod-start.cmd; do
  [ -f "$_f" ] || continue
  if grep -qE $'^[[:space:]]*echo[^\r]*\xe3\x80\x8c' "$_f" ||
     grep -qE $'^[[:space:]]*echo[^\r]*\xe3\x80\x81' "$_f" ||
     grep -qE $'^[[:space:]]*echo[^\r]*\xef\xbc\x9b' "$_f"; then
    fail "$_f 的 echo 行含全角标点（，、；），cmd.exe 会把它后面的内容当命令执行"
  fi
done
echo "   echo 行标点检查通过"

echo "==> 检查一键旁路脚本"
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
cp wowmod.exe wowmod_loader.exe wowmod_rt.dll wowmod-start.cmd wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd README.md "$STAGE/"
cp scripts/wowmod-start.ps1 "$STAGE/scripts/"
mkdir -p "$STAGE/tools"
cp tools/listid.py "$STAGE/tools/"

echo "==> 压缩"
rm -f "$ZIP"
( cd "$STAGE" && zip -9 -r "$ZIP" \
    wowmod-start.cmd wowmod-dump.cmd wowmod-probe.cmd wowmod-patch.cmd wowmod.exe wowmod_loader.exe wowmod_rt.dll \
    scripts/wowmod-start.ps1 tools/listid.py README.md >/dev/null )

echo "==> 复验 zip 内容"
VERIFY="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$VERIFY"' EXIT
( cd "$VERIFY" && unzip -q "$ZIP" )
a=$(md5sum "$VERIFY/wowmod_loader.exe" | cut -d' ' -f1)
b=$(md5sum "$DIST/wowmod_loader.exe" | cut -d' ' -f1)
[ "$a" = "$b" ] || fail "zip 里的 loader 与 dist 不一致"
grep -aq "patch-v12" "$VERIFY/wowmod_loader.exe" || fail "zip 里的 loader 缺构建标记"
grep -aq "sigscan" "$VERIFY/scripts/wowmod-start.ps1" || fail "zip 里的脚本没有 sigscan 菜单"
[ -f "$VERIFY/wowmod-dump.cmd" ] || fail "zip 里缺 wowmod-dump.cmd"
grep -aq "dump-module" "$VERIFY/wowmod-dump.cmd" || fail "zip 里的 wowmod-dump.cmd 内容不完整"
[ -f "$VERIFY/wowmod-probe.cmd" ] || fail "zip 里缺 wowmod-probe.cmd"
[ -f "$VERIFY/wowmod-patch.cmd" ] || fail "zip 里缺 wowmod-patch.cmd"
grep -aq -- "--mode patch" "$VERIFY/wowmod-patch.cmd" || fail "zip 里的 wowmod-patch.cmd 没调用 --mode patch"
[ -f "$VERIFY/tools/listid.py" ] || fail "zip 里缺 tools/listid.py"
grep -aq "character/bloodelf/female" "$VERIFY/tools/listid.py" || fail "listid.py 内容不完整"

echo
echo "OK  $ZIP  ($(stat -c%s "$ZIP") 字节)"
echo "    loader build tag: patch-v12"
echo "    用户可用 \`wowmod_loader.exe --version\` 自查版本"
