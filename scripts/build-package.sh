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
grep -aq "sigscan-dump-v3" "$ROOT/wowmod_loader.exe" \
  || fail "wowmod_loader.exe 不含构建标记 sigscan-dump-v3"
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

echo "==> 组装"
mkdir -p "$STAGE/scripts"
cp wowmod.exe wowmod_loader.exe wowmod_rt.dll wowmod-start.cmd README.md "$STAGE/"
cp scripts/wowmod-start.ps1 "$STAGE/scripts/"

echo "==> 压缩"
rm -f "$ZIP"
( cd "$STAGE" && zip -9 -r "$ZIP" \
    wowmod-start.cmd wowmod.exe wowmod_loader.exe wowmod_rt.dll \
    scripts/wowmod-start.ps1 README.md >/dev/null )

echo "==> 复验 zip 内容"
VERIFY="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$VERIFY"' EXIT
( cd "$VERIFY" && unzip -q "$ZIP" )
a=$(md5sum "$VERIFY/wowmod_loader.exe" | cut -d' ' -f1)
b=$(md5sum "$DIST/wowmod_loader.exe" | cut -d' ' -f1)
[ "$a" = "$b" ] || fail "zip 里的 loader 与 dist 不一致"
grep -aq "sigscan-dump-v3" "$VERIFY/wowmod_loader.exe" || fail "zip 里的 loader 缺构建标记"
grep -aq "sigscan" "$VERIFY/scripts/wowmod-start.ps1" || fail "zip 里的脚本没有 sigscan 菜单"

echo
echo "OK  $ZIP  ($(stat -c%s "$ZIP") 字节)"
echo "    loader build tag: sigscan-dump-v3"
echo "    用户可用 \`wowmod_loader.exe --version\` 自查版本"
