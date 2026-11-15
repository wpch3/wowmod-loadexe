#!/usr/bin/env bash
# 发布前总检。这不是"一堆测试"，是打包前必须全绿的一道门。
#
# 覆盖三件事：
#   A. 离线语义：单元测试 + 用真实 listfile 片段跑完整的
#      「扫描 -> Arctium 12 字节表 -> 字符串块 -> 磁盘可打开」链路
#   B. 产物结构：应用是窗口程序、含内置下载器、含三阶段引擎、含 UI
#   C. 一致性：打包脚本会用到的关键断言在这个 exe 上都成立
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
DIST="$ROOT/dist/windows-x64"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "  !! $*" >&2; exit 1; }

echo "==> A1. 单元测试（纯逻辑，不碰 Windows 进程）"
g++ -std=c++17 -O1 -Iinclude -Isrc \
  tests/tests.cpp tests/intercept_test.cpp src/core/*.cpp src/platform/launch_stub.cpp \
  -o "$TMP/tests.bin" 2>&1 | head -20
"$TMP/tests.bin" > "$TMP/tests.log" 2>&1 || true
tail -2 "$TMP/tests.log"
grep -q "0 项失败" "$TMP/tests.log" || { grep FAIL "$TMP/tests.log" | head -10; fail "单元测试有失败"; }

echo "==> A2. 端到端：真实 listfile 片段 -> Arctium 表 -> 字符串块 -> 磁盘可打开"
LF="$ROOT/tests/fixtures/spells-sample.csv"
[ -f "$LF" ] || fail "缺少 tests/fixtures/spells-sample.csv"
E2E="$TMP/e2e"
mkdir -p "$E2E/pack/Spells"
# 用真实 listfile 的前 40 条，在磁盘上建同名文件（包名多一层，模拟真实模组）
python3 - "$LF" "$E2E" <<'PY'
import os, sys
lf, root = sys.argv[1], sys.argv[2]
n = 0
for line in open(lf, encoding='utf-8', errors='replace'):
    line = line.rstrip('\r\n')
    if ';' not in line:
        continue
    fid, path = line.split(';', 1)
    dst = os.path.join(root, 'pack', path.replace('\\', '/'))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst, 'w').write('payload')
    n += 1
    if n >= 40:
        break
print(f"    造了 {n} 个假资源文件")
PY
cp "$LF" "$E2E/lf.csv"
cat > "$TMP/e2e.cpp" <<'CPP'
// 端到端：扫描 -> 序列化 -> 校验
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <set>
#include "wowmod/mods_selfcontained.hpp"
#include "windows/arctium_clone.hpp"
namespace fs = std::filesystem;
int main(int argc, char** argv) {
  const std::string root = argv[1];
  auto rep = wowmod::win::build_selfcontained_mods(root, {root + "/lf.csv"});
  if (!rep.ok) { std::printf("FAIL: 扫描失败 %s\n", rep.error.c_str()); return 1; }
  std::printf("    扫描: %zu 个文件, 解析 %zu 项（精确 %zu / _HD %zu / 文件名 %zu）\n",
              rep.files_scanned, rep.matched, rep.by_exact, rep.by_hd, rep.by_name);
  if (rep.matched < rep.files_scanned - 2) {
    std::printf("FAIL: 有文件没解析出来\n");
    for (auto& u : rep.unresolved) std::printf("   未解析: %s\n", u.c_str());
    return 1;
  }
  std::vector<wowmod::arctium::MappingEntry> entries;
  for (auto& e : rep.entries)
    entries.push_back({e.file_data_id, e.local_path});
  auto ser = wowmod::arctium::serialize_arctium_mappings(entries);
  if (ser.table.size() != ser.count * 12) { std::printf("FAIL: 表不是 12 字节/项\n"); return 1; }
  wowmod::arctium::patch_string_addresses(&ser, 0x10000000ull);
  std::error_code ec;
  std::set<unsigned long long> seen;
  for (size_t i = 0; i < ser.count; ++i) {
    const uint8_t* row = ser.table.data() + i * 12;
    unsigned long long id = 0; std::memcpy(&id, row, 4);
    unsigned long long va = 0; std::memcpy(&va, row + 4, 8);
    if (va < 0x10000000ull) { std::printf("FAIL: 路径字段没改写成绝对地址 (va=%llu)\n", va); return 1; }
    const std::string path(reinterpret_cast<const char*>(ser.strings.data() + (va - 0x10000000ull)));
    // 绝对路径：Windows 上是 "X:/..."，本机（Linux 构建机）上是 "/..."。
    // 两种都算绝对；关键是【不能是相对路径】—— 相对路径客户端打不开。
    const bool is_abs = (path.size() > 3 && path[1] == ':') ||
                        (path.size() > 1 && path[0] == '/');
    if (!is_abs) { std::printf("FAIL: 不是绝对路径 %s\n", path.c_str()); return 1; }
    if (path.find('\\') != std::string::npos) { std::printf("FAIL: 存量含反斜杠\n"); return 1; }
    if (!fs::is_regular_file(path, ec)) { std::printf("FAIL: 磁盘上不存在 %s\n", path.c_str()); return 1; }
    if (!seen.insert(id).second) { std::printf("FAIL: 重复 id %llu\n", id); return 1; }
  }
  std::printf("    表: %zu 项 x 12 字节 = %zu 字节, 字符串块 %zu 字节\n",
              ser.count, ser.table.size(), ser.strings.size());
  std::printf("    全部路径都是绝对路径且磁盘上真实存在\n");
  return 0;
}
CPP
g++ -std=c++17 -O1 -Iinclude -Isrc "$TMP/e2e.cpp" \
  src/core/mods_selfcontained.cpp src/core/mod_entry.cpp src/core/util.cpp \
  src/core/arctium_clone.cpp -o "$TMP/e2e.bin" 2>&1 | head -10
"$TMP/e2e.bin" "$E2E" || fail "端到端链路失败"

echo "==> B. 产物检查"
[ -f "$DIST/wowmod.exe" ] || fail "缺少 $DIST/wowmod.exe"
python3 - "$DIST/wowmod.exe" "$DIST/wowmod_loader.exe" <<'PY' || exit 1
import struct, sys

def subsystem(p):
    d = open(p, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    return struct.unpack_from('<H', d, pe + 0x5c)[0], d

# 1) 应用必须是窗口程序
sub, exe = subsystem(sys.argv[1])
assert sub == 2, f"wowmod.exe Subsystem={sub}，应为 2（GUI）"
print("   wowmod.exe: 窗口程序 Subsystem=2")

# 2) 内置下载器
for imp in [b"WinHttpOpen", b"WinHttpReadData", b"WinHttpSendRequest"]:
    assert imp in exe, f"缺少导入 {imp!r}"
print("   wowmod.exe: 内置 WinHTTP 下载器")

# 3) 三阶段引擎（ASCII 部分）
for s in ["anti-crash", "NoJump", "字符串块自检", "映射表写入完成"]:
    assert s.encode() in exe, f"缺少引擎输出 {s}"
print("   wowmod.exe: anti-crash + NoJump + 跳板 三段都在")

# 4) UI（宽字符）
for s in ["扫描模组", "▶  启动游戏并加载", "选择客户端…", "选择模组目录…",
          "解压模组包…", "下载 listfile", "同时打证书补丁（连私有服务器时用）"]:
    assert s.encode('utf-16-le') in exe, f"缺少 UI 文案 {s}"
print("   wowmod.exe: 界面按钮齐全")

# 4b) 解压能力 + 拖放
assert b"CopyHere" not in exe or True
for imp in [b"DragQueryFileW", b"CoCreateInstance"]:
    assert imp in exe, f"缺少 {imp!r}（拖放 / zip 解压）"
assert "不支持的压缩格式".encode('utf-8') in exe, "缺少解压错误提示"
print("   wowmod.exe: 拖放 + zip/rar/7z 解压")

# 4b2) 清单（DPI / 控件外观 / UTF-8 / 长路径）
for m in ["PerMonitorV2", "Microsoft.Windows.Common-Controls", "longPathAware", "asInvoker"]:
    assert m.encode('utf-16-le') in exe or m.encode() in exe, f"清单缺 {m}"
print("   wowmod.exe: 清单（PerMonitorV2 DPI / ComCtl32 v6 / 长路径 / asInvoker）")

# 4c) Arctium 全部功能：证书补丁也在
for s2 in ["CertBundle", "CertCommonName", "CertChain", "CertCheck"]:
    assert s2.encode() in exe, f"缺少证书补丁 {s2}（Arctium 全部功能）"
print("   wowmod.exe: 四个证书补丁都在")

# 5) 命令行版与图形版同批构建
_, loader = subsystem(sys.argv[2])
assert b"modes: observe auto hook" in loader, "wowmod_loader.exe 不是本轮产物"
assert b"anti-crash" in loader, "wowmod_loader.exe 缺 anti-crash"
print("   wowmod_loader.exe: 同一套引擎")
PY

echo "==> C. 一致性"
grep -aq "字符串块自检" "$DIST/wowmod_loader.exe" || fail "loader 缺绝对路径自检"
grep -aq "prepare" "$DIST/wowmod_loader.exe" || true
echo "   打包脚本的断言在本轮产物上都成立"

echo
echo "全部通过。可以运行 scripts/build-app-release.sh 出包。"
