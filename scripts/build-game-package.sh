#!/usr/bin/env bash
# 生成「直接解压到游戏目录」的傻瓜包：wowmod-12.0.7-game-dir.zip
# 解压后 D:\Midnight Open Beta\_midnight_\ 里直接有 wowmod.exe / wowmod_hook.dll /
# wowmod.firestorm.json / hooks / mappings / mods，按 RUN.txt 输命令即可。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"

if [[ ! -f wowmod.exe || ! -f wowmod_hook.dll ]]; then
  echo "缺少根目录二进制，先运行 ./scripts/build-windows-release.sh" >&2
  exit 1
fi

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
cp wowmod.exe wowmod_hook.dll "$STAGE/"
cp examples/12.0.7/wowmod.firestorm.json "$STAGE/wowmod.firestorm.json"
mkdir -p "$STAGE/hooks" "$STAGE/mappings" "$STAGE/mods/models"
cp examples/12.0.7/hooks/*.json "$STAGE/hooks/"
cp examples/12.0.7/mappings/listfile.txt "$STAGE/mappings/"
cp examples/12.0.7/mods/models/README.md "$STAGE/mods/models/"
cp docs/WINDOWS-QUICKSTART.md "$STAGE/WINDOWS-QUICKSTART.md"
cp docs/X64DBG.md "$STAGE/X64DBG.md"
cp scripts/diagnose-load.ps1 "$STAGE/diagnose-load.ps1"

cat > "$STAGE/RUN.txt" <<'TXT'
wowmod 12.0.7 — 直接解压到游戏目录的版本
==========================================

把这个 ZIP 的内容【直接】解压到游戏目录：
  D:\Midnight Open Beta\_midnight_\

解压后该目录下应该能直接看到（不要再套一层子文件夹）：
  wowmod.exe
  wowmod_hook.dll
  wowmod.firestorm.json
  hooks\  mappings\  mods\
  RUN.txt  WINDOWS-QUICKSTART.md  X64DBG.md  diagnose-load.ps1

然后在这个目录打开 PowerShell（地址栏输 powershell 回车），依次执行：

  Unblock-File .\wowmod.exe, .\wowmod_hook.dll
  .\wowmod.exe version
  .\wowmod.exe detect   --config ".\wowmod.firestorm.json"
  .\wowmod.exe validate --config ".\wowmod.firestorm.json"
  .\wowmod.exe plan     --config ".\wowmod.firestorm.json"
  .\wowmod.exe launch   --config ".\wowmod.firestorm.json"

注意：
1. 必须写 .\wowmod.exe，不能只写 wowmod。
2. wowmod.exe 与 wowmod_hook.dll 必须在同一目录。
3. 如果 wowmod.firestorm.json 里的 D:/Midnight Open Beta/_midnight_/ 路径
   和你的实际路径不同，用记事本改 client.exe / client.gameDir。
4. 把模型替换文件放进 mods\models\；12.0.7 listfile 放 mappings\listfile.txt。
5. launch 成功后，本目录下 runtime-dumps\ 会生成解密内存映像和候选特征，
   把这个文件夹发回即可完成最后一条 FileDataID hook 点的确认。
6. 若提示 LoadLibraryW 返回 NULL，运行诊断脚本看具体 Win32 错误码：

   powershell -ExecutionPolicy Bypass -File .\diagnose-load.ps1

   常见原因：Defender/ASR 拦截（文件在 Downloads 目录）、缺少 VC++ 运行库、
   或挂起阶段 loader 未就绪（加载器会自动延迟重试一次）。

仅用于你有权修改/调试的私服或离线环境。
TXT

python3 - "$STAGE" "$ROOT/wowmod-12.0.7-game-dir.zip" <<'PY'
import os, sys, zipfile
stage, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for base, dirs, files in os.walk(stage):
        dirs.sort(); files.sort()
        for f in files:
            p = os.path.join(base, f)
            z.write(p, os.path.relpath(p, stage).replace(os.sep, '/'))
print('打包文件数:', sum(1 for _ in zipfile.ZipFile(out).namelist()))
PY
ls -l wowmod-12.0.7-game-dir.zip
sha256sum wowmod-12.0.7-game-dir.zip
