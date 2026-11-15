#!/usr/bin/env python3
"""回归测试：模组目录形状 -> 游戏相对路径解析。

用用户真实上传过的三种模组包结构当夹具（不含任何游戏文件，只有空文件）：

  T21WarriorNSFW/item/texturecomponents/belt.blp
  Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelite.m2
  Wrath NPC Pack/Textures/BakedNpcTextures/CreatureDisplayExtra-15876.blp

第三种以前会被 MOD_PREFIXES 整体丢弃（目录名不叫 creature/），
表现是"扫到 0 个文件"。现在必须靠「文件名 + 尾部目录打分」在 listfile
里确定唯一 id，且对 common.blp 这种重名文件必须拒绝而不是乱猜。

输出 "OK" 表示全过；否则输出失败项，由 build-package.sh 拒绝打包。
SPDX-License-Identifier: MIT
"""
import importlib.util
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "build-mod-mappings.py")

spec = importlib.util.spec_from_file_location("bm", TOOL)
bm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bm)


def main():
    root = tempfile.mkdtemp(prefix="wowmod-shape-")
    bad = []

    def mk(rel):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write("x")

    mk("T21WarriorNSFW/item/texturecomponents/belt.blp")
    mk("Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelite.m2")
    mk("Titaa Hawkstrider Mount/Creature/cockatrice/cockatricelite00.skin")
    mk("Wrath NPC Pack/Textures/BakedNpcTextures/CreatureDisplayExtra-15876.blp")
    mk("Loose/Textures/common.blp")

    lf = os.path.join(root, "lf.csv")
    open(lf, "w", encoding="utf-8").write("\n".join([
        "1;item/texturecomponents/belt.blp",
        "2;creature/cockatrice/cockatricelite.m2",
        "3;creature/cockatrice/cockatricelite00.skin",
        "4;creature/bakednpctextures/creaturedisplayextra-15876.blp",
        "5;character/human/female/common.blp",
        "6;character/orc/male/common.blp",
    ]))

    table, table_path, _by_id = bm.load_listfile([lf])
    idx = bm.build_name_index(table, table_path)

    def resolve(moddir, rel):
        fid, official, how = bm.lookup_variants(table, table_path, rel)
        if fid is None:
            hit = bm.lookup_by_suffix(idx, rel)
            if hit:
                fid, official, how = hit
        return fid

    cases = [
        ("T21WarriorNSFW", "item/texturecomponents/belt.blp", 1),
        ("Titaa Hawkstrider Mount", "Creature/cockatrice/cockatricelite.m2", 2),
        ("Titaa Hawkstrider Mount", "Creature/cockatrice/cockatricelite00.skin", 3),
        ("Wrath NPC Pack",
         "Wrath NPC Pack/Textures/BakedNpcTextures/CreatureDisplayExtra-15876.blp", 4),
    ]
    for mod, rel, want in cases:
        got = resolve(mod, rel)
        if got != want:
            bad.append(f"resolve({rel}) = {got}, want {want}")

    # 歧义必须被拒绝（拒绝 = 不生效，猜错 = 别的资源变成这张图）
    if resolve("Loose", "Textures/common.blp") is not None:
        bad.append("ambiguous common.blp must be rejected")

    # walk_mod 必须真的把这几个文件收进来（不能因为前缀不认识就丢掉）
    for mod, want_n in (("T21WarriorNSFW", 1), ("Titaa Hawkstrider Mount", 2),
                        ("Wrath NPC Pack", 1)):
        files, _skipped = bm.walk_mod(os.path.join(root, mod))
        if len(files) != want_n:
            bad.append(f"walk_mod({mod}) = {len(files)} files, want {want_n}")
            continue
        for rel in files:
            low = rel.lower()
            if not any(low.startswith(p) for p in bm.MOD_PREFIXES):
                # 允许不认识的前缀存在（由文件名索引兜底），但必须有 id
                if resolve(mod, rel) is None:
                    bad.append(f"unprefixed file with no id: {rel}")

    shutil.rmtree(root, ignore_errors=True)
    print(" ".join(bad) if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
