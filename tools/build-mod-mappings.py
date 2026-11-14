#!/usr/bin/env python3
"""把一棵「游戏相对路径」的模组目录树，变成加载器能直接吃的 mappings + files。

为什么需要这个工具：
  Arctium 的机制只认两样东西 ——
    wowmod\\mappings\\*.txt   每行 "<FileDataID>;<游戏相对路径>"
    wowmod\\files\\           实际文件，保持同样的相对路径
  用户手上的模组往往是一棵裸目录树（例如 _midnight_\\Character\\BloodElf\\Female\\*.blp），
  既不在这里也不在那里。手工整理两百多个文件再逐个查 FileDataID 不现实，
  而查错一个 id 的后果是「游戏里某个部位变成别的贴图」—— 极难排查。
  所以这里把它做成一步：扫树 → 对 listfile → 生成两条命令的产物。

用法:
  # 只看会做什么，不写任何文件
  python3 tools/build-mod-mappings.py --mod "D:\\Midnight Open Beta\\_midnight_\\Character" \\
      --gamedir "D:\\Midnight Open Beta\\_midnight_" \\
      --listfile listfile.csv --dry-run

  # 真正生成到 wowmod\\mappings 和 wowmod\\files
  python3 tools/build-mod-mappings.py --mod "...\\Character" --gamedir "...\\_midnight_" \\
      --listfile listfile.csv --out "D:\\Midnight Open Beta\\_midnight_\\wowmod"

输出的 mappings 文件格式与 Arctium 完全一致（"id;path"，path 用 / 分隔、不复含前缀），
files 目录用【硬链接】而不是复制：同一份 12MB 贴图不占两份空间，
删掉任意一边另一边仍在（Windows 同一卷支持）。
SPDX-License-Identifier: MIT
"""
import argparse
import os
import re
import shutil
import sys

# 游戏里真正按 FileDataID 存取的资源前缀。
# 这些是会把「路径」暴露给客户端的类别：模型、贴图、声音、界面、字体、地形。
# 出现在别的前缀下（docs/、src/、tools/ ...）的目录一律不当作模组内容，
# 否则仓库源码里的同名目录也会被当成模组塞进去。
MOD_PREFIXES = (
    "character/",
    "creature/",
    "item/",
    "interface/",
    "sound/",
    "fonts/",
    "world/",
    "spells/",
    "particles/",
    "environments/",
    "dungeons/",
    "tileset/",
    "cameras/",
    "anim/",
)


def load_listfile(paths):
    """读一个或多个 "id;path" 文件。

    返回三个映射：
      by_key   : 归一化键(小写/去空格) -> id     —— 只用于【查找】
      by_id    : id -> 表里的原始路径             —— 用于回查官方写法
      path_of  : 归一化键 -> 表里的原始路径
    必须区分"查找键"和"输出路径"：listfile 里确实有 31944 条路径
    自带空格（例如 "Creature/Lord Kezzak/LordKezzak.M2"），
    而游戏用的名字就是那个带空格的形式。归一化只用来容错查找，
    绝不能拿它去覆盖写进 mappings 的路径。
    """
    table = {}          # key -> id
    path_of = {}        # key -> 原始路径
    by_id = {}          # id -> 原始路径
    dup = 0
    for p in paths:
        if not os.path.isfile(p):
            print(f"  [跳过] 找不到 listfile: {p}", file=sys.stderr)
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ";" not in line:
                    continue
                a, b = line.split(";", 1)
                if not a.isdigit():
                    continue
                raw = b.replace("\\", "/").strip()
                key = raw.replace(" ", "").lower()
                fid = int(a)
                if key in table:
                    dup += 1
                    continue
                table[key] = fid
                path_of[key] = raw
                by_id.setdefault(fid, raw)
    if dup:
        print(f"  [提示] listfile 里有 {dup} 条重复路径，已保留第一次出现的 id")
    return table, path_of, by_id


def normalize_key(path):
    """把路径规范化成 listfile 的比较键。

    实测中发现的三种不一致（都来自用户手上真实模组）：
      1. 文件名里混进了空格： "goblinfemalenakedpelvisskin00_ 12_hd.blp"
         —— 空格来自打包工具的失误，游戏里没有这种名字，必须去掉。
      2. 大小写不同：listfile 里同一个资源既可能是 .BLP 也可能是 .blp。
      3. 后缀差异：模组给的是 "xxx.blp"，listfile 里只有 "xxx_HD.blp"
         （HD 皮肤是独立 FileDataID，官方并非总是同时登记两个名字）。
    所以比较时统一：小写 + 去空格 + 反斜杠转正斜杠。
    """
    return path.replace("\\", "/").replace(" ", "").strip().lower()


def lookup_variants(table, table_path, rel):
    """按 prio 顺序尝试几个变体，返回 (id, 命中的键) 或 (None, None)。

    顺序很重要：精确匹配优先，其次才是"加/去 _HD"这类推断。
    推断出来的映射会单独统计并打印，绝不和精确匹配混在一起 ——
    用户必须知道哪些是猜的，否则贴图错了根本无从排查。
    """
    k = normalize_key(rel)
    if k in table:
        return table[k], table_path[k], "exact"

    # HD 后缀的有无。只在这一个维度上推断，不做别的模糊匹配：
    # 别的推断（比如改数字）都是凭空猜，猜错就是别的部位变样。
    cands = []
    if k.endswith(".blp"):
        base = k[: -len(".blp")]
        if base.endswith("_hd"):
            cands.append(base[: -len("_hd")] + ".blp")
        else:
            cands.append(base + "_hd.blp")
    for c in cands:
        if c in table:
            return table[c], table_path[c], "hd_variant"
    return None, None, None


FAMILY_NUM = re.compile(r"_?(\d+)(_hd)?\.blp$", re.I)


def family_stem(name):
    """去掉 _HD 后缀和末尾编号，得到"同族"前缀。"""
    n = os.path.basename(name).lower().replace(" ", "")
    n = re.sub(r"(_hd)?\.blp$", "", n)
    return re.sub(r"_?\d+$", "", n)


def guess_by_family(table, table_path, rel):
    """用「同族编号」推断：同一目录、同一前缀、但编号不同的文件。

    注意这是【凭位置猜】，比 _HD 推断危险得多：
      * 编号在 listfile 里通常连续（如 DwarfFemaleNakedPelvisSkin00_00..15
        对应 118316..118331），所以缺号时按位置可以大致确定；
      * 但列表里可能缺号、也可能有编号跳变（Dwarf 就有 _18 而没有 _16/_17），
        按"第几个"去对齐会整体错位，结果就是别的部位用了这张图。
    所以：
      * 默认【不做】这个推断；
      * 打开时只输出候选，全部标 guess，让用户自己核对；
      * 绝不静默使用。
    返回 [(候选 id, 候选路径)]，按编号排序。
    """
    d, f = os.path.split(rel)
    stem = family_stem(f)
    want = None
    m = FAMILY_NUM.search(os.path.basename(f).lower().replace(" ", ""))
    if m:
        want = int(m.group(1))
    out = []
    prefix = (d + "/").lower().replace(" ", "") if d else ""
    for key, fid in table.items():
        if not key.startswith(prefix):
            continue
        base = os.path.basename(key)
        if family_stem(base) != stem:
            continue
        mm = FAMILY_NUM.search(base)
        if not mm:
            continue
        out.append((int(mm.group(1)), fid, table_path[key]))
    out.sort()
    if want is None:
        return []
    return [(fid, path) for num, fid, path in out if num != want]


def walk_mod(mod_root):
    """遍历模组树，返回 {游戏相对路径: 绝对磁盘路径}。

    关键点：以 mod_root 的【父目录】为基准算相对路径。
    这样 --mod "...\\_midnight_\\Character" 得到的是
    "Character/BloodElf/Female/xxx.blp"，正好是游戏内的路径形式。
    如果直接把 mod_root 当基准，会丢掉最外层那一段，得到
    "BloodElf/Female/xxx.blp" —— 那是错的，客户端永远匹配不上。
    """
    root = os.path.abspath(mod_root)
    base = os.path.dirname(root)
    out = {}
    skipped_prefix = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for name in filenames:
            if name.startswith("."):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base).replace("\\", "/")
            low = rel.lower()
            if not any(low.startswith(p) for p in MOD_PREFIXES):
                skipped_prefix += 1
                continue
            out[rel] = full
    return out, skipped_prefix


def link_or_copy(src, dst):
    """优先硬链接（省空间），失败则复制。返回 'link' 或 'copy'。"""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        try:
            if os.path.samefile(src, dst):
                return "same"
        except OSError:
            pass
        os.remove(dst)
    try:
        os.link(src, dst)
        return "link"
    except OSError:
        shutil.copy2(src, dst)
        return "copy"


def main():
    ap = argparse.ArgumentParser(description="扫描模组目录树，生成 Arctium 风格的 mappings + files")
    ap.add_argument("--mod", required=True, help="模组目录（例如 ...\\_midnight_\\Character）")
    ap.add_argument("--listfile", nargs="+", required=True, help="一个或多个 id;path 文件")
    ap.add_argument("--out", help="输出到 <out>\\mappings 与 <out>\\files（不给则只打印）")
    ap.add_argument("--mapping-name", default="mod.txt", help="生成的 mappings 文件名")
    ap.add_argument("--copy", action="store_true", help="复制而不是硬链接")
    ap.add_argument("--dry-run", action="store_true", help="只打印，不写任何文件")
    ap.add_argument("--guess-family", action="store_true",
                    help="对匹配不到的编号，尝试用同族编号推断（危险，需人工核对）")
    args = ap.parse_args()

    missing_lf = [p for p in args.listfile if not os.path.isfile(p)]
    if missing_lf:
        print("[失败] 找不到 listfile，无法把路径换算成 FileDataID：", file=sys.stderr)
        for p in missing_lf:
            print(f"        {p}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  先跑一次 tools\\fetch-listfile.cmd 下载（约 147 MB，只需一次）。", file=sys.stderr)
        print("  或者自己指定：--listfile <任意 id;path 文件>", file=sys.stderr)
        return 2

    if not os.path.isdir(args.mod):
        print(f"[失败] 模组目录不存在: {args.mod}", file=sys.stderr)
        return 2

    print(f"==> 读 listfile")
    table, table_path, table_by_id = load_listfile(args.listfile)
    print(f"    条目 {len(table)}")

    print(f"==> 扫描模组树: {args.mod}")
    files, skipped = walk_mod(args.mod)
    print(f"    游戏资源文件 {len(files)} 个（另有 {skipped} 个非资源路径已忽略）")
    if not files:
        print("[失败] 没有找到任何游戏资源文件。", file=sys.stderr)
        print("       路径必须以 character/ creature/ item/ interface/ sound/ fonts/ 等开头。",
              file=sys.stderr)
        return 2

    # ---- 三步走，顺序很重要 ----
    #
    # 1) 每个本地文件 -> FileDataID
    # 2) 输出路径改用【listfile 里的官方写法】
    # 3) 按 id 去重（一个 id 只能有一个生效文件）
    #
    # 第 2 步是这版的关键修正。上一版直接把本地路径写进 mappings，
    # 于是出现 "humanfemalenakedtorsoskin00_ 15.blp" 这种带空格的名字
    # 和官方 "HumanFemaleNakedTorsoSkin00_15_HD.blp" 同时映射到 1348798。
    # 客户端只会用其中一个，而带空格的那个是错的 —— 表现就是"没反应"。
    # 既然 listfile 已经明确告诉我们官方名字，就该用官方的。
    matched, missing, inferred = [], [], []
    for rel in sorted(files):
        fid, official, how = lookup_variants(table, table_path, rel)
        if fid is None:
            missing.append(rel)
            continue
        # 官方路径缺失时退回本地路径（极少见，但要能工作）
        out_rel = official or rel
        matched.append((fid, out_rel, rel))
        if how != "exact":
            inferred.append((rel, official, fid, how))

    # ---- 按 FileDataID 去重 ----
    #
    # 同一个 id 对应多个本地文件时，只有一个会生效，而且顺序不确定 ——
    # 那是最难排查的一类故障（有时生效有时不生效）。
    # 这里明确挑一个，并把被丢弃的打印出来。
    deduped = []
    dropped = []
    seen = {}
    for fid, out_rel, src_rel in matched:
        if fid in seen:
            kept = seen[fid]
            # 优先保留路径更长更具体的那条（真实文件名通常比占位名长），
            # 长度相同时保留本地文件名与官方名完全一致的那条。
            k_same = kept[2].replace(" ", "").lower() == kept[1].replace(" ", "").lower()
            n_same = src_rel.replace(" ", "").lower() == out_rel.replace(" ", "").lower()
            if n_same and not k_same:
                dropped.append((fid, kept[2], kept[1], src_rel))
                deduped = [x for x in deduped if x[0] != fid]
                deduped.append((fid, out_rel, src_rel))
                seen[fid] = (fid, out_rel, src_rel)
            else:
                dropped.append((fid, src_rel, out_rel, kept[2]))
            continue
        seen[fid] = (fid, out_rel, src_rel)
        deduped.append((fid, out_rel, src_rel))
    matched = deduped

    print(f"==> 对 listfile")
    print(f"    匹配到 FileDataID: {len(matched)}")
    print(f"    找不到 id:        {len(missing)}")

    if inferred:
        print(f"    其中 {len(inferred)} 个是靠推断得到的（精确路径在 listfile 里没有）:")
        for rel, key, fid, how in inferred[:15]:
            print(f"      {rel}")
            print(f"        -> {key}  = {fid}   [{how}]")
        if len(inferred) > 15:
            print(f"      ... 还有 {len(inferred) - 15} 个")
        print("    推断的依据只有「_HD 后缀的有无」这一个维度。若模型出现错位/串色，")
        print("    优先检查这几条。")

    family_cands = []
    if args.guess_family and missing:
        print("\n    --guess-family：对找不到 id 的文件给出同族候选（仅供参考，不会写进 mappings）")
        for rel in missing:
            cands = guess_by_family(table, table_path, rel)
            if not cands:
                print(f"      {rel}")
                print(f"        -> 同族里也没有可参考的编号")
                continue
            print(f"      {rel}")
            for fid, path in cands[:4]:
                print(f"        ? {fid}  {path}")
            family_cands.append((rel, cands))

    if missing:
        print("\n    以下文件在公开 listfile 里没有 id（不会生效，但也不影响其它文件）:")
        for rel in missing[:20]:
            print(f"      {rel}")
        if len(missing) > 20:
            print(f"      ... 还有 {len(missing) - 20} 个")

    if not matched:
        print("\n[失败] 一个都没匹配上，生成的 mappings 会是空的。", file=sys.stderr)
        return 2

    if dropped:
        print(f"\n    [已处理] {len(dropped)} 个 FileDataID 对应多个本地文件，已各留一条:")
        for fid, lose, lose_path, keep in dropped[:10]:
            print(f"      {fid}: 保留 {lose_path}")
            print(f"           丢弃 {keep}")

    if args.dry_run:
        print("\n[演练] 没有写任何文件。去掉 --dry-run 才会真正生成。")
        print(f"    将生成 {len(matched)} 条映射，链接 {len(matched)} 个文件。")
        print("\n    前 5 条示例:")
        for fid, out_rel, _src in matched[:5]:
            print(f"      {fid};{out_rel}")
        return 0

    if not args.out:
        print("\n[提示] 没有给 --out，只在上面打印统计。要写文件请加 --out <wowmod目录>")
        return 0

    map_dir = os.path.join(args.out, "mappings")
    file_dir = os.path.join(args.out, "files")
    os.makedirs(map_dir, exist_ok=True)
    os.makedirs(file_dir, exist_ok=True)

    map_path = os.path.join(map_dir, args.mapping_name)
    print(f"\n==> 写 mappings: {map_path}")
    with open(map_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# 由 tools/build-mod-mappings.py 生成\n")
        f.write(f"# 模组: {args.mod}\n")
        f.write(f"# 格式: <FileDataID>;<游戏相对路径>  (Arctium 兼容)\n")
        if inferred:
            f.write(f"# 注意: 其中 {len(inferred)} 条是靠 _HD 后缀推断得到的：\n")
            for rel, key, fid, how in inferred:
                f.write(f"#   {fid} <- {rel}  (官方路径 {key})\n")
        # 不能在这行后面追加 "# inferred"：加载器按第一个 ';' 切分，
        # 注释会直接成为路径的一部分，那条映射反而永远匹配不上。
        # 推断明细只写在文件头，不放进行内。
        for fid, out_rel, _src in matched:
            f.write(f"{fid};{out_rel}\n")
    print(f"    {len(matched)} 条")

    print(f"==> 铺设 files: {file_dir}")
    n_link = n_copy = 0
    for fid, out_rel, src_rel in matched:
        src = files[src_rel]
        dst = os.path.join(file_dir, out_rel.replace("/", os.sep))
        how = link_or_copy(src, dst)
        if how == "copy":
            n_copy += 1
        elif how == "link":
            n_link += 1

    total = sum(os.path.getsize(files[src_rel]) for _, _o, src_rel in matched)
    print(f"    硬链接 {n_link} 个，复制 {n_copy} 个（源文件合计 {total / 1048576:.1f} MB）")
    if args.copy:
        print("    （用了 --copy，全部是复制）")

    print(f"\n完成。加载器会读:")
    print(f"  {map_dir}\\*.txt")
    print(f"  {file_dir}\\")
    return 0


if __name__ == "__main__":
    sys.exit(main())
