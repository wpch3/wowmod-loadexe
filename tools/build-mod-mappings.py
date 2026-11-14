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
    """读一个或多个 "id;path" 文件，返回 {lower_path: id}。"""
    table = {}
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
                key = b.replace("\\", "/").strip().lower()
                fid = int(a)
                if key in table:
                    dup += 1
                    continue
                table[key] = fid
    if dup:
        print(f"  [提示] listfile 里有 {dup} 条重复路径，已保留第一次出现的 id")
    return table


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
    table = load_listfile(args.listfile)
    print(f"    条目 {len(table)}")

    print(f"==> 扫描模组树: {args.mod}")
    files, skipped = walk_mod(args.mod)
    print(f"    游戏资源文件 {len(files)} 个（另有 {skipped} 个非资源路径已忽略）")
    if not files:
        print("[失败] 没有找到任何游戏资源文件。", file=sys.stderr)
        print("       路径必须以 character/ creature/ item/ interface/ sound/ fonts/ 等开头。",
              file=sys.stderr)
        return 2

    matched, missing = [], []
    for rel in sorted(files):
        fid = table.get(rel.lower())
        if fid is None:
            missing.append(rel)
        else:
            matched.append((fid, rel))

    print(f"==> 对 listfile")
    print(f"    匹配到 FileDataID: {len(matched)}")
    print(f"    找不到 id:        {len(missing)}")

    if missing:
        print("\n    以下文件在公开 listfile 里没有 id（不会生效，但也不影响其它文件）:")
        for rel in missing[:20]:
            print(f"      {rel}")
        if len(missing) > 20:
            print(f"      ... 还有 {len(missing) - 20} 个")

    if not matched:
        print("\n[失败] 一个都没匹配上，生成的 mappings 会是空的。", file=sys.stderr)
        return 2

    # id 冲突检查：同一个 FileDataID 对应两个本地文件时，只有一个会生效，
    # 而且顺序不确定 —— 必须报出来，不能让它静默发生。
    by_id = {}
    for fid, rel in matched:
        by_id.setdefault(fid, []).append(rel)
    conflicts = {k: v for k, v in by_id.items() if len(v) > 1}
    if conflicts:
        print(f"\n    [警告] {len(conflicts)} 个 FileDataID 对应多个本地文件（只有一个会生效）:")
        for fid, rels in list(conflicts.items())[:10]:
            print(f"      {fid}: {', '.join(rels)}")

    if args.dry_run:
        print("\n[演练] 没有写任何文件。去掉 --dry-run 才会真正生成。")
        print(f"    将生成 {len(matched)} 条映射，链接 {len(matched)} 个文件。")
        print("\n    前 5 条示例:")
        for fid, rel in matched[:5]:
            print(f"      {fid};{rel}")
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
        for fid, rel in matched:
            f.write(f"{fid};{rel}\n")
    print(f"    {len(matched)} 条")

    print(f"==> 铺设 files: {file_dir}")
    n_link = n_copy = 0
    for fid, rel in matched:
        src = files[rel]
        dst = os.path.join(file_dir, rel.replace("/", os.sep))
        how = link_or_copy(src, dst)
        if how == "copy":
            n_copy += 1
        elif how == "link":
            n_link += 1

    total = sum(os.path.getsize(files[rel]) for _, rel in matched)
    print(f"    硬链接 {n_link} 个，复制 {n_copy} 个（源文件合计 {total / 1048576:.1f} MB）")
    if args.copy:
        print("    （用了 --copy，全部是复制）")

    print(f"\n完成。加载器会读:")
    print(f"  {map_dir}\\*.txt")
    print(f"  {file_dir}\\")
    return 0


if __name__ == "__main__":
    sys.exit(main())
