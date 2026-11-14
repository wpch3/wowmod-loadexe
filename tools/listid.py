#!/usr/bin/env python3
"""把探针记录到的 FileDataID 与 listfile 对起来，并回答一个关键问题：
客户端到底有没有通过"这个函数"去加载角色模型贴图？

为什么需要它：
  探针（--mode probe）只证明"这个函数被调用了 1895 次"，但它没说
  这些 id 是什么。没有 listfile 就只能瞎猜。
  2026 年的实测结论：这个函数抓到的是 interface/ 与 sound/，
  character/ 一个都没有 —— 也就是说角色模型贴图不走这条路径。
  这个工具就是把这件事变成可复现的数字，而不是靠人肉 grep。

用法:
  python3 listid.py --probe wowmod-probe.txt --listfile parts/*.csv \
                    --filter character/bloodelf/female
  python3 listid.py --probe wowmod-probe.txt --listfile parts/misc.csv --top 30

listfile 来源（公开）：
  https://github.com/wowdev/wow-listfile
  parts/*.csv 是 "fileId;filePath" 格式；release 里的 community-listfile.csv 也是。
SPDX-License-Identifier: MIT
"""
import argparse
import collections
import os
import re
import sys


def load_listfile(paths):
    """读一个或多个 id;path 文件，返回 {id: path}。"""
    table = {}
    for p in paths:
        if not os.path.isfile(p):
            print(f"  [跳过] 找不到 {p}", file=sys.stderr)
            continue
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ";" not in line:
                    continue
                a, b = line.split(";", 1)
                if a.isdigit():
                    table[int(a)] = b
    return table


def load_probe(path):
    """从 wowmod-probe.txt 里取出 (seq, id) 序列。"""
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            m = re.match(r"seq=(\d+)\s+id=(\d+)", line)
            if m:
                out.append((int(m.group(1)), int(m.group(2))))
    return out


def main():
    ap = argparse.ArgumentParser(description="探针 id 与 listfile 对账")
    ap.add_argument("--probe", required=True, help="wowmod-probe.txt 路径")
    ap.add_argument("--listfile", nargs="+", required=True, help="id;path 文件（可多个）")
    ap.add_argument("--filter", default="", help="只看路径包含该子串的条目（不区分大小写）")
    ap.add_argument("--top", type=int, default=20, help="显示前 N 个高频路径")
    args = ap.parse_args()

    calls = load_probe(args.probe)
    if not calls:
        print(f"探针文件里没有 seq=/id= 记录: {args.probe}", file=sys.stderr)
        return 2
    ids = [i for _, i in calls]
    uniq = set(ids)

    table = load_listfile(args.listfile)
    print(f"探针: {len(calls)} 次调用, {len(uniq)} 个唯一 FileDataID")
    print(f"listfile: {len(table)} 个已知 id")

    known = {i: table[i] for i in uniq if i in table}
    print(f"可查到路径的 id: {len(known)}/{len(uniq)} = {100.0*len(known)/len(uniq):.1f}%")

    # 按顶层目录归类，直观看"这个函数到底在加载什么"
    def bucket(p):
        low = p.lower()
        for k in ("character/", "creature/", "interface/", "sound/", "world/",
                  "spells/", "item/", "environments/", "tileset/", "dungeons/",
                  "particles/", "fonts/", "shaders/", "engine/"):
            if low.startswith(k):
                return k
        ext = os.path.splitext(low)[1]
        return f"(其它{ext})" if ext else "(其它)"

    counts = collections.Counter()
    calls_per_bucket = collections.Counter()
    for _, i in calls:
        p = table.get(i)
        if p:
            b = bucket(p)
            counts[b] += 1
            calls_per_bucket[b] += 1
    print("\n按路径顶层目录分布（按调用次数）:")
    for k, v in calls_per_bucket.most_common():
        print(f"  {v:6d} 次   {k}")

    # 关键判定
    if args.filter:
        needle = args.filter.lower()
        matched_paths = {i: p for i, p in table.items() if needle in p.lower()}
        hits = uniq & set(matched_paths)
        print(f"\n== 过滤 '{args.filter}' ==")
        print(f"  listfile 中匹配的 id 总数: {len(matched_paths)}")
        print(f"  探针抓到其中: {len(hits)} 个")
        if hits:
            print("  命中样本:")
            for i in sorted(hits)[:40]:
                print(f"    {i:>9}  {table[i]}")
            print("\n  结论: 这个函数【确实】在加载该类资源，可以在这里做替换。")
        else:
            print("\n  结论: 这个函数【完全没有】加载该类资源。")
            print("        在这条路径上做替换是无效的 —— 客户端不从这里取这些文件。")
            print("        需要换目标：找到真正加载该类资源的那个函数。")
        return 0 if hits else 1

    # 高频路径
    per_id = collections.Counter(i for _, i in calls)
    print(f"\n调用最频繁的 {args.top} 个 id:")
    for i, n in per_id.most_common(args.top):
        print(f"  {i:>9}  x{n:<4} {table.get(i, '(listfile 里没有)')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
