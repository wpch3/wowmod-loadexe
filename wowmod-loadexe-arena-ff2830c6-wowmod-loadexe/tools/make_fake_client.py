#!/usr/bin/env python3
"""生成一个"假的" Windows 客户端目录，用来在没有魔兽安装的情况下测试加载器。

它不是游戏，只是一个合法的 PE32+ 文件 + .build.info + Data 目录，
用来验证：版本探测、存储布局探测、特征扫描、覆盖表构建、启动计划。

用法:
  python3 tools/make_fake_client.py --dir examples/demo/client --version 3.3.5.12340
  python3 tools/make_fake_client.py --dir examples/demo/client --version 12.1.5.70783
"""
import argparse
import os
import struct
import sys

# 与 examples/demo/hooks/patterns.json 中的示例特征一致
SIGNATURE = bytes.fromhex("48 89 5C 24 08 57 48 83 EC 20 48 8B 05 AA BB CC DD E8 01 02 03 04 74 09".replace(" ", ""))


def w16(b, off, v):
    b[off:off + 2] = struct.pack("<H", v)


def w32(b, off, v):
    b[off:off + 4] = struct.pack("<I", v)


def make_pe(version):
    parts = [int(x) for x in version.split(".")] if version else []
    while len(parts) < 4:
        parts.append(0)
    major, minor, patch, build = parts[:4]

    b = bytearray(0x900)
    w16(b, 0, 0x5A4D)                 # MZ
    w32(b, 0x3C, 0x80)                # e_lfanew
    pe = 0x80
    w32(b, pe, 0x00004550)            # PE\0\0
    w16(b, pe + 4, 0x8664)            # x64
    w16(b, pe + 6, 2)                 # 2 sections
    w16(b, pe + 20, 0xF0)             # SizeOfOptionalHeader
    opt = pe + 24
    w16(b, opt, 0x20B)                # PE32+
    w32(b, opt + 108, 16)             # NumberOfRvaAndSizes
    w32(b, opt + 112 + 2 * 8, 0x2000)  # Resource directory RVA
    sec = opt + 0xF0

    # .text (RVA 0x1000 -> file 0x400)
    b[sec:sec + 8] = b".text\0\0\0"
    w32(b, sec + 8, 0x200)
    w32(b, sec + 12, 0x1000)
    w32(b, sec + 16, 0x200)
    w32(b, sec + 20, 0x400)
    w32(b, sec + 36, 0x60000020)      # CODE | EXECUTE | READ
    # .rsrc (RVA 0x2000 -> file 0x600)
    s2 = sec + 40
    b[s2:s2 + 8] = b".rsrc\0\0\0"
    w32(b, s2 + 8, 0x200)
    w32(b, s2 + 12, 0x2000)
    w32(b, s2 + 16, 0x200)
    w32(b, s2 + 20, 0x600)
    w32(b, s2 + 36, 0x40000040)       # INITIALIZED_DATA | READ

    # 让特征在 .text 里唯一出现（真实客户端里这就是 "按 FileDataID 读文件" 的函数入口）
    b[0x400:0x400 + len(SIGNATURE)] = SIGNATURE
    # 再放一个字符串 + 一条指向它的 RIP 相对 LEA，用来演示 wowmod discover
    anchor = b"DBFilesClient\\"
    b[0x480:0x480 + len(anchor)] = anchor
    # LEA 指令在 file 0x450 => RVA 0x1050；字符串 RVA 0x1080
    disp = 0x1080 - (0x1050 + 7)
    b[0x450:0x457] = bytes([0x48, 0x8D, 0x0D]) + struct.pack("<i", disp)

    # 资源树（RT_VERSION）@ file 0x600 / RVA 0x2000
    w16(b, 0x600 + 14, 1)
    w32(b, 0x610, 16)                  # RT_VERSION
    w32(b, 0x614, 0x80000020)          # -> 0x2020 (file 0x620)
    w16(b, 0x620 + 14, 1)
    w32(b, 0x630, 1)
    w32(b, 0x634, 0x80000040)          # -> 0x2040 (file 0x640)
    w16(b, 0x640 + 14, 1)
    w32(b, 0x650, 0x409)
    w32(b, 0x654, 0x60)                # IMAGE_RESOURCE_DATA_ENTRY @ 0x2060 (file 0x660)
    w32(b, 0x660, 0x2080)              # data RVA -> file 0x680
    w32(b, 0x664, 0x5C)

    # VS_VERSION_INFO
    w16(b, 0x680, 0x5C)
    w16(b, 0x682, 52)
    w16(b, 0x684, 0)
    key = "VS_VERSION_INFO"
    for i, ch in enumerate(key):
        w16(b, 0x686 + i * 2, ord(ch))
    w16(b, 0x686 + 30, 0)
    fixed = 0x680 + 40
    w32(b, fixed, 0xFEEF04BD)
    w32(b, fixed + 4, 0x10000)
    w32(b, fixed + 8, (major << 16) | minor)
    w32(b, fixed + 12, (patch << 16) | build)
    return bytes(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="生成的假客户端目录")
    ap.add_argument("--version", default="3.3.5.12340", help="任意版本字符串，例如 12.1.5.70783")
    ap.add_argument("--product", default="wow_private")
    ap.add_argument("--portal", default="old.server.example")
    args = ap.parse_args()

    d = args.dir
    os.makedirs(os.path.join(d, "Data", "data", "00"), exist_ok=True)
    os.makedirs(os.path.join(d, "WTF"), exist_ok=True)
    with open(os.path.join(d, "Wow.exe"), "wb") as f:
        f.write(make_pe(args.version))
    with open(os.path.join(d, ".build.info"), "w", encoding="utf-8") as f:
        f.write("Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Version!STRING:0|Product!STRING:0\n")
        f.write(f"private|1|aabbccdd|eeff0011|{args.version}|{args.product}\n")
    with open(os.path.join(d, "WTF", "Config.wtf"), "w", encoding="utf-8") as f:
        f.write(f'SET locale "zhCN"\nSET portal "{args.portal}"\nSET hwDetect "0"\n')
    with open(os.path.join(d, "Data", "data", "00", "00000001"), "wb") as f:
        f.write(b"fake casc blob")
    print(f"已生成假客户端: {d} ({args.version})")
    print("注意: 这只是用于测试加载器的合成 PE，不是游戏客户端。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
