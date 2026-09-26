#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ziptool.py - Termux 没有 zipalign，这里用纯 Python 实现同样的功能

规则与 `zipalign -p 4` 一致：
  * STORED（未压缩）条目：普通条目 4 字节对齐，.so 4096 字节页对齐
  * DEFLATED（压缩）条目：原样搬运，不重新压缩
"""
import struct

LFH = b"PK\x03\x04"
CDH = b"PK\x01\x02"
EOCD = b"PK\x05\x06"


def _parse_cd(data):
    off = data.rfind(EOCD)
    if off < 0:
        raise SystemExit("不是 zip（找不到 EOCD）")
    total, cd_size, cd_off = struct.unpack_from("<HII", data, off + 10)
    entries, p = [], cd_off
    for _ in range(total):
        if data[p:p + 4] != CDH:
            raise SystemExit("中央目录损坏 @%d" % p)
        (_, ver_made, ver_need, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, disk, iattr, eattr, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, p)
        entries.append(dict(ver_made=ver_made, ver_need=ver_need, flags=flags, method=method,
                            mtime=mtime, mdate=mdate, crc=crc, csize=csize, usize=usize,
                            name=data[p + 46:p + 46 + nlen],
                            extra=data[p + 46 + nlen:p + 46 + nlen + elen],
                            comment=data[p + 46 + nlen + elen:p + 46 + nlen + elen + clen],
                            iattr=iattr, eattr=eattr, lho=lho))
        p += 46 + nlen + elen + clen
    return entries


def _data_offset(data, lho):
    if data[lho:lho + 4] != LFH:
        raise SystemExit("本地文件头损坏 @%d" % lho)
    nlen, elen = struct.unpack_from("<HH", data, lho + 26)
    return lho + 30 + nlen + elen


def align(src, dst, log=print):
    data = open(src, "rb").read()
    entries = _parse_cd(data)
    out, cd = bytearray(), bytearray()
    padded = 0

    for e in entries:
        doff = _data_offset(data, e["lho"])
        raw = data[doff:doff + e["csize"]]
        flags = e["flags"] & ~0x08          # 自己写真实尺寸，去掉 data descriptor 标记
        if e["method"] == 0:
            alignment = 4096 if e["name"].endswith(b".so") else 4
        else:
            alignment = 1
        new_lho = len(out)
        pad = (-(new_lho + 30 + len(e["name"]) + 4)) % alignment
        extra = struct.pack("<HH", 0xD935, pad) + b"\x00" * pad
        if pad:
            padded += 1
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, e["ver_need"], flags, e["method"],
                           e["mtime"], e["mdate"], e["crc"], e["csize"], e["usize"],
                           len(e["name"]), len(extra))
        out += e["name"] + extra + raw
        assert (len(out) - len(raw)) % alignment == 0, "对齐失败: %s" % e["name"]
        cd += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, e["ver_made"], e["ver_need"], flags,
                          e["method"], e["mtime"], e["mdate"], e["crc"], e["csize"], e["usize"],
                          len(e["name"]), len(e["extra"]), len(e["comment"]), 0,
                          e["iattr"], e["eattr"], new_lho)
        cd += e["name"] + e["extra"] + e["comment"]

    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(cd), cd_off, 0)
    open(dst, "wb").write(out)
    log("对齐完成：%d 个条目（%d 个补了填充）" % (len(entries), padded))
    return len(entries), padded


def check(path):
    """检查对齐情况，返回未对齐条目列表"""
    import zipfile
    data = open(path, "rb").read()
    z = zipfile.ZipFile(path)
    bad = []
    for i in z.infolist():
        if i.compress_type != 0:
            continue
        doff = _data_offset(data, i.header_offset)
        a = 4096 if i.filename.endswith(".so") else 4
        if doff % a:
            bad.append((i.filename, doff, a))
    return bad, z


def dex_ok(path, name="classes.dex"):
    """校验 dex 的 adler32 / sha1，防止打包出坏 dex"""
    import hashlib
    import zipfile
    import zlib
    try:
        d = zipfile.ZipFile(path).read(name)
    except KeyError:
        return None
    if d[:4] != b"dex\n":
        return False
    checksum, sig = struct.unpack_from("<I", d, 8)[0], d[12:32]
    return (zlib.adler32(d[12:]) & 0xFFFFFFFF) == checksum and hashlib.sha1(d[32:]).digest() == sig
