#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zipedit.py - 外科式重建 APK：原样搬运压缩数据，只删/换指定条目

* 不重新压缩（2.9 GB 的包也是几秒）
* 未压缩条目按原包的对齐要求补填充（.so 4096，其它 4），保持页对齐
* 自动丢弃旧签名文件，交给 apksigner 重新签
"""
import mmap
import struct
import zlib

LFH, CDH, EOCD = b'PK\x03\x04', b'PK\x01\x02', b'PK\x05\x06'
SIG_FILES = {'META-INF/MANIFEST.MF'}


def _align_of(offset, method):
    if method != 0:
        return 1
    return 4096 if offset % 4096 == 0 else 4


def is_signature(name):
    if name in SIG_FILES:
        return True
    up = name.upper()
    return up.startswith('META-INF/') and (up.endswith('.RSA') or up.endswith('.DSA')
                                          or up.endswith('.EC') or up.endswith('.SF'))


def rewrite(src, dst, drop=(), replace=None, keep_signatures=False, log=print):
    """drop: 要删除的条目名集合; replace: {条目名: 新内容(bytes)}"""
    drop = set(drop)
    replace = dict(replace or {})
    f = open(src, 'rb')
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    e = mm.rfind(EOCD)
    total, cd_size, cd_off, clen = struct.unpack_from('<HIIH', mm, e + 10)
    comment = mm[e + 22:e + 22 + clen]

    out = open(dst, 'wb', buffering=1 << 20)
    cd = bytearray()
    p = cd_off
    kept, dropped, replaced = 0, [], []

    for _ in range(total):
        (_, vm, vn, flags, method, mtime, mdate, crc, csize, usize,
         nl, el, cl, dk, ia, ea, lho) = struct.unpack_from('<IHHHHHHIIIHHHHHII', mm, p)
        name = mm[p + 46:p + 46 + nl].decode('utf-8', 'replace')
        cextra = mm[p + 46 + nl:p + 46 + nl + el]
        ccomment = mm[p + 46 + nl + el:p + 46 + nl + el + cl]
        p += 46 + nl + el + cl

        if name in drop or (not keep_signatures and is_signature(name)):
            dropped.append(name)
            continue

        lnl, lel = struct.unpack_from('<HH', mm, lho + 26)
        doff = lho + 30 + lnl + lel

        if name in replace:
            raw = replace[name]
            crc, usize = zlib.crc32(raw) & 0xffffffff, len(raw)
            co = zlib.compressobj(6, zlib.DEFLATED, -15)
            body = co.compress(raw) + co.flush()
            csize, method, flags = len(body), 8, flags & ~0x08
            replaced.append(name)
        else:
            body = mm[doff:doff + csize]

        align = _align_of(doff, method)
        new_lho = out.tell()
        pad = (-(new_lho + 30 + nl + 4)) % align
        xextra = struct.pack('<HH', 0xD935, pad) + b'\x00' * pad
        out.write(struct.pack('<IHHHHHIIIHH', 0x04034B50, vn, flags & ~0x08, method,
                              mtime, mdate, crc, csize, usize, nl, len(xextra)))
        out.write(name.encode('utf-8'))
        out.write(xextra)
        out.write(body)
        assert (new_lho + 30 + nl + len(xextra)) % align == 0, "对齐失败 " + name

        cd += struct.pack('<IHHHHHHIIIHHHHHII', 0x02014B50, vm, vn, flags & ~0x08, method,
                          mtime, mdate, crc, csize, usize, nl, len(cextra), len(ccomment),
                          0, ia, ea, new_lho)
        cd += name.encode('utf-8') + cextra + ccomment
        kept += 1

    cd_off_new = out.tell()
    out.write(cd)
    out.write(struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, kept, kept, len(cd), cd_off_new,
                          len(comment)) + comment)
    out.close()
    mm.close()
    f.close()
    log("重建完成：保留 %d 条目，删除 %d（%s），替换 %d"
        % (kept, len(dropped), ", ".join(dropped) or "无", len(replaced)))
    return dict(kept=kept, dropped=dropped, replaced=replaced)
