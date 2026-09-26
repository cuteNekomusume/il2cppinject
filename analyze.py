#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze.py - 分析 Android .so，找出注入所需的关键信息（纯 Python，无第三方依赖）

产出：
  * ABI / 架构（决定放到 lib/<abi>/）
  * SONAME、依赖的库
  * 是否自启动（看 .init_array 与 JNI_OnLoad）
  * 导出的 JNI 方法 -> 反推出 Java 类名、方法名、方法签名
  * 推荐的库文件名、推荐入口方法
"""
import hashlib
import json
import os
import struct

MACHINES = {
    0x03: ("x86", "Intel 80386"),
    0x08: ("mips", "MIPS"),
    0x28: ("armeabi-v7a", "ARM"),
    0x3E: ("x86_64", "x86-64"),
    0xB7: ("arm64-v8a", "AArch64"),
    0xF3: ("riscv64", "RISC-V"),
}

PRIM = {"V": "void", "Z": "boolean", "B": "byte", "C": "char",
        "S": "short", "I": "int", "J": "long", "F": "float", "D": "double"}

# 短名 JNI 导出（没有 __ 签名后缀）时的猜测表：宁可多给参数，不要少给
SHORT_HEURISTIC = {
    "onsurfacecreate": "(Landroid/view/Surface;)V",
    "onsurfacecreated": "(Landroid/view/Surface;)V",
    "surfacecreated": "(Landroid/view/Surface;)V",
    "onsurfaceavailable": "(Landroid/view/Surface;)V",
    "onsurfacechanged": "(II)V",
    "surfacechanged": "(II)V",
    "ondrawframe": "()V",
    "drawframe": "()V",
    "onsurface": "()V",
    "oncreate": "()V",
    "onstart": "()V",
    "init": "()V",
    "initialize": "()V",
    "preload": "()V",
    "load": "()V",
    "start": "()V",
    "startup": "()V",
    "entry": "()V",
    "main": "()V",
    "setup": "()V",
    "attach": "()V",
    "attachactivity": "(Landroid/app/Activity;)V",
    "setactivity": "(Landroid/app/Activity;)V",
    "setcontext": "(Landroid/content/Context;)V",
    "ontouch": "(Landroid/view/MotionEvent;)Z",
    "ontouchevent": "(Landroid/view/MotionEvent;)Z",
    "ontouchscreen": "(Landroid/view/MotionEvent;)Z",
    "onkeydown": "(ILandroid/view/KeyEvent;)Z",
    "onkeyup": "(ILandroid/view/KeyEvent;)Z",
    "onkeyevent": "(ILandroid/view/KeyEvent;)Z",
}

# 入口方法优先级（越靠前越像“启动整个菜单”的方法）
BOOT_PRIORITY = [
    "onsurfacecreate", "onsurfacecreated", "surfacecreated", "onsurfaceavailable",
    "init", "initialize", "start", "startup", "entry", "attach", "attachbasecontext",
    "preload", "load", "onstart", "setup", "main", "oncreate", "onload",
]


def _cstr(data, off):
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", "replace")


def _unpack(data, fmt, off):
    return struct.unpack_from(fmt, data, off)


def parse_elf(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("不是 ELF 文件")
    bits = data[4]
    endian = "<" if data[5] == 1 else ">"
    if bits not in (1, 2):
        raise ValueError("非法 ELF class")

    machine, e_type = _unpack(data, endian + "HH", 0x12)
    if bits == 2:
        shoff = _unpack(data, endian + "Q", 0x28)[0]
        shentsize, shnum, shstrndx = _unpack(data, endian + "HHH", 0x3A)
    else:
        shoff = _unpack(data, endian + "I", 0x20)[0]
        shentsize, shnum, shstrndx = _unpack(data, endian + "HHH", 0x2E)

    sections = []
    for i in range(shnum):
        o = shoff + i * shentsize
        if bits == 2:
            (name, typ, flags, addr, off, size, link, info, align, entsize) = \
                _unpack(data, endian + "IIQQQQIIQQ", o)
        else:
            (name, typ, flags, addr, off, size, link, info, align, entsize) = \
                _unpack(data, endian + "IIIIIIIIII", o)
        sections.append(dict(name=name, type=typ, addr=addr, off=off, size=size,
                             link=link, entsize=entsize, sn=""))
    if shstrndx < len(sections):
        strtab = sections[shstrndx]
        for s in sections:
            s["sn"] = _cstr(data, strtab["off"] + s["name"])
    return dict(bits=bits, endian=endian, machine=machine, e_type=e_type, sections=sections)


def _section(elf, name):
    for s in elf["sections"]:
        if s["sn"] == name:
            return s
    return None


def read_dynsym(data, elf):
    sym, dynstr = _section(elf, ".dynsym"), _section(elf, ".dynstr")
    if not sym or not dynstr:
        return []
    entsize = sym["entsize"] or (24 if elf["bits"] == 2 else 16)
    out = []
    for i in range(sym["size"] // entsize):
        o = sym["off"] + i * entsize
        if elf["bits"] == 2:
            nm, info, other, shndx, value, size = _unpack(data, elf["endian"] + "IBBHQQ", o)
        else:
            nm, value, size, info, other, shndx = _unpack(data, elf["endian"] + "IIIBBH", o)
        if nm == 0:
            continue
        out.append(dict(name=_cstr(data, dynstr["off"] + nm), info=info,
                        shndx=shndx, value=value, size=size))
    return out


def read_dynamic(data, elf):
    dyn, dynstr = _section(elf, ".dynamic"), _section(elf, ".dynstr")
    info = dict(soname=None, needed=[])
    if not dyn or not dynstr:
        return info
    step = 16 if elf["bits"] == 2 else 8
    fmt = elf["endian"] + ("QQ" if elf["bits"] == 2 else "II")
    for i in range(dyn["size"] // step):
        tag, val = _unpack(data, fmt, dyn["off"] + i * step)
        if tag == 0:
            break
        if tag == 14:      # DT_SONAME
            info["soname"] = _cstr(data, dynstr["off"] + val)
        elif tag == 1:     # DT_NEEDED
            info["needed"].append(_cstr(data, dynstr["off"] + val))
    return info


def init_array_nonempty(data, elf, endian):
    sec = _section(elf, ".init_array")
    if not sec or sec["size"] == 0:
        return False
    step = 8 if elf["bits"] == 2 else 4
    for i in range(sec["size"] // step):
        v = _unpack(data, elf["endian"] + ("Q" if step == 8 else "I"), sec["off"] + i * step)[0]
        if v:
            return True
    return False


def split_jni_identifier(text):
    """把 imgui_il2cpp_tool_NativeMethods 拆成 [imgui, il2cpp, tool, NativeMethods]
    （JNI 转义：_1 -> _ , _2 -> ; , _3 -> [ ）"""
    parts, cur = [], []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "_" and i + 1 < len(text) and text[i + 1] in "123":
            cur.append({"_1": "_", "_2": ";", "_3": "["}[text[i:i + 2]])
            i += 2
            continue
        if ch == "_":
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p for p in parts if p]


def parse_mangled_jni_signature(sig):
    """解析 JNI 名字里 __ 后的签名 (如 II_V / Landroid_view_Surface_2V) -> Java 描述符"""
    types, i, cur = [], 0, None
    while i < len(sig):
        ch = sig[i]
        if ch == "_" and sig[i:i + 2] == "_3":
            cur = (cur or "") + "["
            i += 2
            continue
        if ch == "L":
            j, name = i + 1, []
            while j < len(sig):
                if sig[j:j + 2] == "_2":
                    break
                name.append(sig[j])
                j += 1
            types.append("L" + "".join(name).replace("_", "/") + ";")
            i = j + 2
            continue
        if ch in PRIM:
            types.append("V" if ch == "V" else ch)
            i += 1
            continue
        i += 1

    if not types:
        return None
    if types[-1] == "V":
        return "(" + "".join(types[:-1]) + ")V"
    return "(" + "".join(types) + ")V"


def parse_jni_symbol(sym):
    """Java_pkg_Class_method[__sig] -> (类名, 方法名, 描述符或 None)"""
    if not sym.startswith("Java_"):
        return None
    rest = sym[5:]
    if "__" in rest:
        left, sig = rest.split("__", 1)
    else:
        left, sig = rest, None
    ids = split_jni_identifier(left)
    if len(ids) < 2:
        return None
    method = ids[-1]
    klass = ".".join(ids[:-1])
    if not klass or not klass[0].isalpha():
        return None
    desc = parse_mangled_jni_signature(sig) if sig else None
    return klass, method, desc, bool(sig)


def descriptor_of_return(desc):
    if not desc:
        return "V"
    depth, i = 0, desc.find(")")
    return desc[i + 1:] if i >= 0 else "V"


def guess_descriptor(method):
    return SHORT_HEURISTIC.get(method.lower().replace("_", ""), "()V")


def analyze(path):
    data = open(path, "rb").read()
    elf = parse_elf(data)
    abi, machine_name = MACHINES.get(elf["machine"], ("unknown", hex(elf["machine"])))
    dyn = read_dynamic(data, elf)
    syms = read_dynsym(data, elf)

    exported = [s["name"] for s in syms if s["name"]]
    natives, owners = [], {}
    for s in syms:
        if s["shndx"] == 0 or (s["info"] & 0xF) != 0x2 or not s["name"].startswith("Java_"):
            continue
        parsed = parse_jni_symbol(s["name"])
        if not parsed:
            continue
        klass, method, desc, mangled = parsed
        native = dict(name=method, descriptor=desc or guess_descriptor(method),
                      from_signature=mangled, owner=klass)
        natives.append(native)
        owners.setdefault(klass, []).append(native)

    # 类名取“出现次数最多”的那个
    owner = None
    if owners:
        owner = sorted(owners.items(), key=lambda kv: (-len(kv[1]), kv[0]))[0][0]

    boot = None
    pool = [n for n in natives if owner is None or n["owner"] == owner]
    if pool:
        def rank(n):
            low = n["name"].lower()
            return (BOOT_PRIORITY.index(low) if low in BOOT_PRIORITY else len(BOOT_PRIORITY), low)
        boot = sorted(pool, key=rank)[0]

    # 库文件名（优先 SONAME）
    base = os.path.basename(path)[:-3] if path.lower().endswith(".so") else os.path.basename(path)
    if dyn["soname"]:
        son = os.path.basename(dyn["soname"])
        lib_file = son if son.endswith(".so") else son + ".so"
        lib_base = lib_file[3:-3] if lib_file.startswith("lib") else lib_file[:-3]
    else:
        lib_base = base[3:] if base.startswith("lib") else base
        lib_file = "lib" + lib_base + ".so"

    has_onload = "JNI_OnLoad" in exported
    ctors = init_array_nonempty(data, elf, elf["endian"])

    return dict(
        path=os.path.abspath(path),
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        abi=abi,
        machine=machine_name,
        bits=64 if elf["bits"] == 2 else 32,
        elf_type="DYN" if elf["e_type"] == 3 else str(elf["e_type"]),
        soname=dyn["soname"],
        needed=sorted(set(dyn["needed"])),
        has_jni_onload=has_onload,
        init_array_nonempty=ctors,
        self_starting=bool(ctors),
        java_class=owner,
        natives=natives,
        boot_method=(boot["name"] if boot else None),
        boot_descriptor=(boot["descriptor"] if boot else None),
        boot_return=(descriptor_of_return(boot["descriptor"]) if boot else None),
        lib_base=lib_base,
        lib_file=lib_file,
        warnings=([w for w in [
            None if has_onload else "该 so 没有导出 JNI_OnLoad，可能不是给 Android 用的动态库",
            None if natives else "没有找到任何 Java_* 导出符号，Java 侧无法调用它，注入后大概率没反应",
            "该 so 带 .init_array 构造器（可能加载即自启动，Java 侧不调用也可能生效）" if ctors else None,
            "该 so 没有构造器且 JNI_OnLoad 只做初始化，必须由 Java 侧调用入口方法才会启动" if (not ctors and natives) else None,
        ] if w]),
    )


def main():
    import argparse
    ap = argparse.ArgumentParser(description="分析 Android .so")
    ap.add_argument("so")
    ap.add_argument("--json", action="store_true", help="只输出 JSON")
    args = ap.parse_args()
    info = analyze(args.so)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return
    print("文件      : %s" % info["path"])
    print("大小/哈希 : %.2f MB / %s" % (info["size"] / 1048576.0, info["md5"]))
    print("架构      : %s (%s/%d 位)" % (info["abi"], info["machine"], info["bits"]))
    print("SONAME    : %s" % info["soname"])
    print("依赖      : %s" % ", ".join(info["needed"]))
    print("JNI_OnLoad: %s" % ("有" if info["has_jni_onload"] else "无"))
    print("构造器    : %s" % ("有（可能自启动）" if info["init_array_nonempty"] else "无"))
    print("Java 类   : %s" % info["java_class"])
    print("导出 JNI  :")
    for n in info["natives"]:
        print("    %s%s  (来自签名: %s)" % (n["name"], n["descriptor"], "是" if n["from_signature"] else "否"))
    print("推荐入口  : %s%s" % (info["boot_method"], info["boot_descriptor"]))
    print("库文件名  : %s   (System.loadLibrary(\"%s\"))" % (info["lib_file"], info["lib_base"]))


if __name__ == "__main__":
    main()
