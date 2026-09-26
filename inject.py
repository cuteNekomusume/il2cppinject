#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
il2cppinject - 手机端（Termux）IL2CPP / Unity APK 注入器

用法：
    ./inject                      # 交互菜单（推荐）
    ./inject 游戏.apk 菜单.so      # 直接一条龙注入
    ./inject --analyze-so x.so    # 只分析 so
    ./inject --verify y.apk       # 验证 APK
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

import patcher                      # noqa: E402
import stripmenu                    # noqa: E402
import zipedit                      # noqa: E402
import ziptool                      # noqa: E402
from analyze import analyze         # noqa: E402

WORK = os.path.join(BASE, ".work")
KEYSTORE = os.path.join(BASE, "keystore.jks")
KS_PASS = "il2cppinject"
KS_ALIAS = "il2cppinject"
DEFAULT_OUTDIR = "/sdcard/Download"
SCAN_DIRS = ["/sdcard/Download", "/sdcard/Documents", "/sdcard", os.path.expanduser("~")]
VERSION = "1.1.2"

TTY = sys.stdout.isatty()


def col(text, code):
    return "\033[%sm%s\033[0m" % (code, text) if TTY else text


def head(t):
    print("\n" + col("══ %s " % t, "1;36") + col("═" * max(0, 46 - len(t)), "36"))


def step(t):
    print(col("▶ ", "1;33") + t)


def ok(t):
    print(col("  ✔ ", "1;32") + t)


def warn(t):
    print(col("  ! ", "1;33") + t)


def bad(t):
    print(col("  ✘ ", "1;31") + t)


def note(t):
    print("    " + col(t, "90"))


def ask(prompt, default=""):
    try:
        s = input(col("? ", "1;35") + prompt + (" [%s]" % default if default else "") + ": ").strip()
    except EOFError:
        return default
    return s or default


def choose(prompt, options, default=1):
    """options: [(标题, 值), ...] 返回选中的值"""
    print()
    for i, (title, _) in enumerate(options, 1):
        print("   %s) %s" % (col(str(i), "1;36"), title))
    while True:
        s = ask(prompt, str(default))
        if s.isdigit() and 1 <= int(s) <= len(options):
            return options[int(s) - 1][1]
        bad("请输入 1-%d" % len(options))


def yes(prompt, default=True):
    s = ask(prompt + ("(Y/n)" if default else "(y/N)"), "y" if default else "n").lower()
    return s.startswith("y")


# ------------------------------------------------------------------ 环境
def missing_deps():
    need = {"java": "openjdk-17", "apktool": "apktool",
            "apksigner": "apksigner", "keytool": "openjdk-17", "python3": "python"}
    return sorted({pkg for cmd, pkg in need.items() if not shutil.which(cmd)})


def check_deps(auto=True):
    miss = missing_deps()
    if not miss:
        return True
    bad("缺少依赖：" + " ".join(miss))
    note("安装命令：pkg install " + " ".join(miss))
    if auto and shutil.which("pkg") and yes("现在自动安装？", True):
        subprocess.call(["pkg", "install", "-y"] + miss)
        return not missing_deps()
    return False


def run(cmd, logf, cwd=None):
    logf.write("\n$ %s\n" % " ".join(cmd))
    logf.flush()
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, bufsize=1,
                         errors="replace")
    for line in p.stdout:
        line = line.rstrip("\n")
        if line.strip():
            print("   " + col(line, "90"))
        logf.write(line + "\n")
    logf.flush()
    return p.wait()


def run_capture(cmd, logf, cwd=None):
    """跑命令并把输出同时回显/写日志，返回 (返回码, 输出文本)"""
    logf.write("\n$ %s\n" % " ".join(cmd))
    logf.flush()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")
    txt = (p.stdout or "") + (p.stderr or "")
    for line in txt.splitlines():
        print("   " + col(line, "90"))
    logf.write(txt + "\n")
    logf.flush()
    return p.returncode, txt


def resolve_out(out, apk):
    """输出路径是目录（或以 / 结尾）时自动补上文件名"""
    out = os.path.expanduser(out.strip().strip("'\""))
    stem = os.path.splitext(os.path.basename(apk))[0]
    fname = stem + (".apk" if stem.upper().endswith("_MOD") else "_MOD.apk")
    if out.endswith("/") or os.path.isdir(out):
        return os.path.join(out, fname)
    return out


def check_out(out, apk_size=0):
    """开始干活之前先确认输出路径没问题，返回 (是否可以, 说明)"""
    out = resolve_out(out, "x.apk") if out.endswith("/") else out
    d = os.path.dirname(os.path.abspath(out)) or "."
    if os.path.isdir(out):
        return False, "输出路径 %s 是一个目录，请写成完整文件名，例如 %s" % (
            out, os.path.join(out, os.path.basename(out) + "_MOD.apk"))
    if not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            return False, "输出目录不存在且无法创建：%s（%s）" % (d, e)
    if not os.access(d, os.W_OK):
        return False, "输出目录不可写：%s" % d
    if apk_size:
        need = apk_size * 3
        free = shutil.disk_usage(d).free
        if free < need:
            return False, "空间不足：需要约 %.1f GB，%s 只剩 %.1f GB" % (
                need / 2 ** 30, d, free / 2 ** 30)
    return True, out


def ensure_keystore(log=print):
    if os.path.isfile(KEYSTORE):
        return True
    log("生成签名证书 %s" % KEYSTORE)
    rc = subprocess.call([
        "keytool", "-genkeypair", "-keystore", KEYSTORE, "-storepass", KS_PASS,
        "-keypass", KS_PASS, "-alias", KS_ALIAS, "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000", "-dname", "CN=il2cppinject, O=Mod, C=NA"],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return rc == 0


# ------------------------------------------------------------------ 文件选择
def scan(exts, dirs=SCAN_DIRS, limit=40):
    found = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for n in names:
            if n.lower().endswith(tuple(exts)):
                p = os.path.join(d, n)
                if os.path.isfile(p):
                    found.append(p)
    found.sort(key=lambda p: -os.path.getmtime(p))
    return found[:limit]


def pick_file(title, exts):
    head(title)
    items = scan(exts)
    for i, p in enumerate(items, 1):
        print("   %s) %s %s" % (col(str(i), "1;36"), col(os.path.basename(p), "0"),
                                col("(%.1f MB)  %s" % (os.path.getsize(p) / 1048576.0,
                                                       os.path.dirname(p)), "90")))
    print("   %s) 手动输入路径" % col("m", "1;36"))
    while True:
        s = ask("请选择", "1" if items else "m")
        if s.lower() == "m" or (not items and s == "m"):
            p = ask("完整路径")
            p = os.path.expanduser(p.strip().strip("'\""))
            if os.path.isfile(p):
                return p
            bad("找不到文件：%s" % p)
            continue
        if s.isdigit() and 1 <= int(s) <= len(items):
            return items[int(s) - 1]
        bad("无效选择")


# ------------------------------------------------------------------ 主流程
def sanitize(name):
    return re.sub(r"[^0-9A-Za-z._\u4e00-\u9fff-]", "_", name)


def pipeline(apk, so, out, cfg, logf):
    t0 = time.time()
    apk, so = os.path.abspath(apk), os.path.abspath(so)

    head("1/7 分析目标 so")
    info = analyze(so)
    ok("架构 %s   SONAME %s" % (info["abi"], info["soname"]))
    ok("Java 类 %s" % info["java_class"])
    ok("入口 %s%s" % (info["boot_method"], info["boot_descriptor"]))
    for w in info["warnings"]:
        warn(w)

    if not info["java_class"]:
        if not info["self_starting"]:
            raise SystemExit("这个 so 既没有 JNI 导出、也没有构造器，注入后不会生效")
        boot_method, boot_desc = None, None
        pkg = cfg.get("pkg") or "il2cpp.inject"
        cls = cfg.get("cls") or "Loader"
        ok("该 so 自启动（.init_array 有构造器），只做加载，不调用入口")
    else:
        pkg = cfg.get("pkg") or ".".join(info["java_class"].split(".")[:-1])
        cls = cfg.get("cls") or info["java_class"].split(".")[-1]
        boot_method = cfg.get("boot_method") or info["boot_method"]
        boot_desc = cfg.get("boot_descriptor") or info["boot_descriptor"]

    lib_base = cfg.get("libname") or info["lib_base"]
    lib_file = cfg.get("libfile") or ("lib%s.so" % lib_base)
    abi = cfg.get("abi") or info["abi"]
    mode = cfg.get("mode", "activity")
    boot_on = cfg.get("boot_on", "focus")
    delay = cfg.get("delay", 6)

    if abi == "unknown":
        raise SystemExit("无法识别 so 架构，请用 --abi 指定")
    logf.write(json.dumps(info, ensure_ascii=False, indent=2) + "\n")

    out = resolve_out(out, apk)
    ok_out, msg = check_out(out, os.path.getsize(apk))
    if not ok_out:
        raise SystemExit(msg)
    out = msg
    ok("输出：%s" % out)

    wd = os.path.join(WORK, "%s_%s" % (sanitize(os.path.basename(apk))[:28],
                                       time.strftime("%m%d-%H%M%S")))
    os.makedirs(wd, exist_ok=True)
    src = os.path.join(wd, "orig.apk")
    shutil.copy2(apk, src)
    logf.write("工作目录: %s\n" % wd)

    head("2/7 反编译 APK（大包约 1-3 分钟，请勿退出）")
    decoded = os.path.join(wd, "decoded")
    if run(["apktool", "d", "-f", "-o", decoded, src], logf) != 0:
        raise SystemExit("apktool 反编译失败，详见日志")

    head("3/7 放入 so")
    libdir = os.path.join(decoded, "lib", abi)
    have_abis = []
    libroot = os.path.join(decoded, "lib")
    if os.path.isdir(libroot):
        have_abis = sorted(os.listdir(libroot))
    os.makedirs(libdir, exist_ok=True)
    dst_so = os.path.join(libdir, lib_file)
    if os.path.isfile(dst_so):
        warn("覆盖已存在的 %s/%s" % (abi, lib_file))
    shutil.copy2(so, dst_so)
    ok("已放入 lib/%s/%s（%.1f MB）" % (abi, lib_file, os.path.getsize(so) / 1048576.0))
    if have_abis and abi not in have_abis:
        warn("该 APK 原本只有 ABI %s，注入的 %s 只在对应 CPU 上生效" % (",".join(have_abis), abi))
    if not os.path.isfile(os.path.join(decoded, "lib", abi, "libil2cpp.so")):
        if any(os.path.isfile(os.path.join(libroot, a, "libil2cpp.so")) for a in have_abis
               if os.path.isdir(os.path.join(libroot, a))):
            note("检测到 libil2cpp.so，确认是 IL2CPP 游戏")
        else:
            warn("没看到 libil2cpp.so，这可能不是 IL2CPP/Unity 游戏（仍可继续）")

    head("4/7 生成加载器并打补丁")
    res = patcher.patch(decoded, pkg, cls, lib_base, info["natives"],
                        boot_method, boot_desc, boot_on=boot_on, delay=delay,
                        mode=mode, log=ok)
    logf.write(json.dumps(res, ensure_ascii=False, indent=2) + "\n")

    head("5/7 重新打包")
    unsigned = os.path.join(wd, "unsigned.apk")
    if run(["apktool", "b", "-f", "-o", unsigned, decoded], logf) != 0:
        raise SystemExit("apktool 打包失败，详见日志")
    ok("打包完成 %.1f MB" % (os.path.getsize(unsigned) / 1048576.0))

    head("6/7 对齐 + 签名")
    aligned = os.path.join(wd, "aligned.apk")
    ziptool.align(unsigned, aligned, log=ok)
    if not ensure_keystore(log=ok):
        raise SystemExit("生成签名证书失败")
    final = os.path.abspath(out)
    os.makedirs(os.path.dirname(final) or ".", exist_ok=True)
    rc, txt = run_capture(["apksigner", "sign", "--ks", KEYSTORE,
                           "--ks-pass", "pass:" + KS_PASS, "--key-pass", "pass:" + KS_PASS,
                           "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                           "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--alignment-preserved", "true", "-out", final, aligned], logf)
    if rc != 0:
        tail = [l for l in txt.splitlines() if l.strip()][-3:]
        note("打包好的 APK 还留在 %s" % wd)
        note("可以只重新签名：./inject --resign \"%s\"" % wd)
        raise SystemExit("签名失败：" + (" / ".join(tail) if tail else "未知错误"))

    head("7/7 校验产物")
    lines = verify_apk(final, quiet=True)
    for l in lines:
        ok(l) if l.startswith("OK") else warn(l)
    logf.write("\n".join(lines) + "\n")

    size = os.path.getsize(final) / 1048576.0
    print()
    print(col(" ✔ 完成！%s  (%.1f MB，用时 %.0f 秒)" % (final, size, time.time() - t0), "1;32"))
    return dict(final=final, wd=wd, decoded=decoded, info=info, patched=res)


def verify_apk(path, quiet=False):
    out = []
    if not os.path.isfile(path):
        raise SystemExit("文件不存在: %s" % path)
    out.append("OK 文件 %.1f MB" % (os.path.getsize(path) / 1048576.0))
    # 签名
    p = subprocess.run(["apksigner", "verify", "-v", path], capture_output=True, text=True)
    txt = (p.stdout or "") + (p.stderr or "")
    if p.returncode == 0:
        schemes = [s.split()[-1] for s in txt.splitlines()
                   if s.startswith("Verified using v") and s.strip().endswith("true")]
        out.append("OK 签名有效（%s）" % ("、".join(schemes) or "v1/v2/v3"))
    else:
        out.append("签名校验失败: " + txt.strip().splitlines()[-1:][0] if txt.strip() else "签名校验失败")
    # dex
    d = ziptool.dex_ok(path)
    out.append("OK classes.dex 校验和正常" if d else "classes.dex 校验和异常")
    # 对齐
    bad_align, z = ziptool.check(path)
    out.append("OK 未压缩条目均已对齐" if not bad_align
               else "未对齐条目 %d 个（安装一般仍可用）" % len(bad_align))
    # 内容
    names = z.namelist()
    libs = [n for n in names if n.startswith("lib/")]
    out.append("OK 包含 %d 个 so：%s" % (
        len(libs), ", ".join(sorted({n.split("/")[1] for n in libs}))))
    # Unity / 运行库自带的 so 不算“注入的库”
    mods = [n for n in libs if re.search(r"(tool|mod|menu|cheat|hack|inject|il2cpptool)",
                                         os.path.basename(n), re.I)]
    if mods:
        for n in sorted(mods):
            out.append("OK 菜单类 so：%s（%.1f MB）"
                       % (n, z.getinfo(n).file_size / 1048576.0))
    out.append("OK 全部 so：%s" % ", ".join(sorted(os.path.basename(n) for n in libs)))
    if not quiet:
        print()
        for l in out:
            (ok if l.startswith("OK") else warn)(l)
    return out


# ------------------------------------------------------------------ 交互向导
def wizard():
    if not check_deps():
        return
    head("IL2CPP 注入向导")

    apk = pick_file("选择要注入的 APK", [".apk", ".apks", ".xapk"])
    so = pick_file("选择要注入的 so（菜单/工具库）", [".so"])

    head("分析 so")
    info = analyze(so)
    print("   架构      : %s (%d 位)" % (col(info["abi"], "1;32"), info["bits"]))
    print("   SONAME    : %s" % info["soname"])
    print("   Java 类   : %s" % col(info["java_class"] or "未识别", "1;32"))
    print("   入口方法  : %s%s" % (info["boot_method"], info["boot_descriptor"]))
    print("   库文件名  : %s   → System.loadLibrary(\"%s\")" % (info["lib_file"], info["lib_base"]))
    for w in info["warnings"]:
        warn(w)
    if not info["java_class"]:
        if not info["self_starting"]:
            bad("这个 so 既没有 JNI 导出、也没有构造器，没法注入")
            return
        warn("该 so 没有 JNI 导出，但有构造器 → 只做加载（自动模式）")
        pkg, cls = "il2cpp.inject", "Loader"
        boot_method = None
    else:
        pkg = ".".join(info["java_class"].split(".")[:-1])
        cls = info["java_class"].split(".")[-1]
        boot_method = info["boot_method"]
    lib_base = info["lib_base"]

    mode = choose("注入方式", [
        ("自动（先试 activity，被加固成 native 就改 app 模式）—— 推荐", "auto"),
        ("activity 模式：改启动 Activity", "activity"),
        ("app 模式：新建 Application 类，注册到清单里", "app"),
    ], 1)
    boot_on = choose("菜单启动时机", [
        ("窗口获得焦点时启动（推荐，最准）", "focus"),
        ("进游戏 %d 秒后启动（最稳，适合卡住/不显示）" % 6, "delay"),
        ("onResume 时启动", "resume"),
        ("onCreate 时启动（最早）", "create"),
    ], 1)

    default_out = os.path.join(DEFAULT_OUTDIR,
                               os.path.splitext(os.path.basename(apk))[0] + "_MOD.apk")
    while True:
        out = resolve_out(ask("输出 APK 路径", default_out), apk)
        good, msg = check_out(out, os.path.getsize(apk))
        if good:
            out = msg
            break
        bad(msg)
        default_out = os.path.join(os.path.dirname(out) or DEFAULT_OUTDIR,
                                   os.path.splitext(os.path.basename(apk))[0] + "_MOD.apk")

    if yes("修改高级参数（包名/类名/库名/入口）？", False):
        pkg = ask("Java 包名", pkg)
        cls = ask("Java 类名", cls)
        lib_base = ask("loadLibrary 名字", lib_base)
        boot_method = ask("入口方法名", boot_method)

    head("确认")
    print("   输入 APK : %s" % apk)
    print("   输入 SO  : %s" % so)
    print("   输出 APK : %s" % out)
    print("   注入方式 : %s / 启动时机 %s" % (mode, boot_on))
    if not yes("开始注入？", True):
        return

    logpath = os.path.join(BASE, "last_run.log")
    with open(logpath, "w", encoding="utf-8") as logf:
        try:
            r = pipeline(apk, so, out, dict(mode=mode, boot_on=boot_on), logf)
        except SystemExit as e:
            bad(str(e))
            note("日志：%s" % logpath)
            return
        except KeyboardInterrupt:
            bad("已中断")
            return

    after_build(r, logpath)


def after_build(r, logpath):
    final = r["final"]
    if not final.startswith(DEFAULT_OUTDIR + "/") and os.path.isdir(DEFAULT_OUTDIR):
        if yes("复制一份到 %s ？" % DEFAULT_OUTDIR, True):
            dst = os.path.join(DEFAULT_OUTDIR, os.path.basename(final))
            shutil.copy2(final, dst)
            ok("已复制到 %s" % dst)
            final = dst
    if yes("现在安装？", False):
        install(final)
    if yes("删除临时文件（反编译工程，省空间）？", True):
        shutil.rmtree(r["wd"], ignore_errors=True)
        ok("已清理 %s" % r["wd"])
    note("日志：%s" % logpath)


def install(path):
    if shutil.which("termux-open"):
        step("正在调起安装界面…")
        subprocess.call(["termux-open", "--content-type",
                         "application/vnd.android.package-archive", path])
        return
    note("请用文件管理器打开：%s" % path)


# ------------------------------------------------------------------ 去除注入的菜单
def print_scan(rep):
    head("检测结果")
    print("   目标包 : %s" % rep["apk"])
    print("   包名   : %s" % (rep["package"] or "未知"))
    print("   dex    : %d 个    so：%d 个" % (len(rep["dexs"]), len(rep["libs"])))
    if not rep["mods"]:
        warn("没有检测到注入的菜单（so + Java 加载器），不用清理")
        return False
    for i, m in enumerate(rep["mods"], 1):
        print(col("   ▶ [%d] 疑似注入模块：%s（%.1f MB）"
                  % (i, m["base"], m["size"] / 1048576.0), "1;33"))
        print("       架构      : %s" % ", ".join(sorted(set(m["abis"]))))
        print("       so 条目   : %s" % ", ".join(m["entries"]))
        print("       Java 加载器: %s" % (m["java_class"] or "未识别"))
        print("       处理方式  : %s" % ("删除整包 " + ", ".join(m["packages"])
                                        if m["packages"] else "只删加载器类 %s" % m["java_class"]))
        for e in m["evidence"]:
            print("       证据      : %s" % col(e, "90"))
    for l in rep["libs"]:
        if not l["is_mod"]:
            if l["runtime"]:
                why = "系统/引擎库"
            elif l.get("self_lib"):
                why = "应用自身的库（JNI 类是清单里的组件/应用自身包）"
            else:
                why = "无加载器特征（不是自带 Java 加载器的菜单）"
            note("保留 %s（%s）" % (l["entry"], why))
    return True


def pick_mods(rep):
    """让用户选要清除哪些模块；返回 [] 表示全部"""
    mods = rep["mods"]
    if len(mods) == 1:
        m = mods[0]
        return [m["base"]] if yes("确认移除 [1] %s？" % m["base"], True) else None
    print()
    print("   检测到 %d 个注入模块，请选择要清除的：" % len(mods))
    for i, m in enumerate(mods, 1):
        print("     %-3s %-24s 加载器 %-34s %6.1f MB"
              % ("%d)" % i, m["base"], m["java_class"] or "无", m["size"] / 1048576.0))
    while True:
        s = ask("输入序号（如 1,3 / all / 回车=全部）", "all").strip().lower()
        if s in ("", "all", "a", "*"):
            return [m["base"] for m in mods]
        try:
            idx = [int(x) for x in re.split(r"[,\s]+", s) if x]
        except ValueError:
            bad("格式不对，例如 1,3")
            continue
        if idx and all(1 <= i <= len(mods) for i in idx):
            picked = [mods[i - 1]["base"] for i in sorted(set(idx))]
            ok("将清除：" + ", ".join(picked))
            return picked
        bad("序号要在 1-%d 之间" % len(mods))


def strip_verify(final, r):
    """复查成品：so 没了、类没了、签名有效"""
    out = []
    z = zipfile.ZipFile(final)
    names = z.namelist()
    left_libs = [n for n in names if os.path.basename(n) in {os.path.basename(x) for x in r["dropped"]}]
    out.append(("OK " if not left_libs else "⚠ ") + "注入的 so：%s"
               % ("已全部移除" if not left_libs else "仍存在 " + ", ".join(left_libs)))
    prefixes = sorted({p for m in r["report"]["mods"] for p in m["prefixes"]})
    hit = []
    for n in names:
        if re.fullmatch(r"classes\d*\.dex", n):
            d = z.read(n)
            for p in prefixes:
                if p.encode() in d:
                    hit.append("%s→%s" % (n, p))
    out.append(("OK " if not hit else "⚠ ") + "加载器类残留：%s"
               % ("无" if not hit else ", ".join(hit)))
    out.append("OK 被删除条目：%s" % ", ".join(os.path.basename(x) for x in r["dropped"]))
    if r["stats"]["calls"]:
        out.append("OK 清理调用点 %d 处（应用侧调用已删）" % len(r["stats"]["calls"]))
    return out


def do_strip(apk, out=None, dry=False, force=False, keep_work=False, force_so=(),
             only=(), interactive=True):
    if not check_deps():
        return
    rep = stripmenu.scan(apk, log=note, force_so=force_so)
    if not print_scan(rep) or dry:
        return
    picker_used = False
    if interactive:
        only = pick_mods(rep)
        picker_used = True
        if only is None:            # 用户在单选确认里选了否
            return
    default_out = os.path.join(DEFAULT_OUTDIR,
                               os.path.splitext(os.path.basename(apk))[0] + "_STRIPPED.apk")
    out = resolve_out(out or ask("输出 APK 路径", default_out), default_out)
    good, msg = check_out(out, os.path.getsize(apk))
    if not good:
        bad(msg)
        return
    out = msg
    if not picker_used and not only:
        # 非交互/自动模式：只自动清理带 hook 特征的（Dobby/imgui/…），
        # 其余候选（可能只是正常插件 SDK 的 JNI 绑定）必须显式指定，避免误删引擎库
        auto = [m["base"] for m in rep["mods"] if m.get("hooky") or m.get("forced")]
        skip = [m for m in rep["mods"] if not (m.get("hooky") or m.get("forced"))]
        if skip:
            warn("以下候选没有 hook 特征，自动模式不处理（可能是正常插件 SDK）：")
            for m in skip:
                note("%s（加载器 %s）→ 要删请加 --strip-only %s"
                     % (m["base"], m["java_class"] or "无", m["base"]))
        if not auto:
            bad("没有被识别为菜单的模块，需要手动指定 --strip-only <库名>")
            return
        only = auto
    if not interactive and not yes("确认移除上面这些内容？", True):
        return

    wd = os.path.join(WORK, "strip_%s_%s" % (sanitize(os.path.basename(apk))[:24],
                                             time.strftime("%m%d-%H%M%S")))
    os.makedirs(wd, exist_ok=True)
    logpath = os.path.join(BASE, "last_run.log")
    with open(logpath, "a", encoding="utf-8") as logf:
        logf.write("\n===== strip %s =====\n" % apk)
        try:
            r = stripmenu.strip(apk, out, wd, force=force, force_so=force_so,
                                only=only, log=ok)
        except SystemExit as e:
            bad(str(e))
            return
        if not ensure_keystore(log=ok):
            bad("生成签名证书失败")
            return
        rc, txt = run_capture(["apksigner", "sign", "--ks", KEYSTORE,
                               "--ks-pass", "pass:" + KS_PASS, "--key-pass", "pass:" + KS_PASS,
                               "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                               "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
                               "--alignment-preserved", "true", "-out", out, r["unsigned"]], logf)
        if rc != 0:
            tail = [l for l in txt.splitlines() if l.strip()][-3:]
            bad("签名失败：" + (" / ".join(tail) if tail else "未知错误"))
            return
    head("复查")
    for l in strip_verify(out, r) + verify_apk(out, quiet=True):
        (ok if l.startswith("OK") else warn)(l)
    print()
    print(col(" ✔ 已清理：%s  (%.1f MB)" % (out, os.path.getsize(out) / 1048576.0), "1;32"))
    if yes("现在安装？（记得先卸载原版，签名不同）", False):
        install(out)
    if not keep_work:
        shutil.rmtree(wd, ignore_errors=True)
    note("日志：%s" % logpath)


# ------------------------------------------------------------------ 重新签名
def find_artifact(path):
    """给出 APK 文件 / 工作目录 / .work 目录，找出可签名的包"""
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        for name in ("aligned.apk", "unsigned.apk"):
            p = os.path.join(path, name)
            if os.path.isfile(p):
                return p
        subs = []
        for n in os.listdir(path):
            d = os.path.join(path, n)
            if os.path.isdir(d):
                for name in ("aligned.apk", "unsigned.apk"):
                    p = os.path.join(d, name)
                    if os.path.isfile(p):
                        subs.append((os.path.getmtime(p), p))
        if subs:
            return sorted(subs)[-1][1]
        for n in os.listdir(path):
            if n.lower().endswith(".apk"):
                return os.path.join(path, n)
    return None


def resign(target, out=None):
    if not check_deps():
        return
    src = find_artifact(target)
    if not src:
        bad("在 %s 里找不到 aligned.apk / unsigned.apk / apk" % target)
        return
    ok("要签名的包：%s（%.1f MB）" % (src, os.path.getsize(src) / 1048576.0))
    base = os.path.basename(src)
    if base in ("aligned.apk", "unsigned.apk"):
        # 用工作目录名（=原 APK 名 + 时间戳）当默认输出名
        base = re.sub(r"_\d{4}-\d{6}$", "", os.path.basename(os.path.dirname(src))) or "mod"
    default_out = os.path.join(DEFAULT_OUTDIR, os.path.splitext(base)[0] + "_MOD.apk")
    out = resolve_out(out or ask("输出 APK 路径", default_out), default_out)
    good, msg = check_out(out, os.path.getsize(src))
    if not good:
        bad(msg)
        return
    out = msg
    if not ensure_keystore(log=ok):
        bad("生成签名证书失败")
        return
    logpath = os.path.join(BASE, "last_run.log")
    with open(logpath, "a", encoding="utf-8") as logf:
        rc, txt = run_capture(["apksigner", "sign", "--ks", KEYSTORE,
                               "--ks-pass", "pass:" + KS_PASS, "--key-pass", "pass:" + KS_PASS,
                               "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                               "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--alignment-preserved", "true", "-out", out, src], logf)
    if rc != 0:
        tail = [l for l in txt.splitlines() if l.strip()][-3:]
        bad("签名失败：" + (" / ".join(tail) if tail else "未知错误"))
        return
    print()
    print(col(" ✔ 完成！%s  (%.1f MB)" % (out, os.path.getsize(out) / 1048576.0), "1;32"))
    for l in verify_apk(out, quiet=True):
        ok(l) if l.startswith("OK") else warn(l)
    if yes("现在安装？", False):
        install(out)


# ------------------------------------------------------------------ 菜单
def menu():
    while True:
        print()
        print(col("╔══════════════════════════════════════════╗", "1;36"))
        print(col("║", "1;36") + "     IL2CPP 注入器 v%s  (Termux)        " % VERSION +
              col("║", "1;36"))
        print(col("╚══════════════════════════════════════════╝", "1;36"))
        print("   %s) 注入 APK（向导）" % col("1", "1;36"))
        print("   %s) 只分析 so" % col("2", "1;36"))
        print("   %s) 验证 APK（签名/对齐/dex）" % col("3", "1;36"))
        print("   %s) 重新签名（包已打好，只差签名）" % col("4", "1;36"))
        print("   %s) 去除注入的菜单（还原包）" % col("5", "1;36"))
        print("   %s) 清理临时文件" % col("6", "1;36"))
        print("   %s) 退出" % col("0", "1;36"))
        c = ask("选择", "1")
        if c == "1":
            wizard()
        elif c == "2":
            if check_deps(auto=False):
                so = pick_file("选择 so", [".so"])
                print()
                subprocess.call([sys.executable, os.path.join(BASE, "analyze.py"), so])
        elif c == "3":
            if check_deps(auto=False):
                apk = pick_file("选择 APK", [".apk"])
                verify_apk(apk)
        elif c == "4":
            if os.path.isdir(WORK) and os.listdir(WORK):
                note("可以直接回车，用最近一次打包的产物重新签名")
            resign(ask("APK 文件或工作目录", WORK))
        elif c == "5":
            do_strip(pick_file("选择要清理的 APK", [".apk"]))
        elif c == "6":
            clean_work()
        elif c in ("0", "q", "exit"):
            return
        else:
            bad("无效选择")


def clean_work():
    if not os.path.isdir(WORK):
        ok("没有临时文件")
        return
    total = 0
    for root, _dirs, files in os.walk(WORK):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    print("   临时目录 %s 共 %.1f MB" % (WORK, total / 1048576.0))
    if yes("全部删除？", True):
        shutil.rmtree(WORK, ignore_errors=True)
        ok("已清理")


# ------------------------------------------------------------------ 命令行
def main():
    ap = argparse.ArgumentParser(
        description="IL2CPP/Unity APK 注入器（手机端）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="不带参数运行会进入交互菜单")
    ap.add_argument("apk", nargs="?", help="目标 APK")
    ap.add_argument("so", nargs="?", help="要注入的 .so")
    ap.add_argument("-o", "--output", help="输出 APK 路径")
    ap.add_argument("--mode", choices=["auto", "activity", "app"], default="auto",
                    help="auto 会先试 activity，方法被加固成 native 就自动改 app 模式")
    ap.add_argument("--boot-on", choices=["focus", "resume", "delay", "create"], default="focus")
    ap.add_argument("--delay", type=int, default=6, help="boot-on=delay 时的秒数")
    ap.add_argument("--libname", help="loadLibrary 的名字（默认从 SONAME 推）")
    ap.add_argument("--libfile", help="放进 lib/<abi>/ 的文件名（默认 lib<libname>.so）")
    ap.add_argument("--pkg", help="覆盖 Java 包名")
    ap.add_argument("--class", dest="cls", help="覆盖 Java 类名")
    ap.add_argument("--boot-method", help="覆盖入口方法名")
    ap.add_argument("--abi", help="覆盖 ABI 目录")
    ap.add_argument("--keep-work", action="store_true", help="保留反编译工程")
    ap.add_argument("--analyze-so", metavar="SO", help="只分析 so")
    ap.add_argument("--verify", metavar="APK", help="验证 APK")
    ap.add_argument("--clean", action="store_true", help="清理临时文件")
    ap.add_argument("--resign", metavar="APK或工作目录",
                    help="只给已经打好包的 APK 重新签名")
    ap.add_argument("--strip", metavar="APK", help="检测并移除注入的 mod 菜单（so+加载器+调用点）")
    ap.add_argument("--strip-dry-run", action="store_true", help="只检测报告，不修改")
    ap.add_argument("--strip-force", action="store_true", help="有外部引用时仍继续")
    ap.add_argument("--strip-only", action="append", default=[], metavar="NAME",
                    help="只清除指定的注入模块（库名/加载器类名，可重复）")
    ap.add_argument("--strip-so", action="append", default=[], metavar="NAME",
                    help="手动指定要移除的 so（可重复），用于没有 JNI 导出的自启动库")
    a = ap.parse_args()

    if a.strip:
        check_deps(auto=False)
        do_strip(a.strip, a.output, dry=a.strip_dry_run, force=a.strip_force,
                 keep_work=a.keep_work, force_so=a.strip_so, only=a.strip_only,
                 interactive=not (a.strip_only or a.strip_dry_run))
        return

    if a.analyze_so:
        subprocess.call([sys.executable, os.path.join(BASE, "analyze.py"), a.analyze_so])
        return
    if a.verify:
        check_deps(auto=False)
        verify_apk(a.verify)
        return
    if a.clean:
        clean_work()
        return
    if a.resign:
        resign(a.resign, a.output)
        return

    if not a.apk or not a.so:
        menu()
        return

    if not check_deps():
        return
    out = a.output or os.path.join(
        DEFAULT_OUTDIR, os.path.splitext(os.path.basename(a.apk))[0] + "_MOD.apk")
    logpath = os.path.join(BASE, "last_run.log")
    with open(logpath, "w", encoding="utf-8") as logf:
        try:
            r = pipeline(a.apk, a.so, out, dict(mode=a.mode, boot_on=a.boot_on, delay=a.delay,
                                               libname=a.libname, libfile=a.libfile,
                                               pkg=a.pkg, cls=a.cls, boot_method=a.boot_method,
                                               abi=a.abi), logf)
        except SystemExit as e:
            bad(str(e))
            note("日志：%s" % logpath)
            sys.exit(1)
    if a.keep_work:
        note("工作目录：%s" % r["wd"])
    else:
        shutil.rmtree(r["wd"], ignore_errors=True)
    note("日志：%s" % logpath)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        bad("已中断")
        sys.exit(130)
