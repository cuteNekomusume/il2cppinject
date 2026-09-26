#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patcher.py - 往 apktool 反编译出来的工程里注入加载器（生成 smali / 打补丁 / 改清单）

两种模式：
  activity（默认，推荐）：
      preload() 插到启动 Activity 的 onCreate 末尾；
      start() 按 boot_on 选择时机触发（focus / resume / delay / create）
  app：
      新建 Application 子类（若原清单已有 android:name，则继承它并调用 super），
      在 attachBaseContext 里预加载、onCreate 里延时启动

补丁点全部只用参数寄存器、不碰任何局部寄存器，因此对原方法的 .locals 数量无要求。
"""
import os
import re
import xml.etree.ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"
MARK = "# injected by il2cppinject"
SKIP_LABEL = ":il2cppinject_skip"


class NeedAppMode(Exception):
    """activity 模式打不了补丁（加固成 native），需要改用 app 模式"""
    pass


def W(tag):
    return "{%s}%s" % (ANDROID_NS, tag)


def _params_smali(desc):
    return desc[1:desc.index(")")] if desc and desc.startswith("(") else ""


def _ret_smali(desc):
    return desc.split(")")[1] if desc and ")" in desc else "V"


def _split_desc_types(args):
    out, i = [], 0
    while i < len(args):
        c = args[i]
        if c == "[":
            j = i
            while args[j] == "[":
                j += 1
            j = args.index(";", j) + 1 if args[j] == "L" else j + 1
            out.append(args[i:j])
            i = j
        elif c == "L":
            j = args.index(";", i) + 1
            out.append(args[i:j])
            i = j
        else:
            out.append(c)
            i += 1
    return out


# ---------------------------------------------------------------- smali 生成
LOADER_TMPL = """.class public L@@PKG@@/@@NAME@@;
.super Ljava/lang/Object;
.source "@@NAME@@.java"

@@MARK@@

# static fields
.field private static volatile sStarted:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    :try_start_0
    const-string v0, "@@LIBBASE@@"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    :goto_0
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
@@NATIVES@@
# 只为了让 <clinit> 提前执行（= 提前 System.loadLibrary）
.method public static preload()V
    .locals 0

    return-void
.end method

@@START@@"""

START_TMPL = """
# 只启动一次；真正的 native 调用放在 @@NAME@@Boot 里，避免卡住主线程
.method public static start()V
    .locals 4

    sget-boolean v0, L@@PKG@@/@@NAME@@;->sStarted:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    sput-boolean v0, L@@PKG@@/@@NAME@@;->sStarted:Z

    :try_start_0
    new-instance v0, Ljava/lang/Thread;

    new-instance v1, L@@PKG@@/@@NAME@@Boot;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, L@@PKG@@/@@NAME@@Boot;-><init>(I)V

    const-string v2, "il2cpp-inject-start"

    invoke-direct {v0, v1, v2}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    :goto_0
    return-void
.end method

# 延时 @@DELAY@@ 秒后启动（等窗口准备好，最稳的兜底方式）
.method public static startDelayedDefault()V
    .locals 4

    sget-boolean v0, L@@PKG@@/@@NAME@@;->sStarted:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    sput-boolean v0, L@@PKG@@/@@NAME@@;->sStarted:Z

    :try_start_0
    new-instance v0, Ljava/lang/Thread;

    new-instance v1, L@@PKG@@/@@NAME@@Boot;

    const/16 v2, @@DELAY@@

    invoke-direct {v1, v2}, L@@PKG@@/@@NAME@@Boot;-><init>(I)V

    const-string v2, "il2cpp-inject-start"

    invoke-direct {v0, v1, v2}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    :goto_0
    return-void
.end method
"""

NATIVE_TMPL = """.method public static native @@NAME@@(@@PARAMS@@)@@RET@@
.end method

"""
BOOT_TMPL = """.class final L@@PKG@@/@@NAME@@Boot;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;
.source "@@NAME@@.java"

@@MARK@@

# instance fields
.field private final delay:I


# direct methods
.method constructor <init>(I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, L@@PKG@@/@@NAME@@Boot;->delay:I

    return-void
.end method


# virtual methods
.method public run()V
    .locals @@LOCALS@@

    :try_start_0
    iget v0, p0, L@@PKG@@/@@NAME@@Boot;->delay:I

    if-lez v0, :cond_0

    int-to-long v0, v0

    const-wide/16 v2, 0x3e8

    mul-long/2addr v0, v2

    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V

    :cond_0
@@ZERO@@@@CALL@@
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    :goto_0
    return-void
.end method
"""

APP_TMPL = """.class public L@@PKG@@/@@APPNAME@@;
.super L@@SUPER@@;
.source "@@APPNAME@@.java"

@@MARK@@

# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method protected attachBaseContext(Landroid/content/Context;)V
    .locals 0

    invoke-super {p0, p1}, L@@SUPER@@;->attachBaseContext(Landroid/content/Context;)V

    invoke-static {}, L@@PKG@@/@@NAME@@;->preload()V

    return-void
.end method

.method public onCreate()V
    .locals 0

    invoke-super {p0}, L@@SUPER@@;->onCreate()V

    invoke-static {}, L@@PKG@@/@@NAME@@;->startDelayedDefault()V

    return-void
.end method
"""


def build_loader(pkg, name, lib_base, natives, delay, has_boot=True):
    nats = ""
    for n in natives:
        nats += (NATIVE_TMPL
                 .replace("@@NAME@@", n["name"])
                 .replace("@@PARAMS@@", _params_smali(n["descriptor"]))
                 .replace("@@RET@@", _ret_smali(n["descriptor"])))
    start = ""
    if has_boot:
        start = (START_TMPL
                 .replace("@@PKG@@", pkg.replace(".", "/"))
                 .replace("@@NAME@@", name)
                 .replace("@@DELAY@@", str(delay)))
    return (LOADER_TMPL
            .replace("@@MARK@@", MARK)
            .replace("@@PKG@@", pkg.replace(".", "/"))
            .replace("@@NAME@@", name)
            .replace("@@LIBBASE@@", lib_base)
            .replace("@@NATIVES@@", nats)
            .replace("@@START@@", start))


def build_boot(pkg, name, boot):
    params = _params_smali(boot["descriptor"])
    zero, args, idx, words = [], [], 0, 0
    for t in _split_desc_types(params):
        reg = "v%d" % (4 + idx)
        if t in ("J", "D"):
            zero.append("    const-wide/16 %s, 0x0" % reg)
            args.append("%s, v%d" % (reg, 4 + idx + 1))
            idx += 2
            words += 2
        else:
            zero.append("    const/4 %s, 0x0" % reg)
            args.append(reg)
            idx += 1
            words += 1
    if not args:
        zero.append("    const/4 v4, 0x0")
    call = "    invoke-static {%s}, L%s;->%s(%s)%s" % (
        ", ".join(args), pkg.replace(".", "/") + "/" + name,
        boot["name"], params, _ret_smali(boot["descriptor"]))
    if _ret_smali(boot["descriptor"]) != "V":       # native 有返回值时丢弃结果
        call = "    move-result v%d\n\n" % (4 + idx) + call
        words = max(words, idx + 1)
    return (BOOT_TMPL
            .replace("@@MARK@@", MARK)
            .replace("@@PKG@@", pkg.replace(".", "/"))
            .replace("@@NAME@@", name)
            .replace("@@LOCALS@@", str(4 + max(words, 1)))
            .replace("@@ZERO@@", "".join(z + "\n\n" for z in zero))
            .replace("@@CALL@@", call + "\n"))


def build_app(pkg, app_name, super_class, name, has_boot=True):
    out = (APP_TMPL
           .replace("@@MARK@@", MARK)
           .replace("@@PKG@@", pkg.replace(".", "/"))
           .replace("@@APPNAME@@", app_name)
           .replace("@@SUPER@@", super_class)
           .replace("@@NAME@@", name))
    if not has_boot:
        out = out.replace("    invoke-static {}, L%s;->startDelayedDefault()V\n\n" % (pkg.replace(".", "/") + "/" + name), "")
    return out


# ---------------------------------------------------------------- 工程定位
def smali_dirs(decoded):
    out = []
    for name in sorted(os.listdir(decoded)):
        if os.path.isdir(os.path.join(decoded, name)) and re.fullmatch(r"smali(_classes\d+)?", name):
            out.append(os.path.join(decoded, name))
    return out


def find_class_file(decoded, dotted):
    rel = dotted.replace(".", "/") + ".smali"
    for d in smali_dirs(decoded):
        f = os.path.join(d, rel)
        if os.path.isfile(f):
            return f
    return None


def launcher_activity(decoded):
    root = ET.parse(os.path.join(decoded, "AndroidManifest.xml")).getroot()
    pkg = root.get("package") or ""
    for act in root.iter("activity"):
        for flt in act.findall("intent-filter"):
            actions = {a.get(W("name")) for a in flt.findall("action")}
            cats = {c.get(W("name")) for c in flt.findall("category")}
            if "android.intent.action.MAIN" in actions and \
               ("android.intent.category.LAUNCHER" in cats or
                    "android.intent.category.LEANBACK_LAUNCHER" in cats):
                name = act.get(W("name")) or ""
                if name.startswith("."):
                    name = pkg + name
                elif "." not in name:
                    name = pkg + "." + name
                return name, pkg
    raise SystemExit("清单里找不到启动 Activity（MAIN/LAUNCHER）")


def super_of(text):
    m = re.search(r"^\.super\s+(L[^\s;]+;)", text, re.M)
    if not m:
        raise SystemExit("smali 文件里没有 .super")
    return m.group(1)


# ---------------------------------------------------------------- 方法补丁
def method_block(text, name, sig):
    pat = re.compile(r"^\.method\b[^\n]*\b%s%s\s*$" % (re.escape(name), re.escape(sig)), re.M)
    m = pat.search(text)
    if not m:
        return None
    end = text.find("\n.end method", m.end())
    if end < 0:
        return None
    return m.start(), end, text[m.end():end]


NATIVE_DECL = re.compile(r"\b(native|abstract)\b")


def add_or_patch_method(path, smali_super, method_name, sig, body_lines, kind):
    """确保类里有 method_name+sig。

    返回 "patched" / "added" / "already" / "native" / "empty"；
    native|abstract 方法不能塞代码（Dex2C 类加固会把方法体搬进 so，只留 native 声明），
    空方法体同理——遇到这两种就返回状态，由调用方换策略。
    """
    text = open(path, encoding="utf-8").read()
    body_code = "".join("\n    " + l if l.strip() else "\n" for l in body_lines)
    blk = method_block(text, method_name, sig)

    if blk:
        start, end, body = blk
        decl = text[start:text.find("\n", start)].strip()
        if NATIVE_DECL.search(decl):
            return "native"
        if not body.strip():
            return "empty"
        if ("%s: %s" % (MARK, kind)) in body:
            return "already"
        idx = body.rfind("\n    return-void")
        if idx < 0:
            idx = len(body)
        new_body = body[:idx] + body_code + "\n" + body[idx:]
        text = text[:start] + text[start:end].replace(body, new_body, 1) + text[end:]
        open(path, "w", encoding="utf-8").write(text)
        return "patched"

    CREATE = {
        "onCreate": (".method protected onCreate(Landroid/os/Bundle;)V",
                     "invoke-super {p0, p1}, %s->onCreate(Landroid/os/Bundle;)V"),
        "onResume": (".method protected onResume()V",
                     "invoke-super {p0}, %s->onResume()V"),
        "onWindowFocusChanged": (".method public onWindowFocusChanged(Z)V",
                                 "invoke-super {p0, p1}, %s->onWindowFocusChanged(Z)V"),
        "attachBaseContext": (".method protected attachBaseContext(Landroid/content/Context;)V",
                              "invoke-super {p0, p1}, %s->attachBaseContext(Landroid/content/Context;)V"),
        "onStart": (".method protected onStart()V",
                    "invoke-super {p0}, %s->onStart()V"),
        "onPostCreate": (".method protected onPostCreate(Landroid/os/Bundle;)V",
                         "invoke-super {p0, p1}, %s->onPostCreate(Landroid/os/Bundle;)V"),
    }
    if method_name not in CREATE:
        raise SystemExit("不支持自动创建方法 %s" % method_name)
    decl, super_call = CREATE[method_name]
    super_call = super_call % smali_super

    text = text.rstrip("\n") + "\n\n" + "\n".join([
        decl,
        "    .locals 0",
        "",
        "    %s: %s" % (MARK, kind),
        "",
        "    " + super_call,
        body_code.strip("\n"),
        "",
        "    return-void",
        ".end method",
        "",
    ])
    open(path, "w", encoding="utf-8").write(text)
    return "added"


# 打补丁时的候选方法（加固过的 native 方法要跳过，这里依次尝试）
PRELOAD_SITES = [("onCreate", "(Landroid/os/Bundle;)V"),
                 ("attachBaseContext", "(Landroid/content/Context;)V"),
                 ("onPostCreate", "(Landroid/os/Bundle;)V"),
                 ("onStart", "()V"),
                 ("onResume", "()V"),
                 ("onWindowFocusChanged", "(Z)V")]
BOOT_SITES = {"focus": [("onWindowFocusChanged", "(Z)V"), ("onResume", "()V"), ("onStart", "()V")],
              "resume": [("onResume", "()V"), ("onWindowFocusChanged", "(Z)V")],
              "delay": [("onCreate", "(Landroid/os/Bundle;)V"),
                        ("attachBaseContext", "(Landroid/content/Context;)V"),
                        ("onStart", "()V")],
              "create": [("onCreate", "(Landroid/os/Bundle;)V"),
                         ("attachBaseContext", "(Landroid/content/Context;)V"),
                         ("onStart", "()V")]}


def _try_sites(path, smali_super, sites, make_body, tag, log, focus_gate=False):
    """依次尝试多个候选方法，返回 (方法名, 结果) 或 (None, 原因)"""
    reasons = []
    for name, sig in sites:
        body = make_body(name)
        if focus_gate and name == "onWindowFocusChanged":
            body = ["if-eqz p1, %s" % SKIP_LABEL] + body + [SKIP_LABEL]
        st = add_or_patch_method(path, smali_super, name, sig, body, tag)
        if st in ("patched", "added", "already"):
            return name, st
        reasons.append("%s→%s" % (name, st))
    return None, ", ".join(reasons)


# ---------------------------------------------------------------- 总入口
def patch(decoded, pkg, cls, lib_base, natives, boot_method, boot_descriptor,
          boot_on="focus", delay=6, mode="activity", activity=None, log=print):
    target = (smali_dirs(decoded) or [None])[0]
    if not target:
        raise SystemExit("工程里找不到 smali 目录")
    name = cls.split(".")[-1]
    pkg_path = pkg.replace(".", "/")
    os.makedirs(os.path.join(target, pkg_path), exist_ok=True)

    # boot_method 为空 = 该 so 自启动（.init_array 里有构造器），只需加载
    has_boot = bool(boot_method)
    open(os.path.join(target, pkg_path, name + ".smali"), "w", encoding="utf-8").write(
        build_loader(pkg, name, lib_base, natives, delay, has_boot=has_boot))
    files = ["%s/%s.smali" % (pkg_path, name)]
    if has_boot:
        boot = dict(name=boot_method, descriptor=boot_descriptor)
        open(os.path.join(target, pkg_path, name + "Boot.smali"), "w", encoding="utf-8").write(
            build_boot(pkg, name, boot))
        files.append("%s/%sBoot.smali" % (pkg_path, name))
        log("生成加载器 %s.%s（loadLibrary(\"%s\")，入口 %s%s）"
            % (pkg, name, lib_base, boot_method, boot_descriptor))
    else:
        log("生成加载器 %s.%s（loadLibrary(\"%s\")，该 so 自启动，无需调用入口）"
            % (pkg, name, lib_base))

    result = dict(mode=mode, loader="%s.%s" % (pkg, name), files=files, actions=[])

    def do_app_mode(note=""):
        root = ET.parse(os.path.join(decoded, "AndroidManifest.xml"))
        mroot = root.getroot()
        app_el = mroot.find("application")
        old = app_el.get(W("name"))
        super_dotted = old or "android.app.Application"
        if old and old.startswith("."):
            super_dotted = (mroot.get("package") or "") + old
        app_name = name + "App"
        with open(os.path.join(target, pkg_path, app_name + ".smali"), "w",
                  encoding="utf-8") as fh:
            fh.write(build_app(pkg, app_name, "L" + super_dotted.replace(".", "/") + ";",
                               name, has_boot))
        app_el.set(W("name"), pkg + "." + app_name)
        root.write(os.path.join(decoded, "AndroidManifest.xml"),
                   encoding="utf-8", xml_declaration=True)
        result["mode"] = "app"
        result["files"].append("%s/%s.smali" % (pkg_path, app_name))
        result["actions"].append("AndroidManifest: application name=%s.%s（继承 %s）%s%s"
                                 % (pkg, app_name, super_dotted,
                                    "，延时 %ds 启动" % delay if has_boot else "",
                                    "；" + note if note else ""))
        log(result["actions"][-1])
        return result

    if mode == "app":
        return do_app_mode()

    act = activity or launcher_activity(decoded)[0]
    f = find_class_file(decoded, act)
    if not f:
        if mode == "auto":
            log("smali 里找不到启动 Activity %s，自动改用 app 模式" % act)
            return do_app_mode("找不到启动 Activity")
        raise SystemExit("smali 里找不到启动 Activity %s，请改用 --mode app" % act)
    snapshot = open(f, encoding="utf-8").read()
    smali_super = super_of(snapshot)
    result["activity"] = act
    result["activity_file"] = os.path.relpath(f, decoded)

    call = "invoke-static {}, L%s;->%%s()V" % (pkg_path + "/" + name)

    try:
        # 预加载：依次在多个生命周期方法里找可下手的（加固包的方法可能是 native 空方法）
        site, st = _try_sites(f, smali_super, PRELOAD_SITES,
                              lambda m: [call % "preload"], "onCreate", log)
        if not site:
            raise NeedAppMode("启动 Activity(%s) 的生命周期方法都被加固成 native/空方法，无法打补丁：%s"
                              % (act, st))
        result["actions"].append("%s.%s ← preload() [%s]" % (act, site, st))
        result["preload_site"] = site

        if has_boot:
            want = {"focus": "start", "resume": "start", "delay": "startDelayedDefault",
                    "create": "start"}[boot_on]
            site2, st2 = _try_sites(f, smali_super, BOOT_SITES[boot_on],
                                    lambda m: [call % want], "boot-" + boot_on,
                                    log, focus_gate=True)
            if not site2:
                raise NeedAppMode("启动时机 %s 的候选方法也都不可用：%s" % (boot_on, st2))
            result["actions"].append("%s.%s ← %s() [%s]" % (act, site2, want, st2))
            result["boot_site"] = site2
    except NeedAppMode as e:
        if mode == "activity":
            open(f, "w", encoding="utf-8").write(snapshot)     # 还原，别留半成品
            raise SystemExit(str(e) + "（可改用 --mode app）")
        open(f, "w", encoding="utf-8").write(snapshot)         # 还原后再走 app 模式
        log("！%s" % e)
        log("→ 自动改用 app 模式")
        result["actions"] = []
        return do_app_mode(str(e))

    for line in result["actions"]:
        log(line)
    return result


if __name__ == "__main__":
    import argparse
    import json
    ap = argparse.ArgumentParser(description="给 apktool 工程注入加载器")
    ap.add_argument("decoded")
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--class", dest="cls", required=True)
    ap.add_argument("--libbase", required=True)
    ap.add_argument("--info", required=True, help="analyze.py --json 输出文件")
    ap.add_argument("--boot-on", default="focus", choices=["focus", "resume", "delay", "create"])
    ap.add_argument("--delay", type=int, default=6)
    ap.add_argument("--mode", default="auto", choices=["auto", "activity", "app"])
    ap.add_argument("--activity", default=None)
    a = ap.parse_args()
    info = json.load(open(a.info, encoding="utf-8"))
    r = patch(a.decoded, a.pkg, a.cls, a.libbase, info["natives"],
              info["boot_method"], info["boot_descriptor"],
              boot_on=a.boot_on, delay=a.delay, mode=a.mode, activity=a.activity)
    print(json.dumps(r, ensure_ascii=False, indent=2))
