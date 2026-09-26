#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
stripmenu.py - 检测并移除注入到 APK 里的 mod 菜单

移除对象（三件套）：
  1) 注入进去的 .so（各 ABI 目录里的同名库）
  2) 它的 Java 加载器类（从 so 的 Java_* 导出符号反推类名，整包一并删除）
  3) 其它类里对它的调用点（invoke → 删除该行；含返回值时连 move-result 一起删），
     以及指向该库的 System.loadLibrary(...) 调用

不碰的东西：应用自身的代码（除非它就是加载器）、PairIP/加固层、清单、资源。
"""
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile

import analyze
import zipedit

# Unity / 系统运行库白名单：永远不会被当成注入物
RUNTIME = re.compile(
    r'^lib(il2cpp|unity|main|_burst_generated|mono|monobdwgc|unityforandroid|'
    r'c\+\+_shared|swappy|swappywrapper|fmod|audioplugin|firebase|crashlytics|'
    r'crashpad|unwind|androidx|media|opengl|vulkan|gfx|ovrplugin|native|'
    r'RNSk|hermes|jsc|node|sqlite|realm|flutter|arcore|mediapipe)', re.I)

MARKERS = [b'DobbyHook', b'KittyMemory', b'shadowhook', b'xhook', b'And64InlineHook',
           b'frida', b'substrate', b'imgui', b'ImGui', b'IL2CPP Tool', b'il2cpp']


# ------------------------------------------------------------------ 工具
def run(cmd, log=print, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors='replace')
    txt = (p.stdout or '') + (p.stderr or '')
    for line in txt.splitlines():
        if line.strip():
            log(line.strip()[:160])
    return p.returncode, txt


def apk_package(apk):
    try:
        p = subprocess.run(['aapt2', 'dump', 'badging', apk], capture_output=True,
                           text=True, errors='replace')
        m = re.search(r"package: name='([^']+)'", p.stdout or '')
        return m.group(1) if m else ''
    except Exception:
        return ''


_MCLASSES = {}


def manifest_classes(apk):
    """清单里出现过的类名（activity/service/provider/receiver/application 等）"""
    if apk in _MCLASSES:
        return _MCLASSES[apk]
    out = set()
    try:
        p = subprocess.run(['aapt2', 'dump', 'xmltree', '--file', 'AndroidManifest.xml', apk],
                           capture_output=True, text=True, errors='replace')
        out = set(re.findall(r'name\(0x01010003\)="([^"]+)"', p.stdout or ''))
    except Exception:
        pass
    _MCLASSES[apk] = out
    return out


def dex_names(z):
    return [n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex', n)]


def declared_classes(data):
    """解析 dex 的 class_defs（class_idx → type_ids → 描述符）"""
    try:
        ssize, soff = struct.unpack_from('<II', data, 0x38)
        tsize, toff = struct.unpack_from('<II', data, 0x40)
        csize, coff = struct.unpack_from('<II', data, 0x60)
    except struct.error:
        return set()

    def string(sidx):
        off = struct.unpack_from('<I', data, soff + 4 * sidx)[0]
        p = off
        while data[p] & 0x80:
            p += 1
        p += 1
        return data[p:data.index(b'\x00', p)].decode('utf-8', 'replace')

    out = set()
    for i in range(csize):
        tidx = struct.unpack_from('<I', data, coff + 32 * i)[0]
        out.add(string(struct.unpack_from('<I', data, toff + 4 * tidx)[0]))
    return out


def class_hierarchy(data):
    """{类描述符: 父类描述符}，用于判断某个 JNI 类是不是应用的基类"""
    try:
        ssize, soff = struct.unpack_from('<II', data, 0x38)
        tsize, toff = struct.unpack_from('<II', data, 0x40)
        csize, coff = struct.unpack_from('<II', data, 0x60)
    except struct.error:
        return {}

    def desc(tidx):
        sidx = struct.unpack_from('<I', data, toff + 4 * tidx)[0]
        off = struct.unpack_from('<I', data, soff + 4 * sidx)[0]
        p = off
        while data[p] & 0x80:
            p += 1
        p += 1
        return data[p:data.index(b'\x00', p)].decode('utf-8', 'replace')

    out = {}
    for i in range(csize):
        o = coff + 32 * i
        cidx = struct.unpack_from('<I', data, o)[0]
        sidx = struct.unpack_from('<I', data, o + 8)[0]
        out[desc(cidx)] = desc(sidx) if sidx != 0xFFFFFFFF else None
    return out


# ------------------------------------------------------------------ 检测
def scan(apk, log=print, force_so=()):
    z = zipfile.ZipFile(apk)
    exts = [n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex', n)]
    dex_data = {n: z.read(n) for n in exts}
    dex_classes = {n: declared_classes(d) for n, d in dex_data.items()}
    pkg = apk_package(apk)
    mclasses = manifest_classes(apk)
    all_dex_bytes = b''.join(dex_data.values())

    # 清单里声明的类，以及它们的全部父类 —— 这些是"应用自身"，不是注入物
    hier = {}
    for d in dex_data.values():
        hier.update(class_hierarchy(d))
    anchored = {'L%s;' % c.replace('.', '/') for c in mclasses} & set(hier)
    ancestors = set()
    for a in anchored:
        d = hier.get(a)
        while d and d not in ancestors:
            ancestors.add(d)
            d = hier.get(d)
    force = {os.path.basename(x) for x in force_so} | set(force_so)

    libs = [n for n in z.namelist() if n.startswith('lib/') and n.endswith('.so')]
    found = []
    tmpdir = tempfile.mkdtemp(prefix='stripso')
    try:
        for entry in libs:
            base = os.path.basename(entry)
            abi = entry.split('/')[1]
            blob = z.read(entry)
            tmp = os.path.join(tmpdir, base)
            open(tmp, 'wb').write(blob)
            info = analyze.analyze(tmp)
            ev = []

            # 判定依据（强）：so 导出的 JNI 方法所属的 Java 类存在于 dex 里，
            #   且这个类**不是应用自己在清单里声明的东西**、也不属于应用自身包
            #   —— 这才是"自带 Java 加载器的注入菜单"。
            #   （AGDK 的 libgame.so -> com.google.androidgamesdk.GameActivity 就是应用自身，
            #    只按"类在 dex 里"判定会误删引擎库。）
            jni_in_dex, legit = False, ''
            jni_cls = info.get('java_class')
            if jni_cls:
                loader_desc = 'L%s;' % jni_cls.replace('.', '/')
                where = [d for d, cs in dex_classes.items() if loader_desc in cs]
                owner_pkg = jni_cls.rsplit('.', 1)[0]
                if loader_desc in {'L%s;' % c.replace('.', '/') for c in mclasses}:
                    legit = '类是清单里声明的组件（应用自身）'
                elif loader_desc in ancestors:
                    legit = '类是其启动组件的父类（例如 Unity 的 GameActivity 基类）'
                elif pkg and (owner_pkg == pkg or owner_pkg.startswith(pkg + '.')
                              or pkg.startswith(owner_pkg + '.')):
                    legit = '类属于应用自身包 %s' % pkg
                if where and not legit:
                    jni_in_dex = True
                    ev.append('JNI 类 %s 存在于 %s（强证据）' % (jni_cls, ','.join(where)))
                elif where and legit:
                    ev.append('JNI 类 %s 在 dex 里，但%s → 判定为应用自身，跳过' % (jni_cls, legit))
                else:
                    ev.append('JNI 类 %s 不在 dex 里' % jni_cls)
            else:
                ev.append('没有 Java_* 导出（自身不含 Java 加载器）')

            lib_base = info.get('lib_base') or ''
            hits = all_dex_bytes.count(lib_base.encode()) if lib_base else 0
            if hits:
                ev.append('dex 里 %d 次出现 "%s"（可能是加载者，弱证据）' % (hits, lib_base))

            marks = [m.decode() for m in MARKERS if m in blob]
            if marks:
                ev.append('含标记：' + ', '.join(marks[:4]) + '（弱证据）')

            runtime = bool(RUNTIME.match(base))
            is_self_lib = bool(legit)
            forced = base in force or entry in force
            rec = dict(entry=entry, abi=abi, base=base, size=len(blob), abis=[abi],
                       soname=info.get('soname'), java_class=jni_cls,
                       boot=(info.get('boot_method'), info.get('boot_descriptor')),
                       evidence=ev, runtime=runtime, self_lib=is_self_lib,
                       hooky=bool(marks), jni_in_dex=jni_in_dex, forced=forced,
                       is_mod=bool((jni_in_dex or forced) and not runtime and not is_self_lib))
            if forced and not jni_in_dex:
                ev.append('由 --strip-so 手动指定')
            found.append(rec)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # 合并同一库的多 ABI 条目
    mods = []
    for r in found:
        if not r['is_mod']:
            continue
        key = r['base']
        g = next((m for m in mods if m['base'] == key), None)
        if g:
            g['entries'].append(r['entry'])
            g['abis'].append(r['abi'])
            g['size'] += r['size']
            g['hooky'] = g['hooky'] or r['hooky']
        else:
            g = dict(r)
            g['entries'] = [r['entry']]
            mods.append(g)

    # 要删的类：加载器所在包的整包（前提是该包不属于应用自己）
    for m in mods:
        pkgs, classes = [], []
        jc = m.get('java_class')
        if jc:
            p = jc.rsplit('.', 1)[0]
            self_pkg = pkg and (p == pkg or p.startswith(pkg + '.') or pkg.startswith(p + '.'))
            if self_pkg:
                classes = [jc]                      # 包属于应用自己，只删这一个类
                m['note'] = '包 %s 属于应用自身，只删加载器类' % p
            else:
                pkgs = [p]
                classes = []
        else:
            pkgs, classes = [], []
        m['packages'] = pkgs
        m['classes'] = classes
        m['prefixes'] = ['L%s/' % p.replace('.', '/') for p in pkgs] + \
                        ['L%s;' % c.replace('.', '/') for c in classes]

    # 其它 dex 是否引用了这些包（引用不到 = 可以整包删）
    for m in mods:
        hits = []
        for name, data in dex_data.items():
            for pre in m['prefixes']:
                if pre.encode() in data:
                    hits.append((name, pre))
        m['dex_hits'] = sorted(set(h[0] for h in hits))
        m['dex_of_prefix'] = hits

    return dict(apk=apk, package=pkg, dexs=exts, libs=found, mods=mods,
                manifest_classes=sorted(mclasses), ancestors=sorted(ancestors))


# ------------------------------------------------------------------ 移除
def _make_project(apk, workdir, log):
    """把 APK 里的 dex + 原始清单/资源表做成瘦工程并反编译"""
    z = zipfile.ZipFile(apk)
    slim = os.path.join(workdir, 'slim.apk')
    with zipfile.ZipFile(slim, 'w', zipfile.ZIP_DEFLATED) as o:
        for n in ('AndroidManifest.xml', 'resources.arsc'):
            o.writestr(n, z.read(n))
        for n in dex_names(z):
            o.writestr(n, z.read(n))
    proj = os.path.join(workdir, 'proj')
    rc, _ = run(['apktool', 'd', '-r', '-f', '-o', proj, slim], log)
    if rc != 0:
        raise SystemExit('反编译 dex 失败')
    return proj


def _smali_dirs(proj):
    out = []
    for n in sorted(os.listdir(proj)):
        if os.path.isdir(os.path.join(proj, n)) and re.fullmatch(r'smali(_classes\d+)?', n):
            out.append(os.path.join(proj, n))
    return out


INVOKE = re.compile(r'^\s*invoke-\S+.*->')      # smali 的 invoke 指令一定带 ->
RESULT = re.compile(r'^\s*move-result')


def _strip_classes(proj, prefixes, lib_bases, log, protect=()):
    """删类 + 删调用点，返回统计

    protect: 不能删的描述符前缀（清单组件、其父类、应用自身包）
    """
    removed_files, fixed_calls, fixed_loads = 0, [], []
    dirs = _smali_dirs(proj)
    prefixes = list(prefixes)

    # 0) 先按 loadLibrary 定位加载器类：即使它被改过名、和 JNI 类不同名也能清掉
    for d in dirs:
        for root, _dirs, files in os.walk(d):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                path = os.path.join(root, f)
                txt = open(path, encoding='utf-8').read()
                if 'loadLibrary' not in txt:
                    continue
                if not any('"%s"' % b in txt for b in lib_bases):
                    continue
                desc = 'L' + os.path.relpath(path, d)[:-6].replace(os.sep, '/')
                if any(desc.startswith(p) for p in prefixes):
                    continue
                if any(desc.startswith(p) for p in protect):
                    log("  跳过 %s（应用自身/清单组件的类）" % desc)
                    continue
                prefixes.append(desc)
                log("  按 loadLibrary 定位到加载器类 %s" % desc)

    # 1) 删类文件
    for d in dirs:
        for root, _dirs, files in os.walk(d):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                path = os.path.join(root, f)
                rel = os.path.relpath(path, d)
                desc = 'L' + rel[:-6].replace(os.sep, '/') + ';'
                if any(desc.startswith(p) for p in prefixes):
                    os.remove(path)
                    removed_files += 1

    # 2) 调用点：删掉引用已删类的指令行（及紧随的 move-result）
    for d in dirs:
        for root, _dirs, files in os.walk(d):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                path = os.path.join(root, f)
                lines = open(path, encoding='utf-8').read().split('\n')
                keep, i, changed = [], 0, 0
                while i < len(lines):
                    ln = lines[i]
                    if INVOKE.match(ln) and any(p in ln for p in prefixes):
                        changed += 1
                        fixed_calls.append('%s: %s' % (os.path.relpath(path, d), ln.strip()))
                        if i + 1 < len(lines) and RESULT.match(lines[i + 1]):
                            i += 2
                        else:
                            i += 1
                        continue
                    keep.append(ln)
                    i += 1
                if changed:
                    open(path, 'w', encoding='utf-8').write('\n'.join(keep))

    # 3) System.loadLibrary("<被删的库>") 调用（const-string + invoke 两行一起删）
    for d in dirs:
        for root, _dirs, files in os.walk(d):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                path = os.path.join(root, f)
                lines = open(path, encoding='utf-8').read().split('\n')
                out, i, changed = [], 0, 0
                while i < len(lines):
                    m = re.match(r'^\s*const-string (v\d+|p\d+), "([^"]+)"', lines[i])
                    if m and m.group(2) in lib_bases:
                        j = i + 1
                        while j < len(lines) and j <= i + 4:
                            if 'loadLibrary' in lines[j]:
                                fixed_loads.append('%s: %s' % (os.path.relpath(path, d),
                                                               lines[j].strip()))
                                i = j + 1
                                changed += 1
                                break
                            j += 1
                        else:
                            out.append(lines[i])
                            i += 1
                        continue
                    out.append(lines[i])
                    i += 1
                if changed:
                    open(path, 'w', encoding='utf-8').write('\n'.join(out))

    log("删除 smali 文件 %d 个，清理调用点 %d 处，清理 loadLibrary %d 处"
        % (removed_files, len(fixed_calls), len(fixed_loads)))
    return dict(files=removed_files, calls=fixed_calls, loads=fixed_loads)


def matches(m, want):
    """m 是否被 want 里的任一项指定（库名 / 条目路径 / 加载器类名 / 加载器包名）"""
    if not want:
        return True
    cands = {m['base'], m['java_class'], m.get('soname') or ''}
    cands |= set(m['entries']) | set(m.get('packages') or [])
    return bool(cands & set(want))


def strip(apk, out, workdir, drop_libs=True, force=False, force_so=(), only=(), log=print):
    rep = scan(apk, log, force_so=force_so)
    mods = rep['mods']
    if not mods:
        raise SystemExit('没有检测到注入的菜单（so+Java 加载器），无需清理')

    if only:                                   # 只清理指定的模块
        picked = [m for m in mods if matches(m, only)]
        known = {c for m in mods for c in
                 ({m['base'], m['java_class']} | set(m['entries']) | set(m.get('packages') or []))}
        unknown = [x for x in only if x not in known]
        if unknown:
            log("⚠ 这些名字不在检测结果里，已忽略：%s（要强制删 so 请用 --strip-so）"
                % ", ".join(unknown))
        if not picked:
            raise SystemExit("指定的模块都没匹配上，已取消")
        log("按选择只清理 %d/%d 个模块：%s"
            % (len(picked), len(mods), ", ".join(m['base'] for m in picked)))
        rep['mods'] = mods = picked

    z = zipfile.ZipFile(apk)
    orig_dex = {n: z.read(n) for n in rep['dexs']}
    orig_classes = {n: declared_classes(d) for n, d in orig_dex.items()}

    prefixes = sorted({p for m in mods for p in m['prefixes']})
    lib_bases = sorted({m['base'] for m in mods})
    # 应用自身：清单组件 + 它们的父类 + 应用包，任何情况下都不删
    protect = {'L%s;' % c.replace('.', '/') for c in rep.get('manifest_classes', ())}
    protect |= set(rep.get('ancestors', ()))
    if rep.get('package'):
        protect.add('L%s/' % rep['package'].replace('.', '/'))
    drop = set()
    if drop_libs:
        for m in mods:
            drop.update(m['entries'])

    log("要移除的模块：")
    for m in mods:
        log("  - %s（%s）加载器 %s，整包 %s"
            % (m['base'], "/".join(sorted(set(m['abis']))), m['java_class'],
               ", ".join(m['packages']) or "（无）"))

    proj = _make_project(apk, workdir, log)
    stats = _strip_classes(proj, prefixes, lib_bases, log, protect=protect)

    rebuilt = os.path.join(workdir, 'rebuilt.apk')
    rc, _ = run(['apktool', 'b', '-f', '-o', rebuilt, proj], log)
    if rc != 0:
        raise SystemExit('重新汇编 dex 失败')

    rz = zipfile.ZipFile(rebuilt)
    replace = {}
    for n in rep['dexs']:
        new = rz.read(n)
        if declared_classes(new) != orig_classes[n]:
            replace[n] = new
            log("替换 %s（类数 %d → %d）"
                % (n, len(orig_classes[n]), len(declared_classes(new))))
        else:
            log("%s 无变化，保留原始字节" % n)

    # 最终校验：新 dex 里不能再出现被删的类
    left = []
    for n, data in replace.items():
        for p in prefixes:
            if p.encode() in data:
                left.append('%s 里还有 %s' % (n, p))
    if left:
        log("⚠ 残留：" + "; ".join(left))

    unsigned = os.path.join(workdir, 'stripped_unsigned.apk')
    zipedit.rewrite(apk, unsigned, drop=drop, replace=replace, log=log)
    return dict(unsigned=unsigned, report=rep, stats=stats, replaced=sorted(replace),
                dropped=sorted(drop), outside=stats['calls'], leftovers=left)
