# IL2CPP 注入器（手机端 / Termux）

把 mod 菜单 `.so`（IL2CPPTool 之类）注入到任意 Unity / IL2CPP 游戏的 APK 里，
全程在手机上完成：**反编译 → 放 so → 生成加载器 → 打补丁 → 重打包 → 对齐 → 签名**。

## 用法

```bash
cd ~/il2cppinject
./inject                     # 交互菜单（推荐，手机上最好用）
```

菜单里选「1) 注入 APK（向导）」，然后按提示选 APK、选 so 就行。

一条命令直接跑（不改动交互流程）：

```bash
./inject "游戏.apk" "菜单.so"
./inject 游戏.apk 菜单.so -o /sdcard/Download/游戏_MOD.apk --boot-on delay
./inject 游戏.apk 菜单.so -o /sdcard/Download/ilbtool      # 输出写目录也行，会自动补文件名
```

其它：

```bash
./inject --analyze-so 菜单.so           # 只看 so 信息（架构/JNI 导出/入口）
./inject --verify 游戏_MOD.apk          # 验证输出：签名/对齐/dex/so
./inject --resign .work                 # 包已经打好了，只重新签名（省时间）
./inject --resign .work -o /sdcard/Download/xxx_MOD.apk
./inject --clean                        # 清理临时文件
```

装成全局命令（可选）：

```bash
ln -s ~/il2cppinject/inject $PREFIX/bin/il2cppinject
```

## 向导里的三个选项

| 选项 | 说明 |
| --- | --- |
| 注入方式 | `activity`（默认，改启动 Activity）／`app`（新建 Application 类，activity 找不到时用） |
| 启动时机 | `focus` 窗口获得焦点时（默认、最准）／`delay` 进游戏 N 秒后（最稳）／`resume`／`create` |
| 高级参数 | 可改 Java 包名、类名、`loadLibrary` 名字、入口方法名 |

## 它是怎么知道该调用什么的

`analyze.py` 直接解析 ELF：

* **架构** → 决定放进 `lib/arm64-v8a/` 还是 `lib/armeabi-v7a/`
* **SONAME** → 决定文件名 `libTool.so` 和 `System.loadLibrary("Tool")`
* **`.init_array` + `JNI_OnLoad`** → 判断 so 是「加载即自启动」还是「必须由 Java 调用入口」
* **`Java_*` 导出符号** → 反推 Java 类名（如 `imgui.il2cpp.tool.NativeMethods`）、方法名与方法签名
  * 带签名后缀（`..._onSurfaceCreate__IIV`）的直接解析出参数
  * 短名的用内置表猜（宁可多给参数也不少给），入口方法按优先级挑（`onSurfaceCreate` > `init` > `start` …）

## 注入后的改动

```
lib/<abi>/<libXXX>.so                     ← 你的 so（原字节）
smali*/<包名>/<类名>.smali                 ← 加载器：<clinit> 里 System.loadLibrary（try/catch）
smali*/<包名>/<类名>Boot.smali             ← 另起线程调用 native 入口，异常全吞
smali*/<启动Activity>.smali                ← onCreate ← preload()；onWindowFocusChanged/onResume ← start()
```

* 补丁只用参数寄存器、不碰局部寄存器，所以不用管原方法 `.locals` 是几
* 启动 Activity 从 `AndroidManifest.xml` 的 MAIN/LAUNCHER 自动识别，不写死 `UnityPlayerActivity`
* 只启动一次（`sStarted` 守卫），不会重复初始化
* 重复注入同一个 APK 不会重复插入（有 `# injected by il2cppinject` 标记）

## 签名说明

首次运行会生成 `keystore.jks`（口令 `il2cppinject`），之后一直复用它，
所以同一台手机上重新打包的 APK 签名一致，可以覆盖安装。

**签名和原版不同，必须卸载原版才能装**（存档会一起没）。想保存档先备份
`/data/data/<包名>/`（需要 root）。

## 校验

每次打包后自动校验：apksigner 三种签名方案、classes.dex 的 adler32/SHA-1、
未压缩条目对齐、so 列表、dex 里能否找到注入的类。也可以随时 `./inject --verify xxx.apk`。

## 常见问题

| 现象 | 处理 |
| --- | --- |
| 装完进游戏没有菜单 | 向导里把「启动时机」改成 `delay`（默认 6 秒）再打一次 |
| 闪退 | 用 `--mode app` 或换个启动时机；`adb logcat \| grep -iE "il2cpp\|overlay"` 看日志 |
| 提示找不到启动 Activity | 用 `--mode app` |
| 32 位设备无效 | so 只有 arm64 时，32 位机器上会跳过加载（游戏照常跑） |
| 没反应且 so 无 JNI 导出 | 该 so 必须自己会在构造器里启动；否则注入了也不会生效 |

## 依赖

`pkg install python openjdk-17 apktool apksigner`（首次运行会自动检测并提示安装）

Zipalign 用纯 Python 实现（`ziptool.py`），因为 Termux 没有 zipalign 命令。

## 变更记录

* **v1.0.1**
  * 输出路径是目录（或以 `/` 结尾）时自动补文件名 —— 之前会报
    `java.io.FileNotFoundException: ... (Is a directory)`；
    现在改成目录也能直接输出。
  * 开始干活之前先校验输出目录可写、磁盘空间够（大包按 3 倍体积估）。
  * 签名失败时回显 apksigner 的真实报错，并提示可用 `--resign` 只重签。
  * 新增 `--resign`（菜单第 4 项）：给已经打好的 `aligned.apk` / `unsigned.apk`
    重新签名，不用重跑反编译和打包。
  * 校验输出里列出全部 so，并标出疑似注入的菜单库。

* **v1.0.2**
  * 签名加 `--alignment-preserved true`：apksigner 0.9 默认会**重新对齐**（未压缩 .so 按
    `--lib-page-alignment` 默认 16384、其它按 4 字节），会破坏我们排好的 4096 页对齐。
    实测：不加该参数时原包页对齐的 .so 会变成非页对齐（`extractNativeLibs=true` 时不影响
    运行，但属于回退），加上后与原包一致。

* **v1.1.0 —— 新增「去除注入的菜单」**
  * 菜单第 5 项 / `./inject --strip 包.apk`：检测并移除塞进 APK 的 mod 菜单三件套
    1. 注入的 `.so`（各 ABI 里的同名库）
    2. 它的 Java 加载器包（从 so 的 `Java_*` 导出反推类名，整包删除）
    3. 其它类里的调用点（`invoke ...->preload()/start()V` 等），以及指向该库的 `System.loadLibrary`
  * 判定依据（强）：**so 导出的 JNI 方法所属的 Java 类真的存在于该包的 dex 里**。
    只"dex 里出现过 loadLibrary(该库)"不算——加固层（如 `libstub.so`）和应用自身的库也会这样被加载，
    实测这个弱信号会误删 `libstub.so` 导致整包崩溃，已改为弱证据。
  * `--strip-dry-run` 只检测报告；`--strip-so NAME` 手动指定（用于没有 JNI 导出的自启动库）；
    `--strip-force` 有外部引用时仍继续。
  * 实测：对着 apkvision 的 ADOFAI 包，与手工清理结果**完全等价**（条目/类集合/其它 dex 字节全部一致）；
    对注入器自己打的包也能把 `onCreate`/`onWindowFocusChanged` 里的调用点一起清掉，恢复到原版结构。

* **v1.1.1 —— 修复「加固包注入失败」**
  * **修 bug**：补丁会往 Dex2C 加固后的 `native` 空方法里塞指令（
    `.method protected native onCreate(...)V` + `.end method`），apktool 报
    `missing EOF at 'invoke-static'`，整包打不出来。现在识别 `native`/`abstract`/空方法体并跳过。
  * 启动方法改成**候选列表依次尝试**：`onCreate → attachBaseContext → onPostCreate →
    onStart → onResume → onWindowFocusChanged`（加固包通常只剩 `attachBaseContext` 能下手）。
  * 新增 `--mode auto`（**默认**）：activity 模式实在打不了补丁时，自动切 app 模式
    （新建 Application 子类、继承原 Application 类、注册进清单、延时启动）；显式
    `--mode activity` 则只报错不改策略。失败时会先把已改的 smali 还原，不留半成品。
  * **修 bug**：自动新建生命周期方法时模板多带一个分号（生成 `Landroid/app/Activity;;->attachBaseContext`），
    只在"原类没有该方法、需要新建"时触发——之前测的包都自带这些方法所以一直没暴露。

* **v1.1.2 —— 还原功能支持「挑模块删」+ 修两处误判**
  * **新增选择功能**：检测出多个注入模块时，向导里会列出来让你挑（`1,3` / `all`），
    CLI 用 `--strip-only <库名或加载器类名>`（可重复）。实测：双模块包分别只删其中一个，
    另一个的 so / 类 / 调用点全部完好。
  * **修误判 1**：把游戏自己的引擎库当成注入物（例：AGDK 的 `libgame.so` +
    `com.google.androidgamesdk.GameActivity`）。现在会排除「清单里声明的组件」「它们的父类」
    「应用自身包」这三类，干净的 AGDK 游戏现在报告 0 个注入模块。
  * **修误判 2（安全阀）**：非交互的自动模式只清「带 hook 特征（Dobby/imgui/…）」的模块；
    仅有 JNI 绑定特征的候选只提示、需显式 `--strip-only` 指定，避免误删正常插件 SDK。
  * **支持改名的加载器**：除了按 JNI 类名定位，还会扫 `System.loadLibrary("<库名>")` 的调用者类，
    把重命名过的加载器一起清掉（清单组件/应用类会跳过）。

   # (注意)这是AI写的，这玩意的稳定性谁都不敢保证，纯吃饱了没事干的项目
