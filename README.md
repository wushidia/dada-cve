# dada-cve

小米 15（`dada`，Android 15 / kernel 6.6.118 GKI）的 POSIX CPU timer 提权实现，
以及集成它的 GhostLock App 源码。跑通之后得到的是 KernelSU 的 root：

```
$ su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ grep kernelsu /proc/modules
kernelsu 180224 1 - Live 0x0000000000000000 (O)
```

仓库包含两部分：

| 目录 | 内容 |
| --- | --- |
| `kernel/` `tools/` `build.sh` | 独立的提权 payload（C 单文件 + 两个镜像解析脚本） |
| `app/` | GhostLock App 完整 Gradle 工程，正是它把 payload 打包进 assets、经 Shizuku 的 shell 通道投放并拉起 KernelSU |

## 原理

### 1. 漏洞点

`posix_cpu_timer_del()` 在定时器已经脱离队列时仍然读写 `timerqueue_node`，
于是 `k_itimer` 被 `kfree`（`posix_timers_cache`，order-1 slab，31 对象/页）后，
其中的 `rb_node` 仍会被 `rb_erase()` 当作红黑树节点操作。这是一次
**use-after-free 后的有限写**：谁重新占用了那块 slab 页，谁就控制写入目标与写入值。

### 2. 把控制权交给用户态

1. 目标进程创建大量 `CLOCK_THREAD_CPUTIME_ID` 定时器（`NTIMERS = 4096`），
   其中一个是 victim，带 `SIGEV_SIGNAL`。
2. 进程 `execve("/proc/self/exe")`。exec 时旧的 `signal_struct` 被释放，
   victim 定时器随之 `posix_cpu_timer_del()` → 触发 UAF，`k_itimer` 归还 slab。
3. 释放前用 tracefs 的 `kmem_cache_alloc` 记录拿到 victim 的**真实内核地址**
   （`V`）和 `do_timer_create` 的 call site，从而算出 KASLR slide。
   `/sys/kernel/tracing/per_cpu/cpu*/trace_pipe_raw` 保留真实指针，
   而文本 `/trace` 输出是哈希过的，这也是不少旧移植版泄漏不到指针的原因。
4. 释放之后用 socket 缓冲区（`SOCK_STREAM` + 16 MiB `SO_SNDBUF`）重新占用这块
   order-1 页，页内容是精心构造的 payload：
   - 定时器节点偏移处写 `rb_node`，让 `rb_erase()` 走 case-1-left 路径，
     产生**一次 8 字节写入**；
   - 同一页上按 `struct cred` 布局铺一份 fake cred。

   落点判定不靠猜：读 `mm_page_alloc` 记录，只有当这个 pfn 是被我们自己的
   spray 线程拿走时才继续 reap。被别人抢走就放弃并重试，因此不会把系统页
   当作 `rb_node` 去擦。

### 3. 写入原语

`rb_erase()` 在 case-1-left 下会写 `rb_left->__rb_parent_color`。payload 里：

- `__rb_parent_color = A`（节点自身地址，自引用 → `RB_EMPTY_NODE` 为真）
- `rb_right = NULL`（保证走左分支）
- `rb_left = S`（要写的目标地址）

于是 `*(uint64_t *)S = 0`。把 `S` 指向 `task->cred` 就能让任务凭据指向 fake cred；
把 `S` 指向 `selinux_state.enforcing` 就能关掉 SELinux 强制模式。

### 4. fake cred

页上的 fake cred 按 BTF 偏移铺好，关键字段：

- `cap_effective / cap_permitted / cap_bset = FULLCAP (0x1ffffffffff)`
- `euid = fsuid = 0`
- `security` 指向页内另一个偏移处的 LSM blob，`sid = 1`（kernel sid）
- `user / user_ns / ucounts / group_info` 指向内核里现成的 `root_user`、
  `init_user_ns`、`init_ucounts`、`init_groups`

这些指针需要 **KASLR slide**，slide 由第 2 步测得的 call site 减去镜像里的
链接地址得到。

### 5. 交给 KernelSU

`cap_effective` 已是全量、`euid` 已是 0，但 `init_module` 的真正门槛是
`CAP_SYS_MODULE`，所以还要握住一份有效 cred 的进程去执行 `ksud late-load`。
子进程 exec 安装脚本，脚本解析已安装的 KernelSU manager 的 `libksud.so`，
按本机 KMI（`android15-6.6`）late-load 模块，最后内核里出现 `kernelsu`。

SELinux 必须是 permissive 才能 insmod，所以同时把 `selinux_state.enforcing`
置 0。`panic_on_warn` 也一并置 0，因为自引用节点的 `rb_erase()` 会触发一次
`RB_EMPTY_NODE` 的 WARN。

## 编译

### 提权 payload

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk    # NDK r26+
./build.sh                    # 产出 ./cve-2026-98260
./build.sh /tmp/payload       # 或指定输出路径
```

产物是静态、非 PIE 的 arm64 可执行文件。单独跑：

```bash
adb push cve-2026-98260 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/cve-2026-98260
adb shell /data/local/tmp/cve-2026-98260 fake
```

运行模式：

| 参数 | 作用 |
| --- | --- |
| `fake` | 完整链路：fake cred → 关 SELinux → `ksud late-load` |
| `check` | 只做只读自检（tracefs、direct map base） |
| `leak` | 只泄漏 cred 与 `task_struct`，不改任何内核数据 |
| `selftest` | 把写原语打在自己进程的页上，安全验证 |
| `shell` / `daemon` | 零写 uid 路径，走临时 su，不需要 KernelSU |

> `fake` 成功后进程会一直驻留（`pause()`），这是**故意的**：那块页现在承载
> 活着的 `task->cred`，进程退出就会把页还给 slab，随后的 `cleanup_timerqueue()`
> 会在陈旧的 `rb_node` 上操作并 panic。**清理只能重启设备**，不要 `kill`。

### GhostLock App

`app/` 是完整 Gradle 工程，`app/app/src/main/assets/` 里已带好 payload，
clone 后可直接编译：

```bash
cd app
./gradlew assembleRelease      # 或 assembleDebug
```

产物在 `app/build/app/outputs/apk/release/`。需要用本机 Android SDK / NDK 时
创建 `local.properties`（不要提交）：

```properties
sdk.dir=/path/to/android-sdk
ndk.dir=/path/to/android-sdk/ndk/27.0.12077973
```

如果要出签名版，`app/app/build.gradle.kts` 会从属性里读
`KEYSTORE_PATH` / `KEYSTORE_PASS` / `KEY_ALIAS` / `KEY_PASSWORD`；
不提供时自动退回 debug 签名，仍然可以直接安装。

`app/app/src/main/jniLibs/arm64-v8a/` 下的 `libghostlock.so` 与
`libextract.so` 是预编译产物，已随仓库提供（含编译期路径字符串，无影响）；
需要自行重建时使用 `app/src/Makefile`。

装上之后：授予 Shizuku 权限 → App 内点执行 → payload 走 fake cred 链 →
`ksud late-load` 把 KernelSU 模块载入内核 → 设备上出现可用的 `su`。

## 针对本机重新标定

源码里的常量都来自 `dada` 这一版 `boot.img`，换机型或换版本必须重算。

```bash
# 1. 从 boot.img 取出 arm64 kernel（去掉 ANDROID! 头）
# 2. 解出 kallsyms
python3 tools/kallsyms_dump.py /path/to/kernel.bin kallsyms.txt

# 3. BTF 字段偏移（cred / task_struct / k_itimer）
python3 tools/btf_dump.py /path/to/vmlinux.btf
```

需要替换的宏集中在 `kernel/cve-2026-98260.c` 顶部：

```c
#define STATIC_TIMER_SITE   0xffffffc080195d94ULL  /* do_timer_create+0xa8 */
#define SELINUX_STATE_STATIC 0xffffffc08237a378ULL
#define PANIC_ON_WARN_STATIC 0xffffffc08212ae0cULL
#define ROOT_USER_STATIC    0xffffffc08214f220ULL
#define INIT_USER_NS_STATIC 0xffffffc08214ef90ULL
#define INIT_UCOUNTS_STATIC 0xffffffc082150cf0ULL
#define INIT_GROUPS_STATIC  0xffffffc082150780ULL
#define OFF_TASK_CRED       0x820ULL
#define TASK_ALLOC_LOW21    0xab93cUL
#define TASK_ALLOC_BYTES    0x14c0ULL
```

`do_timer_create` 的 call site 由 trace 实测，与 `STATIC_TIMER_SITE` 相减得到
slide；`TASK_ALLOC_*` 是 `copy_process()` 里 `task_struct_cachep` 那次分配在
`kmem_cache_alloc` 记录中的 low21 与 `bytes_req`。

## 参考

- 原始漏洞思路与零写实现：[woshigenm](https://github.com/woshigenm)
- fake cred + `ksud late-load` 流程（本项目直接沿用）：[YuKongA](https://github.com/YuKongA)
- KernelSU：[tiann/KernelSU](https://github.com/tiann/KernelSU)
- Shizuku：[RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku)
- GhostLock 宿主项目：[wushidia/ghostlock](https://github.com/wushidia/ghostlock)
