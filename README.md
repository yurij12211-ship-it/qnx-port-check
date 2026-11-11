# qnx-port-check

**Find what stops a Linux C/C++ project from building and running on QNX 8.0, before you spend a day fighting the cross-compiler.**

Porting open-source code to QNX usually fails the same way: `epoll`, `<linux/...>` headers, `sched_setaffinity`, `-lrt` in the build, sockets without `-lsocket`, `/proc/cpuinfo` parsing. Each one costs a compile-fix-recompile loop with `qcc`. `qnx-port-check` finds all of them in seconds, tells you the QNX way to do it, and, when the QNX SDP is installed, verifies every system header against the real QNX 8.0 headers.

```
$ qnx-port-check scan ./my-linux-daemon
ERROR   src/server.c:25  QPC002 epoll
        int ep = epoll_create1(0);
        fix: Use poll()/select() for portable code. For event-driven QNX servers use ionotify()
             with pulses delivered to a channel (ChannelCreate/MsgReceivePulse).
ERROR   src/server.c:19  QPC006 CPU affinity (Linux API)
        sched_setaffinity(0, sizeof(set), &set);
        fix: Use ThreadCtl(_NTO_TCTL_RUNMASK, ...) with a runmask from <sys/neutrino.h>.
WARNING CMakeLists.txt:1  QPB004 Sockets used but libsocket not linked
        fix: Add `socket` to target_link_libraries for QNX builds.
...
Scanned 2 files against QNX SDP 8.0.0
11 errors, 4 warnings. Verdict: Significant porting effort (about 12 h).
```

## Why it is not just grep

- **Understands the preprocessor.** Code inside `#ifdef __linux__`, `#ifdef __APPLE__`, or the `#else` after an existing `#if defined(__QNX__)` branch is not reported, because QNX never compiles it. Code behind build options (`#ifdef HAVE_EPOLL`, `#ifdef SO_BINDTODEVICE`) is downgraded to info.
- **Understands CMake branches.** `target_link_libraries(x dl)` inside `if(APPLE)` or in the `else()` after `elseif(QNX)` is fine and stays quiet.
- **Skips files built only for other OSes** (`linux.c`, `win32/`, `os390.c`, ...) and says which ones it skipped.
- **Ignores comments and string contents**, so `// TODO: drop epoll_wait(` is not a finding.
- **Ground truth from the SDP.** With `QNX_TARGET` set (source `qnxsdp-env.sh`), every `#include <...>` that exists on Linux is looked up in `$QNX_TARGET/usr/include`. Missing headers become verified `QPH001` errors, and matching rule findings are marked `[verified in SDP]`.

Results on real projects (static mode):

| Project | Errors | Warnings | Notes |
|---|---|---|---|
| eclipse-mosquitto | 0 | 3 | already supports QNX; remaining warnings are Makefile `-ldl` |
| libuv | 0 | 4 | 65 OS-specific files correctly skipped |
| ninja | 0 | 0 | Linux paths are all guarded |
| examples/event-server/before | 14 | 4 | epoll, timerfd, prctl, affinity, `/proc/cpuinfo`, `-lrt` |
| examples/event-server/after | 0 | 0 | ported in the [codelab](docs/codelab.md) |

## Install

```bash
pip install git+https://github.com/yurij12211-ship-it/qnx-port-check
```

Python 3.8+, no dependencies.

## Use

```bash
qnx-port-check scan path/to/project                 # human-readable
qnx-port-check scan . -f md -o QNX_PORTING.md       # porting report for an issue/PR
qnx-port-check scan . -f sarif -o qnx.sarif         # GitHub code scanning
qnx-port-check scan . -f json                        # for scripts
qnx-port-check rules                                 # list all rules and fixes
qnx-port-check toolchain --arch aarch64le            # CMake toolchain for qcc/q++

source ~/qnx800/qnxsdp-env.sh                        # with the QNX SDP: verify headers
qnx-port-check scan . --arch aarch64le
```

Exit code is 1 when errors are found (`--fail-on warning|never` to change). Silence a line with `// qnx-port-check: ignore QPC002`.

### GitHub Action

```yaml
- uses: yurij12211-ship-it/qnx-port-check@main
  with:
    path: .
```

Findings appear as code-scanning alerts on the pull request (see `action.yml`).

## Rules

| ID | Severity | What | QNX replacement |
|---|---|---|---|
| QPC001 | error | `<linux/...>` headers | POSIX / devctl() / io-sock APIs |
| QPC002 | error | epoll | poll()/select(), ionotify() + pulses |
| QPC003 | error | timerfd, signalfd | timer_create() + SIGEV_PULSE, sigwaitinfo() |
| QPC004 | warning | eventfd | pipe(), MsgSendPulse() |
| QPC005 | warning | inotify | needs fsevmgr on the target |
| QPC006 | error | sched_setaffinity, cpu_set_t | ThreadCtl(_NTO_TCTL_RUNMASK) |
| QPC007 | error | prctl | pthread_setname_np(), procmgr_ability() |
| QPC008 | error | raw syscall() | libc call; QNX uses message passing |
| QPC009 | error | clone, unshare, setns | posix_spawn(), pthread_create() |
| QPC010 | warning | /proc/cpuinfo, /proc/self/maps | sysconf(), SYSPAGE_ENTRY, devctl(DCMD_PROC_*) |
| QPC011 | error | sysinfo() | system page, sysconf() |
| QPC012 | error | futex | pthread sync / atomics |
| QPC013 | warning | glibc-only extensions | guard with `__GLIBC__`, getprogname() |
| QPC014 | error | AF_PACKET, netlink, SIOCGIFHWADDR | getifaddrs()+AF_LINK, BPF, PF_ROUTE |
| QPC015 | warning | execinfo backtrace | QNX libbacktrace |
| QPC016 | warning | fallocate, O_DIRECT, O_TMPFILE | posix_fallocate(), mkstemp() |
| QPC017 | error | getauxval | build-time detection, SYSPAGE cpuinfo |
| QPC018 | warning | MAP_POPULATE, MADV_*, mremap | drop flag, mlock(), munmap+mmap |
| QPC019 | info | `#ifdef __linux__` without QNX branch | add `#elif defined(__QNX__)` |
| QPB001 | warning | `-lrt`, `-ldl`, `-lpthread` | in libc on QNX |
| QPB002 | warning | `-march=native`, host compiler | qcc -Vgcc_ntoaarch64le |
| QPB003 | info | Linux-only build branch | add a QNX branch |
| QPB004 | warning | sockets without libsocket | link `socket` |
| QPH001 | error | header missing from installed SDP | verified against `$QNX_TARGET` |

The rules are a starting point, not a compiler. A clean report means "worth trying a QNX build", which `qnx-port-check toolchain` helps you set up.

## Tutorial

[docs/codelab.md](docs/codelab.md): port a small Linux event server to QNX 8.0 step by step, from the first scan to a binary running in QEMU.

## License

Apache-2.0
