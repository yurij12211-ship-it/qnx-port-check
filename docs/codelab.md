# Codelab: port a Linux event server to QNX 8.0 with qnx-port-check

**Time:** about 45 minutes. **You need:** Linux or WSL, Python 3.8+, CMake, and the free QNX SDP 8.0 from [QNX Everywhere](https://www.qnx.com/products/everywhere/) for the build steps.

**What you will do:** take a small TCP echo server written the Linux way (epoll, timerfd, prctl, CPU affinity, `/proc/cpuinfo`), find every QNX blocker in one scan, fix each one the QNX way, and cross-compile the result with `qcc`.

The code is in [`examples/event-server`](../examples/event-server): `before/` is the starting point, `after/` is the finished port.

---

## 1. Install the checker

```bash
pip install git+https://github.com/yurij12211-ship-it/qnx-port-check
qnx-port-check --version
```

## 2. Scan before you compile

```bash
git clone https://github.com/yurij12211-ship-it/qnx-port-check
cd qnx-port-check/examples/event-server/before
qnx-port-check scan .
```

You get 14 errors and 4 warnings grouped into eight problems:

| Problem | Rule | Lines |
|---|---|---|
| epoll event loop | QPC002 | include, create, ctl, wait |
| timerfd heartbeat | QPC003 | include, create, settime |
| prctl thread name | QPC007 | include, call |
| sched_setaffinity / cpu_set_t | QPC006 | 4 lines |
| `/proc/cpuinfo` parsing | QPC010 | warning |
| `rt pthread` in CMake | QPB001 | warning |
| `-march=native` | QPB002 | warning |
| sockets but no libsocket | QPB004 | warning |

That list is the whole porting plan. Without it you would discover these one `qcc` error at a time. Save it for your PR:

```bash
qnx-port-check scan . -f md -o QNX_PORTING.md
```

## 3. Replace epoll with poll()

epoll does not exist on QNX. For a handful of descriptors, `poll()` is portable and simple:

```c
struct pollfd fds[2] = {{.fd = srv, .events = POLLIN}, {.fd = -1}};
for (;;) {
    if (poll(fds, 2, -1) <= 0) continue;
    if (fds[0].revents & POLLIN) { /* accept + echo */ }
}
```

For large event-driven servers on QNX, the native pattern is `ionotify()` arming a pulse to a channel, so one thread can wait on sockets, timers and messages at once.

## 4. Replace timerfd with a timer pulse

On QNX a timer can deliver a **pulse**, a small kernel message, to a channel. That is the QNX equivalent of a readable timerfd:

```c
#if defined(__QNX__)
#include <sys/neutrino.h>
#define PULSE_HEARTBEAT (_PULSE_CODE_MINAVAIL + 1)

static void *heartbeat(void *arg) {
    int chid = ChannelCreate(0);
    int coid = ConnectAttach(0, 0, chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, coid, SIGEV_PULSE_PRIO_INHERIT, PULSE_HEARTBEAT, 0);
    timer_t t;
    timer_create(CLOCK_MONOTONIC, &ev, &t);
    struct itimerspec its = {{1, 0}, {1, 0}};
    timer_settime(t, 0, &its, NULL);
    for (;;) {
        struct _pulse p;
        if (MsgReceivePulse(chid, &p, sizeof p, NULL) == 0 && p.code == PULSE_HEARTBEAT)
            printf("heartbeat %lu\n", ++beats);
    }
}
#endif
```

The Linux timerfd path stays in the `#else` branch. qnx-port-check knows that a branch after `#if defined(__QNX__)` is never compiled on QNX, so it stops reporting it.

## 5. Thread name, CPU pinning, CPU count

```c
pthread_setname_np(pthread_self(), "echo-server");     /* instead of prctl(PR_SET_NAME) */

long n = sysconf(_SC_NPROCESSORS_ONLN);                 /* instead of parsing /proc/cpuinfo */

#if defined(__QNX__)
ThreadCtl(_NTO_TCTL_RUNMASK, (void *)(uintptr_t)(1u << cpu));   /* instead of sched_setaffinity */
#else
cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu, &set);
sched_setaffinity(0, sizeof set, &set);
#endif
```

## 6. Fix the build

```cmake
find_package(Threads REQUIRED)
target_link_libraries(echo-server Threads::Threads)
if(QNX)
  target_link_libraries(echo-server socket)   # BSD sockets are in libsocket on QNX
endif()
```

Drop `rt` (part of libc on QNX) and `-march=native` (a host flag that breaks cross-compiling).

Scan again:

```bash
cd ../after
qnx-port-check scan .
# 0 errors, 0 warnings. Verdict: Ready to try a QNX build
```

## 7. Cross-compile with qcc

```bash
source ~/qnx800/qnxsdp-env.sh
qnx-port-check scan . --arch aarch64le          # now also verifies every header against the SDP
qnx-port-check toolchain --arch aarch64le      # writes qnx-aarch64le.cmake
cmake -B build-qnx -DCMAKE_TOOLCHAIN_FILE=qnx-aarch64le.cmake
cmake --build build-qnx
file build-qnx/echo-server                     # ELF 64-bit LSB executable, ARM aarch64 ... QNX
```

With `QNX_TARGET` set, any Linux system header that is not in your SDP is reported as `QPH001` and confirmed by the real headers, not by a rule list.

## 8. Run it

Copy `echo-server` to a Raspberry Pi 5 running the QNX 8.0 image, or to a QEMU target from QNX Everywhere, then:

```bash
./echo-server &
echo hello | nc localhost 7000      # prints: hello
# heartbeat 1, heartbeat 2, ... once per second from the timer pulse
```

## 9. Keep it ported

Add the checker to CI, so a new `epoll_wait` or `-ldl` shows up as a pull-request annotation instead of a broken QNX build a month later:

```yaml
- uses: yurij12211-ship-it/qnx-port-check@main
```

## Recap

| Linux | QNX 8.0 |
|---|---|
| epoll | poll(), or ionotify() + pulses |
| timerfd | timer_create() + SIGEV_PULSE + MsgReceivePulse() |
| prctl(PR_SET_NAME) | pthread_setname_np() |
| sched_setaffinity | ThreadCtl(_NTO_TCTL_RUNMASK) |
| /proc/cpuinfo | sysconf(_SC_NPROCESSORS_ONLN), SYSPAGE_ENTRY |
| -lrt -ldl | in libc |
| sockets | link `socket` |
