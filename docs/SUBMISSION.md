# QNX Global Hackathon submission draft

**Project:** qnx-port-check
**Category:** Developer Tooling & Host Tools
**Bonus:** Best Codelab / Tutorial — [docs/codelab.md](codelab.md)
**Video:** https://youtu.be/D5b6wVY39Y0
**Repo:** https://github.com/yurij12211-ship-it/qnx-port-check (Apache-2.0)
**QNX version / target / toolchain:** QNX SDP 8.0; host tool runs on Linux, macOS or Windows with Python 3.8+; analyzes code targeting QNX 8.0 (aarch64le, x86_64) and generates a CMake toolchain for qcc/q++.

## Tagline
Find what stops a Linux C/C++ project from building and running on QNX 8.0, before the first qcc error.

## What it does
Porting open-source or in-house Linux code to QNX fails in predictable places: epoll, timerfd/signalfd, prctl, sched_setaffinity, `<linux/...>` headers, `/proc/cpuinfo` parsing, `-lrt`/`-ldl` in the build, sockets without libsocket. Each costs a compile → fix → recompile loop with qcc. qnx-port-check finds all of them in one scan and gives the QNX 8.0 replacement for each: poll() or ionotify() with pulses, timer_create() with SIGEV_PULSE, ThreadCtl(_NTO_TCTL_RUNMASK), pthread_setname_np(), sysconf/SYSPAGE_ENTRY, linking libsocket.

- 23 rules for C/C++ sources and CMake/Make/Meson build files, each with a concrete fix.
- Preprocessor-aware: code under `#ifdef __linux__`, other-OS branches, and branches after an existing `#if defined(__QNX__)` are not reported; feature-guarded code (`HAVE_*`, `#ifdef SO_BINDTODEVICE`) is downgraded to info.
- CMake-aware: `if(APPLE)` branches and the `else()` after `elseif(QNX)` stay quiet.
- Skips files built only for other OSes (`linux.c`, `win32/`, `os390.c`) and lists them.
- **Ground truth from the SDP:** with QNX_TARGET set, every system `#include` is checked against `$QNX_TARGET/usr/include` and the arch include dir; missing headers become verified QPH001 errors and matching rule findings are marked verified.
- Outputs: terminal, Markdown porting report with an effort estimate, JSON, SARIF 2.1.0 for GitHub code scanning, plus a composite GitHub Action.
- `qnx-port-check toolchain --arch aarch64le|x86_64` writes a CMake toolchain file for qcc/q++.

## How it uses QNX (evidence)
- `qnx_port_check/rules.py`: every rule's replacement is a QNX 8.0 API (ChannelCreate/ConnectAttach/MsgReceivePulse, SIGEV_PULSE_INIT, ThreadCtl runmask, SYSPAGE_ENTRY, devctl DCMD_PROC_*, procmgr_ability, libsocket, fsevmgr). Replacements are cross-checked with QNX's own porting guide (system call replacement matrix) and the 8.0 io-sock migration guide; links are in the README.
- `qnx_port_check/sdp.py`: reads the installed SDP (QNX_TARGET, `sys/nto_version.h`) and verifies headers.
- `qnx_port_check/toolchain.py`: CMake toolchain for qcc/q++ (gcc_ntoaarch64le, gcc_ntox86_64) with CMAKE_SYSROOT=$QNX_TARGET.
- `examples/event-server/after/server.c`: the ported example uses QNX-native timer pulses and ThreadCtl runmask under `#if defined(__QNX__)`.

## Results on real projects (static mode)
- eclipse-mosquitto: 0 errors, 3 warnings (already supports QNX).
- libuv: 0 errors, 4 warnings; 65 OS-specific files correctly skipped.
- ninja: 0 errors, 0 warnings.
- examples/event-server/before: 14 errors, 4 warnings → after: 0 / 0.

## Challenges
Avoiding false positives was the main work: a plain grep flags hundreds of lines in libuv that QNX never compiles. Tracking `#if/#elif/#else` stacks, recognising branches after an explicit QNX branch, and skipping OS-specific files brought libuv from 41 errors to 0 while still catching real issues in code that does compile on QNX.

## What's next
Parse `qcc` build logs and map compiler errors back to rules; more rules for io-sock differences; a VS Code extension using the SARIF output.

## Video script (≤ 3 min)
Title → problem → scan of the Linux event server → timerfd/epoll vs pulse + poll → affinity/name/libsocket → scan after (0/0) → libuv (65 skipped, 0 errors) → SDP header verification → toolchain → SARIF + Action → repo.
