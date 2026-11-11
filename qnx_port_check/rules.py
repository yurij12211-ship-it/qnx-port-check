"""Portability rules: Linux/glibc constructs that break or behave differently on QNX 8.0.

Each rule is a regex over one source or build file. Rules are deliberately
conservative and every finding carries a concrete QNX replacement. When the
QNX SDP is installed (QNX_TARGET is set) header findings are additionally
verified against the real QNX 8.0 headers, see sdp.py.
"""
from dataclasses import dataclass, field
import re

ERROR, WARNING, INFO = "error", "warning", "info"

DOCS = "https://www.qnx.com/developers/docs/8.0/"

C_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".ipp", ".inl")
BUILD_NAMES = ("CMakeLists.txt", "Makefile", "makefile", "GNUmakefile", "meson.build",
               "configure.ac", "configure.in", "BUILD", "BUILD.bazel")
BUILD_EXT = (".cmake", ".mk", ".mak", ".am")


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    pattern: str
    why: str
    fix: str
    kind: str = "source"  # "source" or "build"
    in_strings: bool = False  # match inside string literals (paths)
    flags: int = re.MULTILINE
    regex: re.Pattern = field(init=False, repr=False)

    def __post_init__(self):
        self.regex = re.compile(self.pattern, self.flags)


RULES = [
    # ---------------- source rules ----------------
    Rule("QPC001", "Linux kernel header", ERROR,
         r"#\s*include\s*<linux/[\w/.]+>",
         "Headers under <linux/...> describe the Linux kernel ABI. QNX is a microkernel with a different ABI; these headers do not exist in the QNX SDP.",
         "Replace the kernel interface with its POSIX or QNX equivalent (devctl() for device control, io-sock/BSD socket APIs for networking) and guard the Linux path with #ifdef __linux__."),
    Rule("QPC002", "epoll", ERROR,
         r"#\s*include\s*<sys/epoll\.h>|\bepoll_(?:create1?|ctl|wait|pwait)\s*\(",
         "epoll is Linux-only. QNX 8.0 has no epoll.",
         "Use poll()/select() for portable code. For event-driven QNX servers use ionotify() with pulses delivered to a channel (ChannelCreate/MsgReceivePulse)."),
    Rule("QPC003", "timerfd / signalfd", ERROR,
         r"#\s*include\s*<sys/(?:timerfd|signalfd)\.h>|\b(?:timerfd_create|timerfd_settime|signalfd)\s*\(",
         "timerfd and signalfd are Linux file-descriptor wrappers that QNX does not provide.",
         "Timers: timer_create() with a SIGEV_PULSE sigevent (SIGEV_PULSE_INIT) and receive the pulse on a channel. Signals: block them and use sigwaitinfo() in a dedicated thread."),
    Rule("QPC004", "eventfd", WARNING,
         r"#\s*include\s*<sys/eventfd\.h>|\beventfd\s*\(",
         "eventfd is a Linux extension; do not rely on it on QNX.",
         "Use a pipe() pair for poll()-based wakeups, or MsgSendPulse() to a channel for QNX-native event loops."),
    Rule("QPC005", "inotify", WARNING,
         r"#\s*include\s*<sys/inotify\.h>|\binotify_(?:init1?|add_watch)\s*\(",
         "On QNX file-system change notification is provided by the fsevmgr service, which must be running on the target; behaviour differs from Linux inotify.",
         "Make sure fsevmgr is started in the target image, or fall back to periodic stat() polling."),
    Rule("QPC006", "CPU affinity (Linux API)", ERROR,
         r"\b(?:sched_setaffinity|sched_getaffinity|pthread_setaffinity_np|pthread_getaffinity_np)\s*\(|\bcpu_set_t\b|\bCPU_(?:SET|ZERO|ISSET)\s*\(",
         "cpu_set_t and the *_affinity calls are glibc/Linux APIs.",
         "Use ThreadCtl(_NTO_TCTL_RUNMASK, ...) or _NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT with a runmask (RMSK_SET) from <sys/neutrino.h>."),
    Rule("QPC007", "prctl", ERROR,
         r"#\s*include\s*<sys/prctl\.h>|\bprctl\s*\(",
         "prctl() is Linux-only.",
         "For thread names use pthread_setname_np(). Other prctl options (seccomp, dumpable, no_new_privs) need a QNX-specific design, e.g. procmgr_ability() for privilege control."),
    Rule("QPC008", "raw syscall()", ERROR,
         r"\bsyscall\s*\(\s*(?:SYS_|__NR_)|#\s*include\s*<sys/syscall\.h>",
         "Linux syscall numbers do not exist on QNX: system services are reached through message passing to resource managers.",
         "Call the POSIX/libc function instead (gettid() -> pthread_self() or gettid() from <process.h>, getrandom() -> arc4random_buf())."),
    Rule("QPC009", "clone / namespaces", ERROR,
         r"\b(?:clone|clone3|unshare|setns)\s*\(",
         "clone() and Linux namespaces are not available on QNX.",
         "Use posix_spawn() or QNX spawn() for processes and pthread_create() for threads."),
    Rule("QPC010", "/proc layout assumptions", WARNING,
         r"[\"']/proc/(?:self/(?:maps|status|stat|fd|exe|cmdline)|cpuinfo|meminfo|loadavg|net/)",
         "QNX has a /proc filesystem, but its layout is different: /proc/<pid>/as is the address space and there is no /proc/cpuinfo or /proc/meminfo text file.",
         "Use sysconf(_SC_NPROCESSORS_ONLN) for CPU count, the system page (SYSPAGE_ENTRY) for hardware info, and devctl(DCMD_PROC_*) on /proc/<pid>/as for process details.",
         in_strings=True),
    Rule("QPC011", "sysinfo()", ERROR,
         r"#\s*include\s*<sys/sysinfo\.h>|\bsysinfo\s*\(\s*&",
         "sysinfo() and <sys/sysinfo.h> are Linux-specific.",
         "Read memory and CPU information from the QNX system page (SYSPAGE_ENTRY) or use sysconf()."),
    Rule("QPC012", "futex", ERROR,
         r"\bFUTEX_(?:WAIT|WAKE)\w*|#\s*include\s*<linux/futex\.h>",
         "Futexes are a Linux kernel primitive.",
         "Use pthread mutexes/condition variables or C11/C++ atomics with std::atomic::wait; QNX implements them on top of SyncMutex*/SyncCondvar* kernel calls."),
    Rule("QPC013", "glibc-only extension", WARNING,
         r"\b(?:mallinfo2?|malloc_trim|malloc_usable_size|program_invocation(?:_short)?_name|__GLIBC__|gnu_get_libc_version|secure_getenv)\b",
         "QNX ships its own C library, not glibc. GNU extensions may be missing or behave differently.",
         "Guard the code with #ifdef __GLIBC__ and provide a fallback for QNX (e.g. getprogname() instead of program_invocation_name)."),
    Rule("QPC014", "Linux-only networking", ERROR,
         r"\bAF_PACKET\b|\bPF_PACKET\b|\bSIOCGIFHWADDR\b|\bSO_BINDTODEVICE\b|\bNETLINK_\w+|\bAF_NETLINK\b",
         "The QNX 8.0 network stack (io-sock) is based on FreeBSD, so Linux packet sockets, netlink and these ioctls are not available.",
         "MAC addresses: getifaddrs() and AF_LINK entries (struct sockaddr_dl). Raw frames: BPF (/dev/bpf). Route/link events: a PF_ROUTE routing socket."),
    Rule("QPC015", "execinfo backtrace", WARNING,
         r"#\s*include\s*<execinfo\.h>|\bbacktrace_symbols(?:_fd)?\s*\(",
         "<execinfo.h> is a glibc header.",
         "QNX provides its own backtrace library (<backtrace.h>, bt_* functions, link with -lbacktrace). Verify against your SDP."),
    Rule("QPC016", "fallocate / Linux file flags", WARNING,
         r"\bfallocate\s*\(|\bO_DIRECT\b|\bO_TMPFILE\b|\bFALLOC_FL_\w+",
         "These are Linux file-system extensions.",
         "Use posix_fallocate() and regular open()/mkstemp(); treat O_DIRECT behaviour as file-system specific."),
    Rule("QPC017", "getauxval", ERROR,
         r"\bgetauxval\s*\(|#\s*include\s*<sys/auxv\.h>",
         "getauxval() and the ELF auxiliary vector API are glibc/Linux specific.",
         "Detect CPU features at build time, or read them from the QNX system page (SYSPAGE_ENTRY(cpuinfo))."),
    Rule("QPC018", "Linux mmap flags", WARNING,
         r"\bMAP_(?:POPULATE|HUGETLB|LOCKED|NORESERVE|GROWSDOWN)\b|\bMADV_(?:HUGEPAGE|DONTDUMP|DONTFORK|WIPEONFORK)\b|\bmremap\s*\(",
         "These mmap/madvise flags and mremap() are Linux-specific.",
         "Drop the flag or guard it with #ifdef; use mlock() instead of MAP_LOCKED and munmap()+mmap() instead of mremap()."),
    Rule("QPC019", "Linux-only platform guard", INFO,
         r"#\s*(?:ifdef\s+__linux__\b|(?:el)?if\b[^\n]*\b__linux__\b)(?![^\n]*__QNX)",
         "Code is selected for Linux only; on QNX this branch is skipped and a fallback (or nothing) is compiled.",
         "Add an explicit `#elif defined(__QNX__)` branch so the QNX behaviour is intentional rather than accidental."),

    # ---------------- build rules ----------------
    Rule("QPB001", "Linking librt / libdl / libpthread", WARNING,
         r"-l(?:rt|dl|pthread)\b|\btarget_link_libraries\s*\([^)]*\b(?:rt|dl|pthread)\b[^)]*\)|\bdependency\(\s*['\"](?:dl|rt)['\"]",
         "On QNX the real-time, dynamic-loading and pthread functions live in libc; separate librt/libdl are not shipped, so -lrt or -ldl fails at link time.",
         "Link these libraries only when not building for QNX, e.g. `if(NOT CMAKE_SYSTEM_NAME STREQUAL \"QNX\")`, or use Threads::Threads and CMAKE_DL_LIBS.",
         kind="build"),
    Rule("QPB002", "Host-specific compiler flags", WARNING,
         r"-march=native|-mtune=native|-m(?:sse\d?|avx\d*)\b|\bCMAKE_C_COMPILER\s+gcc\b",
         "Host-tuned flags break cross-compilation for QNX targets such as aarch64le.",
         "Build with the QNX toolchain (qcc/q++ with -Vgcc_ntoaarch64le or -Vgcc_ntox86_64) and keep CPU tuning per target.",
         kind="build"),
    Rule("QPB003", "Linux-only build branch", INFO,
         r"CMAKE_SYSTEM_NAME\s+(?:STREQUAL|MATCHES)\s+\"?Linux\"?|host_machine\.system\(\)\s*==\s*['\"]linux['\"]",
         "The build has Linux-specific configuration and no QNX branch.",
         "Add an equivalent branch for CMAKE_SYSTEM_NAME STREQUAL \"QNX\" (sockets need -lsocket, no -lrt/-ldl).",
         kind="build"),
]

RULES_BY_ID = {r.id: r for r in RULES}

# Cross-file rule: sockets on QNX need libsocket.
SOCKET_USE = re.compile(r"\b(?:socket|getaddrinfo|gethostbyname|inet_pton|bind)\s*\(")
SOCKET_LINK = re.compile(r"-lsocket\b|\bsocket\b")
QNX_SOCKET_RULE = Rule(
    "QPB004", "Sockets used but libsocket not linked", WARNING, r"$^",
    "On QNX the BSD socket API is in libsocket, not libc. Without -lsocket the link fails with undefined socket symbols.",
    "Add `socket` to target_link_libraries for QNX builds (or -lsocket to LDLIBS).", kind="build")
RULES_BY_ID[QNX_SOCKET_RULE.id] = QNX_SOCKET_RULE


def is_source(path):
    return path.lower().endswith(C_EXT)


def is_build(path):
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return name in BUILD_NAMES or name.lower().endswith(BUILD_EXT)
