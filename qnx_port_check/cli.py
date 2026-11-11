import argparse
import os
import sys

from . import __version__, report
from .rules import RULES, QNX_SOCKET_RULE, ERROR, WARNING
from .scanner import scan_path, summarize
from .toolchain import cmake_toolchain, ARCHES


def cmd_scan(a):
    sdp = None
    target = a.qnx_target or os.environ.get("QNX_TARGET")
    if target and not a.no_sdp:
        from .sdp import SDP
        try:
            sdp = SDP(target, arch=a.arch)
        except ValueError as e:
            print(f"warning: {e}; continuing with static rules only", file=sys.stderr)
    result = scan_path(a.path, exclude=a.exclude or (), sdp=sdp, platform_files=a.platform_files)
    if a.ignore:
        ign = set(a.ignore)
        result["findings"] = [f for f in result["findings"] if f.rule not in ign]
    project = os.path.basename(os.path.abspath(a.path))
    if a.format == "json":
        out = report.as_json(result)
    elif a.format == "sarif":
        out = report.sarif(result)
    elif a.format == "md":
        out = report.markdown(result, project)
    else:
        out = report.text(result, color=sys.stdout.isatty() and not a.no_color, show_info=a.show_info)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    counts = summarize(result["findings"])["counts"]
    fail = {"error": counts[ERROR], "warning": counts[ERROR] + counts[WARNING], "never": 0}[a.fail_on]
    return 1 if fail else 0


def cmd_rules(a):
    for r in RULES + [QNX_SOCKET_RULE]:
        print(f"{r.id}  {r.severity:7}  {r.title}\n          {r.fix}")
    print("QPH001  error    System header missing from the installed QNX SDP (requires QNX_TARGET)")
    return 0


def cmd_toolchain(a):
    text = cmake_toolchain(a.arch)
    path = a.output or f"qnx-{a.arch}.cmake"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {path}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="qnx-port-check",
                                description="Find what stops a Linux C/C++ project from building and running on QNX 8.0.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a project directory or file")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "md"], default="text")
    s.add_argument("-o", "--output")
    s.add_argument("--qnx-target", help="QNX SDP target dir (defaults to $QNX_TARGET) to verify headers")
    s.add_argument("--arch", choices=list(ARCHES), help="target architecture for SDP header lookup")
    s.add_argument("--no-sdp", action="store_true", help="ignore QNX_TARGET, static rules only")
    s.add_argument("--exclude", action="append", help="path prefix to skip (repeatable)")
    s.add_argument("--ignore", action="append", help="rule id to ignore (repeatable)")
    s.add_argument("--fail-on", choices=["error", "warning", "never"], default="error")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--show-info", action="store_true", help="also print info-level findings in text output")
    s.add_argument("--platform-files", action="store_true",
                   help="also scan files named for another OS (linux.c, win32/, os390.c), skipped by default")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list all rules")
    r.set_defaults(func=cmd_rules)

    t = sub.add_parser("toolchain", help="write a CMake toolchain file for QNX 8.0")
    t.add_argument("--arch", choices=list(ARCHES), default="aarch64le")
    t.add_argument("-o", "--output")
    t.set_defaults(func=cmd_toolchain)

    a = p.parse_args(argv)
    if not a.cmd:
        a = p.parse_args(["scan"] + (argv if argv is not None else sys.argv[1:]))
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
