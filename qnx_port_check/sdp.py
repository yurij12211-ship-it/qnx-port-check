"""Ground-truth checks against an installed QNX SDP 8.0.

When QNX_TARGET points at the SDP target directory (set by sourcing qnxsdp-env.sh),
every system header the project includes is looked up in the real QNX headers.
A header that exists on the Linux host but not in the SDP is reported as QPH001,
and static-rule findings about that header are marked as verified.
"""
import os
import re

from .scanner import Finding
from .rules import ERROR

HOST_INCLUDE_DIRS = ["/usr/include", "/usr/local/include", "/usr/include/x86_64-linux-gnu",
                     "/usr/include/aarch64-linux-gnu"]


class SDP:
    def __init__(self, qnx_target, arch=None, host_dirs=None):
        self.target = os.path.abspath(qnx_target)
        if not os.path.isdir(os.path.join(self.target, "usr", "include")):
            raise ValueError(f"{qnx_target} does not look like a QNX target directory (no usr/include)")
        self.arch = arch
        self.include_dirs = [os.path.join(self.target, "usr", "include")]
        for a in ([arch] if arch else ["aarch64le", "x86_64"]):
            d = os.path.join(self.target, a, "usr", "include")
            if os.path.isdir(d):
                self.include_dirs.append(d)
        self.host_dirs = host_dirs if host_dirs is not None else [d for d in HOST_INCLUDE_DIRS if os.path.isdir(d)]
        self.version = self._detect_version()

    def _detect_version(self):
        # qnxsdp-env.sh exports QNX_HOST/QNX_TARGET; the version is part of the SDP path or in sys/nto_version.h
        hdr = os.path.join(self.target, "usr", "include", "sys", "nto_version.h")
        try:
            with open(hdr, encoding="utf-8", errors="replace") as fh:
                m = re.search(r"#define\s+_NTO_VERSION\s+(\d+)", fh.read())
                if m:
                    v = int(m.group(1))
                    return f"{v // 100}.{(v % 100) // 10}.{v % 10}"
        except OSError:
            pass
        return "unknown"

    def describe(self):
        return {"qnx_target": self.target, "version": self.version, "include_dirs": self.include_dirs}

    def has_header(self, name):
        return any(os.path.isfile(os.path.join(d, name)) for d in self.include_dirs)

    def on_host(self, name):
        return any(os.path.isfile(os.path.join(d, name)) for d in self.host_dirs)

    def verify(self, findings, includes):
        missing = {}
        for rel, line, header in includes:
            if header in missing:
                missing[header].append((rel, line))
                continue
            if self.has_header(header):
                continue
            # only system headers: present on the Linux host or in a well-known system namespace
            if self.on_host(header) or re.match(r"(linux|asm|sys|net|netinet|arpa|bits)/", header):
                missing[header] = [(rel, line)]

        verified_lines = set()
        out = list(findings)
        for header, places in missing.items():
            for rel, line in places:
                verified_lines.add((rel, line))
                out.append(Finding(
                    "QPH001", f"<{header}> is not in the QNX SDP", ERROR, rel, line,
                    f"#include <{header}>",
                    f"Checked against the installed QNX SDP ({self.version}): no {header} in "
                    + ", ".join(os.path.relpath(d, self.target) for d in self.include_dirs) + ".",
                    "Remove the include on QNX or replace it; see the related QPC finding on the same line for the API to use.",
                    verified=True))
        for f in out:
            if (f.path, f.line) in verified_lines:
                f.verified = True
        # a static header rule on the same line duplicates QPH001; keep the more specific static one
        static_lines = {(f.path, f.line) for f in out if f.rule.startswith("QPC")}
        return [f for f in out if not (f.rule == "QPH001" and (f.path, f.line) in static_lines)]
