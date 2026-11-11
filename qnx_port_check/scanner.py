"""Walk a project, apply rules, return findings."""
from dataclasses import dataclass, asdict
import os
import re

from .rules import RULES, QNX_SOCKET_RULE, SOCKET_USE, SOCKET_LINK, is_source, is_build, ERROR, WARNING, INFO

SKIP_DIRS = {".git", "build", "_build", "out", "node_modules", "third_party", "3rdparty", "vendor", ".venv", "venv"}
MAX_BYTES = 2_000_000
# Files/dirs that build systems compile only for another OS (libuv's linux.c, win32/, os390.c ...)
PLATFORM_PATH = re.compile(r"(?:^|[-_./])(?:linux|cygwin|os390|zos|aix|darwin|mac|macos|osx|ios|freebsd|openbsd|netbsd|"
                           r"dragonfly|sunos|solaris|win|win32|win64|windows|msvc|mingw|android|haiku|ibmi|hurd|epoll|"
                           r"kqueue|iocp|sysinfo-loadavg|sysinfo-memory)(?=[-_./]|$)", re.I)
SUPPRESS = re.compile(r"qnx-port-check:\s*ignore(?:\s+(QP[CBH]\d{3}))?")


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    path: str
    line: int
    snippet: str
    why: str
    fix: str
    verified: bool = False  # True when confirmed against real QNX SDP headers

    def to_dict(self):
        return asdict(self)


_TOKENS = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/', re.S)


def _blank(s):
    return re.sub(r"[^\n]", " ", s)


def _strip_comments(text, strings=False):
    """Blank out comments (and optionally string contents) keeping line structure intact."""
    def repl(m):
        t = m.group(0)
        if t[0] in "\"'":
            return t[0] + _blank(t[1:-1]) + t[-1] if strings else t
        return _blank(t)
    return _TOKENS.sub(repl, text)


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def iter_files(root, exclude=()):
    root = os.path.abspath(root)
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if any(rel.startswith(e.rstrip("/") + "/") or rel == e for e in exclude):
                continue
            if is_source(rel) or is_build(rel):
                yield full, rel


def scan_text(rel, text, rules=RULES):
    findings = []
    kind = "source" if is_source(rel) else "build"
    lines = text.split("\n")
    code = _strip_comments(text, strings=True) if kind == "source" else None
    body = _strip_comments(text) if kind == "source" else re.sub(r"(?m)#[^\n]*$", lambda m: " " * len(m.group(0)), text) if rel.endswith(("CMakeLists.txt", ".cmake", "meson.build")) else text
    guards = preprocessor_guards(code) if code is not None else cmake_guards(body) if rel.endswith(("CMakeLists.txt", ".cmake")) else None
    for rule in rules:
        if rule.kind != kind:
            continue
        seen = set()
        hay = code if (code is not None and not rule.in_strings) else body
        for m in rule.regex.finditer(hay):
            ln = _line_of(hay, m.start())
            if ln in seen:
                continue
            seen.add(ln)
            src = lines[ln - 1] if ln - 1 < len(lines) else ""
            s = SUPPRESS.search(src)
            if s and (s.group(1) in (None, rule.id)):
                continue
            severity, why = rule.severity, rule.why
            if guards is not None and rule.id != "QPC019":
                g = guards[ln - 1] if ln - 1 < len(guards) else None
                if g in ("platform", "directive"):
                    continue  # Linux/other-OS-only code, or the #if test itself (a guard is the fix, not the problem)
                if g == "feature" and severity != INFO:
                    severity = INFO
                    why = why + " This line sits behind a build option (HAVE_/WITH_/USE_...), so it only matters if that option is enabled for QNX."
            findings.append(Finding(rule.id, rule.title, severity, rel, ln, src.strip()[:160], why, rule.fix))
    return findings


_PLATFORM = re.compile(r"\b(?:__linux__|__linux|linux|__gnu_linux__|__GLIBC__|__GLIBC_MINOR__|__UCLIBC__|__BIONIC__|__ANDROID__|__ANDROID_API__|"
                       r"__APPLE__|__MACH__|_WIN32|_WIN64|_MSC_VER|__MINGW32__|__MINGW64__|__CYGWIN__|__FreeBSD__|__OpenBSD__|"
                       r"__NetBSD__|__DragonFly__|__sun|__SVR4|_AIX|__PASE__|__hpux|__HAIKU__|__EMSCRIPTEN__|__Fuchsia__|__wasi__)\b")
# a branch selected by a feature macro: HAVE_X / WITH_X or `#ifdef SOME_MACRO` (feature detection)
_FEATURE = re.compile(r"\b(?:HAVE|WITH|USE|ENABLE)_\w+|^\s*!?\s*(?:defined\s*\(?\s*)?[A-Z][A-Z0-9_]+\s*\)?\s*$")
_DIRECTIVE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")


def _classify(cond, negated):
    """Return 'platform', 'feature' or None for one #if branch condition."""
    if negated:
        return None
    if re.search(r"!\s*(?:defined\s*\(?\s*)?__QNX", cond) and "||" not in cond:
        return "platform"  # `#if !defined(__QNX__)`: never compiled on QNX
    if "__QNX" in cond:
        return None
    # `#if !defined(__linux__)` or `#ifndef` style conditions select non-Linux code
    if re.search(r"!\s*(?:defined\s*\(?\s*)?" + _PLATFORM.pattern, cond):
        return None
    if _PLATFORM.search(cond):
        # every alternative of an OR must be another platform for the branch to be off on QNX
        if all(_PLATFORM.search(part) for part in cond.split("||")):
            return "platform"
    if _FEATURE.search(cond):
        return "feature"
    return None


def _qnx_branch(cond, negated):
    return not negated and "__QNX" in cond and not re.search(r"!\s*(?:defined\s*\(?\s*)?__QNX", cond)


def preprocessor_guards(code):
    """Per line: 'platform' if inside a Linux/glibc/other-OS-only branch, 'feature' if behind a build option."""
    stack, out = [], []
    for line in code.split("\n"):
        m = _DIRECTIVE.match(line)
        if m:
            d, rest = m.group(1), m.group(2)
            if d == "ifdef":
                stack.append([rest.strip(), False, False])
            elif d == "ifndef":
                stack.append(["!" + rest.strip(), False, False])
            elif d == "if":
                stack.append([rest.strip(), False, False])
            elif d == "elif" and stack:
                stack[-1] = [rest.strip(), False, stack[-1][2] or _qnx_branch(stack[-1][0], stack[-1][1])]
            elif d == "else" and stack:
                stack[-1][2] = stack[-1][2] or _qnx_branch(stack[-1][0], stack[-1][1])
                stack[-1][1] = True
            elif d == "endif" and stack:
                stack.pop()
            out.append("directive")
            continue
        # a branch after an explicit __QNX__ branch is never taken on QNX
        kinds = ["platform" if q else _classify(c, n) for c, n, q in stack]
        out.append("platform" if "platform" in kinds else "feature" if "feature" in kinds else None)
    return out


def is_platform_file(rel):
    return bool(PLATFORM_PATH.search(rel.rsplit(".", 1)[0])) and "qnx" not in rel.lower()


def scan_path(root, exclude=(), sdp=None, platform_files=False):
    findings, uses_sockets, build_files, links_socket = [], None, [], False
    skipped = []
    includes = []  # (rel, line, header)
    files = 0
    for full, rel in iter_files(root, exclude):
        try:
            if os.path.getsize(full) > MAX_BYTES:
                continue
            with open(full, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if is_source(rel) and not platform_files and is_platform_file(rel):
            skipped.append(rel)
            continue
        files += 1
        findings.extend(scan_text(rel, text))
        if is_source(rel):
            clean = _strip_comments(text)
            m = SOCKET_USE.search(clean)
            if m and uses_sockets is None:
                uses_sockets = (rel, _line_of(clean, m.start()))
            for im in re.finditer(r"#\s*include\s*<([^>]+)>", clean):
                includes.append((rel, _line_of(clean, im.start()), im.group(1).strip()))
        else:
            build_files.append(rel)
            if SOCKET_LINK.search(text):
                links_socket = True

    if uses_sockets and build_files and not links_socket:
        r = QNX_SOCKET_RULE
        findings.append(Finding(r.id, r.title, r.severity, build_files[0], 1,
                                f"socket API used in {uses_sockets[0]}:{uses_sockets[1]}", r.why, r.fix))

    if sdp is not None:
        findings = sdp.verify(findings, includes)

    order = {ERROR: 0, WARNING: 1, INFO: 2}
    findings.sort(key=lambda f: (order[f.severity], f.path, f.line))
    return {"files": files, "findings": findings, "sdp": sdp.describe() if sdp else None,
            "skipped_platform_files": skipped}


def summarize(findings):
    counts = {ERROR: 0, WARNING: 0, INFO: 0}
    for f in findings:
        counts[f.severity] += 1
    # rough porting effort: errors need code changes, warnings need a check
    # effort per distinct problem in a file, not per line: ten epoll calls in one file are one rewrite
    distinct = {(f.rule, f.path, f.severity) for f in findings}
    hours = sum(2 if sev == ERROR else 0.5 if sev == WARNING else 0 for _, _, sev in distinct)
    if counts[ERROR] == 0 and counts[WARNING] == 0:
        verdict = "Ready to try a QNX build"
    elif counts[ERROR] == 0:
        verdict = "Likely to build; review warnings"
    elif counts[ERROR] <= 5:
        verdict = "Small porting effort"
    else:
        verdict = "Significant porting effort"
    return {"counts": counts, "estimated_hours": hours, "verdict": verdict}


_CMAKE_DIR = re.compile(r"^\s*(if|elseif|else|endif)\s*\((.*)$", re.I)
_CMAKE_PLATFORM = re.compile(r"\b(?:APPLE|WIN32|MSVC|MINGW|CYGWIN|ANDROID|IOS|EMSCRIPTEN|Linux|OpenBSD|FreeBSD|NetBSD|Darwin|Windows|SunOS|AIX|Haiku)\b")


def _cmake_qnx(cond, negated):
    return not negated and re.search(r"\bQNX\b", cond) and not re.search(r"\bNOT\s+QNX", cond)


def cmake_guards(body):
    """Per line: 'platform' inside an if() branch that only another OS takes (APPLE, WIN32, Linux...)."""
    stack, out = [], []
    for line in body.split("\n"):
        m = _CMAKE_DIR.match(line)
        if m:
            d, cond = m.group(1).lower(), m.group(2)
            if d == "if":
                stack.append([cond, False, False])
            elif d == "elseif" and stack:
                stack[-1] = [cond, False, stack[-1][2] or _cmake_qnx(stack[-1][0], stack[-1][1])]
            elif d == "else" and stack:
                stack[-1][2] = stack[-1][2] or _cmake_qnx(stack[-1][0], stack[-1][1])
                stack[-1][1] = True
            elif d == "endif" and stack:
                stack.pop()
            out.append("directive")
            continue
        plat = any(q for _, _, q in stack) or any(not neg and _CMAKE_PLATFORM.search(c) and not re.search(r"\bNOT\b|QNX", c)
                   and all(_CMAKE_PLATFORM.search(p) for p in re.split(r"\bOR\b", c)) for c, neg, _ in stack)
        out.append("platform" if plat else None)
    return out
