import json
import os
import tempfile
import unittest

from qnx_port_check.scanner import scan_path, scan_text, summarize
from qnx_port_check import report
from qnx_port_check.sdp import SDP
from qnx_port_check.toolchain import cmake_toolchain
from qnx_port_check.cli import main

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "fixtures", "sample")


def rules_of(findings):
    return sorted({f.rule for f in findings})


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self.result = scan_path(SAMPLE)
        self.f = self.result["findings"]

    def test_expected_rules(self):
        self.assertEqual(rules_of(self.f), ["QPB001", "QPB002", "QPB004", "QPC001", "QPC002", "QPC003",
                                            "QPC006", "QPC007", "QPC010", "QPC019"])

    def test_comment_and_string_not_reported(self):
        epoll_lines = [f.line for f in self.f if f.rule == "QPC002"]
        self.assertEqual(epoll_lines, [5, 25])  # include and the real call only

    def test_cmake_comment_ignored(self):
        self.assertEqual([f.line for f in self.f if f.rule == "QPB001"], [5])

    def test_errors_sorted_first(self):
        sev = [f.severity for f in self.f]
        self.assertEqual(sev, sorted(sev, key=["error", "warning", "info"].index))

    def test_suppression(self):
        f = scan_text("a.c", "int x = epoll_create1(0); // qnx-port-check: ignore QPC002\n")
        self.assertEqual(f, [])

    def test_qnx_guard_is_fine(self):
        f = scan_text("a.c", "#if defined(__linux__) || defined(__QNX__)\n#endif\n")
        self.assertEqual(f, [])

    def test_linux_only_branch_skipped(self):
        src = ("#ifdef __linux__\n#include <sys/epoll.h>\nint a = epoll_create1(0);\n#else\n"
               "int b = epoll_create1(0);\n#endif\n"
               "#if defined(HAVE_EPOLL)\nint c = epoll_create1(0);\n#endif\n"
               "#ifndef __linux__\nint d = epoll_create1(0);\n#endif\n")
        f = {(x.line, x.rule): x.severity for x in scan_text("a.c", src)}
        self.assertNotIn((2, "QPC002"), f)          # Linux-only branch
        self.assertNotIn((3, "QPC002"), f)
        self.assertEqual(f[(5, "QPC002")], "error")  # #else branch is what QNX compiles
        self.assertEqual(f[(8, "QPC002")], "info")   # behind a build option
        self.assertEqual(f[(11, "QPC002")], "error")  # explicitly non-Linux

    def test_branch_after_qnx_branch_skipped(self):
        src = "#if defined(__QNX__)\nint q = 1;\n#else\nint e = epoll_create1(0);\n#endif\n"
        self.assertEqual(scan_text("a.c", src), [])
        cm = "if(APPLE)\n  target_link_libraries(x dl)\nelseif(QNX)\n  target_link_libraries(x socket)\nelse()\n  target_link_libraries(x dl)\nendif()\n"
        self.assertEqual(scan_text("CMakeLists.txt", cm), [])

    def test_summary(self):
        s = summarize(self.f)
        self.assertGreater(s["counts"]["error"], 0)
        self.assertIn(s["verdict"], ["Small porting effort", "Significant porting effort"])

    def test_sarif_valid(self):
        d = json.loads(report.sarif(self.result))
        self.assertEqual(d["version"], "2.1.0")
        self.assertEqual(len(d["runs"][0]["results"]), len(self.f))

    def test_markdown(self):
        md = report.markdown(self.result, "sample")
        self.assertIn("# QNX 8.0 porting report: sample", md)


class SdpTest(unittest.TestCase):
    """Fake SDP tree: verifies the header ground-truth logic without a real install."""

    def test_missing_header_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            inc = os.path.join(tmp, "usr", "include", "sys")
            os.makedirs(inc)
            for h in ("socket.h", "neutrino.h"):
                open(os.path.join(inc, h), "w").close()
            with open(os.path.join(inc, "nto_version.h"), "w") as fh:
                fh.write("#define _NTO_VERSION 800\n")
            sdp = SDP(tmp, host_dirs=[])
            self.assertEqual(sdp.version, "8.0.0")
            proj = os.path.join(tmp, "proj")
            os.makedirs(proj)
            with open(os.path.join(proj, "m.c"), "w") as fh:
                fh.write("#include <sys/socket.h>\n#include <sys/epoll.h>\n#include <sys/random_linux.h>\n")
            res = scan_path(proj, sdp=sdp)
            by = {(f.rule, f.line): f for f in res["findings"]}
            self.assertTrue(by[("QPC002", 2)].verified)         # static rule confirmed by SDP
            self.assertIn(("QPH001", 3), by)                      # unknown header caught only by SDP
            self.assertNotIn(("QPH001", 1), by)                   # present in SDP
            self.assertNotIn(("QPH001", 2), by)                   # deduplicated with QPC002


class CliTest(unittest.TestCase):
    def test_exit_codes_and_toolchain(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.json")
            self.assertEqual(main(["scan", SAMPLE, "-f", "json", "-o", out, "--no-sdp"]), 1)
            self.assertEqual(main(["scan", SAMPLE, "-f", "json", "-o", out, "--no-sdp", "--fail-on", "never"]), 0)
            tc = os.path.join(tmp, "t.cmake")
            main(["toolchain", "--arch", "x86_64", "-o", tc])
            self.assertIn("gcc_ntox86_64", open(tc).read())
        self.assertIn("CMAKE_SYSTEM_NAME QNX", cmake_toolchain())


if __name__ == "__main__":
    unittest.main()
