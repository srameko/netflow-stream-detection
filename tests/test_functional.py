"""End-to-end tests against a REAL nfdump and a real nfcapd capture.

A synthetic NetFlow v5 stream is sent to a loopback nfcapd (see make_capture.py),
then the actual command line (`python flowspot.py ...`) is run as a subprocess.
The whole module is skipped when nfdump/nfcapd are not installed.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import flowspot  # noqa: E402
import make_capture  # noqa: E402

HAVE_NFDUMP = bool(shutil.which("nfdump") and shutil.which("nfcapd"))


@unittest.skipUnless(HAVE_NFDUMP, "nfdump/nfcapd not installed")
class Functional(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.capture = make_capture.build(Path(cls.tmp.name) / "cap")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_tool(self, *args, capture=None):
        proc = subprocess.run(
            [sys.executable, "-I", str(ROOT / "flowspot.py"), *args, str(capture or self.capture)]
            if args and args[0] in ("streaming", "remote", "ipcam", "auto")
            else [sys.executable, "-I", str(ROOT / "flowspot.py"), str(capture or self.capture), *args],
            capture_output=True, text=True, timeout=300,
        )
        return proc

    def run_cmd(self, command, *options, capture=None):
        """flowspot COMMAND FILE [options]"""
        return subprocess.run(
            [sys.executable, "-I", str(ROOT / "flowspot.py"), command, str(capture or self.capture), *options],
            capture_output=True, text=True, timeout=300,
        )

    # -- every shipped filter must be valid nfdump syntax ----------------------------------

    def test_all_signatures_are_accepted_by_nfdump(self):
        nf = flowspot.NfDump(flowspot.find_nfdump(None), self.capture)
        filters = [r.filter for r in flowspot.streaming_rules(["8.8.8.8"], ["81.0.206.1"], ["77.75.73.242"], True)]
        filters += [r.filter for r in flowspot.streaming_rules([], [], [], True)]
        filters += [
            flowspot.SSH_X_FILTER, flowspot.VNC_FILTER, flowspot.TEAMVIEWER_TCP_FILTER,
            flowspot.TEAMVIEWER_UDP_FILTER.format(p=41000), flowspot.SKYPE_FILTER,
            "src net 192.168.0.0/16 AND dst net 192.168.0.0/16",
        ]
        self.assertGreater(len(filters), 20)
        for flt in filters:
            with self.subTest(filter=flt[:80]):
                nf.query(flt, "%sa")  # raises FlowspotError on any syntax error

    # -- commands --------------------------------------------------------------------------

    def test_streaming(self):
        p = self.run_cmd("streaming", "--no-dns", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        hits = {(d["service"], d["variant"]): len(d["flows"]) for d in data["detections"] if d["flows"]}
        self.assertEqual(hits[("ulozto.cz/live", "")], 3)
        self.assertEqual(hits[("youtube.com", "html5")], 1)
        ulozto = next(d for d in data["detections"] if d["service"] == "ulozto.cz/live")
        self.assertEqual({f["src"] for f in ulozto["flows"]}, {"93.99.92.1", "93.99.92.2", "93.99.92.3"})
        self.assertEqual(ulozto["flows"][0]["proto"], "TCP")
        self.assertEqual(ulozto["flows"][0]["flags"], ".AP...")

    def test_streaming_generic_flag(self):
        plain = json.loads(self.run_cmd("streaming", "--no-dns", "--json").stdout)
        generic = json.loads(self.run_cmd("streaming", "--no-dns", "--generic", "--json").stdout)
        has = lambda d: any(x["service"].startswith("generic") and x["flows"] for x in d["detections"])  # noqa: E731
        self.assertFalse(has(plain))
        self.assertTrue(has(generic))

    def test_remote(self):
        p = self.run_cmd("remote", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        hits = {d["service"]: d["flows"] for d in data["detections"] if d["flows"]}
        self.assertEqual(len(hits["ssh -X"]), 1)
        self.assertEqual(hits["VNC"][0]["dport"], 5900)
        self.assertEqual({f["proto"] for f in hits["TeamViewer"]}, {"TCP", "UDP"})

    def test_remote_with_skype_runs(self):
        p = self.run_cmd("remote", "--skype")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_ipcam(self):
        p = self.run_cmd("ipcam", "--net", "192.168.0.0/16", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        extra = json.loads(p.stdout)["extra"]
        self.assertIn("192.168.1.50", extra["likely_cameras"])
        self.assertNotIn("192.168.1.7", extra["likely_cameras"])  # the NAS
        self.assertEqual(extra["busy_ports"], [445])
        self.assertIn(554, extra["camera_ports"])

    def test_ipcam_ignore_port(self):
        p = self.run_cmd("ipcam", "--net", "192.168.0.0/16", "--ignore-port", "554", "5353", "--json")
        self.assertNotIn("192.168.1.50", json.loads(p.stdout)["extra"]["likely_cameras"])

    def test_nothing_found_exit_1(self):
        p = self.run_cmd("ipcam", "--net", "172.20.0.0/16")
        self.assertEqual(p.returncode, 1, p.stderr)

    # -- auto mode (no command) ------------------------------------------------------------

    def test_auto_default_ranks_findings(self):
        p = self.run_tool("--no-dns", "--net", "192.168.0.0/16")  # flowspot FILE --no-dns ...
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ulozto.cz/live", p.stdout)
        self.assertIn("TeamViewer", p.stdout)
        self.assertIn("IP cameras in 192.168.0.0/16", p.stdout)
        self.assertIn("192.168.1.50", p.stdout)
        self.assertLess(p.stdout.index("ulozto.cz/live"), p.stdout.index("ssh -X"))  # ranked

    def test_auto_json(self):
        p = self.run_tool("--no-dns", "--json")
        data = json.loads(p.stdout)
        verdict = data["extra"]["verdict"]
        self.assertTrue(verdict)
        self.assertEqual(verdict[0]["service"], "ulozto.cz/live")
        scores = [v["score"] for v in verdict]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertTrue(all(0 <= s <= 1 for s in scores))
        self.assertTrue(all(v["confidence"] in ("likely", "possible", "weak") for v in verdict))

    # -- directories, limit, DNS cache -----------------------------------------------------

    def test_directory_of_captures_is_analysed_recursively(self):
        d = Path(self.tmp.name) / "tree"
        (d / "2026" / "11").mkdir(parents=True)
        shutil.copy(self.capture, d / "nfcapd.202601010000")
        shutil.copy(self.capture, d / "2026" / "11" / "nfcapd.202601010005")
        p = self.run_cmd("streaming", "--no-dns", "--json", capture=d)
        self.assertEqual(p.returncode, 0, p.stderr)
        ulozto = next(x for x in json.loads(p.stdout)["detections"] if x["service"] == "ulozto.cz/live")
        self.assertEqual(len(ulozto["flows"]), 6)  # 3 flows in each of the two files

    def test_limit_with_real_nfdump(self):
        p = self.run_cmd("streaming", "--no-dns", "--limit", "2", "--json")
        ulozto = next(x for x in json.loads(p.stdout)["detections"] if x["service"] == "ulozto.cz/live")
        self.assertEqual((len(ulozto["flows"]), ulozto["truncated"]), (2, True))
        p = self.run_cmd("streaming", "--no-dns", "--limit", "3", "--json")
        ulozto = next(x for x in json.loads(p.stdout)["detections"] if x["service"] == "ulozto.cz/live")
        self.assertEqual((len(ulozto["flows"]), ulozto["truncated"]), (3, False))
        text = self.run_cmd("streaming", "--no-dns", "--limit", "2").stdout
        self.assertIn("ulozto.cz/live - 2+ flow(s)", text)

    def test_dns_cache_pins_answers_end_to_end(self):
        cache = Path(self.tmp.name) / "dns.json"
        flowspot.save_dns_cache(cache, {"x.cdn0.grooveshark.com": ["93.99.92.1"]}, "2013-05-16T10:00:00Z")
        p = self.run_cmd("streaming", "--dns-cache", str(cache), "--no-dns", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["extra"]["dns"]["source"], "cache")
        groove = next(x for x in data["detections"] if x["service"] == "grooveshark.com")
        self.assertEqual(len(groove["flows"]), 1)  # matched via the cached address 93.99.92.1

    # -- robustness & security against the real binary ------------------------------------

    def test_garbage_file_is_a_clean_error(self):
        bad = Path(self.tmp.name) / "garbage.nfcapd"
        bad.write_bytes(b"this is not a flow file" * 10)
        p = self.run_cmd("remote", capture=bad)
        self.assertEqual(p.returncode, 2)
        self.assertIn("error", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_hostile_file_name_is_not_executed(self):
        evil = Path(self.tmp.name) / "a b;$(touch pwned)`touch pwned2`.nfcapd"
        shutil.copy(self.capture, evil)
        p = self.run_cmd("remote", capture=evil)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse((Path(self.tmp.name) / "pwned").exists())
        self.assertFalse((Path.cwd() / "pwned").exists())

    def test_verbose_logs_filters_to_stderr(self):
        p = self.run_cmd("remote", "-v")
        self.assertIn("filter:", p.stderr)

    def test_capture_is_not_modified(self):
        before = self.capture.read_bytes()
        self.run_tool("--no-dns")
        self.assertEqual(self.capture.read_bytes(), before)

    def test_signatures_command_needs_no_nfdump(self):
        p = subprocess.run([sys.executable, "-I", str(ROOT / "flowspot.py"), "signatures"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertIn("youtube.com", p.stdout)


if __name__ == "__main__":
    unittest.main()
