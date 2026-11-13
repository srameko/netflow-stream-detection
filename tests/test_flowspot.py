"""Tests run without nfdump: a tiny fake `nfdump` executable replays canned output."""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import flowspot  # noqa: E402

FAKE_TEMPLATE = """#!{python}
import json, sys, time
spec = json.load(open({spec!r}))
with open({log!r}, "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
flt = sys.argv[-1]
for rule in spec:
    if rule["match"] in flt:
        if rule.get("sleep"):
            time.sleep(rule["sleep"])
        if rule.get("err"):
            sys.stderr.write(rule["err"])
        sys.stdout.write(rule.get("out", ""))
        sys.exit(rule.get("code", 0))
"""

FLOW_ROW = "2013-05-16 10:00:00.000,2013-05-16 10:00:05.000,TCP,{sa},{sp},{da},{dp},.AP...,{pkt},{byt}\n"


class Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.log = self.dir / "argv.log"
        self.spec = self.dir / "spec.json"
        self.fake = self.dir / "nfdump"
        self.capture = self.dir / "flows.nfcapd"
        self.capture.write_bytes(b"")
        self.set_rules([])

    def tearDown(self):
        self.tmp.cleanup()

    def set_rules(self, rules):
        self.spec.write_text(json.dumps(rules))
        self.fake.write_text(FAKE_TEMPLATE.format(python=sys.executable, spec=str(self.spec), log=str(self.log)))
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = flowspot.main(list(args))
            except SystemExit as exc:  # argparse errors
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def argv_calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]


class FilterTests(unittest.TestCase):
    def test_youtube_covers_all_google_nets_and_variants(self):
        rules = {r.variant: r for r in flowspot.streaming_rules([], [], [], False) if r.service == "youtube.com"}
        self.assertEqual(set(rules), {"live", "html5", "https", "http"})
        for rule in rules.values():
            for net in flowspot.GOOGLE_NETS:
                self.assertIn(f"net {net}", rule.filter)
            self.assertEqual(rule.filter.count("("), rule.filter.count(")"))

    def test_seznam_branches_are_exclusive(self):
        names = lambda d: {r.service for r in flowspot.streaming_rules([], [], d, False)}  # noqa: E731
        self.assertIn("seznam.cz", names([]))
        self.assertNotIn("mixer.cz", names([]))
        self.assertIn("mixer.cz", names(["1.2.3.4"]))
        self.assertIn("stream.cz", names(["1.2.3.4"]))
        self.assertNotIn("seznam.cz", names(["1.2.3.4"]))

    def test_generic_only_on_request(self):
        self.assertFalse(any("generic" in r.service for r in flowspot.streaming_rules([], [], [], False)))
        self.assertTrue(any("generic" in r.service for r in flowspot.streaming_rules([], [], [], True)))

    def test_skype_filter_groups_local_nets(self):
        # The original relied on OR/AND precedence; make sure the OR group is parenthesised.
        self.assertTrue(flowspot.SKYPE_FILTER.startswith("(dst net 10.0.0.0/8 OR"))

    def test_signatures_command_prints(self):
        text = flowspot.render_signatures()
        for needle in ("youtube.com", "TeamViewer", "VNC", "ipcam", "port 5900"):
            self.assertIn(needle, text)


class ParsingTests(unittest.TestCase):
    def test_parse_flow_ok_and_bad(self):
        row = FLOW_ROW.format(sa="10.0.0.1", sp=80, da="10.0.0.2", dp=5000, pkt=3, byt=900).strip().split(",")
        flow = flowspot.parse_flow(row)
        self.assertEqual((flow.src, flow.sport, flow.bytes), ("10.0.0.1", 80, 900))
        row[3] = "1.2.3.4; rm -rf /"
        self.assertIsNone(flowspot.parse_flow(row))
        self.assertIsNone(flowspot.parse_flow(["too", "short"]))

    def test_printable_strips_escapes(self):
        self.assertEqual(flowspot.printable("a\x1b[31mb\x07"), "a[31mb")

    def test_arg_validators(self):
        self.assertEqual(flowspot.cidr_arg("192.168.1.5/16"), "192.168.0.0/16")
        for bad in ("nope", "1.2.3.4/99", "1.2.3.4; id"):
            with self.assertRaises(Exception):
                flowspot.cidr_arg(bad)
        self.assertEqual(flowspot.port_arg("443"), 443)
        for bad in ("0", "70000", "x"):
            with self.assertRaises(Exception):
                flowspot.port_arg(bad)


class CliTests(Harness):
    def test_nothing_found_exit_1(self):
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_NONE)
        self.assertIn("No flows", out)

    def test_vnc_found_text_and_json(self):
        row = FLOW_ROW.format(sa="10.0.0.5", sp=40000, da="10.0.0.9", dp=5900, pkt=500, byt=50000)
        self.set_rules([{"match": "port 5900", "out": row}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("VNC - 1 flow(s)", out)
        self.assertIn("10.0.0.5:40000 -> 10.0.0.9:5900", out)

        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--json")
        data = json.loads(out)
        self.assertTrue(data["found"])
        vnc = next(d for d in data["detections"] if d["service"] == "VNC")
        self.assertEqual(vnc["flows"][0]["dport"], 5900)

    def test_argv_is_passed_verbatim_without_shell(self):
        evil = self.dir / "a b;$(touch pwned)`id`.nfcapd"
        evil.write_bytes(b"")
        self.run_cli("remote", str(evil), "--nfdump", str(self.fake))
        calls = self.argv_calls()
        self.assertTrue(calls)
        for argv in calls:
            self.assertEqual(argv[argv.index("-r") + 1], str(evil.resolve()))
        self.assertFalse((self.dir / "pwned").exists())
        self.assertFalse(Path("pwned").exists())

    def test_relative_dash_path_is_made_absolute(self):
        cwd = os.getcwd()
        try:
            os.chdir(self.dir)
            (self.dir / "-evil").write_bytes(b"")
            p =flowspot.validate_capture("./-evil")
            self.assertTrue(p.is_absolute())
        finally:
            os.chdir(cwd)

    def test_errors_exit_2(self):
        code, _, err = self.run_cli("remote", str(self.dir / "missing"), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("not found", err)
        code, _, err = self.run_cli("remote", str(self.capture), "--nfdump", str(self.dir / "nope"))
        self.assertEqual(code, flowspot.EXIT_ERROR)
        # argparse rejects a bad CIDR with exit status 2 before nfdump is ever run
        code, _, _ = self.run_cli("ipcam", str(self.capture), "--net", "bogus")
        self.assertEqual(code, 2)

    def test_nfdump_failure_is_reported(self):
        self.fake.write_text(f"#!{sys.executable}\nimport sys\nsys.stderr.write('boom\\n')\nsys.exit(3)\n")
        code, _, err = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("boom", err)

    def test_streaming_no_dns_finds_ulozto(self):
        row = FLOW_ROW.format(sa="93.99.92.7", sp=80, da="10.0.0.2", dp=50000, pkt=5000, byt=7_000_000)
        self.set_rules([{"match": "93.99.92.0/24", "out": row}])
        code, out, _ = self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("ulozto.cz/live - 1 flow(s)", out)
        self.assertIn("DNS look-ups disabled", out)

    def test_teamviewer_two_stage(self):
        tcp = "10.0.0.5,8.8.8.8,41000,5938\n"
        udp = "8.8.4.4,5939\n"
        self.set_rules([
            {"match": "packets = 4", "out": tcp},
            {"match": "proto UDP AND bytes = 124", "out": udp},
            {"match": "ip 8.8.8.8 AND port 41000", "out": FLOW_ROW.format(sa="10.0.0.5", sp=41000, da="8.8.8.8", dp=5938, pkt=4, byt=500)},
        ])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("TeamViewer - 1 flow(s)", out)

    def test_ipcam_pipeline(self):
        # camera 10.0.0.50 streams on port 554 (small packets), the NAS on 445 is bulk data.
        rows = "".join([
            "10.0.0.50,10.0.0.9,554,40000,1000,1000000\n",
            "10.0.0.50,10.0.0.9,554,40001,1000,900000\n",
            "10.0.0.7,10.0.0.9,445,40002,1000,3000000\n",
            "10.0.0.8,10.0.0.9,5353,5353,2,200\n",
        ])
        self.set_rules([{"match": "src net 10.0.0.0/8 AND dst net", "out": rows}])
        code, out, _ = self.run_cli("ipcam", str(self.capture), "--nfdump", str(self.fake),
                                    "--net", "10.0.0.0/8", "--json")
        data = json.loads(out)
        self.assertEqual(data["extra"]["busy_ports"], [445])
        self.assertIn(554, data["extra"]["camera_ports"])
        self.assertNotIn(445, data["extra"]["camera_ports"])
        self.assertIn("10.0.0.50", data["extra"]["likely_cameras"])
        self.assertNotIn("10.0.0.7", data["extra"]["likely_cameras"])
        self.assertEqual(code, flowspot.EXIT_FOUND)

    def test_ipcam_ignore_port(self):
        rows = "10.0.0.50,10.0.0.9,554,40000,1000,1000000\n"
        self.set_rules([{"match": "src net", "out": rows}])
        code, out, _ = self.run_cli("ipcam", str(self.capture), "--nfdump", str(self.fake),
                                    "--net", "10.0.0.0/8", "-p", "554", "40000", "--json")
        self.assertEqual(json.loads(out)["extra"]["camera_ports"], [])
        self.assertEqual(code, flowspot.EXIT_NONE)

    def test_oversized_filter_rejected(self):
        nf = flowspot.NfDump(str(self.fake), self.capture)
        with self.assertRaises(flowspot.FlowspotError):
            nf.query("x" * (flowspot.MAX_FILTER_LEN + 1), "%sa")


class RunnerTests(Harness):
    def test_timeout_is_reported(self):
        self.set_rules([{"match": "port 5900", "sleep": 5}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--timeout", "1")
        # VNC times out but the other stages succeed -> a skipped-stage note, not a crash
        self.assertEqual(code, flowspot.EXIT_NONE)
        self.assertIn("VNC: skipped (nfdump did not finish within 1s", out)

    def test_corrupt_capture_with_exit_0_is_an_error(self):
        # real nfdump prints "No matching flows" on stdout and the diagnostic on stderr, exit 0
        self.set_rules([{"match": "", "out": "No matching flows\n", "err": "bad magic: 0x6874\n"}])
        code, _, err = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("bad magic", err)

    def test_no_matching_flows_line_is_not_nothing_wrong(self):
        self.set_rules([{"match": "", "out": "No matching flows\n"}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_NONE)

    def test_empty_filter_refused(self):
        nf = flowspot.NfDump(str(self.fake), self.capture)
        with self.assertRaises(flowspot.FlowspotError):
            nf.query("  ", "%sa")

    def test_validate_capture_accepts_directory_with_files(self):
        self.assertEqual(flowspot.validate_capture(str(self.dir)), self.dir.resolve())

    def test_validate_capture_rejects_empty_directory(self):
        empty = self.dir / "empty"
        empty.mkdir()
        with self.assertRaises(flowspot.FlowspotError):
            flowspot.validate_capture(str(empty))

    def test_find_nfdump_missing_from_path(self):
        old = os.environ.get("PATH")
        os.environ["PATH"] = str(self.dir / "empty")
        try:
            with self.assertRaises(flowspot.FlowspotError):
                flowspot.find_nfdump(None)
        finally:
            os.environ["PATH"] = old

    def test_environment_is_minimal(self):
        env = flowspot.NfDump._env()
        self.assertEqual(env["LC_ALL"], "C")
        self.assertTrue(set(env) <= {"PATH", "LC_ALL", "TZ"})

    def test_no_bidirectional_merge_flag(self):
        self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        for argv in self.argv_calls():
            self.assertNotIn("-B", argv)
            self.assertIn("-N", argv)


class GatherTests(unittest.TestCase):
    def test_partial_failure_becomes_note(self):
        rep = flowspot.Report("x", "f")
        def boom():
            raise flowspot.FlowspotError("bad")
        out = flowspot.gather(rep, [("ok", lambda: 1), ("bad", boom)], jobs=2)
        self.assertEqual(out, [1, None])
        self.assertIn("bad: skipped (bad)", rep.notes)

    def test_all_failing_raises(self):
        def boom():
            raise flowspot.FlowspotError("bad")
        with self.assertRaises(flowspot.FlowspotError):
            flowspot.gather(flowspot.Report("x", "f"), [("a", boom), ("b", boom)], jobs=1)


class DnsTests(unittest.TestCase):
    def setUp(self):
        self._orig = flowspot.socket.getaddrinfo

    def tearDown(self):
        flowspot.socket.getaddrinfo = self._orig

    def test_resolves_and_counts(self):
        def fake(host, *a, **k):
            if host.startswith("bad"):
                raise OSError("nxdomain")
            return [(2, 1, 6, "", ("203.0.113.7", 0)), (2, 1, 6, "", ("203.0.113.7", 0))]
        flowspot.socket.getaddrinfo = fake
        out = flowspot.resolve_hosts(["good1", "good2", "bad1"])
        self.assertEqual(out, {"good1": ["203.0.113.7"], "good2": ["203.0.113.7"], "bad1": []})

    def test_hung_resolver_does_not_block(self):
        import time
        flowspot.socket.getaddrinfo = lambda *a, **k: time.sleep(30)
        start = time.monotonic()
        out = flowspot.resolve_hosts(["slow"], timeout=0.3)
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(out, {"slow": []})


class PartialFailureTests(Harness):
    def test_one_failing_rule_does_not_hide_the_rest(self):
        row = FLOW_ROW.format(sa="93.99.92.7", sp=80, da="10.0.0.2", dp=50000, pkt=5000, byt=7_000_000)
        self.set_rules([
            {"match": "90.183.101.0/24 AND packets < 200", "code": 3, "err": "filter error"},
            {"match": "93.99.92.0/24", "out": row},
        ])
        code, out, _ = self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("ulozto.cz/live", out)
        self.assertIn("skipped", out)

    def test_everything_failing_is_an_error(self):
        self.set_rules([{"match": "", "code": 3, "err": "nope"}])
        code, _, err = self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("nope", err)


class SeznamAndSkypeTests(Harness):
    def filters(self):
        return [argv[-1] for argv in self.argv_calls()]

    def test_dispatcher_seen_enables_mixer_and_stream(self):
        self.set_rules([{"match": "src ip 77.75.73.242", "out": "77.75.73.242\n"}])
        self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        joined = "\n".join(self.filters())
        self.assertIn("src ip 77.75.73.242 AND bpp > 1000", joined)
        self.assertIn("src ip 77.75.73.242 AND bpp > 1200", joined)
        self.assertNotIn("duration > 30000", joined)

    def test_no_dispatcher_uses_live_heuristic(self):
        self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        joined = "\n".join(self.filters())
        self.assertIn("duration > 30000", joined)
        self.assertNotIn("bpp > 1200)", joined.replace("bpp > 1200 AND pps", ""))  # no stream.cz rule

    def test_skype_flow(self):
        udp = "10.0.0.5,54321\n10.0.0.5,54321\n10.0.0.6,40000\n"
        final = FLOW_ROW.format(sa="1.2.3.4", sp=1000, da="10.0.0.5", dp=54321, pkt=3, byt=150)
        self.set_rules([
            {"match": "proto UDP AND pps = 0 AND bps > 10", "out": udp},
            {"match": "157.56.0.0/16", "out": final},
        ])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--skype")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("Skype (experimental) - 1 flow(s)", out)
        self.assertIn("10.0.0.5:54321", out)
        self.assertNotIn("10.0.0.6:40000", out)  # seen only once: not repeated

    def test_skype_without_repeats_finds_nothing(self):
        self.set_rules([{"match": "proto UDP AND pps = 0 AND bps > 10", "out": "10.0.0.5,54321\n"}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--skype")
        self.assertEqual(code, flowspot.EXIT_NONE)


class ScoringTests(unittest.TestCase):
    def det(self, service, variant, n, category="streaming", src="1.1.1.1"):
        flows = [flowspot.Flow("t", "t", "TCP", src, 80, "10.0.0.1", 5000 + i, ".AP...", 10, 1000) for i in range(n)]
        return flowspot.Detection(service, variant, "f", flows, category)

    def report(self, *dets, cameras=None):
        r = flowspot.Report("auto", "f", list(dets))
        if cameras:
            r.extra["cameras"] = cameras
        return r

    def test_more_evidence_scores_higher_and_is_bounded(self):
        scores = [flowspot.assess(self.report(self.det("koukni.cz", "", n)))[0]["score"] for n in (1, 3, 10, 100)]
        self.assertEqual(scores, sorted(scores))
        self.assertLessEqual(scores[-1], 1.0)
        self.assertLess(scores[0], flowspot.LIKELY)
        self.assertGreaterEqual(scores[2], flowspot.LIKELY)

    def test_specific_signature_beats_weak_one(self):
        v = flowspot.assess(self.report(self.det("koukni.cz", "", 5), self.det("generic streaming heuristic", "", 5)))
        self.assertEqual(v[0]["service"], "koukni.cz")

    def test_labels(self):
        self.assertEqual(flowspot._label(0.9), "likely")
        self.assertEqual(flowspot._label(0.4), "possible")
        self.assertEqual(flowspot._label(0.1), "weak")

    def test_ambiguous_pair_is_penalised_and_flagged(self):
        alone = flowspot.assess(self.report(self.det("zkouknito.cz", "", 6)))[0]["score"]
        both = flowspot.assess(self.report(self.det("zkouknito.cz", "", 6), self.det("abradio.cz", "player", 6)))
        z = next(e for e in both if e["service"] == "zkouknito.cz")
        self.assertLess(z["score"], alone)
        self.assertEqual(z["ambiguous_with"], "abradio.cz")

    def test_variants_are_merged_per_service(self):
        v = flowspot.assess(self.report(self.det("youtube.com", "live", 2), self.det("youtube.com", "http", 4)))
        self.assertEqual(len(v), 1)
        self.assertEqual(sorted(v[0]["variants"]), ["http", "live"])

    def test_empty_detections_give_empty_verdict(self):
        self.assertEqual(flowspot.assess(self.report(self.det("koukni.cz", "", 0))), [])

    def test_camera_entry(self):
        v = flowspot.assess(self.report(cameras={"192.168.0.0/16": {"likely_cameras": ["192.168.1.50"]}}))
        self.assertEqual(v[0]["category"], "ipcam")
        self.assertEqual(v[0]["addresses"], ["192.168.1.50"])

    def test_ranking_is_descending(self):
        v = flowspot.assess(self.report(self.det("ulozto.cz/live", "", 8), self.det("VNC", "", 1), self.det("koukni.cz", "", 3)))
        scores = [e["score"] for e in v]
        self.assertEqual(scores, sorted(scores, reverse=True))


class FormatTests(unittest.TestCase):
    def test_flags_and_proto(self):
        self.assertEqual(flowspot.flags_str("24"), ".AP...")
        self.assertEqual(flowspot.flags_str("27"), ".AP.SF")
        self.assertEqual(flowspot.flags_str("0"), "......")
        self.assertEqual(flowspot.flags_str(".AP..."), ".AP...")
        self.assertEqual((flowspot.proto_name("6"), flowspot.proto_name("17"), flowspot.proto_name("99")),
                         ("TCP", "UDP", "99"))

    def test_human_bytes(self):
        self.assertEqual(flowspot.human_bytes(644), "644 B")
        self.assertEqual(flowspot.human_bytes(1_500_000), "1.5 MB")

    def test_positive_int(self):
        self.assertEqual(flowspot.positive_int("3"), 3)
        for bad in ("0", "-1", "x"):
            with self.assertRaises(Exception):
                flowspot.positive_int(bad)


class AutoCliTests(Harness):
    def test_no_arguments_prints_help(self):
        code, _, err = self.run_cli()
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("usage:", err)

    def test_version(self):
        code, out, _ = self.run_cli("--version")
        self.assertEqual(code, 0)

    def test_file_only_means_auto(self):
        row = FLOW_ROW.format(sa="93.99.92.7", sp=80, da="10.0.0.2", dp=50000, pkt=5000, byt=7_000_000)
        self.set_rules([{"match": "93.99.92.0/24", "out": row}])
        code, out, _ = self.run_cli(str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("ulozto.cz/live", out)
        self.assertIn("not calibrated probabilities", out)

    def test_auto_nothing_found(self):
        code, out, _ = self.run_cli(str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertEqual(code, flowspot.EXIT_NONE)
        self.assertIn("Nothing matched", out)

    def test_auto_json_is_clean(self):
        row = FLOW_ROW.format(sa="93.99.92.7", sp=80, da="10.0.0.2", dp=50000, pkt=5000, byt=7_000_000)
        self.set_rules([{"match": "93.99.92.0/24", "out": row}])
        code, out, _ = self.run_cli("auto", str(self.capture), "--nfdump", str(self.fake), "--no-dns", "--json")
        data = json.loads(out)
        self.assertNotIn("_examples", data["extra"])
        self.assertTrue(data["found"])
        self.assertEqual(data["extra"]["verdict"][0]["service"], "ulozto.cz/live")

    def test_auto_net_restricts_camera_probe(self):
        self.run_cli(str(self.capture), "--nfdump", str(self.fake), "--no-dns", "--net", "172.20.0.0/16")
        nets = [a[-1] for a in self.argv_calls() if a[-1].startswith("src net 172.20.0.0/16")]
        self.assertEqual(len(nets), 1)
        self.assertFalse(any(a[-1].startswith("src net 192.168.0.0/16 AND dst") for a in self.argv_calls()))

    def test_auto_survives_a_failing_stage(self):
        row = FLOW_ROW.format(sa="10.0.0.5", sp=40000, da="10.0.0.9", dp=5900, pkt=500, byt=50000)
        self.set_rules([{"match": "src net 10.0.0.0/8 AND dst net", "code": 3, "err": "ipcam broke"},
                        {"match": "port 5900", "out": row}])
        code, out, _ = self.run_cli(str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("VNC", out)
        self.assertIn("skipped", out)


class RenderingAndEdgeTests(Harness):
    def test_ipcam_text_report(self):
        rows = "10.0.0.50,10.0.0.9,554,40000,1000,1000000\nbad,row\n10.0.0.1,10.0.0.2,x,1,1,1\n10.0.0.1,10.0.0.2,1,1,a,b\n"
        self.set_rules([{"match": "src net", "out": rows}])
        code, out, _ = self.run_cli("ipcam", str(self.capture), "--nfdump", str(self.fake), "--net", "10.0.0.0/8")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        for needle in ("IP-camera analysis of 10.0.0.0/8", "LIKELY IP CAMERAS", "10.0.0.50", "port 554"):
            self.assertIn(needle, out)

    def test_ipcam_text_empty_sections(self):
        code, out, _ = self.run_cli("ipcam", str(self.capture), "--nfdump", str(self.fake), "--net", "10.0.0.0/8")
        self.assertEqual(code, flowspot.EXIT_NONE)
        self.assertIn("(none)", out)

    def test_verbose_shows_filters(self):
        row = FLOW_ROW.format(sa="10.0.0.5", sp=40000, da="10.0.0.9", dp=5900, pkt=500, byt=50000)
        self.set_rules([{"match": "port 5900", "out": row}])
        code, out, err = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "-v")
        self.assertIn("filter: port 5900 AND proto TCP", out)
        self.assertIn("[flowspot] filter:", err)

    def test_unusable_binary_is_a_clean_error(self):
        self.fake.write_text("#!/nonexistent/interpreter\n")
        code, _, err = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("cannot run nfdump", err)

    def test_unreadable_capture(self):
        self.capture.chmod(0)
        try:
            if os.access(self.capture, os.R_OK):
                self.skipTest("running as a user that ignores file modes")
            code, _, err = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake))
            self.assertEqual(code, flowspot.EXIT_ERROR)
            self.assertIn("not readable", err)
        finally:
            self.capture.chmod(0o644)

    def test_tz_is_passed_through(self):
        old = os.environ.get("TZ")
        os.environ["TZ"] = "UTC"
        try:
            self.assertEqual(flowspot.NfDump._env()["TZ"], "UTC")
        finally:
            if old is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = old

    def test_signatures_in_process(self):
        code, out, _ = self.run_cli("signatures")
        self.assertEqual(code, flowspot.EXIT_FOUND)
        self.assertIn("[TeamViewer]", out)

    def test_dns_enabled_streaming_adds_resolved_addresses_and_notes(self):
        orig = flowspot.resolve_hosts
        flowspot.resolve_hosts = lambda hosts, timeout=5.0: {h: ["198.51.100.9"] for h in hosts}
        try:
            self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake))
        finally:
            flowspot.resolve_hosts = orig
        joined = "\n".join(a[-1] for a in self.argv_calls())
        self.assertIn("src ip 198.51.100.9", joined)
        code, out, _ = self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--no-dns")
        self.assertIn("DNS look-ups disabled", out)

    def test_dns_partial_resolution_is_noted(self):
        orig = flowspot.resolve_hosts
        flowspot.resolve_hosts = lambda hosts, timeout=5.0: {h: [] for h in hosts}
        try:
            row = FLOW_ROW.format(sa="93.99.92.7", sp=80, da="10.0.0.2", dp=50000, pkt=5000, byt=7_000_000)
            self.set_rules([{"match": "93.99.92.0/24", "out": row}])
            code, out, _ = self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake))
        finally:
            flowspot.resolve_hosts = orig
        self.assertIn("0/13 Grooveshark host names resolved", out)

    def test_auto_text_shows_ambiguity_variants_and_cameras(self):
        rep = flowspot.Report("auto", "cap.nfcapd", [
            flowspot.Detection("zkouknito.cz", "", "f", [flowspot.Flow("t", "t", "TCP", "1.1.1.1", 1, "2.2.2.2", 2, ".A....", 9, 9)] * 5, "streaming"),
            flowspot.Detection("abradio.cz", "player", "f", [flowspot.Flow("t", "t", "TCP", "1.1.1.2", 1, "2.2.2.2", 2, ".A....", 9, 9)] * 5, "streaming"),
            flowspot.Detection("youtube.com", "live", "f", [flowspot.Flow("t", "t", "TCP", "9.9.9.9", 1, "2.2.2.2", 2, ".A....", 9, 9)] * 5, "streaming"),
        ])
        rep.extra["cameras"] = {"10.0.0.0/8": {"likely_cameras": ["10.0.0.50"]}}
        rep.extra["verdict"] = flowspot.assess(rep)
        text = flowspot.render_auto(rep, examples=1)
        self.assertIn("shares a network range with abradio.cz", text)
        self.assertIn("youtube.com (live)", text)
        self.assertIn("10.0.0.50", text)
        self.assertIn("e.g.", text)

    def test_small_parsers_reject_garbage(self):
        self.assertIsNone(flowspot.parse_port("abc"))
        self.assertIsNone(flowspot.parse_port("70000"))
        self.assertIsNone(flowspot.parse_ip("999.1.1.1"))
        self.assertEqual(flowspot._endpoints([["only-one-column"]], 0, 1), set())

    def test_human_bytes_large(self):
        self.assertEqual(flowspot.human_bytes(5 * 10**12), "5.0 TB")
        self.assertEqual(flowspot.human_bytes(10**15), "1000.0 TB")


FIVE_ROWS = "".join(
    FLOW_ROW.format(sa=f"10.0.0.{i}", sp=40000, da="10.0.0.9", dp=5900, pkt=500, byt=50000) for i in range(1, 6)
)


class LimitAndDirectoryTests(Harness):
    def test_limit_truncates_and_says_so(self):
        self.set_rules([{"match": "port 5900", "out": FIVE_ROWS}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--limit", "2")
        self.assertIn("VNC - 2+ flow(s)", out)
        self.assertIn("only the first 2 flows are listed", out)
        vnc_calls = [a for a in self.argv_calls() if a[-1].startswith("port 5900")]
        self.assertEqual(vnc_calls[0][vnc_calls[0].index("-c") + 1], "3")  # limit + 1 to detect overflow

    def test_limit_exactly_reached_is_not_truncated(self):
        self.set_rules([{"match": "port 5900", "out": FIVE_ROWS}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--limit", "5", "--json")
        vnc = next(d for d in json.loads(out)["detections"] if d["service"] == "VNC")
        self.assertEqual((len(vnc["flows"]), vnc["truncated"]), (5, False))

    def test_limit_zero_is_unlimited(self):
        self.set_rules([{"match": "port 5900", "out": FIVE_ROWS}])
        code, out, _ = self.run_cli("remote", str(self.capture), "--nfdump", str(self.fake), "--limit", "0")
        self.assertIn("VNC - 5 flow(s)", out)
        self.assertFalse(any("-c" in a for a in self.argv_calls()))

    def test_stage_queries_are_not_limited(self):
        self.run_cli("ipcam", str(self.capture), "--nfdump", str(self.fake), "-n", "10.0.0.0/8", "--limit", "1")
        self.assertFalse(any("-c" in a for a in self.argv_calls()))

    def test_truncation_flag_in_auto_verdict(self):
        self.set_rules([{"match": "port 5900", "out": FIVE_ROWS}])
        code, out, _ = self.run_cli(str(self.capture), "--nfdump", str(self.fake), "--no-dns", "--limit", "2")
        self.assertIn("VNC - 2+ flow(s)", out)

    def test_bad_limit_rejected(self):
        code, _, _ = self.run_cli("remote", str(self.capture), "--limit", "-1")
        self.assertEqual(code, 2)

    def test_directory_uses_recursive_read(self):
        sub = self.dir / "cap"
        (sub / "2026").mkdir(parents=True)
        (sub / "2026" / "nfcapd.1").write_bytes(b"")
        self.run_cli("remote", str(sub), "--nfdump", str(self.fake))
        calls = self.argv_calls()
        self.assertTrue(calls)
        for argv in calls:
            self.assertEqual(argv[argv.index("-R") + 1], str(sub.resolve()))
            self.assertNotIn("-r", argv)

    def test_empty_directory_is_an_error(self):
        empty = self.dir / "nothing"
        empty.mkdir()
        code, _, err = self.run_cli("remote", str(empty), "--nfdump", str(self.fake))
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("no files", err)


class DnsCacheTests(Harness):
    HOSTS = {"x.cdn0.grooveshark.com": ["198.51.100.9"], "wcdn20.nacevi.cz": []}

    def stub_resolver(self):
        calls = []
        orig = flowspot.resolve_hosts

        def fake(hosts, timeout=5.0):
            calls.append(list(hosts))
            return {h: ["198.51.100.9"] if h.startswith("x.cdn0") else [] for h in hosts}
        flowspot.resolve_hosts = fake
        self.addCleanup(setattr, flowspot, "resolve_hosts", orig)
        return calls

    def run_stream(self, *extra):
        return self.run_cli("streaming", str(self.capture), "--nfdump", str(self.fake), "--json", *extra)

    def test_live_lookup_is_recorded_in_the_report(self):
        self.stub_resolver()
        code, out, _ = self.run_stream()
        dns = json.loads(out)["extra"]["dns"]
        self.assertEqual(dns["source"], "live")
        self.assertEqual(dns["hosts"]["x.cdn0.grooveshark.com"], ["198.51.100.9"])
        self.assertRegex(dns["resolved_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_cache_is_written_then_reused_without_lookups(self):
        calls = self.stub_resolver()
        cache = self.dir / "dns.json"
        self.run_stream("--dns-cache", str(cache))
        self.assertEqual(len(calls), 1)
        saved = json.loads(cache.read_text())
        self.assertEqual(saved["version"], 1)
        self.assertEqual(saved["hosts"]["x.cdn0.grooveshark.com"], ["198.51.100.9"])
        self.assertEqual(oct(cache.stat().st_mode & 0o777), "0o644")
        code, out, _ = self.run_stream("--dns-cache", str(cache))
        self.assertEqual(len(calls), 1)  # no second look-up
        self.assertEqual(json.loads(out)["extra"]["dns"]["source"], "cache")
        self.assertIn("src ip 198.51.100.9", "\n".join(a[-1] for a in self.argv_calls()))

    def test_cache_works_with_no_dns(self):
        cache = self.dir / "dns.json"
        flowspot.save_dns_cache(cache, self.HOSTS, "2013-05-16T10:00:00Z")
        calls = self.stub_resolver()
        code, out, _ = self.run_stream("--dns-cache", str(cache), "--no-dns")
        self.assertEqual(calls, [])
        dns = json.loads(out)["extra"]["dns"]
        self.assertEqual((dns["source"], dns["resolved_at"]), ("cache", "2013-05-16T10:00:00Z"))

    def test_refresh_overwrites_cache(self):
        cache = self.dir / "dns.json"
        flowspot.save_dns_cache(cache, {"old.example": ["192.0.2.1"]}, "2013-05-16T10:00:00Z")
        calls = self.stub_resolver()
        self.run_stream("--dns-cache", str(cache), "--refresh-dns")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("old.example", json.loads(cache.read_text())["hosts"])

    def test_refresh_with_no_dns_is_an_error(self):
        code, _, err = self.run_stream("--refresh-dns", "--no-dns")
        self.assertEqual(code, flowspot.EXIT_ERROR)
        self.assertIn("cannot be combined", err)

    def test_auto_records_dns_too(self):
        self.stub_resolver()
        code, out, _ = self.run_cli(str(self.capture), "--nfdump", str(self.fake), "--json")
        self.assertEqual(json.loads(out)["extra"]["dns"]["source"], "live")

    def test_invalid_caches_are_rejected(self):
        bad = {
            "not json": "{{{",
            "wrong version": json.dumps({"version": 2, "resolved_at": "x", "hosts": {}}),
            "missing keys": json.dumps({"version": 1}),
            "hosts not a dict": json.dumps({"version": 1, "resolved_at": "x", "hosts": []}),
            "address not an ip": json.dumps({"version": 1, "resolved_at": "x", "hosts": {"a": ["1.2.3.4; id"]}}),
            "ipv6": json.dumps({"version": 1, "resolved_at": "x", "hosts": {"a": ["::1"]}}),
            "addresses not a list": json.dumps({"version": 1, "resolved_at": "x", "hosts": {"a": "1.2.3.4"}}),
            "number as address": json.dumps({"version": 1, "resolved_at": "x", "hosts": {"a": [5]}}),
        }
        for name, content in bad.items():
            with self.subTest(name):
                path = self.dir / "bad.json"
                path.write_text(content)
                with self.assertRaises(flowspot.FlowspotError):
                    flowspot.load_dns_cache(path)

    def test_oversized_cache_rejected(self):
        path = self.dir / "big.json"
        path.write_text(" " * (flowspot.MAX_DNS_CACHE_BYTES + 1))
        with self.assertRaises(flowspot.FlowspotError):
            flowspot.load_dns_cache(path)

    def test_missing_cache_file_error(self):
        with self.assertRaises(flowspot.FlowspotError):
            flowspot.load_dns_cache(self.dir / "nope.json")

    def test_cache_roundtrip_and_control_chars_stripped(self):
        path = self.dir / "c.json"
        flowspot.save_dns_cache(path, self.HOSTS, "2026-01-01T00:00:00Z\x1b[31m")
        when, hosts = flowspot.load_dns_cache(path)
        self.assertEqual(hosts, self.HOSTS)
        self.assertNotIn("\x1b", when)

    def test_unwritable_cache_location_is_a_clean_error(self):
        with self.assertRaises(flowspot.FlowspotError):
            flowspot.save_dns_cache(self.dir / "no" / "such" / "dir" / "c.json", self.HOSTS, "t")

    def test_cache_does_not_follow_a_symlink(self):
        target = self.dir / "precious.txt"
        target.write_text("keep me")
        link = self.dir / "dns.json"
        link.symlink_to(target)
        flowspot.save_dns_cache(link, self.HOSTS, "t")
        self.assertEqual(target.read_text(), "keep me")
        self.assertFalse(link.is_symlink())

    def test_no_temp_files_left_behind(self):
        flowspot.save_dns_cache(self.dir / "c.json", self.HOSTS, "t")
        self.assertEqual([p.name for p in self.dir.glob("c.json.*")], [])


if __name__ == "__main__":
    unittest.main()
