#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2013, 2026 Ondrej Sramek
"""flowspot - spot streaming, remote-access and IP-camera traffic in NetFlow data.

A single-file, dependency-free rewrite of the original Perl scripts that
accompanied the author's thesis (streaming.pl, other.pl, ipcam.pl).  It drives
the ``nfdump`` tool in read-only mode, applies behavioural signatures to the
flow records and prints what it found.

    flowspot streaming flows.nfcapd
    flowspot remote    flows.nfcapd
    flowspot ipcam     flows.nfcapd --net 192.168.0.0/16
    flowspot signatures

Security model (details in README.md): nfdump is started without a shell, every
value that reaches an nfdump filter is validated (CIDR, port number, IP address),
values parsed back from nfdump output are re-validated before they are reused,
the capture is only ever read, and no network access happens except optional
DNS look-ups of a fixed list of public host names (disable with --no-dns).

Exit status: 0 = something was detected, 1 = nothing detected, 2 = error.
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import math
import tempfile
from datetime import datetime, timezone
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, Union

__version__ = "1.0.0"
PROG = "flowspot"

EXIT_FOUND, EXIT_NONE, EXIT_ERROR = 0, 1, 2

DEFAULT_TIMEOUT = 300  # seconds per nfdump invocation
DNS_TIMEOUT = 5.0  # seconds for the whole batch of look-ups
DEFAULT_JOBS = 4  # parallel nfdump processes
DEFAULT_LIMIT = 1000  # flows listed per detection (0 = unlimited)
MAX_DNS_CACHE_BYTES = 1_000_000
# Linux limits a single argv string to 128 KiB; stay well below it.
MAX_FILTER_LEN = 100_000


class FlowspotError(Exception):
    """A user-facing error (bad input, nfdump failure, ...)."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def printable(text: str) -> str:
    """Drop control characters (e.g. ANSI escapes) before text reaches a terminal."""
    return "".join(ch for ch in text if ch.isprintable())


def any_of(terms: Iterable[str]) -> str:
    """Join nfdump filter terms with OR, parenthesising each of them."""
    return " OR ".join(f"({t})" for t in terms)


def ip_sort_key(value: str) -> Tuple[int, int]:
    addr = ipaddress.ip_address(value)
    return (addr.version, int(addr))


def parse_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def parse_port(text: str) -> Optional[int]:
    try:
        value = int(text.strip())
    except ValueError:
        return None
    return value if 0 <= value <= 65535 else None


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Flow:
    start: str
    end: str
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    flags: str
    packets: int
    bytes: int

    def render(self) -> str:
        return (
            f"{self.start}  {self.proto:<5} {self.src}:{self.sport} -> "
            f"{self.dst}:{self.dport}  flags={self.flags} "
            f"packets={self.packets} bytes={self.bytes}"
        )


@dataclass
class Rule:
    """One named nfdump filter."""

    service: str
    variant: str
    filter: str

    @property
    def title(self) -> str:
        return f"{self.service} ({self.variant})" if self.variant else self.service


@dataclass
class Detection:
    service: str
    variant: str
    filter: str
    flows: List[Flow] = field(default_factory=list)
    category: str = ""  # "streaming" | "remote"
    truncated: bool = False  # more flows matched than --limit allows


@dataclass
class Report:
    command: str
    capture: str
    detections: List[Detection] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    extra: Dict[str, object] = field(default_factory=dict)

    @property
    def found(self) -> bool:
        return any(d.flows for d in self.detections) or bool(self.extra.get("likely_cameras"))


# --------------------------------------------------------------------------- #
# nfdump runner
# --------------------------------------------------------------------------- #

# Fixed column layout we ask nfdump for; parsed back into Flow objects.
FLOW_FMT = "%ts,%te,%pr,%sa,%sp,%da,%dp,%flg,%pkt,%byt"


def parse_flow(row: Sequence[str]) -> Optional[Flow]:
    if len(row) != 10:
        return None
    src, dst = parse_ip(row[3]), parse_ip(row[5])
    sport, dport = parse_port(row[4]), parse_port(row[6])
    try:
        packets, nbytes = int(row[8]), int(row[9])
    except ValueError:
        return None
    if None in (src, dst, sport, dport):
        return None
    return Flow(row[0], row[1], proto_name(row[2]), src, sport, dst, dport, flags_str(row[7]), packets, nbytes)  # type: ignore[arg-type]


PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP", "58": "ICMP6"}


def proto_name(text: str) -> str:
    """nfdump -N prints protocol numbers; show the usual names."""
    return PROTOCOLS.get(text, text)


def flags_str(text: str) -> str:
    """Normalise TCP flags to the 8-letter form CEUAPRSF ('.' = clear).

    Depending on the nfdump build, -N prints flags as a number (macOS/Homebrew 1.7.10) or already as
    letters (Ubuntu); a letters string is passed through unchanged.
    """
    try:
        value = int(text)
    except ValueError:
        return text
    return "".join(ch if value & bit else "." for ch, bit in zip("CEUAPRSF", (0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01)))


def find_nfdump(explicit: Optional[str]) -> str:
    if explicit:
        path = Path(explicit).expanduser()
        if not (path.is_file() and os.access(path, os.X_OK)):
            raise FlowspotError(f"--nfdump {explicit!r} is not an executable file")
        return str(path.resolve())
    found = shutil.which("nfdump")
    if not found:
        raise FlowspotError(
            "nfdump not found in PATH. Install it (apt install nfdump / brew install nfdump) "
            "or point to it with --nfdump /path/to/nfdump"
        )
    return found


def validate_capture(text: str) -> Path:
    """Accept a flow file or a directory of flow files (nfdump -R, recursive)."""
    path = Path(text).expanduser()
    if path.is_dir():
        if ":" in str(path.resolve()):
            raise FlowspotError(
                f"directory path contains ':' which nfdump -R reads as a file-range separator: {text} "
                "(rename the directory or pass the files one by one)"
            )
        if not os.access(path, os.R_OK | os.X_OK):
            raise FlowspotError(f"capture directory is not readable: {text}")
        if not any(p.is_file() for p in path.rglob("*")):
            raise FlowspotError(f"capture directory contains no files: {text}")
    elif not path.is_file():
        raise FlowspotError(f"capture file or directory not found: {text}")
    elif not os.access(path, os.R_OK):
        raise FlowspotError(f"capture file is not readable: {text}")
    # Absolute path: can never be mistaken for an option by nfdump's getopt.
    return path.resolve()


class NfDump:
    """Thin, shell-free wrapper around ``nfdump -r <file> ... <filter>``."""

    def __init__(
        self,
        binary: str,
        capture: Path,
        timeout: int = DEFAULT_TIMEOUT,
        log: Optional[Callable[[str], None]] = None,
        jobs: int = DEFAULT_JOBS,
        limit: int = DEFAULT_LIMIT,
    ) -> None:
        self.binary = binary
        self.capture = capture
        self.timeout = timeout
        self.jobs = jobs
        self.limit = limit
        self.log = log or (lambda _msg: None)

    @staticmethod
    def _env() -> Dict[str, str]:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
        if "TZ" in os.environ:
            env["TZ"] = os.environ["TZ"]
        return env

    def stream(self, flt: str, fmt: str, max_records: int = 0) -> Iterator[List[str]]:
        """Run one filter and yield the output rows (split on commas) as nfdump produces them.

        Rows are not collected, so memory stays flat however many records match. Closing the
        generator early kills nfdump. Errors surface when the iteration ends.

        Records are listed as exported (no -B bidirectional merging, which would reorder
        source/destination and hide which side matched).
        """
        if not flt.strip():
            raise FlowspotError("internal error: refusing to run nfdump with an empty filter")
        if len(flt) > MAX_FILTER_LEN:
            raise FlowspotError(
                f"generated filter is too large ({len(flt)} bytes); the capture contains too many "
                "candidate hosts/ports - analyse a shorter time window"
            )
        source = ["-R", str(self.capture)] if self.capture.is_dir() else ["-r", str(self.capture)]
        cmd = [self.binary, *source, "-q", "-N"]
        if max_records:
            cmd += ["-c", str(max_records)]  # nfdump stops after N records
        cmd += ["-o", f"fmt:{fmt}", flt]
        self.log(f"filter: {flt}")
        err = tempfile.TemporaryFile()  # a file, not a pipe: cannot fill up and deadlock
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err, env=self._env())
        except OSError as exc:  # includes E2BIG
            err.close()
            raise FlowspotError(f"cannot run nfdump: {exc}") from None
        timed_out = threading.Event()

        def kill() -> None:
            timed_out.set()
            proc.kill()

        timer = threading.Timer(self.timeout, kill)
        timer.daemon = True
        timer.start()
        produced = False
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").strip()
                if line and line.lower() != "no matching flows":  # printed on stdout even with -q
                    produced = True
                    yield [cell.strip() for cell in line.split(",")]
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
            if proc.stdout:
                proc.stdout.close()
            proc.wait()
            err.seek(0)
            stderr = err.read(65536).decode("utf-8", "replace")
            err.close()
        if timed_out.is_set() and proc.returncode != 0:
            raise FlowspotError(f"nfdump did not finish within {self.timeout}s (see --timeout)")
        lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
        if proc.returncode != 0:
            raise FlowspotError(f"nfdump failed (exit {proc.returncode}): {printable(lines[0]) if lines else 'no message'}")
        if not produced:
            # nfdump exits 0 even for a corrupt/truncated file ("bad magic", "read() error");
            # an empty result plus diagnostics must not be mistaken for "nothing found".
            problems = [ln for ln in lines if "no matching flows" not in ln.lower()]
            if problems:
                raise FlowspotError(f"nfdump could not read the capture: {printable(problems[0])}")

    def query(self, flt: str, fmt: str, max_records: int = 0) -> List[List[str]]:
        """Like stream(), collected into a list - only for results that are known to be small."""
        return list(self.stream(flt, fmt, max_records))

    def detect(self, service: str, variant: str, flt: str, category: str = "") -> "Detection":
        """Run a filter and wrap the flows (at most ``limit``) in a Detection."""
        rows = self.stream(flt, FLOW_FMT, max_records=self.limit + 1 if self.limit else 0)
        flows = [f for f in (parse_flow(r) for r in rows) if f]
        flows.sort(key=lambda f: f.start)
        truncated = bool(self.limit) and len(flows) > self.limit
        return Detection(service, variant, flt, flows[: self.limit] if self.limit else flows, category, truncated)


def gather(report: "Report", tasks: Sequence[Tuple[str, Callable[[], object]]], jobs: int) -> List[object]:
    """Run independent tasks (in parallel) and survive partial failure.

    A failing task becomes a note on the report and a ``None`` result; only if
    *every* task fails is the first error re-raised.
    """
    def guarded(task: Tuple[str, Callable[[], object]]) -> Tuple[object, Optional[FlowspotError]]:
        try:
            return task[1](), None
        except FlowspotError as exc:
            return None, exc

    if jobs > 1 and len(tasks) > 1:
        with ThreadPoolExecutor(max_workers=min(jobs, len(tasks))) as pool:
            outcomes = list(pool.map(guarded, tasks))
    else:
        outcomes = [guarded(t) for t in tasks]
    errors = [(t[0], e) for t, (_r, e) in zip(tasks, outcomes) if e is not None]
    for label, err in errors:
        report.notes.append(f"{label}: skipped ({err})")
    if tasks and len(errors) == len(tasks):
        raise errors[0][1]
    return [r for r, _e in outcomes]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #


def resolve_hosts(hostnames: Sequence[str], timeout: float = DNS_TIMEOUT) -> Dict[str, List[str]]:
    """Resolve fixed public host names to IPv4 addresses: {host: [addresses]}.

    Every requested host is in the result; one that did not resolve (or timed
    out) maps to []. Look-ups run in daemon threads under one overall deadline
    so a broken resolver can never hang the tool.
    """
    results: Dict[str, List[str]] = {}

    def worker(host: str) -> None:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            return
        results[host] = sorted({ip for ip in (parse_ip(str(i[4][0])) for i in infos) if ip}, key=ip_sort_key)

    threads = [threading.Thread(target=worker, args=(h,), daemon=True) for h in hostnames]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return {h: list(results.get(h, [])) for h in hostnames}


def load_dns_cache(path: Path) -> Tuple[str, Dict[str, List[str]]]:
    """Read and strictly validate a DNS cache written by save_dns_cache()."""
    try:
        if path.stat().st_size > MAX_DNS_CACHE_BYTES:
            raise FlowspotError(f"DNS cache {path} is too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        when, hosts = data["resolved_at"], data["hosts"]
        if data.get("version") != 1 or not isinstance(when, str) or not isinstance(hosts, dict):
            raise ValueError("unexpected structure")
        clean: Dict[str, List[str]] = {}
        for host, ips in hosts.items():
            if not (isinstance(host, str) and 0 < len(host) <= 253 and isinstance(ips, list)):
                raise ValueError("bad host entry")
            parsed = [parse_ip(ip) if isinstance(ip, str) else None for ip in ips]
            if None in parsed or any(ipaddress.ip_address(ip).version != 4 for ip in parsed if ip):
                raise ValueError(f"bad address for {host}")
            clean[host] = [ip for ip in parsed if ip]
        return printable(when)[:40], clean
    except FlowspotError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise FlowspotError(f"cannot use DNS cache {path}: {exc}") from None


def save_dns_cache(path: Path, hosts: Dict[str, List[str]], when: str) -> None:
    """Write the cache atomically (temp file + rename; never follows a symlink at ``path``)."""
    payload = json.dumps({"version": 1, "resolved_at": when, "hosts": hosts}, indent=2, sort_keys=True) + "\n"
    try:
        fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.resolve().parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
    except OSError as exc:
        raise FlowspotError(f"cannot write DNS cache {path}: {exc}") from None


# --------------------------------------------------------------------------- #
# Signatures: streaming
# --------------------------------------------------------------------------- #

# NOTE: the service names below (abradio, koukni, nacevi, ulozto, zkouknito, Seznam, ...) are Czech brand
# names. They are the identifiers shown in the output and are intentionally not translated; see
# docs/DETECTION.md ("Service names") for what each one is.
GROOVESHARK_HOSTS = (
    [f"x.cdn{i}.grooveshark.com" for i in range(10)]
    + ["static.a.gs-cdn.net", "cowbell.grooveshark.com", "preview.grooveshark.com"]
)
GROOVESHARK_NET = "8.20.213.0/24"

NACEVI_HOSTS = [
    f"wcdn{n}.nacevi.cz"
    for n in (20, 21, 23, 24, 25, 26, 27, 31, 32, 34, 35, 36, 37, 38, 39,
              60, 61, 62, 63, 64, 65, 66, 67, 71, 72, 73, 75)
]
NACEVI_STATIC_IPS = ["81.0.206.1", "81.0.206.2", "81.0.206.3", "81.0.206.4"]
NACEVI_NETS = ["89.221.208.0/20", "89.221.216.0/21"]  # also Voyo (Nova)

SZN_DISPATCHER_HOSTS = ["cdn-dispatcher1g.seznam.cz", "cdn-dispatcher-prim.stream.cz"]
SZN_DISPATCHER_STATIC_IPS = ["77.75.73.242", "77.75.77.242"]
SZN_NETS = ["77.75.72.0/23", "77.75.76.0/23", "91.103.160.0/24"]

PRIMA_NETS = ["160.218.6.0/24", "212.47.12.0/24"]
KOUKNI_NET = "93.185.104.0/24"
ABRADIO_ZKOUKNITO_NET = "90.183.101.0/24"  # abradio.cz and zkouknito.cz share a prefix
PLAY_NET = "89.233.146.0/24"
ULOZTO_NET = "93.99.92.0/24"

GOOGLE_NETS = [
    "64.233.160.0/19", "66.102.0.0/20", "66.102.2.0/24", "66.102.3.0/24", "66.102.4.0/24",
    "66.249.64.0/19", "70.32.128.0/19", "72.14.192.0/18", "74.125.0.0/16", "89.207.224.0/21",
    "108.170.192.0/18", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "173.194.0.0/16",
    "192.178.0.0/15", "207.223.160.0/20", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
]

# Flows of YouTube's characteristic length are excluded (durations in ms).
_NOT_BURST = (
    "not(duration > 31000 AND duration < 42000) AND not(duration > 59000 AND duration < 100000) "
    "AND not(duration > 500 AND duration < 7000)"
)
_YT_443 = "{n} AND port 443 AND flags APSF AND packets > 15 AND packets < 400 AND pps = 0"
_YT_SHORT = f"{{n}} AND {_NOT_BURST} AND flags APSF AND packets > 13 AND bpp > 150 AND bpp < 1400 AND pps = 0"

YOUTUBE_VARIANTS: Dict[str, List[str]] = {
    "live": [
        f"{{n}} AND {_NOT_BURST} AND flags APSF AND packets > 15 AND packets < 100 "
        "AND bpp > 70 AND bpp < 1300 AND pps = 0",
        "{n} AND flags APS AND bpp > 1300 AND pps > 20 AND pps < 100",
        _YT_443,
    ],
    "html5": [
        "{n} AND flags APSF AND bpp > 1400 AND pps > 15 AND pps < 100",
        _YT_SHORT,
        _YT_443,
    ],
    "https": [
        "{n} AND flags APSF AND pps > 10 AND pps < 100 AND bpp > 1400",
        _YT_443,
    ],
    "http": [
        "{n} AND flags APSF AND bpp > 1400 AND pps > 20 AND pps < 100",
        _YT_SHORT,
        _YT_443,
    ],
}

GENERIC_FILTER = "packets > 1000 AND pps > 5 AND pps < 800 AND bpp > 1200"

# How specific a signature is, 0..1.  A rule tied to one service's own network range plus behaviour
# limits is strong; one that matches on a shared prefix, a well-known port or pure traffic shape is
# weak.  These are judgement calls made by the author, NOT statistically calibrated probabilities.
SPECIFICITY_DEFAULT = 0.85


@dataclass(frozen=True)
class Each:
    """One filter term per address of the host set ``hosts`` (known only at run time)."""

    hosts: str      # name of the host set: "grooveshark", "nacevi", "szn_seen"
    template: str   # '{ip}' is replaced by each address


Term = Union[str, Each]

# When a rule applies.
ALWAYS, SZN_SEEN, SZN_UNSEEN, GENERIC = "always", "szn_seen", "szn_unseen", "generic"
CONDITIONS = {
    ALWAYS: "",
    SZN_SEEN: "  [only if a Seznam CDN dispatcher is seen in the capture]",
    SZN_UNSEEN: "  [only if no Seznam CDN dispatcher is seen in the capture]",
    GENERIC: "  [only with --generic]",
}


@dataclass(frozen=True)
class RuleSpec:
    """A detection rule as data: name, filter terms, applicability and how specific it is."""

    service: str
    variant: str
    terms: Tuple[Term, ...]          # OR-ed together; an Each expands to one term per address
    specificity: float = SPECIFICITY_DEFAULT
    when: str = ALWAYS
    category: str = "streaming"

    @property
    def title(self) -> str:
        return f"{self.service} ({self.variant})" if self.variant else self.service

    @staticmethod
    def _join(terms: List[str]) -> str:
        return terms[0] if len(terms) == 1 else any_of(terms)

    def build(self, hosts: Mapping[str, Sequence[str]]) -> str:
        """The nfdump filter, with host sets filled in ('' if nothing is left to match)."""
        out: List[str] = []
        for t in self.terms:
            if isinstance(t, Each):
                out += [t.template.format(ip=ip) for ip in hosts.get(t.hosts, ())]
            else:
                out.append(t)
        return self._join(out) if out else ""

    def describe(self) -> str:
        """The filter as shown by `flowspot signatures` (host sets as <placeholders>)."""
        return self._join([
            t.template.format(ip=f"<{t.hosts} addresses>") if isinstance(t, Each) else t for t in self.terms
        ])


def _youtube_terms(variant: str) -> Tuple[Term, ...]:
    templates = YOUTUBE_VARIANTS[variant]
    return tuple(any_of(t.format(n=f"net {net}") for t in templates) for net in GOOGLE_NETS)


# In report order.
STREAMING_SPECS: Tuple[RuleSpec, ...] = (
    RuleSpec("abradio.cz", "web browser", (f"net {ABRADIO_ZKOUKNITO_NET} AND packets < 200",), 0.45),
    RuleSpec("abradio.cz", "player", (f"net {ABRADIO_ZKOUKNITO_NET} AND packets > 300 AND pps < 20",), 0.6),
    RuleSpec("grooveshark.com", "", (Each("grooveshark", "src ip {ip}"), f"net {GROOVESHARK_NET} AND bpp > 1400")),
    RuleSpec("play.prima.cz", "", tuple(f"src net {n} AND bpp > 1300" for n in PRIMA_NETS)),
    RuleSpec("koukni.cz", "", (f"src net {KOUKNI_NET} AND packets > 1000 AND bpp > 1300",)),
    RuleSpec("nacevi/visual", "ceskatelevize.cz, ivysilani.cz, topfun.cz, ...",
             (Each("nacevi", "src ip {ip}"), *(f"src net {n}" for n in NACEVI_NETS))),
    RuleSpec("voyo.cz", "", tuple(f"src net {n}" for n in NACEVI_NETS)),
    RuleSpec("mixer.cz", "",
             (Each("szn_seen", "src ip {ip} AND bpp > 1000"),
              *(f"src net {n} AND packets > 1000 AND bpp > 1000" for n in SZN_NETS)), when=SZN_SEEN),
    RuleSpec("play.cz", "web browser", (f"net {PLAY_NET} AND pps < 10",), 0.45),
    RuleSpec("play.cz", "player", (f"net {PLAY_NET} AND pps > 10",), 0.6),
    RuleSpec("seznam.cz", "live concerts, films, ...",
             tuple(f"src net {n} AND duration > 30000 AND bpp > 1400 AND pps > 50 AND pps < 150" for n in SZN_NETS),
             when=SZN_UNSEEN),
    RuleSpec("stream.cz", "",
             (Each("szn_seen", "src ip {ip} AND bpp > 1200"),
              *(f"src net {n} AND packets > 1000 AND bpp > 1200" for n in SZN_NETS)), when=SZN_SEEN),
    RuleSpec("ulozto.cz/live", "", (f"src net {ULOZTO_NET} AND pps > 100 AND pps < 600 AND bpp > 1400",)),
    *(RuleSpec("youtube.com", v, _youtube_terms(v), 0.7) for v in ("live", "html5", "https", "http")),
    RuleSpec("zkouknito.cz", "", (f"net {ABRADIO_ZKOUKNITO_NET} AND pps > 60",), 0.5),
    RuleSpec("generic streaming heuristic", "", (GENERIC_FILTER,), 0.35, when=GENERIC),
)


def streaming_rules(hosts: Mapping[str, Sequence[str]], generic: bool = False) -> List[Rule]:
    """The streaming rules that apply, in report order, with host sets filled in.

    ``hosts`` maps "grooveshark", "nacevi" and "szn_seen" to addresses. "szn_seen" are the Seznam CDN
    dispatchers actually seen as flow sources in the capture: when there are some, mixer.cz/stream.cz
    are searched, otherwise the Seznam "live" heuristic is used instead.
    """
    active = {ALWAYS, SZN_SEEN if hosts.get("szn_seen") else SZN_UNSEEN}
    if generic:
        active.add(GENERIC)
    built = [(spec, spec.build(hosts)) for spec in STREAMING_SPECS if spec.when in active]
    return [Rule(spec.service, spec.variant, flt) for spec, flt in built if flt]


ALL_DNS_HOSTS = GROOVESHARK_HOSTS + NACEVI_HOSTS + SZN_DISPATCHER_HOSTS


def _note_truncation(report: Report, nf: NfDump) -> None:
    for d in report.detections:
        if d.truncated:
            title = f"{d.service} ({d.variant})" if d.variant else d.service
            report.notes.append(f"{title}: only the first {nf.limit} flows are listed (--limit 0 lists all)")


def _dns_answers(
    report: Report, dns: bool, cache: Optional[Path], refresh: bool
) -> Dict[str, List[str]]:
    """Host -> addresses from a DNS cache or a live look-up; recorded in report.extra['dns']."""
    if refresh and not dns:
        raise FlowspotError("--refresh-dns cannot be combined with --no-dns")
    hosts: Dict[str, List[str]] = {}
    if cache is not None and cache.exists() and not refresh:
        when, hosts = load_dns_cache(cache)
        report.extra["dns"] = {"source": "cache", "resolved_at": when, "cache": str(cache), "hosts": hosts}
        report.notes.append(f"DNS: answers loaded from {cache} (resolved {when}); no look-ups were made")
    elif dns:
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        hosts = resolve_hosts(ALL_DNS_HOSTS)
        report.extra["dns"] = {"source": "live", "resolved_at": when, "hosts": hosts}
        if cache is not None:
            save_dns_cache(cache, hosts, when)
            report.extra["dns"]["cache"] = str(cache)  # type: ignore[index]
            report.notes.append(f"DNS: answers saved to {cache}; reuse them with the same --dns-cache for reproducible runs")
        else:
            report.notes.append("DNS: resolved live now, not at capture time (--dns-cache FILE pins the answers)")
    else:
        report.extra["dns"] = {"source": "none"}
        report.notes.append("DNS look-ups disabled (--no-dns): only fixed network ranges are checked")
    return hosts


def run_streaming(
    nf: NfDump, dns: bool, generic: bool, dns_cache: Optional[Path] = None, refresh_dns: bool = False
) -> Report:
    report = Report("streaming", str(nf.capture))
    answers = _dns_answers(report, dns, dns_cache, refresh_dns)

    def ips_of(hosts: Sequence[str], label: str) -> List[str]:
        if answers:
            ok = sum(1 for h in hosts if answers.get(h))
            if ok < len(hosts):
                report.notes.append(
                    f"DNS: {ok}/{len(hosts)} {label} host names resolved "
                    "(servers may be gone or have changed; fixed network ranges are still checked)"
                )
        return sorted({ip for h in hosts for ip in answers.get(h, [])}, key=ip_sort_key)

    groove_ips = ips_of(GROOVESHARK_HOSTS, "Grooveshark")
    nacevi_ips = sorted(set(NACEVI_STATIC_IPS) | set(ips_of(NACEVI_HOSTS, "nacevi/visual")), key=ip_sort_key)
    dispatchers = sorted(set(SZN_DISPATCHER_STATIC_IPS) | set(ips_of(SZN_DISPATCHER_HOSTS, "Seznam CDN")), key=ip_sort_key)

    # Which Seznam dispatchers actually talk in this capture?
    rows = nf.query(any_of(f"src ip {ip}" for ip in dispatchers), "%sa")
    seen = sorted({ip for ip in (parse_ip(r[0]) for r in rows) if ip}, key=ip_sort_key)

    rules = streaming_rules({"grooveshark": groove_ips, "nacevi": nacevi_ips, "szn_seen": seen}, generic)
    results = gather(report, [(r.title, lambda r=r: nf.detect(r.service, r.variant, r.filter, "streaming")) for r in rules], nf.jobs)
    report.detections.extend(d for d in results if d is not None)  # type: ignore[misc]
    _note_truncation(report, nf)
    return report


# --------------------------------------------------------------------------- #
# Signatures: remote access
# --------------------------------------------------------------------------- #

SSH_X_FILTER = (
    "(port 22 AND packets > 500 AND flags APS AND not flags F AND pps > 20 AND pps < 2000 AND bpp > 60) OR "
    "(port 22 AND packets > 1000 AND flags AP AND not flags SF AND pps > 400 AND bpp > 50) OR "
    "(port 22 AND packets > 500 AND flags APF AND not flags S AND pps > 70 AND pps < 1000 AND bpp > 60) OR "
    "(port 22 AND packets > 500 AND flags APSF AND pps > 10 AND pps < 50 AND bpp > 100)"
)
VNC_FILTER = "port 5900 AND proto TCP AND pps > 3 AND pps < 150"
# TeamViewer: a tiny TCP handshake-like exchange reveals the client's ports ...
TEAMVIEWER_TCP_FILTER = (
    "proto TCP AND packets = 4 AND bytes > 440 AND bytes < 620 AND pps > 10 AND pps < 40 "
    "AND bpp > 110 AND bpp < 155"
)
# ... which are then looked for in 124-byte UDP keep-alive datagrams.
TEAMVIEWER_UDP_FILTER = "port {p} AND proto UDP AND bytes = 124"

LOCAL_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
SKYPE_FILTER = (
    "(" + " OR ".join(f"dst net {n}" for n in LOCAL_NETS) + ") AND "
    + " AND ".join(f"not src net {n}" for n in LOCAL_NETS)
    + " AND proto UDP AND pps = 0 AND bps > 10 AND bps < 21 AND bpp > 30 AND bpp < 70"
)
SKYPE_MICROSOFT_NET = "157.56.0.0/16"


REMOTE_SPECS: Tuple[RuleSpec, ...] = (
    RuleSpec("ssh -X", "X11 forwarding", (SSH_X_FILTER,), 0.6, category="remote"),
    RuleSpec("VNC", "", (VNC_FILTER,), 0.8, category="remote"),
)
# Multi-stage detectors (their filters are built from earlier results).
STAGED_SPECIFICITY: Dict[Tuple[str, str], float] = {("TeamViewer", ""): 0.75, ("Skype", "experimental"): 0.3}


def _endpoint(row: Sequence[str], ip_col: int, port_col: int, min_port: int = 0) -> Optional[Tuple[str, int]]:
    """(address, port) from two columns of an output row, or None if either is invalid."""
    if len(row) <= max(ip_col, port_col):
        return None
    ip, port = parse_ip(row[ip_col]), parse_port(row[port_col])
    return (ip, port) if ip is not None and port is not None and port >= min_port else None


def _teamviewer(nf: NfDump) -> Detection:
    flt_desc = f"{TEAMVIEWER_TCP_FILTER}  ->  {TEAMVIEWER_UDP_FILTER.format(p='<port>')}"
    tcp_sports: Set[int] = set()
    port_pairs: Set[Tuple[str, int]] = set()
    for row in nf.stream(TEAMVIEWER_TCP_FILTER, "%sa,%da,%sp,%dp"):
        src = _endpoint(row, 0, 2)
        if src:
            tcp_sports.add(src[1])
        # NOTE: pairs the destination address with the *source* port, exactly like the
        # original thesis script; "port N" in nfdump matches either direction.
        dst = _endpoint(row, 1, 2, min_port=1000)
        if dst:
            port_pairs.add(dst)
    dport_pairs: Set[Tuple[str, int]] = set()
    if tcp_sports:
        flt = any_of(TEAMVIEWER_UDP_FILTER.format(p=p) for p in sorted(tcp_sports))
        for row in nf.stream(flt, "%da,%dp"):
            ep = _endpoint(row, 0, 1, min_port=1000)
            if ep:
                dport_pairs.add(ep)
    if not (dport_pairs and port_pairs):
        return Detection("TeamViewer", "", flt_desc, [], "remote")
    pairs = sorted(dport_pairs | port_pairs, key=lambda t: (ip_sort_key(t[0]), t[1]))
    return nf.detect("TeamViewer", "", any_of(f"ip {ip} AND port {port}" for ip, port in pairs), "remote")


def _skype(nf: NfDump, report: Report) -> Detection:
    hosts: Set[str] = set()
    counts: Counter = Counter()
    for row in nf.stream(SKYPE_FILTER, "%da,%dp"):
        ep = _endpoint(row, 0, 1)
        if ep:
            hosts.add(ep[0])
        high = _endpoint(row, 0, 1, min_port=10000)
        if high:
            counts[high] += 1
    # Five-digit ports seen in at least two flows (the original `uniq -d`).
    repeated = sorted((p for p, n in counts.items() if n >= 2), key=lambda t: (ip_sort_key(t[0]), t[1]))
    if not repeated:
        return Detection("Skype", "experimental", SKYPE_FILTER, [], "remote")
    terms = [f"proto UDP AND dst ip {ip} AND dst port {port}" for ip, port in repeated]
    for ip in sorted(hosts, key=ip_sort_key):
        for port in (443, 80):
            terms.append(
                f"dst ip {ip} AND packets < 10 AND bpp < 60 AND bpp > 50 AND port {port} "
                "AND flags A AND not flags RUS"
            )
    terms.append(f"src net {SKYPE_MICROSOFT_NET} AND proto TCP")
    report.notes.append("Skype candidates (UDP): " + ", ".join(f"{ip}:{p}" for ip, p in repeated))
    return nf.detect("Skype", "experimental", any_of(terms), "remote")


def run_remote(nf: NfDump, skype: bool) -> Report:
    report = Report("remote", str(nf.capture))
    tasks: List[Tuple[str, Callable[[], object]]] = [
        (spec.title, lambda spec=spec: nf.detect(spec.service, spec.variant, spec.build({}), spec.category))
        for spec in REMOTE_SPECS
    ]
    tasks.append(("TeamViewer", lambda: _teamviewer(nf)))
    if skype:
        tasks.append(("Skype", lambda: _skype(nf, report)))
    else:
        report.notes.append("Skype detection is off (it was disabled in the original scripts); enable with --skype")
    report.detections.extend(d for d in gather(report, tasks, nf.jobs) if d is not None)  # type: ignore[misc]
    _note_truncation(report, nf)
    return report


# --------------------------------------------------------------------------- #
# Signatures: IP cameras
# --------------------------------------------------------------------------- #

CAMERA_PORT_RANGE = (10, 9999)  # the original only considered 2-4 digit ports
BUSY_BPP = 2000  # ports that carry bulk data (> 2000 bytes/packet) are not cameras


def _order(key: Union[str, int]) -> Tuple[int, int]:
    """Numeric ordering for ties: addresses by value, ports by number (not as text)."""
    return ip_sort_key(key) if isinstance(key, str) else (0, key)


def _top(counter_bytes: Counter, counter_pkts: Counter, n: int) -> Tuple[Set, Set]:
    by_bytes = sorted(counter_bytes.items(), key=lambda kv: (-kv[1], _order(kv[0])))[:n]
    bpp = {k: counter_bytes[k] // max(counter_pkts[k], 1) for k in counter_bytes}
    by_bpp = sorted(bpp.items(), key=lambda kv: (-kv[1], _order(kv[0])))[:n]
    return {k for k, _ in by_bytes}, {k for k, _ in by_bpp}


def run_ipcam(nf: NfDump, net: str, ignore_ports: Sequence[int], top: int) -> Report:
    report = Report("ipcam", str(nf.capture))
    inside = f"src net {net} AND dst net {net}"

    # Pass 1: per-host and per-port totals, accumulated while nfdump streams (memory ~ distinct hosts/ports).
    ip_bytes: Counter = Counter()
    ip_pkts: Counter = Counter()
    port_bytes: Counter = Counter()
    port_pkts: Counter = Counter()
    busy: Set[int] = set()
    for r in nf.stream(inside, "%sa,%da,%sp,%dp,%pkt,%byt"):
        if len(r) != 6:
            continue
        sa, da, sp, dp = parse_ip(r[0]), parse_ip(r[1]), parse_port(r[2]), parse_port(r[3])
        try:
            pkts, nbytes = int(r[4]), int(r[5])
        except ValueError:
            continue
        if sa is None or da is None or sp is None or dp is None:
            continue
        for ip in {sa, da}:
            ip_bytes[ip] += nbytes
            ip_pkts[ip] += pkts
        for port in {sp, dp}:
            port_bytes[port] += nbytes
            port_pkts[port] += pkts
        if nbytes // max(pkts, 1) > BUSY_BPP and sp >= CAMERA_PORT_RANGE[0]:
            busy.add(sp)

    # Top-N hosts / ports by volume AND by average packet size.
    a, b = _top(ip_bytes, ip_pkts, top)
    candidates_by_traffic = sorted(a & b, key=ip_sort_key)
    a, b = _top(port_bytes, port_pkts, top)
    lo, hi = CAMERA_PORT_RANGE
    camera_ports = sorted({p for p in a & b if lo <= p <= hi} - busy - set(ignore_ports))

    # Pass 2: which hosts send on those ports (the original script did the same second query).
    by_port: Set[str] = set()
    if camera_ports:
        flt = f"{inside} AND ({' OR '.join(f'port {p}' for p in camera_ports)})"
        by_port = {ip for ip in (parse_ip(r[0]) for r in nf.stream(flt, "%sa") if r) if ip}
    candidates_by_port = sorted(by_port, key=ip_sort_key)
    likely = sorted(set(candidates_by_traffic) & by_port, key=ip_sort_key)

    report.extra = {
        "net": net,
        "candidates_by_traffic": candidates_by_traffic,
        "busy_ports": sorted(busy),
        "camera_ports": camera_ports,
        "candidates_by_port": candidates_by_port,
        "likely_cameras": likely,
    }
    return report


# --------------------------------------------------------------------------- #
# Auto mode: run everything and guess what the capture contains
# --------------------------------------------------------------------------- #

PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Specificity of every rule comes from its RuleSpec (see above); multi-stage detectors are listed separately.
SPECIFICITY: Dict[Tuple[str, str], float] = {
    **{(s.service, s.variant): s.specificity for s in STREAMING_SPECS + REMOTE_SPECS},
    **STAGED_SPECIFICITY,
}
CAMERA_SPECIFICITY = 0.5
# Services that share (part of) a network range: when both hit, neither is certain.
AMBIGUOUS_PAIRS = [("abradio.cz", "zkouknito.cz"), ("voyo.cz", "nacevi/visual")]
AMBIGUITY_FACTOR = 0.85
LIKELY, POSSIBLE = 0.6, 0.3


def _specificity(service: str, variant: str) -> float:
    for key in ((service, variant), (service, "")):
        if key in SPECIFICITY:
            return SPECIFICITY[key]
    return SPECIFICITY_DEFAULT


def _evidence(count: int, scale: float = 3.0) -> float:
    """Saturating 0..1: 1 flow is weak evidence, ~10 flows is nearly conclusive."""
    return 1.0 - math.exp(-count / scale)


def _label(score: float) -> str:
    return "likely" if score >= LIKELY else "possible" if score >= POSSIBLE else "weak"


def assess(report: Report) -> List[Dict[str, object]]:
    """Turn raw detections into a ranked list of guesses with a 0..1 score."""
    best: Dict[str, Dict[str, object]] = {}
    for d in report.detections:
        if not d.flows:
            continue
        score = _specificity(d.service, d.variant) * _evidence(len(d.flows))
        entry = best.setdefault(d.service, {
            "service": d.service, "category": d.category, "score": 0.0, "variants": [],
            "flows": 0, "hosts": 0, "bytes": 0, "truncated": False, "_hosts": set(), "_flows": [],
        })
        if d.variant:
            entry["variants"].append(d.variant)  # type: ignore[union-attr]
        entry["_hosts"].update(f.src for f in d.flows)  # type: ignore[union-attr]
        entry["_flows"].extend(d.flows)  # type: ignore[union-attr]
        if score > entry["score"]:  # type: ignore[operator]
            entry["score"] = score
            entry["flows"] = len(d.flows)
            entry["truncated"] = d.truncated
            entry["bytes"] = sum(f.bytes for f in d.flows)
    for entry in best.values():
        entry["hosts"] = len(entry.pop("_hosts"))  # type: ignore[arg-type]
    for a, b in AMBIGUOUS_PAIRS:
        if a in best and b in best:
            for name, other in ((a, b), (b, a)):
                best[name]["score"] *= AMBIGUITY_FACTOR  # type: ignore[operator]
                best[name]["ambiguous_with"] = other
    cams = report.extra.get("cameras") or {}
    for net, info in cams.items():  # type: ignore[union-attr]
        n = len(info["likely_cameras"])
        if n:
            best[f"IP cameras in {net}"] = {
                "service": f"IP cameras in {net}", "category": "ipcam", "variants": [],
                "score": CAMERA_SPECIFICITY * _evidence(n, 2.0), "flows": 0, "hosts": n, "bytes": 0,
                "addresses": info["likely_cameras"], "_flows": [],
            }
    ranked = sorted(best.values(), key=lambda e: -e["score"])  # type: ignore[operator]
    for e in ranked:
        e["confidence"] = _label(e["score"])  # type: ignore[arg-type]
        e["score"] = round(e["score"], 2)  # type: ignore[arg-type]
    # Variants of one service often match the same flow: keep each flow once.
    report.extra["_examples"] = {e["service"]: list(dict.fromkeys(e.pop("_flows"))) for e in ranked}  # type: ignore[call-overload]
    return ranked


def run_auto(
    nf: NfDump, net: Optional[str], dns: bool, generic: bool, skype: bool,
    dns_cache: Optional[Path] = None, refresh_dns: bool = False,
) -> Report:
    """Run every detector and rank what was found by confidence."""
    report = Report("auto", str(nf.capture))
    nets = [net] if net else PRIVATE_NETS
    tasks: List[Tuple[str, Callable[[], object]]] = [
        ("streaming", lambda: run_streaming(nf, dns, generic, dns_cache, refresh_dns)),
        ("remote", lambda: run_remote(nf, skype)),
    ] + [(f"ipcam {n}", lambda n=n: run_ipcam(nf, n, [], 20)) for n in nets]
    # Stages run one after another (each already parallelises internally).
    cameras: Dict[str, object] = {}
    for result in gather(report, tasks, jobs=1):
        if not isinstance(result, Report):
            continue
        report.detections += result.detections
        report.notes += [n for n in result.notes if n not in report.notes]
        if "dns" in result.extra:
            report.extra["dns"] = result.extra["dns"]
        if result.command == "ipcam":
            cameras[str(result.extra["net"])] = result.extra
    report.extra["cameras"] = cameras
    report.extra["likely_cameras"] = sorted(
        {ip for e in cameras.values() for ip in e["likely_cameras"]}, key=ip_sort_key  # type: ignore[index,union-attr]
    )
    report.extra["verdict"] = assess(report)
    return report


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if size < 1000 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{n} B"  # pragma: no cover  (unreachable)


def render_auto(report: Report, examples: int) -> str:
    verdict: List[Dict[str, object]] = report.extra.get("verdict", [])  # type: ignore[assignment]
    out = [
        f"Capture: {printable(report.capture)}",
        "Best guess of what is in it. Scores are heuristic confidence (signature specificity x amount of",
        "evidence), not calibrated probabilities - treat them as a ranking.",
        "",
    ]
    if not verdict:
        out.append("Nothing matched the known signatures (streaming, remote access, IP cameras).")
    pool: Dict[str, List[Flow]] = report.extra.get("_examples", {})  # type: ignore[assignment]
    for e in verdict:
        name = printable(str(e["service"]))
        if e["variants"]:
            name += " (" + ", ".join(sorted(set(map(str, e["variants"])))) + ")"  # type: ignore[arg-type]
        stats = f"{e['hosts']} host(s)" if e["category"] == "ipcam" else (
            f"{e['flows']}{'+' if e.get('truncated') else ''} flow(s), {e['hosts']} source(s), {human_bytes(int(e['bytes']))}"  # type: ignore[arg-type]
        )
        out.append(f"  {str(e['confidence']).upper():<8} {int(float(e['score']) * 100):>3}%  "  # type: ignore[arg-type]
                   f"[{e['category']}] {name} - {stats}")
        if e.get("ambiguous_with"):
            out.append(f"{'':>17}shares a network range with {e['ambiguous_with']}")
        for addr in e.get("addresses", []):  # type: ignore[union-attr]
            out.append(f"{'':>17}{printable(str(addr))}")
        for f in pool.get(str(e["service"]), [])[:examples]:
            out.append(f"{'':>17}e.g. {printable(f.render())}")
    if report.notes:
        out.append("")
        out.extend(f"note: {printable(n)}" for n in report.notes)
    out.append("")
    out.append("Details: run `flowspot streaming|remote|ipcam FILE` for every matching flow, or add --json.")
    return "\n".join(out)


def render_text(report: Report, show_filters: bool) -> str:
    out: List[str] = []
    if report.command == "ipcam":
        x = report.extra

        def block(title: str, items: Sequence[object], fmt: str = "{}") -> None:
            out.append(f"\n{title}")
            if items:
                out.extend(f"  {fmt.format(i)}" for i in items)
            else:
                out.append("  (none)")

        out.append(f"IP-camera analysis of {printable(str(x['net']))}")
        block("Hosts in the top traffic lists (bytes AND bytes/packet)", x["candidates_by_traffic"])  # type: ignore[arg-type]
        block(f"Bulk-data ports (> {BUSY_BPP} bytes/packet), excluded", x["busy_ports"])  # type: ignore[arg-type]
        block("Candidate camera ports", x["camera_ports"], "port {}")  # type: ignore[arg-type]
        block("Hosts talking on those ports", x["candidates_by_port"])  # type: ignore[arg-type]
        block("LIKELY IP CAMERAS (in both host lists)", x["likely_cameras"])  # type: ignore[arg-type]
    else:
        hits = [d for d in report.detections if d.flows]
        for d in hits:
            title = f"{d.service} ({d.variant})" if d.variant else d.service
            out.append(f"\n{printable(title)} - {len(d.flows)}{'+' if d.truncated else ''} flow(s)")
            if show_filters:
                out.append(f"  filter: {printable(d.filter)}")
            out.extend("  " + printable(f.render()) for f in d.flows)
        if not hits:
            out.append(f"No flows matching the {report.command} signatures were found.")
    if report.notes:
        out.append("")
        out.extend(f"note: {printable(n)}" for n in report.notes)
    return "\n".join(out).lstrip("\n")


def render_signatures() -> str:
    out = [
        "Detection signatures (nfdump filter syntax). <...> marks host lists filled in at run time.",
        "specificity = how much a match tells you (0..1), used by the auto-mode score.",
    ]

    def spec_block(specs: Sequence[RuleSpec]) -> None:
        for sp in specs:
            out.append(f"\n[{sp.title}]  specificity {sp.specificity}{CONDITIONS[sp.when]}\n  {sp.describe()}")

    out.append("\n== streaming ==")
    spec_block(STREAMING_SPECS)
    out.append("\n== remote ==")
    spec_block(REMOTE_SPECS)
    out += [
        f"\n[TeamViewer] (three stages)  specificity {STAGED_SPECIFICITY[('TeamViewer', '')]}\n"
        f"  1. {TEAMVIEWER_TCP_FILTER}\n"
        f"  2. {TEAMVIEWER_UDP_FILTER.format(p='<source port from stage 1>')}\n"
        "  3. all flows of the (address, port) pairs found",
        f"\n[Skype] (experimental, --skype)  specificity {STAGED_SPECIFICITY[('Skype', 'experimental')]}\n  {SKYPE_FILTER}",
        "\n== ipcam ==\n"
        "  Computed in Python from all flows inside --net: hosts and ports that are in the top-N by bytes\n"
        f"  AND by bytes/packet, minus ports with > {BUSY_BPP} bytes/packet and minus --ignore-port.",
    ]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def cidr_arg(text: str) -> str:
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid network in CIDR notation: {text!r}") from None


def port_arg(text: str) -> int:
    value = parse_port(text)
    if value is None or value == 0:
        raise argparse.ArgumentTypeError(f"not a valid port (1-65535): {text!r}")
    return value


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError(f"expected a positive integer, got {text!r}")
    return value


def nonneg_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = -1
    if value < 0:
        raise argparse.ArgumentTypeError(f"expected an integer >= 0, got {text!r}")
    return value


def dns_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dns-cache", metavar="FILE", type=lambda t: Path(t).expanduser(),
                   help="JSON file with the DNS answers: used if it exists (no look-ups, reproducible), "
                        "otherwise the live answers are saved there")
    p.add_argument("--refresh-dns", action="store_true",
                   help="look the host names up again and overwrite --dns-cache")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("capture", metavar="FILE", help="nfcapd/nfdump flow file, or a directory of them (read recursively), analysed read-only")
    g = common.add_argument_group("common options")
    g.add_argument("-j", "--json", action="store_true", help="machine-readable JSON output")
    g.add_argument("-v", "--verbose", action="store_true", help="print the nfdump filters being run (stderr)")
    g.add_argument("--nfdump", metavar="PATH", help="path to the nfdump binary (default: look in PATH)")
    g.add_argument("--timeout", type=positive_int, default=DEFAULT_TIMEOUT, metavar="SEC",
                   help=f"max seconds per nfdump run (default: {DEFAULT_TIMEOUT})")
    g.add_argument("--limit", type=nonneg_int, default=DEFAULT_LIMIT, metavar="N",
                   help=f"max flows listed per detection, 0 = unlimited (default: {DEFAULT_LIMIT})")
    g.add_argument("--jobs", type=positive_int, default=DEFAULT_JOBS, metavar="N",
                   help=f"parallel nfdump processes (default: {DEFAULT_JOBS})")

    parser = argparse.ArgumentParser(
        prog=PROG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Spot streaming, remote-access and IP-camera traffic in NetFlow data (via nfdump).",
        epilog=(
            "examples:\n"
            f"  {PROG} flows.nfcapd                 # no command: try everything, rank the guesses\n"
            f"  {PROG} streaming flows.nfcapd\n"
            f"  {PROG} streaming flows.nfcapd --generic --json | jq '.detections[] | select(.flows|length>0)'\n"
            f"  {PROG} remote flows.nfcapd --skype\n"
            f"  {PROG} ipcam flows.nfcapd --net 192.168.0.0/16 --ignore-port 137 138 445\n"
            f"  {PROG} signatures\n\n"
            "exit status: 0 detected, 1 nothing detected, 2 error\n"
            "requires: Python >= 3.9 and nfdump 1.7.x (https://github.com/phaag/nfdump)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser(
        "auto", parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter,
        help="(default) run everything and guess what the capture contains",
        description="Run all detectors (streaming, remote access, IP cameras) and rank what was found by "
                    "confidence. This is what `flowspot FILE` does when no command is given.",
    )
    p.add_argument("-n", "--net", type=cidr_arg, metavar="CIDR",
                   help="only look for IP cameras in this subnet (default: probe 10/8, 172.16/12, 192.168/16)")
    p.add_argument("-g", "--generic", action="store_true", help="include the generic streaming heuristic")
    p.add_argument("--no-dns", action="store_true", help="do not resolve CDN host names")
    p.add_argument("--skype", action="store_true", help="include the experimental Skype heuristic")
    dns_args(p)
    p.add_argument("--examples", type=int, default=2, metavar="N",
                   help="example flows shown per finding (default: 2)")
    p.set_defaults(func=lambda a, nf: run_auto(nf, a.net, not a.no_dns, a.generic, a.skype, a.dns_cache, a.refresh_dns))

    p = sub.add_parser(
        "streaming", parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter,
        help="find audio/video streaming servers (YouTube, Seznam, nacevi, ...)",
        description="Find streamed audio/video: abradio, grooveshark, iprima, koukni, nacevi/visual "
                    "(ivysilani, voyo, topfun, ...), mixer, play, stream, ulozto/live, youtube, zkouknito.",
    )
    p.add_argument("-g", "--generic", action="store_true",
                   help="also run the generic heuristic (packets > 1000 AND 5 < pps < 800 AND bpp > 1200)")
    p.add_argument("--no-dns", action="store_true",
                   help="do not resolve CDN host names (no network access; fixed ranges only)")
    dns_args(p)
    p.set_defaults(func=lambda a, nf: run_streaming(nf, not a.no_dns, a.generic, a.dns_cache, a.refresh_dns))

    p = sub.add_parser(
        "remote", parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter,
        help="find ssh -X, VNC and TeamViewer (and, experimental Skype)",
        description="Find remote-desktop style traffic: SSH with X11 forwarding, VNC, TeamViewer, Skype.",
    )
    p.add_argument("--skype", action="store_true",
                   help="also run the experimental Skype heuristic (disabled in the original scripts)")
    p.set_defaults(func=lambda a, nf: run_remote(nf, skype=a.skype))

    p = sub.add_parser(
        "ipcam", parents=[common], formatter_class=argparse.RawDescriptionHelpFormatter,
        help="find IP cameras inside a local network",
        description="Find likely IP cameras among the hosts of a subnet by their traffic profile.",
    )
    p.add_argument("-n", "--net", required=True, type=cidr_arg, metavar="CIDR",
                   help="subnet the cameras live in, e.g. 192.168.0.0/16")
    p.add_argument("-p", "--ignore-port", dest="ignore_ports", nargs="+", action="extend", type=port_arg,
                   default=[], metavar="PORT", help="port(s) to exclude, e.g. 137 138 445 (put FILE first)")
    p.add_argument("--top", type=positive_int, default=20, metavar="N",
                   help="size of the top-N lists (default: 20)")
    p.set_defaults(func=lambda a, nf: run_ipcam(nf, a.net, a.ignore_ports, a.top))

    p = sub.add_parser("signatures", help="print all detection signatures (nfdump filters) and exit")
    p.set_defaults(func=None)
    return parser


COMMANDS = ("auto", "streaming", "remote", "ipcam", "signatures")


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        build_parser().print_help(sys.stderr)
        return EXIT_ERROR
    # `flowspot FILE [options]` without a command means `flowspot auto FILE [options]`.
    if argv and argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "auto")
    args = build_parser().parse_args(argv)
    if args.command == "signatures":
        print(render_signatures())
        return EXIT_FOUND
    try:
        log = (lambda msg: print(f"[{PROG}] {msg}", file=sys.stderr)) if args.verbose else None
        nf = NfDump(find_nfdump(args.nfdump), validate_capture(args.capture), args.timeout, log, args.jobs, args.limit)
        report = args.func(args, nf)
    except FlowspotError as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        data = asdict(report)
        data["extra"].pop("_examples", None)
        data["found"] = report.found
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif report.command == "auto":
        print(render_auto(report, args.examples))
    else:
        print(render_text(report, show_filters=args.verbose))
    return EXIT_FOUND if report.found else EXIT_NONE


if __name__ == "__main__":  # pragma: no cover
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. `flowspot ... | head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(EXIT_ERROR)
    except KeyboardInterrupt:
        sys.exit(130)
