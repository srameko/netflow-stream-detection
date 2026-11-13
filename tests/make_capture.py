"""Build a *real* nfcapd capture from synthetic NetFlow v5 records.

Used by the functional tests (and runnable by hand):

    python3 tests/make_capture.py OUT_DIR   # prints the path of the nfcapd file

It starts ``nfcapd`` on a loopback UDP port, sends hand-made NetFlow v5 packets
for a handful of scenarios (see SCENARIOS) and lets nfcapd write the file.
Requires ``nfcapd`` in PATH.  Nothing leaves the loopback interface.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import List, NamedTuple, Optional

ACK, PSH, SYN, FIN = 0x10, 0x08, 0x02, 0x01
TCP, UDP = 6, 17
BASE_MS = 0  # all flows start at the same router uptime


class V5Flow(NamedTuple):
    src: str
    sport: int
    dst: str
    dport: int
    proto: int
    packets: int
    octets: int
    duration_ms: int
    flags: int = ACK | PSH


def flows() -> List[V5Flow]:
    f: List[V5Flow] = []
    # ulozto.cz/live (a Czech streaming service): server 93.99.92.0/24, 200 pps, 1500 bytes/packet
    for i in range(1, 4):
        f.append(V5Flow(f"93.99.92.{i}", 80, "10.0.0.2", 50000 + i, TCP, 5000, 7_500_000, 25_000))
    # VNC
    f.append(V5Flow("10.0.0.5", 40000, "10.0.0.9", 5900, TCP, 1000, 400_000, 20_000))
    # ssh -X (APS, no FIN, 150 pps, 200 bytes/packet)
    f.append(V5Flow("10.0.0.5", 50000, "10.0.0.20", 22, TCP, 3000, 600_000, 20_000, ACK | PSH | SYN))
    # YouTube html5 profile: Google range, APSF, 50 pps, 1500 bytes/packet
    f.append(V5Flow("74.125.1.1", 443, "10.0.0.2", 51000, TCP, 2000, 3_000_000, 40_000, ACK | PSH | SYN | FIN))
    # TeamViewer: tiny 4-packet TCP exchange, then 124-byte UDP datagram on the same port
    f.append(V5Flow("10.0.0.5", 41000, "178.77.120.1", 5938, TCP, 4, 520, 200))
    f.append(V5Flow("10.0.0.5", 41000, "178.77.120.2", 5938, UDP, 1, 124, 0, 0))
    # IP camera 192.168.1.50 streams to a viewer; a NAS moves bulk data on 445; some chatter
    f.append(V5Flow("192.168.1.50", 554, "192.168.1.9", 40000, TCP, 1000, 1_000_000, 10_000))
    f.append(V5Flow("192.168.1.50", 554, "192.168.1.9", 40001, TCP, 1000, 900_000, 10_000))
    f.append(V5Flow("192.168.1.7", 445, "192.168.1.9", 40002, TCP, 1000, 3_000_000, 10_000))
    f.append(V5Flow("192.168.1.8", 5353, "192.168.1.9", 5353, UDP, 2, 200, 100, 0))
    return f


def v5_packet(records: List[V5Flow], seq: int) -> bytes:
    header = struct.pack(">HHIIIIBBH", 5, len(records), 1_000_000, 1_700_000_000, 0, seq, 0, 0, 0)
    body = b""
    for r in records:
        first = BASE_MS
        last = BASE_MS + r.duration_ms
        body += struct.pack(
            ">4s4s4sHHIIIIHHBBBBHHBBH",
            socket.inet_aton(r.src), socket.inet_aton(r.dst), socket.inet_aton("0.0.0.0"),
            0, 0, r.packets, r.octets, first, last, r.sport, r.dport, 0, r.flags, r.proto, 0, 0, 0, 24, 24, 0,
        )
    return header + body


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build(out_dir: Path, nfcapd: Optional[str] = None) -> Path:
    nfcapd = nfcapd or shutil.which("nfcapd")
    if not nfcapd:
        raise RuntimeError("nfcapd not found in PATH")
    out_dir.mkdir(parents=True, exist_ok=True)
    port = free_udp_port()
    proc = subprocess.Popen(
        [nfcapd, "-b", "127.0.0.1", "-p", str(port), "-l", str(out_dir), "-I", "flowspot-test"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        if proc.poll() is not None:
            raise RuntimeError(f"nfcapd exited early with status {proc.returncode}")
        records = flows()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            seq = 0
            for i in range(0, len(records), 5):  # v5 allows up to 30 records per packet
                chunk = records[i:i + 5]
                s.sendto(v5_packet(chunk, seq), ("127.0.0.1", port))
                seq += len(chunk)
        time.sleep(1.0)
    finally:
        proc.send_signal(signal.SIGTERM)  # nfcapd flushes and closes the current file on SIGTERM
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    files = sorted(p for p in out_dir.iterdir() if p.name.startswith("nfcapd.") and "current" not in p.name)
    if not files:
        files = sorted(out_dir.glob("nfcapd.*"))
    if not files:
        raise RuntimeError(f"nfcapd produced no file in {out_dir}")
    return files[-1]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(build(Path(sys.argv[1])))
