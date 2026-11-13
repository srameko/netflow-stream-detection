# flowspot

Spot **streaming**, **remote-access** and **IP-camera** traffic in NetFlow data.

`flowspot` is a single-file, dependency-free Python rewrite of the scripts that accompanied my
thesis (`streaming.pl`, `other.pl`, `ipcam.pl`, 2013). It drives [`nfdump`](https://github.com/phaag/nfdump)
in read-only mode, applies behavioural signatures (packet counts, packets/s, bytes/packet, TCP flags, …)
to the flow records, and reports the matching flows.

```console
$ flowspot streaming flows.nfcapd
ulozto.cz/live - 2 flow(s)
  2013-05-16 10:00:00.000  TCP   93.99.92.7:80 -> 10.0.0.2:50000  flags=...AP... packets=5000 bytes=7000000
...
```

## Requirements

* **Python 3.9 or newer** (standard library only – nothing to `pip install`)
* **nfdump 1.7.x** in `PATH` (or pass `--nfdump /path/to/nfdump`) – tested with 1.7.10; 1.6.x untested
* macOS or Linux (Windows: use WSL)

Details and exactly what was verified: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Install

It is one file. Copy it anywhere:

```bash
curl -O https://raw.githubusercontent.com/srameko/netflow-stream-detection/main/flowspot.py
chmod +x flowspot.py
./flowspot.py --help
```

## Documentation

| | |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | every command and option, output formats, JSON schema, exit codes, examples |
| [docs/DETECTION.md](docs/DETECTION.md) | what each signature looks for and how auto-mode scores are computed |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | supported Python / nfdump / OS versions and what is verified |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | code layout, tests, CI, adding a signature, release |
| [SECURITY.md](SECURITY.md) | security design and how to report a vulnerability |

## Usage

```
flowspot FILE [options]            # = flowspot auto FILE: run everything, rank what was found
                                   # FILE may also be a directory of capture files (read recursively)
flowspot auto       FILE [--net CIDR] [--generic] [--no-dns] [--dns-cache FILE] [--skype] [--examples N]
flowspot streaming  FILE [--generic] [--no-dns] [--dns-cache FILE] [--refresh-dns]
flowspot remote     FILE [--skype]
flowspot ipcam      FILE --net CIDR [--ignore-port PORT ...] [--top N]
flowspot signatures
```

Common options (after the command): `-j/--json`, `-v/--verbose` (print the nfdump filters), `--nfdump PATH`,
`--timeout SEC`, `--jobs N` (parallel nfdump processes, default 4), `--limit N` (flows listed per detection, default 1000, 0 = all). `flowspot COMMAND --help` shows everything.

| Command | What it finds |
|---|---|
| `auto` *(default)* | runs all of the below and ranks the findings by confidence (see next section) |
| `streaming` | abradio, grooveshark, iprima, koukni, nacevi/visual (Czech Television's ivysilani.cz, voyo.cz, topfun.cz, ...), mixer, play.cz, stream.cz, ulozto.cz/live, YouTube (live/html5/https/http), zkouknito; optional generic heuristic (`--generic`) |
| `remote` | `ssh -X` (X11 forwarding), VNC, TeamViewer; experimental Skype (`--skype`) |
| `ipcam` | likely IP cameras inside a subnet, from traffic profile (top hosts/ports by volume *and* bytes/packet, minus bulk-data ports) |
| `signatures` | prints every nfdump filter the tool uses – nothing is hidden |

### Auto mode: what is in this capture?

`flowspot FILE` runs every detector (streaming, remote access, IP cameras – the latter probed in
10/8, 172.16/12 and 192.168/16 unless you pass `--net`) and prints a ranked list of guesses.

Each guess gets a **score 0–100 %** = *signature specificity* × *amount of evidence*:

* **specificity** – how much a match tells you. A rule tied to one service's own network range plus
  behaviour limits is strong (0.85); a shared prefix, a well-known port or pure traffic shape is weak
  (e.g. YouTube ranges 0.7, `ssh -X` 0.6, generic heuristic 0.35).
* **evidence** – saturating in the number of matching flows: 1 flow ≈ 28 %, 3 ≈ 63 %, 10 ≈ 96 %.
* services that share a network range (abradio/zkouknito, Voyo/nacevi) are marked ambiguous and slightly penalised.

Labels: **likely** ≥ 60 %, **possible** ≥ 30 %, **weak** below. **These are heuristic scores, not calibrated
probabilities** – they rank, they don't prove. The numbers live in `SPECIFICITY` in `flowspot.py`; change
them if your data says otherwise. `--json` gives the full `verdict` list under `extra`.

### Examples

```bash
flowspot streaming flows.nfcapd
flowspot streaming flows.nfcapd --generic --no-dns
flowspot remote    flows.nfcapd --skype -v
flowspot ipcam     flows.nfcapd --net 192.168.0.0/16 --ignore-port 137 138 445
flowspot streaming flows.nfcapd --json | jq '.detections[] | select(.flows | length > 0) | .service'
```

### Exit status

| Code | Meaning |
|---|---|
| 0 | something was detected |
| 1 | nothing detected |
| 2 | error (bad input, nfdump missing/failing, timeout) |

Handy in scripts: `flowspot remote today.nfcapd && notify-send "remote access seen"`.

### JSON output

```json
{
  "command": "remote",
  "capture": "/data/flows.nfcapd",
  "detections": [
    {"service": "VNC", "variant": "", "filter": "port 5900 AND ...",
     "flows": [{"start": "...", "proto": "TCP", "src": "10.0.0.5", "sport": 40000,
                "dst": "10.0.0.9", "dport": 5900, "flags": "...AP...", "packets": 500, "bytes": 50000, "end": "..."}]}
  ],
  "notes": [],
  "extra": {},
  "found": true
}
```

`ipcam` puts its lists in `extra` (`candidates_by_traffic`, `busy_ports`, `camera_ports`,
`candidates_by_port`, `likely_cameras`).

## How it works

1. `flowspot` builds an nfdump filter per service (see [docs/DETECTION.md](docs/DETECTION.md) or `flowspot signatures`).
2. It runs `nfdump -r FILE -q -N -o fmt:<columns> '<filter>'` (several in parallel) and parses the comma-separated
   output into flow records. Records are shown as exported, in the direction that matched.
3. Some detections are multi-stage (TeamViewer, Seznam CDN, ipcam): results of one query become validated input to the next.
4. A failing stage is reported as a note and the others still run; only if *everything* fails is it an error.
   (nfdump exits 0 on a corrupt file; `flowspot` notices the diagnostics and reports an error instead of "nothing found".)
5. Matches are printed as text or JSON; `auto` additionally scores and ranks them.

## Security model

The original Perl scripts built shell command lines by string interpolation
(`` `nfdump -r $pth "..."` ``), so a crafted file name meant command execution. This version is designed
to be safe to point at untrusted file names and untrusted capture contents:

* **No shell, ever.** nfdump is started with an argument vector (`subprocess.run([...])`), no `shell=True`,
  no `host | cut | grep` pipelines. The capture path is resolved to an absolute path so it can't be read as an option.
* **Validated inputs.** `--net` must parse as a CIDR network, ports as 1–65535, numbers as positive integers.
* **Validated data flowing back into filters.** IPs and ports parsed from nfdump output are re-parsed with
  `ipaddress`/`int` before being reused in a second-stage filter, so capture contents can't inject filter syntax.
* **Read-only.** Never writes to the capture; the only file it can write is the optional DNS cache you ask for. Minimal environment for nfdump (`PATH`, `LC_ALL=C`, `TZ`).
* **Bounded.** Per-run timeout (`--timeout`), filter size cap (stays below Linux's 128 KiB per-argument limit),
  DNS look-ups under one 5 s deadline in daemon threads.
* **Terminal-safe output.** Control characters are stripped from everything printed.
* **Network access: DNS only**, for a fixed list of public CDN host names, and only for `streaming`.
  `--no-dns` removes even that. The only file ever written is the optional `--dns-cache` (atomic, validated on read). No telemetry, no downloads, no third-party Python packages.

Report vulnerabilities privately – see [SECURITY.md](SECURITY.md).

## Limitations — please read

* **The signatures are from 2013.** They encode what those services looked like on the wire in a specific
  Czech network at that time. Grooveshark shut down in 2015; most streaming is now HTTPS/QUIC with CDN
  addresses that change constantly. Treat results as leads, expect false positives *and* misses on modern traffic.
  The tool is most meaningful for the data set the thesis worked with, as a teaching/reference implementation
  of behaviour-based flow classification, and as a starting point for new signatures.
* **DNS is resolved at analysis time**, not capture time, so host-name based rules may differ from what was
  valid when the flows were recorded. Fixed network ranges are unaffected. The answers used are always recorded in
  the report (`extra.dns`); `--dns-cache FILE` pins them so a run can be reproduced exactly.
* **Tested with nfdump 1.7.x.** The functional tests run the real binary on a capture produced by a real
  `nfcapd` from synthetic NetFlow v5 (and check that *every* shipped filter is valid nfdump syntax); CI runs them
  with the distribution's nfdump. The signatures were written for nfdump 1.6; older releases may differ – open an issue.
* **Scores are not probabilities** (see *Auto mode*).
* `--limit` bounds the *listed* flows only; the `ipcam` statistics and the TeamViewer/Skype stages still read all
  matching records into memory, so analyse very large captures in time slices.
* **Small captures give noisy `ipcam` results**: with few hosts, every host is "top-N", so chatty services on
  low ports can look like cameras.
* IPv4-oriented: DNS resolution is IPv4 only; the signatures are IPv4 prefixes.

## Differences from the Perl originals

* One tool with sub-commands instead of three scripts; `FILE` is positional; `flowspot FILE` guesses.
* No `-B` (bidirectional merge): it swapped source and destination in the listing and changed per-record
  byte/packet statistics that the `ipcam` heuristic relies on.
* All queries use a fixed column layout parsed in Python – no `cut -c 30-60` screen-scraping – and output is
  an aligned list or JSON instead of raw nfdump lines.
* `ipcam`: top-N statistics are computed in Python from one nfdump pass (previously: parsing `-s ip/bytes`
  output with `cut`/`grep`). Ties in the top-N may therefore be broken differently than nfdump would.
* Unresolvable host names are skipped (the original emitted malformed filters such as `src ip `).
* Skype detection, commented out in the original, is opt-in (`--skype`); its filter's `OR`/`AND`
  precedence was fixed so the "local network" group is parenthesised.
* TeamViewer: queries are skipped when a stage yields nothing (the original could end up with an empty filter,
  which nfdump treats as "match everything").
* The generic heuristic uses the values the code always used (`packets > 1000 AND 5 < pps < 800 AND bpp > 1200`);
  the old help text quoted different numbers.
* Exit codes replace `die` messages.

## Development

```bash
python3 -m unittest discover -s tests -v
```

* `tests/test_flowspot.py` – unit tests (≈ 99 % line coverage). A tiny fake `nfdump` replays canned output, so
  they need neither nfdump nor network.
* `tests/test_functional.py` – end-to-end: `tests/make_capture.py` sends synthetic NetFlow v5 to a loopback
  `nfcapd`, then the real command line runs against the real capture (hostile file names, corrupt files,
  every filter's syntax, ranking, JSON). Skipped automatically when `nfdump`/`nfcapd` are not installed
  (`apt install nfdump` / `brew install nfdump`).
* CI (`.github/workflows/ci.yml`): Python 3.9/3.11/3.13 with real nfdump, plus a `zizmor` lint of the workflow.
  Actions are pinned to commit SHAs, permissions are minimal, Dependabot keeps the pins fresh.

## License

GNU GPL v2 (as the original scripts) – see [LICENSE](LICENSE).
