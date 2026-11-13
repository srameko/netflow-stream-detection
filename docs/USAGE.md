# Usage reference

```
flowspot FILE [options]              # same as: flowspot auto FILE [options]
flowspot auto       FILE [-n CIDR] [-g] [--no-dns] [--skype] [--examples N]
flowspot streaming  FILE [-g] [--no-dns]
flowspot remote     FILE [--skype]
flowspot ipcam      FILE -n CIDR [-p PORT [PORT ...]] [--top N]
flowspot signatures
flowspot --version | --help
```

`FILE` is an nfcapd/nfdump flow file **or a directory** of them (read recursively with `nfdump -R`; all files are
analysed together as one capture). Everything is read-only. Options of a command go **after** the command name.
`flowspot COMMAND --help` prints the authoritative help. Run with no arguments to get the help text (exit 2).

## Common options (all commands except `signatures`)

| Option | Meaning |
|---|---|
| `-j`, `--json` | print JSON instead of text |
| `-v`, `--verbose` | print every nfdump filter to stderr; with `streaming`/`remote` also in the text output |
| `--nfdump PATH` | nfdump binary to use (default: first `nfdump` in `PATH`) |
| `--timeout SEC` | max seconds per nfdump run, default 300 |
| `--jobs N` | parallel nfdump processes, default 4 |
| `--limit N` | list at most N flows per detection, default 1000; `0` = unlimited. Bounds memory on huge captures (nfdump stops after N+1 records). A cut-off list is marked `N+ flow(s)`, has `"truncated": true` in JSON and a note |

## Commands

### `auto` (default)

Runs `streaming`, `remote` and `ipcam` and prints a ranked list of guesses with a score (0–100 %),
a label (`likely` ≥ 60 %, `possible` ≥ 30 %, `weak`) and example flows. See *Auto mode* in the README
for how the score is computed – it is a heuristic ranking, not a probability.

| Option | Meaning |
|---|---|
| `-n`, `--net CIDR` | look for IP cameras only in this subnet (default: probe 10/8, 172.16/12, 192.168/16) |
| `-g`, `--generic` | include the generic streaming heuristic |
| `--no-dns` | do not resolve CDN host names |
| `--dns-cache FILE`, `--refresh-dns` | see *DNS answers* below |
| `--skype` | include the experimental Skype heuristic |
| `--examples N` | example flows per finding in text output, default 2 |

### `streaming`

abradio, grooveshark, iprima, koukni, nacevi/visual (Czech Television's ivysilani.cz, voyo.cz, topfun.cz, ...),
mixer, play.cz, stream.cz, ulozto.cz/live, YouTube (live/html5/https/http), zkouknito. These are Czech brand
names used as identifiers - see *Service names* in [DETECTION.md](DETECTION.md).

| Option | Meaning |
|---|---|
| `-g`, `--generic` | also run `packets > 1000 AND pps > 5 AND pps < 800 AND bpp > 1200` |
| `--no-dns` | skip DNS look-ups of CDN host names (the only network access the tool ever makes) |
| `--dns-cache FILE` | use the DNS answers stored in FILE if it exists, otherwise save the live answers there |
| `--refresh-dns` | look the names up again and overwrite the cache (not with `--no-dns`) |

### `remote`

`ssh -X`, VNC, TeamViewer; with `--skype` also the experimental Skype heuristic.

### `ipcam`

| Option | Meaning |
|---|---|
| `-n`, `--net CIDR` | **required**, subnet the cameras live in, e.g. `192.168.0.0/16` (host bits are normalised) |
| `-p`, `--ignore-port PORT ...` | ports to exclude (e.g. NetBIOS/SMB `137 138 445`); give `FILE` first, the list is greedy |
| `--top N` | size of the top-N lists, default 20 |

### `signatures`

Prints every detection signature as an nfdump filter. Needs no nfdump and no file.

## DNS answers (reproducibility)

Some streaming signatures use host names (Grooveshark, nacevi/visual, Seznam CDN dispatchers; 42 names in
total). Their addresses change over time, so an answer looked up *today* may not describe a capture from *last
year*. `flowspot` therefore records what it used:

* every run that resolved or loaded names has `extra.dns` in the JSON: `source` (`live` | `cache` | `none`),
  `resolved_at` (UTC), `hosts` (name → addresses; `[]` = did not resolve) and `cache` (path);
* the text output says whether answers were live or cached;
* `--dns-cache FILE` makes it permanent: if FILE exists its answers are used and **no look-up is made**
  (it also works with `--no-dns`, which only forbids network access); if it does not exist the live answers are
  saved there. Keep the file next to the capture, or build it once from DNS history, and the analysis stays
  reproducible. `--refresh-dns` re-resolves and overwrites it.

Cache file format (version 1, plain JSON, validated strictly when loaded – IPv4 addresses only, max 1 MB):

```json
{ "version": 1, "resolved_at": "2026-11-13T19:00:00Z",
  "hosts": { "x.cdn0.grooveshark.com": ["203.0.113.7"], "wcdn20.nacevi.cz": [] } }
```

It is written atomically (temp file + rename, never through a symlink). This is the only file `flowspot` ever writes,
and only when you pass `--dns-cache`.

## Exit status

| Code | Meaning |
|---|---|
| 0 | something was detected (`signatures`/`--help`/`--version`: success) |
| 1 | nothing detected |
| 2 | error: bad arguments, file not found/unreadable/corrupt, nfdump missing or failing, every stage failed |
| 130 | interrupted (Ctrl-C) |

A single failing stage (e.g. one filter too large) is **not** an error: it appears as `note: <stage>: skipped (...)`
and the other stages still report.

## Output

### Text

`streaming`/`remote` list each service that matched with its flows:

```
ulozto.cz/live - 3 flow(s)
  2023-11-14 22:56:40.000  TCP   93.99.92.1:80 -> 10.0.0.2:50001  flags=...AP... packets=5000 bytes=7500000
```

Flags use the letters `CEUAPRSF` (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN; `.` = not set). Records are shown as exported by the router, i.e. in the direction
that matched the signature. Control characters are stripped from everything printed.

### JSON (`--json`)

```jsonc
{
  "command": "auto",                  // auto | streaming | remote | ipcam
  "capture": "/data/flows.nfcapd",    // absolute path
  "detections": [                     // streaming/remote/auto; empty for ipcam
    {
      "service": "ulozto.cz/live",
      "variant": "",                  // e.g. "html5", "player", "X11 forwarding"
      "category": "streaming",        // streaming | remote
      "filter": "src net 93.99.92.0/24 AND ...",   // exact nfdump filter used
      "truncated": false,             // true when more flows matched than --limit
      "flows": [ { "start": "...", "end": "...", "proto": "TCP", "src": "93.99.92.1", "sport": 80,
                   "dst": "10.0.0.2", "dport": 50001, "flags": "...AP...", "packets": 5000, "bytes": 7500000 } ]
    }
  ],
  "notes": ["DNS look-ups disabled (--no-dns): ..."],   // warnings, skipped stages
  "extra": {
    // ipcam: net, candidates_by_traffic, busy_ports, camera_ports, candidates_by_port, likely_cameras
    // auto:  cameras {net: {...as above}}, likely_cameras [...], verdict [...]
    // streaming/auto: dns {source, resolved_at, hosts, cache}
  },
  "found": true                       // same as exit status 0
}
```

`extra.verdict[]` (auto): `service`, `category` (`streaming|remote|ipcam`), `score` (0–1), `confidence`
(`likely|possible|weak`), `variants`, `flows`, `hosts` (distinct source addresses), `bytes`; optionally
`ambiguous_with` (shares a network range with another service) and `addresses` (cameras); `truncated` is true
when the flow count was cut off by `--limit`.

## Examples

```bash
flowspot flows.nfcapd                                  # what is in here?
flowspot flows.nfcapd --net 192.168.10.0/24 --examples 5
flowspot streaming flows.nfcapd --no-dns -v            # no network, shows the filters
flowspot streaming flows.nfcapd --dns-cache flows.dns.json   # pin DNS answers for reproducibility
flowspot /data/nfsen/profiles-data/live/gate/2026/11/   # a whole directory tree of captures
flowspot flows.nfcapd --limit 50                       # at most 50 flows per detection
flowspot remote flows.nfcapd --skype --json | jq '.detections[] | select(.flows|length>0) | .service'
flowspot ipcam flows.nfcapd -n 192.168.0.0/16 -p 137 138 445
flowspot flows.nfcapd --json > report.json; echo $?    # 0 found, 1 nothing, 2 error
for f in /data/nfcapd.*; do flowspot "$f" --json > "$(basename "$f").json"; done
```

## Environment

nfdump is started with a minimal environment: `PATH`, `LC_ALL=C` and, if set, `TZ` (timestamps are printed in
that time zone; set `TZ=UTC` for reproducible output). No other variables are read.
