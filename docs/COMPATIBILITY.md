# Compatibility

## Summary

| Component | Supported | Notes |
|---|---|---|
| **Python** | **3.9 or newer** | standard library only – no `pip install` |
| **nfdump** | **1.7.x** (tested with 1.7.10) | 1.6.x is expected to work but is **not tested** |
| **OS** | macOS, Linux | anything with Python 3.9+ and nfdump. Windows is not supported |
| **Input** | any file nfdump can read (`nfcapd.*`), or a directory tree of them | NetFlow v5/v9, IPFIX, sFlow – whatever your collector wrote |
| **Traffic** | IPv4 | the signatures are IPv4 prefixes; DNS look-ups are IPv4 only |

## What was actually verified

Verified by running the full test suite (119 tests: unit + end-to-end against a real `nfdump`, ~99 % line coverage):

| Python | nfdump | OS | Result |
|---|---|---|---|
| 3.9.25 | 1.7.10 | macOS 26 (arm64) | ✅ pass |
| 3.11, 3.12, 3.14, 3.15 | 1.7.10 | macOS 26 (arm64) | ✅ pass |

Verified by CI (GitHub Actions, real `nfdump` from the Ubuntu package, 119 tests per job):

| Python | OS | Result |
|---|---|---|
| 3.9, 3.11, 3.13 | Ubuntu 24.04 | ✅ pass |
| 3.13 | `ubuntu-latest` (currently Ubuntu 26.04) | ✅ pass |

The matrix is pinned to Ubuntu 24.04 because Python 3.9 is not provided for newer runner images.

## Python

* Minimum: **3.9**. A static analysis of the code (`vermin`) finds nothing newer than 3.7 in syntax and
  standard-library use; `argparse`'s `extend` action raises the real floor to 3.8. Python 3.8 is end-of-life,
  untested and not supported, 3.9 is the lowest version that is tested.
* Used from the standard library: `argparse`, `ipaddress`, `subprocess`, `socket`, `threading`,
  `concurrent.futures`, `dataclasses`, `json`, `pathlib`, `shutil`, `collections`, `math`.
* No third-party runtime dependencies. Optional development tools (not required): `coverage`, `zizmor`.

## nfdump

`flowspot` calls `nfdump -r FILE -q -N -o fmt:<columns> '<filter>'` and nothing else. It relies on:

* options `-r` / `-R` (file / directory, recursive), `-c` (record limit), `-q` (quiet), `-N` (plain numbers), `-o fmt:` with the columns
  `%ts %te %pr %sa %sp %da %dp %flg %pkt %byt`;
* filter keywords `net`, `ip`, `port`, `proto`, `flags`, `packets`, `bytes`, `bpp`, `pps`, `bps`, `duration`,
  `src`/`dst`, `AND`/`OR`/`not` and parentheses.

Behaviour of nfdump 1.7.10 that the code accounts for (found by testing against the real binary):

* with `-N`, protocols and TCP flags are printed as **numbers** by the Homebrew build but as **letters** by the
  Ubuntu build → both are normalised to `TCP`/`UDP` and the 8-letter flag form `...AP...` (found by CI on Ubuntu);
* `No matching flows` is printed on **stdout** even with `-q`;
* an unreadable or corrupt file makes nfdump print a diagnostic on stderr but **exit 0** → reported as an error,
  not as "nothing found".

If your nfdump prints something different, `flowspot -v ...` shows the exact filters, and
`python3 -m unittest tests.test_functional` checks every shipped filter against your binary.

## Operating systems

* **macOS** – tested (Apple silicon, `brew install nfdump`).
* **Linux** – should work (`apt install nfdump`, or build from <https://github.com/phaag/nfdump>); covered by CI.
* **Windows** – not supported: nfdump is not available natively, and the tests use POSIX file modes.
  WSL works as Linux.

## Not supported / out of scope

* IPv6 detection (the signatures are IPv4 ranges).
* Live capture – `flowspot` analyses stored files only.
