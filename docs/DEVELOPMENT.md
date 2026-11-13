# Development

## Layout

```
flowspot.py              the whole tool (single file, standard library only)
tests/test_flowspot.py   unit tests (fake nfdump)            ~99 % line coverage
tests/test_functional.py end-to-end tests with a real nfdump  (skipped if nfdump/nfcapd are missing)
tests/make_capture.py    builds a real nfcapd capture from synthetic NetFlow v5 (also runnable by hand)
docs/                    USAGE, COMPATIBILITY, DETECTION, DEVELOPMENT
.github/workflows/ci.yml tests on Python 3.9/3.11/3.13 + zizmor lint of the workflow
```

Sections inside `flowspot.py`, top to bottom: helpers → data model (`Flow`, `Rule`, `Detection`, `Report`) →
nfdump runner (`NfDump`, `gather`) → DNS → signatures: streaming / remote / ipcam → auto mode (`assess`,
`run_auto`) → output → CLI (`build_parser`, `main`).

## Running the tests

```bash
python3 -m unittest discover -s tests -v          # everything
python3 -m unittest tests.test_flowspot           # unit tests only, no nfdump needed
python3 -m unittest tests.test_functional         # needs nfdump + nfcapd in PATH
```

Install nfdump with `brew install nfdump` or `apt install nfdump`.

Coverage (optional, not a dependency):

```bash
python3 -m venv /tmp/venv && /tmp/venv/bin/pip install coverage
/tmp/venv/bin/coverage run --include=flowspot.py -m unittest discover -s tests
/tmp/venv/bin/coverage report -m
```

### How the functional tests work

`make_capture.py` starts `nfcapd` on a free loopback UDP port, sends hand-built NetFlow v5 packets that imitate
each scenario (ulozto.cz stream, VNC, ssh -X, YouTube, TeamViewer, an IP camera with a NAS and chatter), stops
`nfcapd` with SIGTERM and returns the resulting file. The tests then run `python flowspot.py ...` as a subprocess
against it. They also feed **every filter the tool can generate** to the real nfdump to prove the syntax is valid.
Nothing leaves the loopback interface.

## Adding or changing a signature

1. Streaming service: add an `add("service", "variant", "<nfdump filter>")` line in `streaming_rules()`
   (constants for networks/hosts live above it). Remote: `run_remote()`. Camera heuristic: `run_ipcam()`.
2. If the rule is weaker or stronger than the default, add it to `SPECIFICITY` (auto-mode score, 0..1).
3. Add a scenario to `tests/make_capture.py` and an assertion to `tests/test_functional.py`; the
   "all signatures are accepted by nfdump" test picks the new filter up automatically.
4. Describe it in `docs/DETECTION.md`.

Rules of thumb: only put validated values (IPs through `ipaddress`, ints) into filters; never build a shell command;
keep each filter parenthesised (`any_of`) – nfdump's `AND` binds tighter than `OR`.

## CI and supply chain

* Every action is pinned to a full commit SHA with the version in a comment; Dependabot proposes updates weekly.
* Workflow permissions are `{}` by default, `contents: read` per job; checkout uses `persist-credentials: false`.
* `step-security/harden-runner` runs in `audit` mode; move to `block` with an allow-list once a baseline exists.
* `zizmor --pedantic .github/workflows/` runs in CI; run it locally before changing a workflow.
* To refresh a pin: `gh api repos/OWNER/REPO/git/ref/tags/TAG --jq .object.sha` (dereference annotated tags).

## Release checklist

1. Tests green on CI; bump `__version__` in `flowspot.py`.
2. `python3 flowspot.py --version`, tag `vX.Y.Z`.
3. Attach `flowspot.py` to the GitHub release (it is the only artefact).
