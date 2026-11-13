# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's *Security → Report a vulnerability* (private
security advisory) on this repository. Do not open a public issue. Include the flowspot version
(`flowspot --version`), nfdump version and, if possible, a minimal capture or command line.

## Design

`flowspot` is meant to be safe to run on untrusted file names and untrusted capture contents:

* nfdump is started with an argument vector – never through a shell; the capture path is made absolute;
* user input is validated (CIDR, ports, integers); values parsed from nfdump output are re-validated as IP
  addresses / port numbers before they are used in a second-stage filter;
* the capture is only read, never written; the one file flowspot can write is the optional `--dns-cache`, which is
  written atomically via a temp file + rename (so a symlink at that path is replaced, never followed) and is validated
  strictly when read back (JSON structure, IPv4 addresses only, size cap) because it feeds addresses into filters;
* nfdump gets a minimal environment;
* bounded: per-run timeout, filter-size cap, DNS under one deadline in daemon threads;
* output is stripped of control characters;
* the only network access is optional DNS for a fixed list of public host names (`--no-dns` disables it);
* no third-party runtime dependencies, no telemetry.

Out of scope: vulnerabilities in nfdump itself (report those to the nfdump project), and the accuracy of the
traffic signatures (a false positive/negative is a bug, not a vulnerability).
