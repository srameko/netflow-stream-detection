# Detection signatures

Run `flowspot signatures` for the exact, current filters. This page explains the *ideas*.
The rationale below is read off the filters themselves; extend it with the reasoning from the thesis text.

Flow metrics used (nfdump names): `packets`, `bytes`, `bpp` (bytes per packet), `pps` (packets per second),
`bps`, `duration` (ms), TCP `flags`, `port`, `net`/`ip`.

## Service names

The streaming signatures were written for the **Czech** network the thesis analysed, so the service names
below are Czech brand names. They are identifiers (they appear in output and JSON) and are deliberately not
translated; this is what they are (brief, approximate):

| Identifier | What it is |
|---|---|
| `abradio.cz`, `play.cz` | Czech internet radio / audio streaming |
| `grooveshark.com` | music streaming service (US), shut down in 2015 |
| `play.prima.cz` | video portal of the Czech TV channel Prima |
| `koukni.cz`, `zkouknito.cz` | Czech video-sharing sites |
| `nacevi/visual` | CDN used by several Czech TV portals (Czech Television's iVysilani, TopFun, ...) |
| `voyo.cz` | video-on-demand of the Czech TV channel Nova |
| `mixer.cz`, `stream.cz`, `seznam.cz` | video/music services of the Czech portal Seznam |
| `ulozto.cz/live` | Czech file-hosting site, live video streaming |
| `youtube.com` | YouTube (all Google network ranges) |

## Streaming (`flowspot streaming`)

Streaming media is long-lived, server→client, bulk: **large packets** (`bpp` > ~1300–1400, i.e. near-MTU),
**steady rate** (`pps` in a band) and **many packets**. Each service adds *where* (network ranges / CDN hosts)
and service-specific limits.

| Service | Idea |
|---|---|
| abradio.cz | fixed prefix; few packets = web page, many packets + low pps = player stream |
| grooveshark.com | CDN host names resolved via DNS + prefix with large packets |
| play.prima.cz | two prefixes, large packets from server |
| koukni.cz | one prefix, > 1000 packets, large packets |
| nacevi/visual (Czech Television's ivysilani.cz, voyo.cz, topfun.cz, ...) | CDN host list + prefixes; Voyo = the Nova prefixes alone |
| mixer.cz / stream.cz | Seznam CDN *dispatchers* seen in the capture (then large-packet flows from those hosts / prefixes; stream.cz needs `bpp > 1200`, mixer.cz `> 1000`) |
| seznam.cz live | used when no dispatcher is seen: Seznam prefixes, long flows (`duration > 30 s`), 50–150 pps |
| play.cz | one prefix; low pps = web, high pps = player |
| ulozto.cz/live | one prefix, 100–600 pps, large packets |
| zkouknito.cz | prefix shared with abradio.cz, `pps > 60` |
| YouTube | all Google prefixes; four profiles (live, html5, https, http) built from: large-packet bursts with `APSF` flags, small-packet constant-rate flows with `pps = 0`, and HTTPS flows; flows with typical short-lived durations are excluded |
| generic (`--generic`) | any server with `packets > 1000`, `5 < pps < 800`, `bpp > 1200` |

## Remote access (`flowspot remote`)

| Service | Idea |
|---|---|
| ssh -X | port 22 flows that look interactive-but-heavy: many packets, `PSH/ACK` flags, high pps – X11 forwarding sends a constant stream of small updates, unlike a shell or scp |
| VNC | TCP port 5900, 3–150 pps |
| TeamViewer | stage 1: tiny 4-packet TCP exchanges (440–620 bytes) reveal client ports; stage 2: 124-byte UDP datagrams on those ports; stage 3: all flows of the (address, port) pairs found |
| Skype *(experimental)* | inbound UDP to local hosts with very low rate and small packets, repeated (address, port) pairs, plus small TCP 80/443 ACK flows and Microsoft's 157.56.0.0/16 |

## IP cameras (`flowspot ipcam`)

IP cameras push a continuous stream of mid-size packets to a recorder/viewer in the same subnet.

1. Take all flows with both endpoints in `--net`.
2. Hosts that are in the top-N by **total bytes** *and* by **bytes per packet** → candidates by traffic.
3. Ports that are in both top-N lists (only 10–9999), minus ports whose flows average > 2000 bytes/packet
   (file transfers, backups: *not* cameras) and minus `--ignore-port` (e.g. NetBIOS/SMB `137 138 445`).
4. Hosts talking on those ports → candidates by port.
5. **Likely cameras = intersection** of both host lists.

## Adding or changing a signature

All signatures live in `flowspot.py` as constants and in `streaming_rules()` / `run_remote()`. A rule is
just an nfdump filter string, so a new streaming service is a one-line `add(...)` call plus a test in
`tests/test_flowspot.py` that checks the filter is produced.

## Auto mode scoring

`flowspot FILE` multiplies a per-signature *specificity* (0..1, table `SPECIFICITY` in `flowspot.py`) by a
saturating *evidence* term `1 - exp(-flows/3)` (cameras: `1 - exp(-hosts/2)`), merges variants of one service
(e.g. the four YouTube profiles), and sorts. Shared-prefix pairs get a 0.85 factor. ≥ 0.6 is *likely*,
≥ 0.3 *possible*. The weights are judgement calls, not fitted to data – adjust them to your network.
