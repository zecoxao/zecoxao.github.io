# netctrl (Poopsploit) — self-hosting the exploit site

Client-side files for the PS5 browser jailbreak, firmware **09.00–12.70**. The
WebKit stage is shared; the kernel stage uses one of three bugs depending on the
firmware (see *Firmware window* below). Tested on a 10.00 devkit and a 12.00
console. This is the browser payload only — you supply the server (DNS spoof +
HTTPS + a beacon sink).

## Files
- `netctrl.html` — entry page. The console loads this and runs the chain.
- `netctrl-ps5.js` — the exploit (race + jailbreak + elfldr loader).
- `rop-worker.js`, `rop_slave.js` — the sacrificial-Worker ROP runner.
- `lapse-runtime.js` — slopkit2 WebKit runtime (offsets, primitives).
- `offsets/` — per-firmware offset tables (slopkit).
- `lapse-ps5.js` — the 09.00–10.01 kernel route (aio double free).
- `elfldr-ps5-1360.elf` — the ELF loader payload written into the console.
  Despite the name this is **not** a 13.60-only build: it selects its own kernel
  offsets at runtime from an internal firmware switch covering 1.00–13.60, so
  the same file serves every firmware below. Do not go looking for a per-version
  elfldr; there isn't one to build.
- `index.html`, `notify.html`, `aioshellcode.js`, `cat.jpg`,
  `kexp_2026_05_25.bin` — support assets referenced by the pages.

## What the server MUST do
1. **DNS-spoof `manuals.playstation.net`** to your server's IP (the PS5 User's
   Guide opens `https://manuals.playstation.net/document/<locale>/ps5/…`). Only
   this host needs spoofing; leave the rest of DNS upstream so the console keeps
   working internet, and block the firmware-update hosts if you don't want it to
   update.
2. **Serve these files under `/document/en/ps5/`** over **HTTPS :443**. The PS5
   browser accepts a self-signed cert here (the reference host uses a Schannel /
   CNG self-signed cert). HTTP :80 is only needed for PS4.
3. **The console must reach `netctrl.html` with the offset query string**, e.g.
   `…/document/en/ps5/netctrl.html?go=1&fw=10.00&hc=…&gd=…&notify=…&gps=…`.
   Copy the exact query from a working host's request log (it encodes the
   firmware + slopkit offsets). Without `?go=1&fw=…` the page loops one reboot
   per load. Simplest: make `/document/en/ps5/` (or the guide root) redirect to
   that URL, or serve `index.html` which sets it.
4. **Accept + log the beacons.** The exploit reports progress via GET requests:
   - `…/document/en/ps5/log/<url-encoded message>`  (per-step trace)
   - `…/REPORT/<name>?<k=v…>`  (structured milestones)
   Your server only needs to return 200 and log the path — the message is in the
   URL. Decode `%20` etc. to read them. This is how you watch a run (twins /
   triplet / make_karw / JAILBROKEN / elfldr / "REBOOT AND TRY AGAIN").

## Firmware window
slopkit2's WebKit entry covers 09.00–13.60. The kernel stage is where the limit
actually is, and it uses **three different bugs** which partition the range
exactly — every supported firmware belongs to one and only one:

| firmware | bug | file | cost |
|---|---|---|---|
| 09.00 – 10.01 | lapse — SceKernelAio double free | `lapse-ps5.js` | seconds |
| 10.20 – 12.00 | poops — netcontrol UAF | `netctrl-ps5.js` | seconds |
| 12.02 – 12.70 | p2jb — cr_refcnt overflow | `netctrl-ps5.js` | **~50 minutes** |

All nineteen retail firmwares in that span ship with their own verified tables:

    09.00  09.20  09.40  09.60
    10.00  10.01  10.20  10.40  10.60
    11.00  11.20  11.40  11.60
    12.00  12.02  12.20  12.40  12.60  12.70

Routing is a set lookup, not a range comparison, and lives in one place:
`LAPSE_FIRMWARES_KERNEL` / `NETCTRL_FIRMWARES` / `P2JB_FIRMWARES` in
`netctrl-ps5.js`. Sending a console down the wrong route does not fail cleanly —
it grinds a race against a bug that is not there and reports a lost race, which
is the hardest failure to tell from a real one.

`lapse-ps5.js` is complete end to end: the `SO_LINGER` aio race, the evf
type-confusion leak, the second (0x100-zone) double free, the pktopts twins, and
`make_karw`. It finishes by forging a pipebuf and then **hands off to
`netctrl-ps5.js`** — the pipe pair it builds is the same primitive that module's
KRW already drives, and allproc / jailbreak / elfldr above it are
route-independent, so there is only ever one copy of the code that writes kernel
memory. Before the handoff it cross-checks the new pipe KRW against its own
pktopts reader on the same address; a disagreement aborts rather than writing.

`index.html` detects the console's firmware, picks the matching entry out of
`offsets/offsets.json`, and forwards it in the `fw=` query value; anything not
in the list above falls through to the notification-only PoC instead of running
a chain built from missing offsets.

Adding a firmware means adding it in seven places, which are checked against
each other: `GADGETS`, `EXTRA_GADGETS`, `ALLPROC_TO_KDATA` and `LIBKERNEL_FN`
in `netctrl-ps5.js`, `LKW_TABLE` in `rop-worker.js`, `LAPSE_FIRMWARES` in
`index.html`, and a block in `offsets/lapse-offsets.json` — plus the one route
set it belongs to. None of them are typed by hand —
`offsets/extract-gadgets.py` regenerates all of them from retail firmware:

    python extract-gadgets.py --db <system_system_ex_database> --check   # drift vs published
    python extract-gadgets.py --db <system_system_ex_database> --write   # lapse-offsets.json
    python extract-gadgets.py --db <system_system_ex_database> --js      # netctrl-ps5.js tables
    python extract-gadgets.py --db <system_system_ex_database> --ropw    # rop-worker.js LKW_TABLE

## Reference server
The bundled reference is a Win32 host (`ps-exploit-host`) run headless:
`ps-exploit-host.exe --console --ip <PC_IP> --guide-site netctrl-run
--no-firewall` — DNS :53 + HTTP :80 + HTTPS :443, logs beacons to stdout. Any
server that satisfies the 4 points above works (nginx/caddy with a DNS spoofer,
a small Python/Node HTTPS server, etc.).
