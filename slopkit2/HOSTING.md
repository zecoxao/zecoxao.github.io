# netctrl (Poopsploit) — self-hosting the exploit site

Client-side files for the PS5 **netcontrol UAF** jailbreak (firmware 9.00–12.00;
tested on a 10.00 devkit). This is the browser payload only — you supply the
server (DNS spoof + HTTPS + a beacon sink).

## Files
- `netctrl.html` — entry page. The console loads this and runs the chain.
- `netctrl-ps5.js` — the exploit (race + jailbreak + elfldr loader).
- `rop-worker.js`, `rop_slave.js` — the sacrificial-Worker ROP runner.
- `lapse-runtime.js` — slopkit2 WebKit runtime (offsets, primitives).
- `offsets/` — per-firmware offset tables (slopkit).
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
slopkit2 WebKit entry 09.00–13.60; netcontrol bug 4.03–12.00. The overlap is
what this kit can run, and all fourteen retail firmwares in it are now shipped
with their own verified tables:

    09.00  09.20  09.40  09.60
    10.00  10.01  10.20  10.40  10.60
    11.00  11.20  11.40  11.60
    12.00

`index.html` detects the console's firmware, picks the matching entry out of
`offsets/offsets.json`, and forwards it in the `fw=` query value; anything not
in the list above falls through to the notification-only PoC instead of running
a chain built from missing offsets. 12.02 and later parse as "in range" but the
netcontrol bug is fixed there, so they are deliberately excluded.

Adding a firmware means adding it in six places, which are checked against each
other: `GADGETS`, `EXTRA_GADGETS` and `ALLPROC_TO_KDATA` in `netctrl-ps5.js`,
`LKW_TABLE` in `rop-worker.js`, `LAPSE_FIRMWARES` in `index.html`, and a block
in `offsets/lapse-offsets.json`. None of them are typed by hand —
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
