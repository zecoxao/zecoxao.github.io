# afterglow (web)

Kernel exploit for the PlayStation 4 on firmware **13.52** and **14.00**,
run from the console's own browser. It leaves the kernel readable and
writable, `uid 0`, `mmap` handing out RWX and `syscall 11` as a kexec gate —
so the usual payloads work as they do after any other kernel exploit.

This is the browser version. The same exploit also runs as a Lua payload from
inside a game process.

## You need

* PS4 on firmware 13.52 or 14.00, on your network
* A machine on the same network with `python3`

Nothing is installed on the console. The pages are static files.

## Running it

```sh
./serve.sh                      # port 8000, or AFTERGLOW_PORT=8080 ./serve.sh
```

Open `http://<host>:8000/` in the console's browser, pick **ps4-hen** or
**GoldHEN**, press start. Tick *autostart* and it goes by itself after five
seconds.

Each run has to begin on that page. The run page arms the chain only when it
was reached from there, so a browser restoring its last session cannot set it
off again with nobody watching.

## What is shipped

| File | What it is |
|---|---|
| `hen.bin` | ps4-hen `pre-release-main-182`, **already patched** (see below) |
| `goldhen.bin` | GoldHEN, included with the author's permission |
| `patchset-1400.bin`, `patchset-1352.bin` | the kernel patches GoldHEN expects to find, one set per firmware |
| `afterglow.js` | this work |
| `jb.js`, `ps4_offsets.js` | the raw13g host, trimmed |
| `core.js`, `mem.js`, `int64.js` | the in-process primitive, by way of that host |
| `index.html`, `jb.html`, `launch.js`, `style.css`, `meme.png` | the landing page and the run page |
| `serve.sh` | the local server, with the headers this needs |
| `cache.appcache`, `make-manifest.sh` | the offline cache and the script that rebuilds it |

### ps4-hen is patched here

Upstream `hen.bin` has a wrong address for `sceSblPfsSetKeys` on 14.00.
Unpatched, **every app launch freezes the console** and the kernel stays broken
until you reboot. The copy in this folder already carries the fix:

```sh
md5sum hen.bin                  # 6417a84a72f9c7988f0e33b3ae190542  (patched)
                                # 9aff7544eddef2f8202f72fc633d2be3  = upstream, do not use
```

If you bring your own build, change `kpayload/source/offsets/1400.c`,
`sceSblPfsSetKeys_addr` from `0x006272B0` to `0x00627270`. Why, and how it was
established: `TECHNICAL.md`.

## If it stops

Expect to repeat one now and then. Ten hand-run rounds on 14.00 landed nine
times; a failure in the WebKit stage costs nothing, so going again is cheap.
13.52 has fewer runs behind it and no number worth quoting yet.

The page tells you which of these happened.

| What it says | What it cost | What to do |
|---|---|---|
| `exploit failed - please retry (reopen browser)` | nothing — no apm unit spent, no kernel byte written | reopen the browser and go again |
| nothing at all, for 45 s | same | the watchdog says the same thing; if even that does not appear, the WebProcess is gone — cold start |
| `the handles are NOT defused` | the chain got far and could not clean up | **do not close the browser** — cold start |

That last one matters. With the handles left armed, the next process exit runs
`fo_close` into `apmclose` and never completes — and closing the browser *is*
that exit, so no browser restart will help afterwards.

There is also a failure that cannot be caught. The reclaimed object supplies
the stack pointer, and the kernel reads it before a single instruction of ours
runs. When some other kernel allocation wins the hole instead, ring 0 carries
on with a stack pointer out of a stranger's object and the console dies right
there — no message, no clean shutdown. Don't run this with anything unsaved on
the console.

## Reviews wanted

Issues and pull requests welcome, and so is a report that it simply worked. Say
which model and firmware you tried.

## Credits

* **raw13g** — [raw13g.github.io](https://github.com/raw13g/raw13g.github.io),
  the host this page grew out of (`jb.js`, `ps4_offsets.js`, the page
  scaffolding), MIT, see `LICENSE-raw13g`
* **aminegold0** — [silverps4hen](https://github.com/aminegold0/silverps4hen),
  the rebuilt version of that host this one actually descends from
* **jordyidk** — [slopkit](https://github.com/jordyidk/slopkit), the PS5
  jailbreak the in-process primitive (`core.js`, `mem.js`, `int64.js`)
  descends from
* **al-azif** — <https://github.com/al-azif/>
* **SiSTRo** — GoldHEN
* **Pharaoh2k**
* **TheFlow, ChendoChap, abc, AlAzif, LightningMods, @egycnq** — the PS4 kernel
  patch and sandbox escape lineage these payloads build on
* everyone who publishes their findings instead of sitting on them

## Legal

Security research on hardware we own. No Sony code is redistributed.

`afterglow.js` and the patch sets are licensed under the GNU Affero General
Public License v3.0 or later; see `LICENSE`. The bundled code keeps its own
terms: `jb.js`, `ps4_offsets.js` and the page scaffolding are raw13g's under
the MIT license, reproduced in `LICENSE-raw13g`. `core.js`, `mem.js` and
`int64.js` are a reworked fork of slopkit's primitive and carry no license of
their own — where they come from is in `TECHNICAL.md`.
