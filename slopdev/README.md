# p2jb / poopsploit — PS5 WebKit exploit host

Static site. Open `index.html` on the console browser; it detects the firmware and
greys out whichever exploit cannot run.

| exploit    | firmware      | technique                              |
|------------|---------------|----------------------------------------|
| Poopsploit | 9.00 – 12.00  | IPv6 `rthdr` UAF                       |
| P2JB       | 12.00 – 12.70 | `cr_ref` overflow via `kqueueex` (~1 h) |

12.00 is the one firmware both cover.

## Hosting

Serve the directory. No build step. Works at a domain root **or in a subdirectory**
(which is what GitHub Pages gives you at `USER.github.io/REPO/`).

`.nojekyll` is required and present — without it Pages runs Jekyll, which silently
drops files and directories whose names begin with `_`.

## What does NOT work on GitHub Pages

**The ELF tile menu cannot deliver payloads from a static host.** Delivering an ELF
needs a real TCP socket to the console's `elfldr` on port 9021: JavaScript has no raw
sockets, and an HTTP POST to :9021 would prepend HTTP headers so `elfldr` would not see
`\x7fELF` at offset 0. The page therefore asks a server-side endpoint,
`api/payload/<name>`, to open that connection — and Pages cannot run one.

Everything else works. The exploit still runs, still jailbreaks, and `elfldr` still
comes up on :9021. Send ELFs yourself:

```
nc <ps5-ip> 9021 < payloads/etaHEN.elf
```

A tile that cannot deliver outlines red and prints the reason plus the `nc` command,
rather than silently doing nothing.

Ready-made handlers ship in `api/` (`payload.php` + `.htaccess`, and `serve.js`) for
any host that can run PHP or Node. On Pages they are inert.

The other endpoints degrade safely: the one-shot latch falls back to `localStorage`
(which survives a reboot and a WebProcess crash, exactly when the guard matters),
progress beacons 404 inside `try/catch`, and the `api/elfldr` probe is content-type
guarded. `?clear=1` clears the latch.

## Warnings

- P2JB spends about an hour on the leak with no output. That is normal — do not interrupt.
- After a jailbreak, ending the WebProcess can panic the kernel. If a run aborts after
  stage 1 the page tells you to power-cycle rather than reload; follow that, because a
  socket still aliases a live kernel object and closing it is what panics.
- Repeated panics degrade the console filesystem. If fsck reports `major>0` at boot, do a
  full power drain and consider Safe Mode → Rebuild Database.

## Credits

See the creds & greetz block on `index.html`. Based on the webkit by j0rdy.
