P2JB / POOPSPLOIT - STANDALONE SITE
===================================
Built 2026-08-17. Serve these files from ANY web server (or a static host / private
website). Nothing here is tied to the machine it was built on: there are no hardcoded
LAN IPs or hostnames anywhere in the site.

FIRMWARE SUPPORT
----------------
  Poopsploit   7.00 - 12.00   (IPv6 rthdr UAF)
  P2JB        12.00 - 12.70   (cr_ref overflow via kqueueex; ~1 hour leak)
index.html detects the console firmware and greys out whichever exploit cannot run.
7.00-8.60 is the Safari 15.4 range and uses core.js's LOWFW_VIEW path. Every offset in
7.00-12.70 was verified offline against that firmware's own retail binaries (22,904
checks, 0 defects); 7.00, 9.05, 12.00, 12.40 and 12.70 are also proven on hardware.
6.00-6.50 is deliberately NOT offered: those profiles still lack lk_worker_wait_return.
Both are selectable on 12.00, the one firmware they overlap on.

Verified on hardware: 12.00 (both exploits) and 12.70 (p2jb, full chain to elfldr).
Every offsets file in both ranges was checked against that firmware's own decrypted
binaries - libkernel/libc exports by NID, all 331 syscall stubs by opcode, all 26 ROP
gadgets by bytes, GOT imports by relocation, and the kernel globals by cross-reference.
The one file with no firmware image available to check against is offsets/11.20.js; its
values match the verified 11.40/11.60, but treat 11.20 as untested.

HOW TO SERVE
------------
Just serve the directory. index.html is the entry point. No build step, no server-side
code required for the exploits themselves. HTTPS or HTTP both work.

WHAT NEEDS A HELPER SERVER, AND WHAT DOES NOT
---------------------------------------------
The pages optionally talk to a few endpoints. All of them degrade safely if absent, so
the site works on a plain static host - with one real limitation, stated honestly below.

  latch, latch/set-, latch/escalate-, latch/clear    NOT REQUIRED
      The one-shot latch stops you re-running the exploit on a console that has already
      been dirtied. If these 404 (or return anything that is not JSON), the page
      automatically falls back to a latch in localStorage. localStorage is used rather
      than sessionStorage deliberately: it survives a reboot and a WebProcess crash, which
      is exactly when the guard matters. So the latch works on your private website with
      no server support at all. ?clear=1 clears it.

  log/<line>                                        NOT REQUIRED
      Progress beacons. These 404 harmlessly on a static host (every call is wrapped in
      try/catch). You simply lose the server-side run log; the on-screen log still works.

  api/elfldr                                        NOT REQUIRED
      Optional "is elfldr already running" probe. Guarded by an r.ok + content-type check,
      so a 404 or an HTML error page falls through with no effect. p2jb also probes the
      console directly (connect to 127.0.0.1:9021), which needs no server at all.

  api/payload/<name>                                NEEDED ONLY FOR THE TILE MENU
      The ELF tile menu asks the server to open a TCP connection to the console's
      elfldr on port 9021 and write the ELF, because a browser cannot: raw sockets are
      not available to JavaScript, and a plain HTTP POST to :9021 would prepend HTTP
      headers so elfldr would not see a valid ELF at offset 0.
      READY-MADE HANDLERS SHIP IN api/ - see "MAKING THE ELF TILE MENU WORK" below.
      Without one, the exploit still runs and still jailbreaks and elfldr still comes
      up; only the tiles cannot deliver. Send ELFs yourself in that case:
          nc <console-ip> 9021 < payloads/etaHEN.elf

CONTENTS
--------
  index.html            entry point, firmware gating
  p2jb.html / p2jb.js   p2jb exploit (12.00-12.70)
  poops.html / poops.js poopsploit (9.00-12.00)
  main.js core.js mem.js rop.js int64.js syscalls.js             shared engine
  rop-worker.js rop_slave.js p2jb_lk.js p2jb_poops.js           p2jb sync executor
  offsets/              per-firmware offsets, one file per version
  payloads/             ELFs (etaHEN, kstuff, ftpsrv, shsrv, websrv, klogsrv, gdbsrv,
                        pldmgr, autoloader, shadowmountplus, elfldr) + the kexp blob
  ui/                   payload menu tile images
  api/                  OPTIONAL payload handlers (payload.php + .htaccess,
                        serve.js). Not needed to jailbreak; only for the tiles.
  *.gif                 background art

OPERATIONAL WARNINGS
--------------------
  - p2jb takes about an hour on the leak stage with no output. That is normal. Do not
    interrupt it.
  - After a jailbreak, ending the WebProcess (reload, back out, close, or a reboot from
    the menu) can panic the kernel. If a run ABORTS after stage 1, the page will tell you
    explicitly to power-cycle rather than reload - follow that, because at that point a
    socket still aliases a live kernel object and closing it is what panics.
  - Repeated panics degrade the console filesystem. If fsck starts reporting major>0 edits
    at boot, do a full power drain (unplug 2-3 minutes) and consider Safe Mode
    "Rebuild Database".

MAKING THE ELF TILE MENU WORK ON YOUR OWN HOST
----------------------------------------------
The tiles need ONE server-side endpoint. A browser cannot deliver an ELF itself:
JavaScript has no raw sockets, and an HTTP POST straight to the console's port 9021
would prepend HTTP headers, so elfldr would not see \x7fELF at offset 0. The page
therefore asks the server to open the TCP connection and write the file verbatim.

Two ready-to-use handlers ship in api/. Both work out the console's address from the
REQUEST ITSELF (the console is the one asking), so there is nothing to configure.

  PHP  (shared hosting, Apache)
      copy api/payload.php and api/.htaccess up with the site.
      .htaccess rewrites  api/payload/<name>  ->  payload.php/<name>.
      nginx equivalent:
          location ~ ^/api/payload/(.+)$ { fastcgi_param PATH_INFO /$1; ... payload.php; }

  NODE (anywhere node runs - also serves the whole site, so it is the quickest option)
      cd <site root> && node api/serve.js 8080
      then point the console at that host:port.

Both reply {"ok":true,"bytes":N} on success, which is what the page expects.

IF YOU DO NOT WANT A HANDLER, send ELFs yourself once elfldr is up on port 9021:
      nc <ps5-ip> 9021 < payloads/etaHEN.elf
A tile that fails now says so: it outlines RED and the reason appears in the status
line, including the nc command to use instead. A green outline means it was delivered.
