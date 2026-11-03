# How it works

The kernel bug, the reclaim, the ring 0 bootstrap and the handle teardown are
the same as in the Lua version of afterglow and are not repeated here.

This file covers what is specific to running it out of the browser.

## The two stages

The browser host does not reach the kernel by itself. It runs in two stages:

1. **`jb.js`** — the raw13g host. It builds the in-process primitive from
   WebKit and hands over four things, and only these four:

   | | |
   |---|---|
   | `sc(num, ...args)` | syscall with an arbitrary number, returns `{lo, hi, i32}` |
   | `bufAddr(arrayBuffer)` | address of a backing store |
   | `p.read1/4/8`, `p.write1/4/8`, `p.readInto` | memory in this process |
   | `keepAlive` | an array, so buffers survive the collector |

2. **`afterglow.js`** — the kernel exploit, which uses nothing else. There is
   no requirement for a way to call native code: the only `native.fcall` in the
   exploit enters a stub that is itself `SYS_syscall(11, body)`, which a host
   with a syscall primitive issues directly.

That boundary is why the same exploit drives both hosts. Anything offering the
four above can carry it.

`probeAfterglow()` fires nothing and answers whether the current process can
carry the exploit at all; `runAfterglow()` is the live chain.

## Which loader, decided by content

There are two forms of enabler image, and from the outside they look alike:

| Form | How it is recognised | Path taken |
|---|---|---|
| raw payload | begins with `e9` (jmp rel32) | map it, start a thread |
| composite image | exactly 964,440 bytes | patch chain, trampoline, padding RW |

`loadEnabler` in `afterglow.js` decides on the content, **not** on the file
name. Deciding by name sends a raw payload down the composite path, where the
length check rejects it.

## The kernel patch set

GoldHEN expects to find a patched kernel. The blob writes **57** kernel text
sites, counted off the blob itself. afterglow covers 25 of them — fifteen from
its `PATCHES` table and ten more written by its bootstrap stub. The remaining
**32** are exactly the ones GoldHEN's code looks for: one block of 29 from
`0x125791` to `0x125871`, plus `0x2fcb5c`, `0x391fc6` and `0x3be3c0`.

That set is position independent and ends in `ret`, and it runs before
**every** GoldHEN payload, in both image forms. It writes fixed kernel
addresses, so there is one per firmware — `patchset-1400.bin` (641 bytes) and
`patchset-1352.bin` (632 bytes) — and `afterglow.js` fetches the one that
matches the firmware it was given.

## Two guards

* **The referrer guard.** The run page arms the chain only when it was reached
  from `index.html` in the same directory. The console's browser restores the
  last page it had open; without this, a page left on the armed chain would run
  it again with nobody in front of the screen. The guard sits in `jb.js`, not
  in the server, so it holds however the files are served.
* **Caching the console can be trusted with.** That browser holds on to
  modules, so a corrected file has to be able to arrive. The pages declare an
  HTML5 Application Cache (`cache.appcache`), in which every entry carries a
  hash of its contents — any edit changes the manifest, so the console
  refetches instead of serving a stale module. `make-manifest.sh` rebuilds it
  and has to be run after changing any shipped file. `serve.sh` additionally
  sends `no-cache, must-revalidate`, which keeps the file but makes every use
  of it conditional; any other server used instead has to do the same.

## The ps4-hen offset

`kpayload/source/offsets/1400.c` gives `sceSblPfsSetKeys_addr = 0x006272B0`.
The function starts at `0x00627270`.

* The two call sites ps4-hen hooks itself (`mountpfs__sceSblPfsSetKeys_hook1`
  at `0x06a39f9`, `hook2` at `0x06a3c2a`) contain `call` instructions whose
  target is `0x0627270`.
* Three calls in the kernel point at `0x0627270`, none at `0x006272B0`.
* `0x0627270` begins `55 48 89 e5`; `0x006272B0` is `89 45 d0`, mid function.

The hook replaces both call sites and then calls the "original" 64 bytes past
its entry, on every PFS mount — that is, on every application launch.

`RsaesPkcs1v15Dec2048CRT_addr = 0x0021BFC0` has no prologue either (nearest at
`0x0021BD20`), but it is never called directly, so this is unconfirmed.

## Where the code comes from

Three layers, and they are not the same provenance.

`afterglow.js` and the patch sets are this work. `jb.js`, `ps4_offsets.js` and
the page scaffolding are raw13g's, under MIT.

`core.js`, `mem.js` and `int64.js` are a fork of the primitive from
[slopkit](https://github.com/jordyidk/slopkit), a PS5 jailbreak, reworked for
this firmware and taken from the raw13g host. The derivation is visible in the
files themselves: the first fifteen lines are slopkit's constants unchanged
(`K=2`, `DUPLICATE_INDEX=2`, `CONTROL_INT=-64000`, `EXPECTED_LENGTH=0x50001`),
and slopkit's own `REVISION` marker travels along — `slopkit-core-final` there,
`slopkit-core-1` here. Where slopkit documents the 9.00 heap geometry, this
copy carries the profiles for 14.00 instead.

| | changed against slopkit | changed against the raw13g copy |
|---|---|---|
| `core.js` | 2434 lines | 125 |
| `mem.js` | 1439 lines | 19 |
| `int64.js` | 156 lines | 0, byte for byte |

slopkit carries no license file, and raw13g's MIT license names these three as
third-party rather than relicensing them, so no grant reaches them from either
side.

## Scope

The kernel patch lives until the console reboots. Nothing here persists.
