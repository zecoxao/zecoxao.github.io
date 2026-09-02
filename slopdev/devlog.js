/* devlog.js - mirror the page's log to the DEVKIT CONSOLE and to on-screen
 * notifications, so a run that ends in a WebProcess crash still leaves a trace.
 *
 * WHY THIS EXISTS
 * ---------------
 * Everything the pages print goes to a <div> and to the optional log/ beacon.
 * Both die with the tab: when the renderer is killed (App Crash reason=0xa /
 * SIGBUS, the 7.00 failure mode) the last and most interesting lines are the
 * ones you never see. sceKernelDebugOutText writes straight through the kernel
 * to the devkit's console output, which survives the process dying.
 *
 * TWO SINKS
 * ---------
 *   klog   sceKernelDebugOutText(channel, text)
 *          = libkernel_web 0xAE00 on devkit 7.60.00.07:
 *              mov rdx, rdi        ; rdx = arg0 = channel
 *              mov edi, 7          ; rdi = op  = MDBG_DEBUG_OUT_TEXT
 *              call <syscall 0x259 stub>
 *          so the SYSCALL form is  mdbg_service(7, text, channel)  with the
 *          string in rsi, NOT rdi. Verified against the kernel's mdbg jump
 *          table: case 7 does malloc(0x1000) then
 *          copyinstr(uap->arg1, buf, 0x1000, NULL) - uap->arg1 is the string.
 *          We issue the raw syscall rather than the libkernel wrapper on
 *          purpose: 0x259 is in EVERY firmware's syscall table in offsets/,
 *          so this needs no new per-firmware constant and cannot go stale.
 *
 *   notify sceKernelSendNotificationRequest(0, req, 0xC30, 0)
 *          = OFFSET_lk_sceKernelSendNotificationRequest (0x8BE0 on 7.x).
 *          The function validates type <= 8, picks an fd out of a table and
 *          write()s the buffer at it; req is the classic 3120-byte struct with
 *          char useless1[45]; char message[3075]. All-zero header is what every
 *          known user of this API sends. Firmwares WITHOUT the offset (3.xx-6.xx,
 *          13.xx) simply get no notifications; klog still works there.
 *
 * RE-ENTRANCY - READ THIS BEFORE MOVING A FLUSH CALL
 * ---------------------------------------------------
 * Emitting a log line means running a ROP chain, and the exploit runs ROP chains
 * too. Two hazards, handled differently:
 *
 *   1. STACK sharing. main.js builds a chain incrementally:
 *          chain.add_syscall_ret(...); await chain.run();
 *      `await` yields even on a non-promise, so a stray flush landing between
 *      those two lines would push OUR gadgets onto the SAME stack, run both,
 *      and then clear() - zeroing the stack the exploit is about to run. That
 *      is a guaranteed crash. Closed structurally: devlog owns a SEPARATE
 *      worker_rop instance with its own stack. We can never touch theirs.
 *
 *   2. WORKER sharing. Both chains are executed by the one hijacked worker via
 *      p.launch_chain, which parks on worker.onmessage. Two launches in flight
 *      at once would cross their completions. Closed by wrapping
 *      p.launch_chain to count in-flight runs; devlog refuses to start while
 *      the count is non-zero and queues instead.
 *
 * So: line() is ALWAYS safe to call from anywhere (it only appends to a JS
 * array). flush() is what talks to the kernel. The default flush points are
 * main.js's `await log(...)` sites and the explicit devlog.flush() calls at the
 * page's stage boundaries - both are places where the exploit is provably
 * between chain operations. ?klognow=1 flushes after every line instead, which
 * is what you want when hunting a hang, at the cost of leaning on the
 * in-flight counter rather than on the call graph.
 *
 * QUERY PARAMETERS
 *   ?klog=0        disable the devkit console sink
 *   ?notify=0      disable notifications
 *   ?klognow=1     flush after every line (chatty, best for hangs)
 *   ?klogmarks=0   do not mirror the telemetry marks, only log() lines
 *   ?klogch=N      DebugOutText channel (default 0)
 *   ?notifymax=N   cap on notifications per run (default 24, 0 = unlimited)
 *   ?klogtag=STR   line prefix (default "slop")
 */
(function () {
    "use strict";
    if (window.devlog) return;

    var Q = null;
    try { Q = new URLSearchParams(location.search); } catch (e) { }
    function qflag(name, dflt) {
        if (!Q) return dflt;
        var v = Q.get(name);
        if (v === null) return dflt;
        return v !== "0" && v !== "false";
    }
    function qnum(name, dflt) {
        if (!Q) return dflt;
        var v = parseInt(Q.get(name) || "", 10);
        return isNaN(v) ? dflt : v;
    }

    var CFG = {
        klog: qflag("klog", true),
        notify: qflag("notify", true),
        eager: qflag("klognow", false),
        marks: qflag("klogmarks", true),
        channel: qnum("klogch", 0),
        notifyMax: qnum("notifymax", 24),
        tag: (Q && Q.get("klogtag")) || "slop"
    };

    var SYS_MDBG_SERVICE = 0x259;
    var MDBG_OP_DEBUG_OUT_TEXT = 7;
    /* Fallback sink. The WebProcess demonstrably has a stdout - the serial log
     * carries "SceNKWebProcess: arg[0] = ..." at every spawn - so if mdbg is
     * refused, write(2, ...) still reaches the same pane. Tried once, then
     * whichever answered is the one used for the rest of the run. */
    var SYS_WRITE = 0x004;
    var FALLBACK_FD = qnum("klogfd", 2);

    /* The kernel copyinstr()s into a 0x1000 buffer. Stay clear of the edge so a
     * truncated line is still NUL terminated inside our own buffer. */
    var KLOG_BUF_SIZE = 0x1000;
    var KLOG_MAX = 0xF00;

    /* struct notify_request { char useless1[45]; char message[3075]; } */
    var NOTIFY_REQ_SIZE = 0xC30;
    var NOTIFY_MSG_OFF = 0x2D;
    var NOTIFY_MSG_MAX = 0xC00;

    var T0 = Date.now();

    var st = {
        p: null,
        chain: null,
        klogBuf: null,
        notifyBuf: null,
        bound: false,
        dead: false,          /* the syscall answered with an error: stop trying */
        inflight: 0,          /* foreign ROP chains currently running */
        queue: [],
        queued: 0,
        emitted: 0,
        dropped: 0,
        notified: 0,
        notifyOff: false,
        lastKlogRet: null,
        lastNotifyRet: null,
        useFd: false,         /* mdbg refused; write(FALLBACK_FD) instead */
        seq: 0,
        probe: null
    };

    var QUEUE_CAP = 4096;

    /* ---- text -------------------------------------------------------- */

    /* The kernel side is a C string. Keep it single-byte and printable so a
     * stray high char cannot terminate or garble the line; \n is kept because
     * a batched flush is one syscall carrying many lines. */
    function ascii(s) {
        s = String(s);
        var out = "";
        for (var i = 0; i < s.length; i++) {
            var c = s.charCodeAt(i);
            if (c === 10) { out += "\n"; continue; }
            out += (c >= 0x20 && c < 0x7F) ? s[i] : ".";
        }
        return out;
    }

    function stamp() {
        var ms = Date.now() - T0;
        var s = Math.floor(ms / 1000), r = ms % 1000;
        return (s < 10 ? "  " : s < 100 ? " " : "") + s + "."
            + (r < 10 ? "00" : r < 100 ? "0" : "") + r;
    }

    /* ---- buffers ------------------------------------------------------ */

    /* p.malloc(n, 1) hands back a pointer whose .backing Uint8Array aliases the
     * same bytes, so filling a buffer is a plain typed-array store instead of
     * thousands of p.write1 round trips through the read/write primitive. */
    function putCString(buf, off, text, max) {
        var b = buf.backing, n = 0;
        for (var i = 0; i < text.length && n < max - 1; i++)
            b[off + (n++)] = text.charCodeAt(i) & 0xFF;
        b[off + n] = 0;
        return n;
    }

    function zero(buf, off, len) {
        var b = buf.backing;
        for (var i = 0; i < len; i++) b[off + i] = 0;
    }

    /* ---- serialisation ------------------------------------------------ */

    var tail = Promise.resolve();
    function serial(fn) {
        var r = tail.then(fn, fn);
        tail = r.then(function () { }, function () { });
        return r;
    }

    function busy() { return st.inflight > 0; }

    /* ---- sinks -------------------------------------------------------- */

    function failed(ret) {
        return !!ret && (ret.low | 0) === -1 && (ret.hi | 0) === -1;
    }

    async function emitKlog(text) {
        if (!CFG.klog || st.dead || !st.bound) return null;
        var n = putCString(st.klogBuf, 0, text, KLOG_MAX);
        if (n === 0) return null;

        if (!st.useFd) {
            var ret = await st.chain.syscall(SYS_MDBG_SERVICE,
                MDBG_OP_DEBUG_OUT_TEXT, st.klogBuf, CFG.channel);
            st.lastKlogRet = ret;
            if (!failed(ret)) { st.emitted++; return ret; }
            /* -1 means the op is refused (mdbg subsystem off, or the sandbox
             * denies syscall 0x259). Try the fd once rather than paying 400
             * more round trips on a run we are trying to observe. */
            screen("devlog: mdbg_service(7) returned -1 - falling back to write(fd "
                + FALLBACK_FD + ")");
            st.useFd = true;
        }

        var w = await st.chain.syscall(SYS_WRITE, FALLBACK_FD, st.klogBuf, n);
        st.lastKlogRet = w;
        if (failed(w)) {
            st.dead = true;
            screen("devlog: write(fd " + FALLBACK_FD + ") also refused"
                + " - devkit console sink disabled (notifications unaffected)");
        } else {
            st.emitted++;
        }
        return w;
    }

    async function emitNotify(text) {
        if (!CFG.notify || st.notifyOff || !st.bound) return null;
        if (CFG.notifyMax > 0 && st.notified >= CFG.notifyMax) return null;
        if (typeof OFFSET_lk_sceKernelSendNotificationRequest === "undefined") {
            st.notifyOff = true;
            return null;
        }
        zero(st.notifyBuf, 0, NOTIFY_MSG_OFF);
        putCString(st.notifyBuf, NOTIFY_MSG_OFF, text, NOTIFY_MSG_MAX);
        var fn = st.p.libKernelBase.add32(OFFSET_lk_sceKernelSendNotificationRequest);
        var ret = await st.chain.call(fn, 0, st.notifyBuf, NOTIFY_REQ_SIZE, 0);
        st.lastNotifyRet = ret;
        st.notified++;
        return ret;
    }

    /* Status about the log, on the page's own log. Prefer screenLine (the pages
     * export it for exactly this) over log(): log() calls back into devlog, and
     * the only reason we are here is usually that a sink just failed. */
    var inScreen = false;
    function screen(text) {
        if (inScreen) return;
        inScreen = true;
        try {
            if (typeof window.screenLine === "function") window.screenLine(text);
            else if (typeof log === "function") log(text, 1);
        } catch (e) { }
        inScreen = false;
    }

    /* ---- public ------------------------------------------------------- */

    function line(text) {
        if (!CFG.klog || st.dead) return;
        text = ascii(text);
        if (!text) return;
        if (st.queue.length >= QUEUE_CAP) {
            st.queue.shift();
            st.dropped++;
        }
        /* Sequence number AND elapsed time. The number is what makes a dead boot
         * readable: the last "[slop N ...]" on the console is exactly where the
         * run stopped, and a gap in N tells you lines were dropped rather than
         * never produced. */
        st.queue.push("[" + CFG.tag + " " + (++st.seq) + " " + stamp() + "] " + text);
        st.queued++;
        if (CFG.eager && st.bound && !busy()) flush();
    }

    /* Drains the queue in as few syscalls as the kernel's 0x1000 buffer allows -
     * one round trip carrying many lines rather than one per line. Callers must
     * already hold the serial() slot and have checked busy(). */
    async function drain() {
        if (!st.bound || st.dead || st.queue.length === 0) return;
        var lines = st.queue.splice(0, st.queue.length);
        var buf = "";
        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            if (l.length > KLOG_MAX - 2) l = l.slice(0, KLOG_MAX - 2);
            if (buf.length + l.length + 1 > KLOG_MAX - 1) {
                await emitKlog(buf);
                buf = "";
                if (st.dead) return;
            }
            buf += l + "\n";
        }
        if (buf) await emitKlog(buf);
    }

    function flush() {
        if (!st.bound || st.dead || st.queue.length === 0) return tail;
        return serial(async function () {
            /* Another chain started between the enqueue and our turn: leave the
             * lines queued rather than crossing two runs on the one worker. */
            if (busy()) return;
            await drain();
        });
    }

    function say(text, alsoNotify) {
        line(text);
        if (alsoNotify) return notify(text);
        return flush();
    }

    function notify(text) {
        text = ascii(text).replace(/\n/g, " ");
        line("NOTIFY " + text);
        if (!st.bound) return tail;
        return serial(async function () {
            if (busy()) return;
            await drain();
            await emitNotify(text);
        });
    }

    /* Called once from main.js the moment the ROP chain is proven working. */
    function bind(p, exploitChain) {
        if (st.bound || !p || !exploitChain) return false;
        try {
            /* Hazard 2: count foreign chain runs so we never start a launch
             * while one is in flight. Every chain object reaches the worker
             * through p.launch_chain, so this one wrapper covers all of them,
             * including the ones poops.js and p2jb.js build for themselves. */
            var origLaunch = p.launch_chain;
            p.launch_chain = function (c) {
                st.inflight++;
                var done = function () { st.inflight--; };
                var r;
                try { r = origLaunch(c); }
                catch (e) { done(); throw e; }
                if (!r || typeof r.then !== "function") { done(); return r; }
                return r.then(function (v) { done(); return v; },
                    function (e) { done(); throw e; });
            };

            /* Hazard 1: our own stack, so a flush can never land in the middle
             * of a chain the exploit is still assembling.
             *
             * Sized down from the exploit's 0x80000/0x10000. reserved_stack is
             * kept at the proven 0x10000: the ROP grows UPWARD from
             * stack_entry_point, so a real function we call (the notification
             * path ends in write()) puts its frame BELOW that point, and the
             * reserved region is what absorbs it. Only the chain area shrinks -
             * 0x4000 is 2048 entries and our longest chain is about twenty.
             * The page has died of renderer OOM before (README), so ~420KB
             * instead of ~1.3MB is worth having. */
            st.chain = new worker_rop(p, 0x14000, 0x10000);
            st.klogBuf = p.malloc(KLOG_BUF_SIZE, 1);
            st.notifyBuf = p.malloc(NOTIFY_REQ_SIZE, 1);
            st.p = p;
            st.bound = true;
        } catch (e) {
            screen("devlog: bind failed - " + e);
            st.bound = false;
            return false;
        }
        return true;
    }

    /* One round trip that answers "does this console accept either sink?".
     * Reported on screen so a run that produces no console output tells you
     * WHY instead of looking like the exploit died silently. */
    function probeSinks() {
        if (!st.bound) return Promise.resolve(null);
        return serial(async function () {
            var out = { klog: null, notify: null };
            if (CFG.klog && !st.dead) {
                var r = await emitKlog("[" + CFG.tag + "] devlog online - fw="
                    + window.fw_str + " ua=" + navigator.userAgent + "\n");
                out.klog = r ? ("0x" + r.toString()) : "skipped";
            } else {
                out.klog = "disabled";
            }
            if (CFG.notify) {
                if (typeof OFFSET_lk_sceKernelSendNotificationRequest === "undefined") {
                    out.notify = "no offset for fw " + window.fw_str;
                    st.notifyOff = true;
                } else {
                    var n = await emitNotify("devlog online (" + window.fw_str + ")");
                    out.notify = n ? ("0x" + n.toString()) : "skipped";
                }
            } else {
                out.notify = "disabled";
            }
            st.probe = out;
            screen("devlog: klog=" + out.klog + " notify=" + out.notify);
            return out;
        });
    }

    /* A crash we can still see coming is worth a line of its own. Both handlers
     * run outside the exploit's call stack, so they queue and only flush when
     * the worker is idle - which after a fatal error it usually is. */
    try {
        window.addEventListener("error", function (e) {
            line("JS-ERROR " + (e && e.message) + " @ "
                + (e && e.filename) + ":" + (e && e.lineno));
            if (!busy()) flush();
        });
        window.addEventListener("unhandledrejection", function (e) {
            var r = e && e.reason;
            line("JS-REJECT " + (r && r.message ? r.message : r));
            if (!busy()) flush();
        });
    } catch (e) { }

    window.devlog = {
        cfg: CFG,
        bind: bind,
        probe: probeSinks,
        line: line,
        say: say,
        notify: notify,
        flush: flush,
        isBound: function () { return st.bound; },
        stats: function () {
            return {
                bound: st.bound, dead: st.dead, queued: st.queued,
                pending: st.queue.length, emitted: st.emitted,
                dropped: st.dropped, notified: st.notified,
                inflight: st.inflight, sink: st.useFd ? ("fd" + FALLBACK_FD) : "mdbg",
                probe: st.probe
            };
        }
    };
})();
