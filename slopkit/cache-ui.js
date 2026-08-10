/* slopkit offline cache -- page side.

   Three strategies, picked by what the browser actually has:

     1. AppCache (window.applicationCache).  This is the one that matters: the
        PS5 browser has no service workers but does have the old HTML5
        Application Cache -- it is what writes webkit/shell/appcache/
        ApplicationCache.db, which main.js knows how to delete.  The download is
        driven by the manifest attribute on <html>, so all this file does is
        report its progress events as a percentage.
     2. Service worker + Cache API, for desktop browsers where AppCache is gone.
        Here we fetch every asset ourselves so bytes can be counted.
     3. No offline support at all -- just warm the HTTP cache, and say so
        instead of claiming the page is offline ready.

   Renders into #cache when that element exists. Requires slopkit-cache.js.

   Query flags:  ?nocache=1  purge the Cache API copy and unregister the worker
                 ?recache=1  force a fresh download of every asset */
(function () {
    "use strict";

    var C = self.SLOPKIT_CACHE;
    if (!C) return;

    var CONCURRENCY = 3;
    var WARM_FLAG = "slopkit-warmed-" + C.VERSION;

    var mode = "warm";          // "appcache" | "cache" | "warm"
    var offline = false;        // true only when the page really works offline
    var doneBytes = 0;
    var credited = Object.create(null);
    var failed = [];
    var running = false;
    var lastPaint = 0;

    var els = null;

    /* ---------------------------------------------------------------- view */

    function build() {
        var host = document.getElementById("cache");
        if (!host) return null;
        host.innerHTML =
            '<div class="cacheHead"><span class="cacheLabel"></span>'
            + '<span class="cachePct">0%</span></div>'
            + '<div class="cacheTrack"><div class="cacheFill"></div></div>'
            + '<div class="cacheInfo"></div>';
        return {
            host: host,
            label: host.querySelector(".cacheLabel"),
            pct: host.querySelector(".cachePct"),
            fill: host.querySelector(".cacheFill"),
            info: host.querySelector(".cacheInfo")
        };
    }

    function mb(n) {
        return (n / 1048576).toFixed(1);
    }

    /* Small diagnostic readout -- on a console there is no dev tools window, so
       this line is the only way to see which strategy actually engaged. The
       trail is persisted because the interesting run is the one BEFORE the
       reload that failed. */
    var TRAIL_KEY = "slopkit-trail";
    var trail = [];
    var extraNote = "";

    function mark(step) {
        if (trail[trail.length - 1] !== step) trail.push(step);
        else return;
        try { localStorage.setItem(TRAIL_KEY, trail.join(">")); } catch (e) { }
        info();
    }

    function prevTrail() {
        try { return localStorage.getItem(TRAIL_KEY) || ""; } catch (e) { return ""; }
    }

    function info(extra) {
        if (!els) return;
        if (extra) extraNote = extra;
        var bits = ["rev" + C.VERSION];
        bits.push("sw:" + (("serviceWorker" in navigator) ? "y" : "n"));
        bits.push("cacheapi:" + (self.caches ? "y" : "n"));
        bits.push("ac:" + acStatus());
        if (trail.length) bits.push("now:" + trail.join(">"));
        else {
            var p = prevTrail();
            if (p) bits.push("last:" + p);
        }
        if (extraNote) bits.push(extraNote);
        els.info.textContent = bits.join("  ");
    }

    var pendingPaint = null;
    var pendingTimer = 0;

    function paint(text, state, force) {
        if (!els) return;
        var now = Date.now();
        if (!force && now - lastPaint < 80) {
            /* Coalesce, but never drop the newest value: without this trailing
               repaint a burst of events inside one window leaves the bar
               showing whatever it happened to say before the burst. */
            pendingPaint = [text, state];
            if (!pendingTimer) {
                pendingTimer = setTimeout(function () {
                    pendingTimer = 0;
                    var a = pendingPaint;
                    pendingPaint = null;
                    if (a) paint(a[0], a[1], true);
                }, 80 - (now - lastPaint));
            }
            return;
        }
        if (pendingTimer) {
            clearTimeout(pendingTimer);
            pendingTimer = 0;
            pendingPaint = null;
        }
        lastPaint = now;

        var frac = C.TOTAL_BYTES ? doneBytes / C.TOTAL_BYTES : 1;
        if (frac > 1) frac = 1;
        if (frac < 0) frac = 0;
        var pct = Math.floor(frac * 100);
        if (pct === 100 && doneBytes < C.TOTAL_BYTES) pct = 99;

        els.pct.textContent = pct + "%";
        els.fill.style.width = (frac * 100) + "%";
        els.label.textContent = text;
        els.host.className = state || "";
        info();
    }

    function setFrac(f) {
        doneBytes = Math.max(0, Math.min(1, f)) * C.TOTAL_BYTES;
    }

    function retryButton(label, fn) {
        if (document.getElementById("cacheRetry")) return;
        var actions = document.getElementById("actions");
        if (!actions) return;
        var a = document.createElement("a");
        a.id = "cacheRetry";
        a.className = "action secondary";
        a.href = "#";
        a.tabIndex = 0;
        a.textContent = label;
        a.addEventListener("click", function (e) {
            e.preventDefault();
            a.parentNode.removeChild(a);
            fn();
        });
        actions.appendChild(a);
    }

    function warmFlag(set) {
        try {
            if (set === undefined) return localStorage.getItem(WARM_FLAG) === "1";
            if (set) localStorage.setItem(WARM_FLAG, "1");
            else localStorage.removeItem(WARM_FLAG);
        } catch (e) { }
        return false;
    }

    /* ------------------------------------------------------------ appcache */

    var AC_NAMES = ["uncached", "idle", "checking", "downloading",
                    "updateready", "obsolete"];

    function appCache() {
        try {
            var ac = self.applicationCache;
            return (ac && typeof ac.addEventListener === "function") ? ac : null;
        } catch (e) {
            return null;
        }
    }

    function acStatus() {
        var ac = appCache();
        if (!ac) return "-";
        var s = ac.status;
        return AC_NAMES[s] !== undefined ? AC_NAMES[s] : String(s);
    }

    /* The browser is already downloading (the manifest attribute on <html>
       started it before this script ran); we only translate its events. */
    function startAppCache() {
        var ac = appCache();
        mode = "appcache";

        var loaded = 0;
        var total = C.URLS.length;
        var sawEvent = false;
        var settled = false;

        function finish(label, state) {
            settled = true;
            offline = (state === "done");
            setFrac(1);
            paint(label, state, true);
        }

        function on(name, fn) {
            try { ac.addEventListener(name, fn, false); } catch (e) { }
        }

        on("checking", function () {
            sawEvent = true;
            mark("chk");
            paint("checking cache...", "busy", true);
        });
        on("downloading", function () {
            sawEvent = true;
            mark("dl");
            paint("caching...", "busy", true);
        });
        on("progress", function (e) {
            sawEvent = true;
            if (e && e.total) {
                total = e.total;
                loaded = e.loaded;
            } else {
                /* Older WebKit fires bare progress events with no counts, so
                   tally them ourselves against the manifest entry count. */
                loaded++;
                if (loaded > total) total = loaded;
            }
            var f = total ? loaded / total : 0;
            if (f > 0.99) f = 0.99;   /* 100% belongs to the cached event */
            setFrac(f);
            /* Record only the latest count, not one trail entry per file. */
            if (trail[trail.length - 1] &&
                trail[trail.length - 1].indexOf("p") === 0) trail.pop();
            mark("p" + loaded + "/" + total);
            /* One event per file, so paint every one rather than coalescing. */
            paint("caching " + loaded + " / " + total + " files", "busy", true);
        });
        on("cached", function () {
            mark("ok");
            finish("cached - offline ready", "done");
        });
        on("noupdate", function () {
            mark("noupd");
            finish("cached - offline ready", "done");
        });
        on("updateready", function () {
            mark("upd");
            try { ac.swapCache(); } catch (e) { }
            finish("updated - reload to apply", "done");
        });
        on("obsolete", function () {
            mark("obs");
            settled = true;
            setFrac(0);
            paint("cache removed by server", "fail", true);
        });
        on("error", function () {
            /* AppCache is all-or-nothing and gives no reason. The usual causes
               are a listed file that 404s, or the console refusing the total
               size -- both leave nothing cached. */
            mark("err");
            if (settled) return;
            settled = true;
            paint("cache failed - too big, or a file 404s", "fail", true);
            retryButton("RETRY CACHE", function () {
                try { ac.update(); } catch (e) { }
                settled = false;
                paint("retrying...", "busy", true);
            });
        });

        /* Status the page saw at boot, before any event of ours could fire. */
        mark("s" + ac.status);

        /* Keep the status text live -- it changes without always firing an
           event we listen for. */
        var tick = setInterval(function () {
            info();
            if (settled) setTimeout(function () { clearInterval(tick); }, 3000);
        }, 1000);

        switch (ac.status) {
            case 1:  /* IDLE       */ finish("cached - offline ready", "done"); return;
            case 4:  /* UPDATEREADY*/ finish("updated - reload to apply", "done"); return;
            case 5:  /* OBSOLETE   */ paint("cache removed by server", "fail", true); return;
            case 2:  /* CHECKING   */
            case 3:  /* DOWNLOADING*/ paint("caching...", "busy", true); break;
            default: /* UNCACHED   */ paint("checking cache...", "busy", true); break;
        }

        /* If the manifest never applied -- wrong MIME type, 404, whatever -- no
           event ever arrives and the status stays UNCACHED. Fall back rather
           than leaving the bar spinning forever. */
        setTimeout(function () {
            if (settled || sawEvent) return;
            if (ac.status !== 0) return;
            info("manifest-not-applied");
            mode = "warm";
            run(false);
        }, 8000);
    }

    /* ------------------------------------------------------------ progress */

    function credit(url, delta) {
        var weight = C.SIZES[url] || 0;
        var was = credited[url] || 0;
        var now = Math.min(weight, was + delta);
        doneBytes += now - was;
        credited[url] = now;
    }

    function complete(url) {
        var weight = C.SIZES[url] || 0;
        var was = credited[url] || 0;
        doneBytes += weight - was;
        credited[url] = weight;
    }

    /* ------------------------------------------------------------ download */

    function copyHeaders(res) {
        try {
            return new Headers(res.headers);
        } catch (e) {
            var h = new Headers();
            var ct = res.headers.get("content-type");
            if (ct) h.set("content-type", ct);
            return h;
        }
    }

    /* Fetches url, reporting bytes as they land when the body is streamable, and
       resolves to a Response that is safe to hand to cache.put(). */
    async function download(url, force, onBytes) {
        /* The marker header makes sw.js ignore this request. Without it the
           worker would buffer the body to cache it itself, which both stores
           every asset twice and hides the byte-by-byte progress. */
        var init = { headers: { "x-slopkit-precache": "1" } };
        if (force) init.cache = "reload";
        var res = await fetch(url, init);
        if (!res.ok) throw new Error("HTTP " + res.status);

        var body = res.body;
        if (!body || typeof body.getReader !== "function") {
            var buf = await res.arrayBuffer();
            onBytes(buf.byteLength);
            return new Response(buf, { status: 200, headers: copyHeaders(res) });
        }

        var reader = body.getReader();
        var chunks = [];
        var total = 0;
        for (;;) {
            var r = await reader.read();
            if (r.done) break;
            chunks.push(r.value);
            total += r.value.length;
            onBytes(r.value.length);
        }
        var out = new Uint8Array(total);
        var off = 0;
        for (var i = 0; i < chunks.length; i++) {
            out.set(chunks[i], off);
            off += chunks[i].length;
        }
        return new Response(out, { status: 200, headers: copyHeaders(res) });
    }

    async function pool(items, worker) {
        var next = 0;
        var lanes = [];
        var n = Math.min(CONCURRENCY, items.length);
        for (var i = 0; i < n; i++) {
            lanes.push((async function () {
                for (;;) {
                    var idx = next++;
                    if (idx >= items.length) return;
                    await worker(items[idx]);
                }
            })());
        }
        await Promise.all(lanes);
    }

    /* ---------------------------------------------------------------- main */

    async function registerWorker() {
        if (!("serviceWorker" in navigator)) return false;
        try {
            var base = new URL(C.BASE);
            await navigator.serviceWorker.register(base.pathname + "sw.js",
                { scope: base.pathname });
            await navigator.serviceWorker.ready;
            return true;
        } catch (e) {
            return false;
        }
    }

    async function run(force) {
        if (running) return;
        running = true;
        failed = [];
        doneBytes = 0;
        credited = Object.create(null);

        var cache = null;
        if (self.caches) {
            try {
                cache = await caches.open(C.CACHE_NAME);
                mode = "cache";
            } catch (e) {
                cache = null;
            }
        }

        if (mode === "cache") {
            offline = await registerWorker();
        } else if (!force && warmFlag()) {
            /* No Cache API: assume the HTTP cache still holds the last warm-up
               rather than pulling several megabytes again on every visit. */
            doneBytes = C.TOTAL_BYTES;
            paint("warmed (not offline capable)", "done", true);
            running = false;
            return;
        }

        var todo = C.URLS.slice();
        if (cache && !force) {
            try {
                var have = await cache.keys();
                var present = Object.create(null);
                for (var i = 0; i < have.length; i++) {
                    present[C.normalize(have[i].url)] = true;
                }
                todo = todo.filter(function (u) {
                    if (!present[u]) return true;
                    complete(u);
                    return false;
                });
            } catch (e) { }
        }

        if (!todo.length) {
            doneBytes = C.TOTAL_BYTES;
            paint(doneLabel(), "done", true);
            running = false;
            return;
        }

        paint("caching...", "busy", true);

        await pool(todo, async function (url) {
            try {
                var res = await download(url, force, function (n) {
                    credit(url, n);
                    paint("caching " + mb(doneBytes) + " / "
                        + mb(C.TOTAL_BYTES) + " MB", "busy");
                });
                if (cache) await cache.put(url, res);
                complete(url);
            } catch (e) {
                failed.push(url);
                /* Roll this file's partial bytes back out so the bar never
                   claims progress for something that is not in the cache. */
                doneBytes -= credited[url] || 0;
                credited[url] = 0;
            }
            paint("caching " + mb(doneBytes) + " / " + mb(C.TOTAL_BYTES) + " MB",
                "busy");
        });

        if (failed.length) {
            paint(failed.length + " file" + (failed.length > 1 ? "s" : "")
                + " failed", "fail", true);
            retryButton("RETRY CACHE", function () { run(true); });
        } else {
            doneBytes = C.TOTAL_BYTES;
            if (mode === "warm") warmFlag(true);
            paint(doneLabel(), "done", true);
        }
        running = false;
    }

    function doneLabel() {
        if (offline) return "cached - offline ready";
        if (mode === "cache") return "cached (no worker, online only)";
        return "warmed (not offline capable)";
    }

    async function purge() {
        warmFlag(false);
        if (self.caches) {
            try {
                var names = await caches.keys();
                for (var i = 0; i < names.length; i++) {
                    if (names[i].indexOf(C.PREFIX) === 0) await caches.delete(names[i]);
                }
            } catch (e) { }
        }
        if ("serviceWorker" in navigator) {
            try {
                var regs = await navigator.serviceWorker.getRegistrations();
                for (var j = 0; j < regs.length; j++) {
                    if (regs[j].scope.indexOf(C.BASE) === 0) await regs[j].unregister();
                }
            } catch (e) { }
        }
        doneBytes = 0;
        credited = Object.create(null);
        /* An AppCache cannot be dropped from script -- only by the site serving
           a 404 for the manifest, or the kit's own appcache-remove tile. */
        paint(appCache() ? "cleared (appcache kept)" : "cache cleared", "", true);
    }

    self.SlopkitCache = {
        run: run,
        purge: purge,
        progress: function () { return doneBytes / (C.TOTAL_BYTES || 1); },
        mode: function () { return mode; }
    };

    function boot() {
        els = build();
        var q;
        try { q = new URLSearchParams(location.search); } catch (e) { q = null; }

        if (q && q.get("nocache") === "1") {
            purge();
            return;
        }
        paint("checking cache...", "busy", true);

        if (appCache()) {
            startAppCache();
            return;
        }
        run(!!(q && q.get("recache") === "1"));
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
