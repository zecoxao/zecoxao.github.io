/* slopkit offline cache -- page side.

   Drives the precache itself (rather than letting the service worker do it on
   install) so every byte can be counted and shown as a percentage. Registers
   sw.js when available; if the browser has no service worker or no Cache API it
   degrades to simply warming the HTTP cache, and the percentage still works.

   Renders into #cache when that element exists, and appends a focusable retry
   button to #actions if anything failed. Requires slopkit-cache.js first.

   Query flags:  ?nocache=1  purge everything and unregister the worker
                 ?recache=1  force a fresh download of every asset */
(function () {
    "use strict";

    var C = self.SLOPKIT_CACHE;
    if (!C) return;

    var CONCURRENCY = 3;
    var WARM_FLAG = "slopkit-warmed-" + C.VERSION;

    var mode = "warm";          // "cache" once the Cache API is confirmed
    var offline = false;        // true once a service worker controls the scope
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
            + '<div class="cacheTrack"><div class="cacheFill"></div></div>';
        return {
            host: host,
            label: host.querySelector(".cacheLabel"),
            pct: host.querySelector(".cachePct"),
            fill: host.querySelector(".cacheFill")
        };
    }

    function mb(n) {
        return (n / 1048576).toFixed(1);
    }

    function paint(text, state, force) {
        if (!els) return;
        var now = Date.now();
        if (!force && now - lastPaint < 80) return;
        lastPaint = now;

        var frac = C.TOTAL_BYTES ? doneBytes / C.TOTAL_BYTES : 1;
        if (frac > 1) frac = 1;
        var pct = Math.floor(frac * 100);
        if (pct === 100 && doneBytes < C.TOTAL_BYTES) pct = 99;

        els.pct.textContent = pct + "%";
        els.fill.style.width = (frac * 100) + "%";
        els.label.textContent = text;
        els.host.className = state || "";
    }

    function retryButton() {
        if (document.getElementById("cacheRetry")) return;
        var actions = document.getElementById("actions");
        if (!actions) return;
        var a = document.createElement("a");
        a.id = "cacheRetry";
        a.className = "action secondary";
        a.href = "#";
        a.tabIndex = 0;
        a.textContent = "RETRY CACHE";
        a.addEventListener("click", function (e) {
            e.preventDefault();
            a.parentNode.removeChild(a);
            run(true);
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
            paint("cached (browser cache)", "done", true);
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
            paint(offline ? "cached - offline ready" : "cached", "done", true);
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
            retryButton();
        } else {
            doneBytes = C.TOTAL_BYTES;
            if (mode === "warm") warmFlag(true);
            paint(offline ? "cached - offline ready" : "cached", "done", true);
        }
        running = false;
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
        paint("cache cleared", "", true);
    }

    self.SlopkitCache = {
        run: run,
        purge: purge,
        progress: function () { return doneBytes / (C.TOTAL_BYTES || 1); }
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
        run(!!(q && q.get("recache") === "1"));
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
