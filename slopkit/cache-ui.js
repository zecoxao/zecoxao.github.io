/* slopkit offline cache -- progress readout.

   The caching itself is done entirely by AppCache: the manifest attribute on
   <html> points at cache.manifest, and the browser downloads every file listed
   there. This file only reports what the browser is doing, the same way
   ntfonto2 does, except drawn as an on-page bar instead of the window title.

   The PS5 browser has no service workers -- AppCache is the only offline
   mechanism it has, which is why main.js knows how to delete
   webkit/shell/appcache/ApplicationCache.db.

   Renders into #cache when that element exists; harmless when it does not. */
(function () {
    "use strict";

    var els = null;
    var frac = 0;
    var settled = false;
    var lastPaint = 0;
    var pendingPaint = null;
    var pendingTimer = 0;

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

        var f = Math.max(0, Math.min(1, frac));
        var pct = Math.floor(f * 100);
        if (pct === 100 && !settled) pct = 99;

        els.pct.textContent = pct + "%";
        els.fill.style.width = (f * 100) + "%";
        els.label.textContent = text;
        els.host.className = state || "";
        info();
    }

    /* --------------------------------------------------------- diagnostics */

    /* On a console there is no dev tools window, so this line is the only way
       to see what happened. The trail is persisted because the interesting run
       is the one BEFORE the reload that failed. */
    var TRAIL_KEY = "slopkit-trail";
    var AC_NAMES = ["uncached", "idle", "checking", "downloading",
                    "updateready", "obsolete"];
    var trail = [];

    function ac() {
        try {
            var a = self.applicationCache;
            return (a && typeof a.addEventListener === "function") ? a : null;
        } catch (e) {
            return null;
        }
    }

    function acStatus() {
        var a = ac();
        if (!a) return "-";
        return AC_NAMES[a.status] !== undefined ? AC_NAMES[a.status]
                                                : String(a.status);
    }

    function mark(step) {
        if (trail[trail.length - 1] === step) return;
        trail.push(step);
        try { localStorage.setItem(TRAIL_KEY, trail.join(">")); } catch (e) { }
        info();
    }

    function info() {
        if (!els) return;
        var bits = ["ac:" + acStatus()];
        if (trail.length) bits.push("now:" + trail.join(">"));
        else {
            var prev = "";
            try { prev = localStorage.getItem(TRAIL_KEY) || ""; } catch (e) { }
            if (prev) bits.push("last:" + prev);
        }
        els.info.textContent = bits.join("  ");
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
            settled = false;
            paint("retrying...", "busy", true);
            try { ac().update(); } catch (err) { }
        });
        actions.appendChild(a);
    }

    /* ---------------------------------------------------------------- main */

    /* Older WebKit fires progress events with no loaded/total. Counting the
       manifest's own entry lines gives a real denominator for that case; the
       manifest is implicitly part of its own cache group, so this still works
       offline. Best effort only. */
    function countManifest(cb) {
        var url = document.documentElement.getAttribute("manifest");
        if (!url || typeof fetch !== "function") return cb(0);
        try {
            fetch(url).then(function (r) {
                return r.ok ? r.text() : "";
            }).then(function (text) {
                var n = 0;
                var lines = text.split("\n");
                for (var i = 1; i < lines.length; i++) {
                    var s = lines[i].replace(/^\s+|\s+$/g, "");
                    if (s && s.charAt(0) !== "#" && s.slice(-1) !== ":") n++;
                }
                cb(n);
            })["catch"](function () { cb(0); });
        } catch (e) {
            cb(0);
        }
    }

    function start() {
        var a = ac();
        var loaded = 0;
        var total = 0;
        var manifestTotal = 0;

        countManifest(function (n) { manifestTotal = n; });

        function finish(label, state) {
            settled = true;
            frac = 1;
            paint(label, state, true);
        }

        function on(name, fn) {
            try { a.addEventListener(name, fn, false); } catch (e) { }
        }

        on("checking", function () {
            mark("chk");
            paint("checking cache...", "busy", true);
        });

        on("downloading", function () {
            mark("dl");
            paint("caching...", "busy", true);
        });

        on("progress", function (e) {
            if (e && e.total) {
                loaded = e.loaded;
                total = e.total;
            } else {
                loaded++;
                total = manifestTotal || 0;
                if (loaded > total) total = loaded;
            }
            frac = total ? loaded / total : 0;
            if (frac > 0.99) frac = 0.99;   /* 100% belongs to the cached event */
            /* Keep only the latest count in the trail, not one entry per file. */
            if (trail.length && trail[trail.length - 1].charAt(0) === "p") trail.pop();
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
            try { a.swapCache(); } catch (e) { }
            finish("updated - reload to apply", "done");
        });

        on("obsolete", function () {
            mark("obs");
            settled = true;
            frac = 0;
            paint("cache removed by server", "fail", true);
        });

        on("error", function () {
            /* AppCache is all-or-nothing and reports no reason. In practice it
               is a listed file that 404s, or the console refusing the total
               size -- either way nothing was cached. */
            mark("err");
            if (settled) return;
            settled = true;
            paint("cache failed - too big, or a file 404s", "fail", true);
            retryButton();
        });

        /* Status the page saw at boot, before any of our listeners could fire. */
        mark("s" + a.status);

        /* Keep the status text live; it changes without always firing an event
           we listen for. */
        var tick = setInterval(function () {
            info();
            if (settled) setTimeout(function () { clearInterval(tick); }, 3000);
        }, 1000);

        switch (a.status) {
            case 1: finish("cached - offline ready", "done"); return;
            case 4: finish("updated - reload to apply", "done"); return;
            case 5: paint("cache removed by server", "fail", true); return;
            case 2:
            case 3: paint("caching...", "busy", true); return;
            default: paint("checking cache...", "busy", true); return;
        }
    }

    function boot() {
        els = build();
        if (!ac()) {
            paint("no offline cache support", "", true);
            return;
        }
        paint("checking cache...", "busy", true);
        start();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
