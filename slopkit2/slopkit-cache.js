/* slopkit offline cache -- shared manifest.
   Loaded both as a plain <script> in the page and via importScripts() in sw.js,
   so it must not touch `window` or `document` unconditionally.

   Bump VERSION whenever any listed asset changes: the service worker drops
   every cache whose name starts with PREFIX but is not the current one. */
(function (g) {
    "use strict";

    var VERSION = "1";
    var PREFIX = "slopkit-";
    var CACHE_NAME = PREFIX + VERSION;

    /* [path relative to this directory, approximate size in bytes].
       Sizes only weight the progress bar, so a stale number is harmless. */
    var ASSETS = [
        ["index.html", 3076],

        ["slopkit/poops.html", 72503],
        ["slopkit/poops.js", 291750],
        ["slopkit/main.js", 43791],
        ["slopkit/core.js", 43220],
        ["slopkit/mem.js", 28202],
        ["slopkit/int64.js", 2787],
        ["slopkit/rop.js", 19165],
        ["slopkit/rop_slave.js", 89],
        ["slopkit/syscalls.js", 16469],
        ["slopkit/cat.jpg", 39942],
        ["slopkit/mmhmm-cats-ps5.gif", 1005802],

        ["offsets/9.00.js", 10769],
        ["offsets/9.20.js", 10455],
        ["offsets/9.40.js", 10455],
        ["offsets/9.60.js", 10455],
        ["offsets/10.00.js", 10455],
        ["offsets/10.01.js", 10455],
        ["offsets/10.20.js", 10455],
        ["offsets/10.40.js", 10455],
        ["offsets/10.60.js", 10455],
        ["offsets/11.00.js", 10455],
        ["offsets/11.20.js", 10455],
        ["offsets/11.40.js", 10455],
        ["offsets/11.60.js", 10455],
        ["offsets/12.00.js", 10455],

        ["payloads/kexp_2026_05_25.bin", 18912],
        ["payloads/elfldr-ps5-1360.elf", 397024],
        ["payloads/ftpsrv-ps5.elf", 191864],
        ["payloads/gdbsrv-ps5.elf", 174248],
        ["payloads/klogsrv-ps5.elf", 136016],
        ["payloads/kstuff.elf", 1572832],
        ["payloads/shsrv-ps5.elf", 986184],
        ["payloads/websrv-ps5.elf", 1597864],

        ["ui/payload-menu-title.png", 1610],
        ["ui/payload-ftp-default.png", 2872],
        ["ui/payload-ftp-sending.png", 2829],
        ["ui/payload-ftp-sent.png", 2812],
        ["ui/payload-ftp-failed.png", 2755],
        ["ui/payload-gdb-default.png", 3070],
        ["ui/payload-gdb-sending.png", 3057],
        ["ui/payload-gdb-sent.png", 3049],
        ["ui/payload-gdb-failed.png", 2982],
        ["ui/payload-klog-default.png", 3014],
        ["ui/payload-klog-sending.png", 2980],
        ["ui/payload-klog-sent.png", 2955],
        ["ui/payload-klog-failed.png", 2904],
        ["ui/payload-kstuff-default.png", 2784],
        ["ui/payload-kstuff-sending.png", 2691],
        ["ui/payload-kstuff-sent.png", 2681],
        ["ui/payload-kstuff-failed.png", 2610],
        ["ui/payload-shell-default.png", 2969],
        ["ui/payload-shell-sending.png", 2886],
        ["ui/payload-shell-sent.png", 2873],
        ["ui/payload-shell-failed.png", 2813],
        ["ui/payload-web-default.png", 3098],
        ["ui/payload-web-sending.png", 3089],
        ["ui/payload-web-sent.png", 3079],
        ["ui/payload-web-failed.png", 3018],

        ["document/en/ps5/index.html", 307]
    ];

    /* Directory this script lives in, as an absolute URL. */
    var BASE = (function () {
        try {
            if (typeof document !== "undefined" && document.currentScript
                && document.currentScript.src) {
                return new URL("./", document.currentScript.src).href;
            }
        } catch (e) { }
        try {
            if (typeof self !== "undefined" && self.registration
                && self.registration.scope) {
                return self.registration.scope;
            }
        } catch (e) { }
        return new URL("./", location.href).href;
    })();

    /* Cache keys ignore the query string, so "main.js?v=16" and "poops.html?go=1"
       both hit the entry stored for the bare path. A directory URL maps to its
       index.html so "/slopkit/" still resolves offline. */
    function normalize(url) {
        var u = new URL(url, BASE);
        var p = u.pathname;
        if (p.charAt(p.length - 1) === "/") p += "index.html";
        return u.origin + p;
    }

    var URLS = [];
    var SIZES = {};
    var TOTAL_BYTES = 0;
    for (var i = 0; i < ASSETS.length; i++) {
        var key = normalize(ASSETS[i][0]);
        if (SIZES[key] !== undefined) continue;
        URLS.push(key);
        SIZES[key] = ASSETS[i][1];
        TOTAL_BYTES += ASSETS[i][1];
    }

    g.SLOPKIT_CACHE = {
        VERSION: VERSION,
        PREFIX: PREFIX,
        CACHE_NAME: CACHE_NAME,
        BASE: BASE,
        URLS: URLS,
        SIZES: SIZES,
        TOTAL_BYTES: TOTAL_BYTES,
        normalize: normalize,
        owns: function (url) {
            try { return SIZES[normalize(url)] !== undefined; } catch (e) { return false; }
        }
    };
})(typeof self !== "undefined" ? self : this);
