/* slopkit offline cache -- service worker.

   Deliberately minimal: it never precaches on its own (the page does that, so it
   can report progress) and it only answers for URLs listed in slopkit-cache.js.
   Anything else -- and any non-GET or cross-origin request -- is left completely
   untouched, so the exploit pages behave exactly as they do without a worker. */

importScripts("slopkit-cache.js");

var C = self.SLOPKIT_CACHE;

self.addEventListener("install", function () {
    self.skipWaiting();
});

self.addEventListener("activate", function (event) {
    event.waitUntil((async function () {
        var names = await caches.keys();
        await Promise.all(names.map(function (n) {
            if (n.indexOf(C.PREFIX) === 0 && n !== C.CACHE_NAME) {
                return caches.delete(n);
            }
            return Promise.resolve();
        }));
        await self.clients.claim();
    })());
});

self.addEventListener("fetch", function (event) {
    var req = event.request;
    if (req.method !== "GET") return;

    /* cache-ui.js marks its own precache fetches so they go straight to the
       network and it -- not this worker -- owns the write and the progress. */
    try {
        if (req.headers.get("x-slopkit-precache")) return;
    } catch (e) { }

    var key;
    try {
        var u = new URL(req.url);
        if (u.origin !== self.location.origin) return;
        key = C.normalize(req.url);
    } catch (e) {
        return;
    }
    if (C.SIZES[key] === undefined) return;

    event.respondWith((async function () {
        var cache = await caches.open(C.CACHE_NAME);
        var hit = await cache.match(key);
        if (hit) return hit;

        var res = await fetch(req);
        if (res && res.ok && res.type === "basic") {
            try { await cache.put(key, res.clone()); } catch (e) { }
        }
        return res;
    })());
});

self.addEventListener("message", function (event) {
    var data = event.data || {};
    if (data.type === "slopkit-cache-purge") {
        event.waitUntil((async function () {
            var names = await caches.keys();
            await Promise.all(names.map(function (n) {
                return n.indexOf(C.PREFIX) === 0 ? caches.delete(n) : Promise.resolve();
            }));
        })());
    }
});
