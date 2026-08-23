#!/usr/bin/env python3
"""Bump every ?v= cache-buster in the site, and check for version splits.

    python tools/bump-version.py          list versions + run the consistency check
    python tools/bump-version.py 107      bump everything to v=107

WHY THIS EXISTS
---------------
1. The PS5 browser caches by URL. A file you edited whose ?v= did not change is never
   re-fetched, so the fix looks applied on disk and does nothing on hardware. poops.js
   sat at ?v=77 through several edits exactly this way.

2. Worse: ES modules are keyed BY URL. If one file imports "./core.js?v=10" and the page
   imports "./core.js?v=106", the browser loads core.js TWICE as two separate instances
   with separate state. That is not theoretical - it broke poopsploit with
   "the (main, worker) pair was NOT promoted / mem: bad numeric address NaN", because
   mem.js held the old version while the page held the new one.

So: bump ALL of them together, and run the check before you ship.
"""
import re, sys, os, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (file, regex containing a group named 'v' around the digits)
TARGETS = [
    ("index.html",    r'\.html\?[^"]*?v=(?P<v>\d+)'),
    ("poops.html",    r'\.js\?v=(?P<v>\d+)'),
    ("p2jb.html",     r'\.js\?v=(?P<v>\d+)'),
    ("p2jb.js",       r'\bv=(?P<v>\d+)"'),
    # ES module imports inside .js files - the class that caused the split above.
    ("mem.js",        r'\.js\?v=(?P<v>\d+)'),
    ("core.js",       r'\.js\?v=(?P<v>\d+)'),
    ("poops.js",      r'\.js\?v=(?P<v>\d+)'),
    ("p2jb_poops.js", r'\.js\?v=(?P<v>\d+)'),
]

IMPORT_RE = re.compile(r'\./([A-Za-z0-9_.-]+\.js)\?v=(\d+)')

def check():
    """A module referenced at two different ?v= loads twice as separate instances."""
    seen = {}
    for f in glob.glob(os.path.join(ROOT, "*.js")) + glob.glob(os.path.join(ROOT, "*.html")):
        if "_frozen" in f:
            continue
        s = open(f, encoding="utf-8", errors="replace", newline="").read()
        for mod, v in IMPORT_RE.findall(s):
            seen.setdefault(mod, set()).add(v)
    bad = {m: vs for m, vs in seen.items() if len(vs) > 1}
    if bad:
        print("\n*** VERSION SPLIT - these modules would load TWICE, as separate instances:")
        for m, vs in sorted(bad.items()):
            print("      %-14s at v=%s" % (m, ", ".join(sorted(vs))))
        print("    Bump everything to one number before shipping.")
        return False
    print("\nconsistency: OK - no module is referenced at two different versions")
    return True

def main():
    if len(sys.argv) == 2 and sys.argv[1].isdigit():
        new, total = sys.argv[1], 0
        for f, pat in TARGETS:
            p = os.path.join(ROOT, f)
            if not os.path.exists(p):
                continue
            s = open(p, encoding="utf-8", errors="replace", newline="").read()
            s2, n = re.subn(pat, lambda m: m.group(0).replace(m.group("v"), new), s)
            if n:
                open(p, "w", encoding="utf-8", newline="").write(s2)
                print("  %-14s %2d marker(s) -> v=%s" % (f, n, new))
                total += n
        print("bumped %d markers to v=%s" % (total, new))
        print("NOTE: index.html sets the run's query string - the console has no address "
              "bar, so its links must carry the new v= too (they do).")
        return 0 if check() else 2
    print(__doc__)
    print("versions in use:")
    for f, pat in TARGETS:
        p = os.path.join(ROOT, f)
        if not os.path.exists(p):
            continue
        s = open(p, encoding="utf-8", errors="replace", newline="").read()
        vs = sorted(set(re.findall(pat.replace("(?P<v>", "("), s)))
        if vs:
            print("   %-14s v=%s" % (f, ", ".join(vs)))
    return 0 if check() else 2
if __name__ == "__main__":
    sys.exit(main())
