"""Generate cache.manifest for slopkit.

Same scheme as ntfonto2: walk the directory, and emit one line per file as

    path/to/file #<sha256 of the file>

The trailing "#..." is a manifest comment, so the browser ignores it when
resolving the URL. Its job is to change the manifest's own bytes whenever any
cached file changes -- that is what makes the console re-download the cache.
It replaces "?v=16" style cache-busting entirely, so asset URLs must stay
query-free or AppCache will not match them.

Deliberately no CACHE: / FALLBACK: / NETWORK: sections -- the implicit section
is the explicit (cache) one, exactly as in ntfonto2.

Usage:  python appcache_manifest_generator.py [directory]
"""
import argparse
import hashlib
import os

# Never cached: the manifest itself, and files the pages never request.
SKIP_NAMES = {"cache.manifest", "README.md", "readme.png",
              ".nojekyll", ".gitignore"}
# Stale duplicates of slopkit/poops.* that reference paths which do not resolve
# from the directory root; caching them would only waste quota.
SKIP_PATHS = {"poops.html", "poops.js"}


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def generate(directory):
    lines = ["CACHE MANIFEST"]
    total = 0
    for root, dirs, files in os.walk(directory):
        dirs.sort()
        for name in sorted(files):
            if name in SKIP_NAMES or name.endswith(".manifest"):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, directory).replace("\\", "/")
            if rel in SKIP_PATHS:
                continue
            lines.append(rel + " #" + file_hash(full))
            total += os.path.getsize(full)
    return lines, total


parser = argparse.ArgumentParser(description="Generate cache.manifest.")
parser.add_argument("directory_path", nargs="?", default="./",
                    help="Directory to generate the manifest for (default './').")
args = parser.parse_args()

manifest, total_bytes = generate(args.directory_path)
out = os.path.join(args.directory_path, "cache.manifest").replace("\\", "/")
with open(out, "w", newline="\n") as f:
    f.write("\n".join(manifest) + "\n")

print("%s: %d files, %.2f MB" % (out, len(manifest) - 1, total_bytes / 1048576.0))
