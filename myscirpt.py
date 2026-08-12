import sys
import time

import mad2_level

LEVEL = r"C:\Program Files (x86)\Activision\Madagascar 2(TM)\Content\Streams\win\penguins.bld"
OUT = "level.txt"


class Progress:
    """Minimal stderr progress bar (no third-party dependency)."""

    def __init__(self, total, width=40, stream=sys.stderr):
        self.total, self.width, self.stream = max(total, 1), width, stream
        self.n = 0
        self.start = time.monotonic()
        self._last = 0.0

    def update(self, n=1):
        self.n += n
        now = time.monotonic()
        if now - self._last < 0.1:          # throttle: redrawing is slow
            return
        self._last = now
        self._draw(now)

    def _draw(self, now):
        frac = min(self.n / self.total, 1.0)
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        self.stream.write("\r[%s] %d/%d (%.1f%%) %.1fs"
                          % (bar, self.n, self.total, frac * 100, now - self.start))
        self.stream.flush()

    def close(self):
        self._draw(time.monotonic())
        self.stream.write("\n")
        self.stream.flush()

MAX_PER_TREE_LEVEL = 700

def ptree(node, out, progress, indent=0, seen=None):
    if seen is None:
        seen = set()

    if not isinstance(node, mad2_level.Obj):
        return

    istr = indent * 4 * " "

    if node.offset in seen:
        out.write(f"{istr}{node.type} @{node.offset:#x} (already shown)\n")
        return
    seen.add(node.offset)
    progress.update()

    out.write(f"\n{istr}{node.type} @{node.offset:#x}\n")
    for fk, f in node.fields.items():
        if isinstance(f, mad2_level.Ref):
            target = node.resolve(f)
            if target is None:
                out.write(f"{istr}    - {fk}: <dangling ref {f.offset:#x}>\n")
            else:
                out.write(f"{istr}    - {fk} ->\n")
                ptree(target, out, progress, indent + 2, seen)
        else:
            out.write(f"{istr}    - {fk}: {f}\n")


    for child in node.children()[:MAX_PER_TREE_LEVEL]:
        ptree(child, out, progress, indent + 1, seen)

    if len(node.children()) > MAX_PER_TREE_LEVEL:
        out.write(f"*#*#*#*#*#*#*#*#*#*# CUTTOF AFTER {MAX_PER_TREE_LEVEL} igOBEJCTS *#*#*#*#*#*#*#*#*#*#")



sys.setrecursionlimit(20000)

arc, level = mad2_level.load(LEVEL)
print(f"{LEVEL}\n{len(level.objects)} objects -> {OUT}", file=sys.stderr)

progress = Progress(len(level.objects))
seen = set()
with open(OUT, "w", encoding="utf-8", buffering=1 << 20) as fh:
    ptree(level.root, fh, progress, 0, seen)
progress.close()

print(f"wrote {OUT}: {len(seen)} objects reachable from root "
      f"({len(level.objects) - len(seen)} not referenced)", file=sys.stderr)
