"""Time the main jobs, best of 3. Run: python bench/bench.py"""
import json, pathlib, struct, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import electron_xray as x


def best(fn, n=3):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return min(out) * 1000


chunk = "function f(a,b){return a.map(function(c){return c+b}).filter(Boolean)};var o={width:1,height:2};el.textContent=o.width;"
text = (chunk * (4 * 1048576 // len(chunk))) + "el.innerHTML=v;"
sink_ms = best(lambda: x.scan_text("big.js", text))

with tempfile.TemporaryDirectory() as d:
    path = pathlib.Path(d) / "app.asar"
    files, blob = {}, b""
    for i in range(2000):
        data = b"x" * 40
        files[f"f{i}.js"] = {"size": len(data), "offset": str(len(blob))}
        blob += data
    raw = json.dumps({"files": {"src": {"files": files}}}).encode()
    pad = (4 - len(raw) % 4) % 4
    pickle = struct.pack("<II", len(raw) + 4 + pad, len(raw)) + raw + b"\0" * pad
    path.write_bytes(struct.pack("<II", 4, len(pickle)) + pickle + blob)
    asar_ms = best(lambda: x.Asar(path))

demo_ms = best(lambda: x.audit(x.open_target(ROOT / "examples" / "unsafe-notes")))
print(f"find sinks in a 4 MB bundle: {sink_ms:.0f} ms")
print(f"parse a 2,000-entry app.asar: {asar_ms:.1f} ms")
print(f"audit the bundled example: {demo_ms:.1f} ms")
