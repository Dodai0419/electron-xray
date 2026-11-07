import json, os, pathlib, struct, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import electron_xray as x

SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"


def make_asar(path, files, unpacked=()):
    """Write a real asar: pickle header, JSON index, then file bytes."""
    tree, blob = {"files": {}}, b""
    for name, data in files.items():
        data = data.encode() if isinstance(data, str) else data
        node = tree
        parts = name.split("/")
        for part in parts[:-1]:
            node = node["files"].setdefault(part, {"files": {}})
        entry = {"size": len(data)}
        if name in unpacked:
            entry["unpacked"] = True
        else:
            entry["offset"] = str(len(blob))
            blob += data
        node["files"][parts[-1]] = entry
    raw = json.dumps(tree).encode()
    pad = (4 - len(raw) % 4) % 4
    pickle = struct.pack("<II", len(raw) + 4 + pad, len(raw)) + raw + b"\0" * pad
    pathlib.Path(path).write_bytes(struct.pack("<II", 4, len(pickle)) + pickle + blob)


BAD_MAIN = """
const {app, BrowserWindow, ipcMain, shell, Menu} = require('electron');
app.setAsDefaultProtocolClient('acme');
function go(){ const w = new BrowserWindow({width:900,height:600,title:'Acme',webPreferences:{nodeIntegration:true,contextIsolation:false,webSecurity:false,preload:'p.js'}});
w.loadURL('http://example.com/app'); ipcMain.handle('notes:save', (e, a) => a); ipcMain.on('notes:delete', () => {});
w.webContents.on('new-window', (e, url) => shell.openExternal(url)); Menu.buildFromTemplate([{label:'Open Note'},{label:'Export'}]); }
"""
GOOD_MAIN = """
const {app, BrowserWindow, session, shell} = require('electron');
const w = new BrowserWindow({webPreferences:{contextIsolation:true,sandbox:true,preload:'p.js'}});
w.loadFile('index.html');
w.webContents.setWindowOpenHandler(() => ({action:'deny'}));
w.webContents.on('will-navigate', e => e.preventDefault());
session.defaultSession.setPermissionRequestHandler((a,b,c) => c(false));
"""
GOOD_HTML = "<html><head><meta http-equiv='Content-Security-Policy' content=\"default-src 'self'\"></head><body></body></html>"


def cli(*args):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "PYTHONIOENCODING")}
    return subprocess.run([sys.executable, str(ROOT / "electron_xray.py"), *map(str, args)], capture_output=True, encoding="utf-8", errors="replace", env=env)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def audit_files(self, files, **kw):
        p = self.d / "app.asar"
        make_asar(p, {"package.json": json.dumps({"name": "t", "version": "1.0.0", "main": "main.js"}), **files})
        return x.audit(x.open_target(p), **kw)

    def ids(self, report):
        return {f["id"] for f in report["findings"]}


class Asar(Base):
    def test_reads_nested_files(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": "{}", "src/deep/main.js": "hello"})
        t = x.open_target(p)
        self.assertEqual(sorted(t.names()), ["package.json", "src/deep/main.js"])
        self.assertEqual(t.read("src/deep/main.js"), b"hello")

    def test_unpacked_files_come_from_the_side_folder(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": "{}", "x/n.node": "BIN"}, unpacked=("x/n.node",))
        side = self.d / "a.asar.unpacked" / "x"
        side.mkdir(parents=True)
        (side / "n.node").write_bytes(b"BIN")
        self.assertEqual(x.open_target(p).read("x/n.node"), b"BIN")

    def test_damaged_asar_is_refused_not_a_traceback(self):
        for data in (b"", b"short", struct.pack("<II", 4, 99999999) + b"x" * 40, struct.pack("<IIII", 4, 12, 8, 4) + b"{bad"):
            p = self.d / "d.asar"
            p.write_bytes(data)
            with self.assertRaises(x.Refused):
                x.open_target(p)

    def test_extract_writes_files_and_never_leaves_the_folder(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": "{}", "a/b.js": "ok", "../evil.js": "no", "..\\win.js": "no"})
        out = self.d / "out"
        self.assertEqual(cli("extract", p, "-o", out).returncode, 0)
        self.assertEqual((out / "a" / "b.js").read_text(), "ok")
        self.assertFalse((self.d / "evil.js").exists())
        self.assertFalse((self.d / "win.js").exists())


class Rules(Base):
    def test_bad_config_is_found_and_reach_is_whole_pc(self):
        r = self.audit_files({"main.js": BAD_MAIN, "index.html": "<html></html>"})
        for rule in ("node-integration", "context-isolation-off", "web-security-off", "insecure-load", "open-external", "no-csp", "no-nav-guard"):
            self.assertIn(rule, self.ids(r))
        self.assertEqual(r["reach"], "pc")

    def test_minified_booleans_count(self):
        r = self.audit_files({"main.js": "new a.BrowserWindow({webPreferences:{nodeIntegration:!0,contextIsolation:!1}})"})
        self.assertIn("node-integration", self.ids(r))
        self.assertIn("context-isolation-off", self.ids(r))

    def test_explicit_false_is_not_a_finding(self):
        r = self.audit_files({"main.js": "new BrowserWindow({webPreferences:{nodeIntegration:false,contextIsolation:true,webSecurity:true}})"})
        self.assertFalse(self.ids(r) & {"node-integration", "context-isolation-off", "web-security-off"})

    def test_good_app_has_no_high_and_window_only_reach(self):
        r = self.audit_files({"main.js": GOOD_MAIN, "index.html": GOOD_HTML})
        self.assertEqual([f for f in r["findings"] if f["severity"] == "high"], [])
        self.assertEqual(r["reach"], "window")

    def test_raw_ipc_bridge_is_high_and_named(self):
        r = self.audit_files({"preload.js": "contextBridge.exposeInMainWorld('api',{ipcRenderer})"})
        self.assertIn("raw-bridge", self.ids(r))
        self.assertEqual(r["reach"], "bridge")

    def test_literal_open_external_is_quiet(self):
        r = self.audit_files({"main.js": "shell.openExternal('https://example.com')"})
        self.assertNotIn("open-external", self.ids(r))

    def test_vendor_code_is_skipped_by_default_and_counted(self):
        files = {"main.js": GOOD_MAIN, "node_modules/lib/x.js": "el.innerHTML = user"}
        r = self.audit_files(files)
        self.assertEqual(r["layers"][1]["matches"], 0)
        self.assertIn("node_modules", " ".join(r["exclusions"]))
        r2 = self.audit_files(files, vendor=True)
        self.assertEqual(r2["layers"][1]["matches"], 1)

    def test_secrets_are_masked_in_every_output(self):
        secret = "AKIAIOSFODNN7ABCDEFG"
        r = self.audit_files({"main.js": f"const k = '{secret}';"})
        self.assertIn("secret", self.ids(r))
        self.assertNotIn(secret, json.dumps(r))
        self.assertNotIn(secret, x.to_markdown(r))

    def test_csp_with_unsafe_inline_is_flagged(self):
        r = self.audit_files({"index.html": "<meta http-equiv='Content-Security-Policy' content=\"script-src 'unsafe-inline'\">"})
        self.assertIn("weak-csp", self.ids(r))

    def test_commented_out_code_is_ignored(self):
        r = self.audit_files({"main.js": "// webPreferences: {nodeIntegration: true}\n  // el.innerHTML = v\n/* */"})
        self.assertNotIn("node-integration", self.ids(r))
        self.assertEqual(r["layers"][1]["matches"], 0)

    def test_url_scheme_check_before_open_external_is_quiet(self):
        r = self.audit_files({"main.js": "if (new URL(u).protocol === 'https:') shell.openExternal(u)"})
        self.assertNotIn("open-external", self.ids(r))

    def test_known_libraries_count_as_vendor(self):
        r = self.audit_files({"view/js/lib/jquery.min.js": "el.innerHTML = v", "view/app.js": "new Function('return this')()"})
        self.assertEqual(r["layers"][1]["matches"], 0)
        self.assertEqual(r["layers"][8]["matches"], 0)

    def test_finding_has_line_and_snippet(self):
        r = self.audit_files({"main.js": "// one\n// two\nnew BrowserWindow({webPreferences:{nodeIntegration:true}})"})
        f = [f for f in r["findings"] if f["id"] == "node-integration"][0]
        self.assertEqual((f["file"], f["line"]), ("main.js", 3))
        self.assertIn("nodeIntegration", f["snippet"])

    def test_huge_minified_line_gives_short_snippet(self):
        r = self.audit_files({"main.js": "a" * 500000 + "el.innerHTML=user;" + "b" * 500000})
        f = [f for f in r["findings"] if f["id"].startswith("layer-1")][0]
        self.assertLess(len(f["snippet"]), 200)


class Layers(Base):
    """Every sink family named in xss-audit's 14 layers must be seen."""
    SAMPLES = {
        1: ["el.innerHTML = v", "el.outerHTML = v", "el.insertAdjacentHTML('beforeend', v)", "document.write(v)", "new DOMParser().parseFromString(v,'text/html')", "el.setHTMLUnsafe(v)", "<div dangerouslySetInnerHTML={{__html: v}}/>", "r.createContextualFragment(v)"],
        2: ["el.setAttribute('onclick', v)", "el.setAttribute('href', v)", "<iframe srcdoc={v}/>", "el.setAttribute('formaction', v)"],
        3: ["window.open(v)", "location.href = v", "location.assign(v)", "location.replace(v)", "if (url.includes('trusted.com')) go()", "<a href={v}>x</a>"],
        4: ["'<script>window.__STATE__=' + JSON.stringify(v) + '</script>'", "<script type='application/ld+json'>${JSON.stringify(v)}</script>"],
        5: ["<a {...props}>x</a>", "<iframe {...rest}/>"],
        6: ["window.addEventListener('message', e => use(e.data))", "w.postMessage(v, '*')", "new BroadcastChannel('x')", "const q = location.hash", "const r = document.referrer"],
        7: ["o['__proto__'] = v", "_.merge(a, v)", "_.defaultsDeep(a, v)", "$.extend(true, a, v)"],
        8: ["eval(v)", "new Function(v)", "setTimeout(v + 'x')", "setTimeout('run()', 1)", "s.src = v; document.createElement('script')", "importScripts(v)", "wc.executeJavaScript(v)", "new Worker(URL.createObjectURL(b))"],
        9: ["el.style.cssText = v", "el.style.setProperty('x', v)", "sheet.insertRule(v)"],
        10: ["document.createElementNS(ns, v)", "el.setAttribute('xlink:href', v)", "<foreignObject>x</foreignObject>", "<annotation-xml>x</annotation-xml>"],
        11: ["marked(v)", "marked.parse(v)", "new MarkdownIt({html: true})", "DOMPurify.sanitize(v, {ADD_ATTR: ['onclick']})", "sanitizeHtml(v, {allowedTags: false})"],
        12: ["<div v-html='v'></div>", "s.bypassSecurityTrustHtml(v)", "{@html v}", "unsafeHTML(v)"],
        13: ["trustedTypes.createPolicy('x', {createHTML: s => s})"],
        14: ["<div ng-bind-html='v'></div>", "$compile(v)", "Handlebars.compile(v)", "<div x-html='v'></div>", "<div data-bind='html: v'></div>", "Vue.compile(v)"],
    }

    def test_all_fourteen_layers_exist(self):
        self.assertEqual(sorted(x.LAYERS), list(range(1, 15)))

    def test_every_sample_is_found_in_its_layer(self):
        for layer, samples in self.SAMPLES.items():
            for sample in samples:
                hits = x.scan_text("a.tsx", sample, vendor_cap=99)
                self.assertTrue(any(h["layer"] == layer for h in hits), f"layer {layer}: {sample}")

    def test_static_strings_do_not_match(self):
        for safe in ("el.innerHTML = '<b>x</b>'", "window.open('https://a.example')", "location.href = '/home'", "el.innerHTML = ''", "setTimeout(run, 1)"):
            hits = [h for h in x.scan_text("a.js", safe, vendor_cap=99) if h["layer"] in (1, 3, 8)]
            self.assertEqual(hits, [], safe)

    def test_message_listener_with_origin_check_is_quiet(self):
        safe = "addEventListener('message', e => { if (e.origin !== 'https://a.example') return; use(e.data) })"
        self.assertFalse([h for h in x.scan_text("a.js", safe, vendor_cap=99) if "message" in h["snippet"]])

    def test_plain_source_folder_works_like_upstream(self):
        src = self.d / "src"
        src.mkdir()
        (src / "App.tsx").write_text("export const A = v => <div dangerouslySetInnerHTML={{__html: v}}/>", encoding="utf-8")
        (src / "node_modules").mkdir()
        (src / "node_modules" / "skip.js").write_text("el.innerHTML = v", encoding="utf-8")
        r = x.audit(x.open_target(src))
        self.assertEqual(r["layers"][1]["matches"], 1)


class Fuses(Base):
    def exe(self, states, name="app.exe"):
        p = self.d / "App" / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(b"MZ" + b"x" * 100 + SENTINEL + bytes([1, len(states)]) + states + b"tail")
        res = p.parent / "resources"
        res.mkdir(exist_ok=True)
        make_asar(res / "app.asar", {"package.json": "{}", "main.js": GOOD_MAIN})
        return p.parent

    def test_reads_fuses_from_the_binary_in_order(self):
        app = self.exe(b"10101010")
        r = x.audit(x.open_target(app))
        self.assertEqual(r["fuses"]["RunAsNode"], True)
        self.assertEqual(r["fuses"]["EnableCookieEncryption"], False)
        self.assertIn("fuse-run-as-node", self.ids(r))

    def test_hardened_binary_has_no_fuse_findings(self):
        app = self.exe(b"01001101")
        r = x.audit(x.open_target(app))
        self.assertFalse([i for i in self.ids(r) if i.startswith("fuse-")])

    def test_no_binary_says_not_checked(self):
        r = self.audit_files({"main.js": GOOD_MAIN})
        self.assertIsNone(r["fuses"])
        self.assertTrue(any("fuses" in e for e in r["exclusions"]))


class Map(Base):
    def test_map_lists_what_an_agent_needs_to_rebuild_it(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": json.dumps({"name": "acme", "version": "2.1.0", "main": "main.js", "dependencies": {"marked": "4.0.0"}}), "main.js": BAD_MAIN, "preload.js": "ipcRenderer.invoke('notes:load')", "pages/index.html": "<title>Acme</title>", "pages/settings.html": "<title>Settings</title>", "x/n.node": "BIN"})
        m = x.build_map(x.open_target(p))
        self.assertEqual(m["app"]["name"], "acme")
        self.assertEqual(sorted(m["pages"]), ["pages/index.html", "pages/settings.html"])
        self.assertEqual(sorted(m["ipc"]), ["notes:delete", "notes:load", "notes:save"])
        self.assertEqual(m["windows"][0]["width"], 900)
        self.assertEqual(m["protocols"], ["acme"])
        self.assertIn("Open Note", m["menus"])
        self.assertEqual(m["native"], ["x/n.node"])
        self.assertEqual(m["dependencies"]["marked"], "4.0.0")


class Cli(Base):
    def test_demo_runs(self):
        r = cli("--demo")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("whole PC", r.stdout)

    def test_report_card_and_json(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": "{}", "main.js": BAD_MAIN + "\nel.innerHTML = '<x>☃' + v"})
        md, svg = self.d / "r.md", self.d / "c.svg"
        r = cli("audit", p, "--report", md, "--card", svg)
        self.assertEqual(r.returncode, 0, r.stderr)
        text = md.read_text(encoding="utf-8")
        for part in ("Executive Summary", "Audited paths", "Exclusions", "Search Results Summary", "not a confirmed"):
            self.assertIn(part, text)
        self.assertIn("<svg", svg.read_text(encoding="utf-8"))
        j = cli("audit", p, "--json")
        self.assertEqual(json.loads(j.stdout)["reach"], "pc")

    def test_fail_on_high_exit_code(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": "{}", "main.js": BAD_MAIN})
        self.assertEqual(cli("audit", p, "--fail-on", "high").returncode, 1)
        make_asar(p, {"package.json": "{}", "main.js": GOOD_MAIN})
        self.assertEqual(cli("audit", p, "--fail-on", "high").returncode, 0)

    def test_bad_targets_exit_2_without_traceback(self):
        empty = self.d / "empty"
        empty.mkdir()
        bad = self.d / "bad.asar"
        bad.write_bytes(b"junk")
        for args in (("audit", self.d / "none"), ("audit", empty), ("audit", bad), ("map", bad), ("extract", bad, "-o", self.d / "o")):
            r = cli(*args)
            self.assertEqual(r.returncode, 2, args)
            self.assertNotIn("Traceback", r.stderr)

    def test_card_escapes_app_names(self):
        p = self.d / "a.asar"
        make_asar(p, {"package.json": json.dumps({"name": "<script>x</script>"}), "main.js": GOOD_MAIN})
        svg = self.d / "c.svg"
        cli("audit", p, "--card", svg)
        self.assertNotIn("<script>", svg.read_text(encoding="utf-8"))

    def test_list_runs_and_finds_a_given_root(self):
        app = self.d / "Apps" / "Foo" / "resources"
        app.mkdir(parents=True)
        make_asar(app / "app.asar", {"package.json": json.dumps({"name": "foo", "version": "1.2.3"})})
        r = cli("list", "--root", self.d / "Apps")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("foo", r.stdout)


if __name__ == "__main__":
    unittest.main()
