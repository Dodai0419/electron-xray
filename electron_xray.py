#!/usr/bin/env python3
"""Check any Electron app for the holes that turn a bad web page into control of your PC, and map how it is built.

Reads the installed app. Never runs it, never changes it, and sends nothing anywhere.
"""
import argparse, html, json, mmap, os, pathlib, re, struct, sys

SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
FUSES = ("RunAsNode", "EnableCookieEncryption", "EnableNodeOptionsEnvironmentVariable", "EnableNodeCliInspectArguments", "EnableEmbeddedAsarIntegrityValidation", "OnlyLoadAppFromAsar", "LoadBrowserProcessSpecificV8Snapshot", "GrantFileProtocolExtraPrivileges")
TEXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".json"}
MAX_FILE, CAP_PER_RULE, SNIPPET = 40 << 20, 5, 140
ON, OFF = r"(?:true|!0|1)\b", r"(?:false|!1|0)\b"
VAR = r"(?![\"'`]|\s*[\"'`])"  # the value is not a plain string literal
ORDER = {"high": 0, "medium": 1, "low": 2, "review": 3}


class Refused(Exception):
    pass


def rx(p):
    return re.compile(p, re.I)


def nonliteral(prefix):
    """prefix( value, unless the value is one plain quoted string with nothing joined to it."""
    return re.compile(prefix + r"""\s*(?!(?:"[^"\n]*"|'[^'\n]*'|`[^`$\n]*`)\s*(?:[,;)\n}]|$))\S""")


LAYERS = {
    1: ("DOM and HTML injection", [nonliteral(r"\b(?:innerHTML|outerHTML)\s*\+?=(?!=)"), rx(r"\binsertAdjacentHTML\s*\("), nonliteral(r"\bdocument\.write(?:ln)?\s*\("), rx(r"\bparseFromString\s*\(|\bDOMParser\b"), rx(r"\bsetHTML(?:Unsafe)?\s*\("), rx(r"dangerouslySetInnerHTML"), rx(r"\bcreateContextualFragment\s*\(")]),
    2: ("Attributes and event handlers", [re.compile(r"""\bsetAttribute\s*\(\s*["'](?:on\w+|href|src|srcdoc|action|formaction|data|poster|style)["']\s*,\s*(?!["'`])""", re.I), rx(r"\bsrcdoc\s*=\s*\{"), rx(r"""\.srcdoc\s*=(?!=)""")]),
    3: ("URLs and navigation", [nonliteral(r"\bwindow\.open\s*\("), nonliteral(r"\blocation(?:\.href)?\s*=(?!=)"), nonliteral(r"\blocation\.(?:assign|replace)\s*\("), re.compile(r"""\.(?:includes|indexOf|startsWith)\s*\(\s*["'](?:https?:|[\w-]+\.(?:com|org|net|io))"""), re.compile(r"""\b(?:href|src|action|formAction)\s*=\s*\{\s*(?!["'`])""")]),
    4: ("Configuration and JSON in script", [rx(r"<script[^>]*>[^<]{0,200}JSON\.stringify\s*\("), rx(r"""<script[^>]*['"]?\s*\+\s*JSON\.stringify|<script[^'"`]{0,80}=['"`]?\s*['"`]?\s*\+\s*JSON\.stringify"""), rx(r"__(?:INITIAL_)?STATE__\s*=\s*['\"`]?\s*\+?\s*\$?\{?\s*JSON\.stringify")]),
    5: ("Props spreading and gadget components", [re.compile(r"<(?:a|iframe|embed|object|form|area|base|script|link)\s+\{\s*\.\.\.")]),
    6: ("Untrusted sources and messaging", [re.compile(r"""addEventListener\s*\(\s*["']message["'](?![^;]{0,400}\.origin)"""), re.compile(r"""\bpostMessage\s*\([^()]{0,200},\s*["']\*["']"""), rx(r"\bnew\s+(?:BroadcastChannel|MessageChannel)\b"), re.compile(r"\blocation\.(?:hash|search)\b"), re.compile(r"\bdocument\.(?:referrer|cookie)\b")]),
    7: ("Prototype pollution", [re.compile(r"""\[\s*["']__proto__["']\s*\]|\.__proto__\s*=(?!=)"""), re.compile(r"\b_\.(?:merge|mergeWith|defaultsDeep|set)\s*\("), re.compile(r"\$\.extend\s*\(\s*(?:true|!0)")]),
    8: ("JavaScript execution", [re.compile(r"(?<![.\w])eval\s*\(\s*(?![\"'`]\s*\w*[\"'`]\s*\))"), re.compile(r"""\bnew\s+Function\s*\((?!\s*["']return this["']\s*\))"""), re.compile(r"""\bset(?:Timeout|Interval)\s*\(\s*(?:["'`]|[\w.]+\s*\+)"""), rx(r"""createElement\s*\(\s*["']script["']"""), re.compile(r"\bimportScripts\s*\(\s*(?![\"'`])"), re.compile(r"\bexecuteJavaScript\s*\("), re.compile(r"\bnew\s+(?:Shared)?Worker\s*\(\s*URL\.createObjectURL")]),
    9: ("CSS and style injection", [nonliteral(r"\.cssText\s*\+?=(?!=)"), re.compile(r"""\.setProperty\s*\([^,()]{1,60},\s*(?!["'`])"""), re.compile(r"\.insertRule\s*\(\s*(?![\"'`])")]),
    10: ("SVG, MathML and XML", [re.compile(r"\bcreateElementNS\s*\([^,()]{1,80},\s*(?![\"'`])"), rx(r"""xlink:href"""), re.compile(r"<foreignObject\b"), re.compile(r"<annotation-xml\b")]),
    11: ("Markdown, sanitizers and mXSS", [re.compile(r"\bmarked(?:\.parse)?\s*\("), rx(r"""\bMarkdownIt\s*\(\s*\{[^}]{0,200}html\s*:\s*(?:true|!0)"""), re.compile(r"DOMPurify\.sanitize\s*\([^;]{0,200}(?:ADD_ATTR|ADD_TAGS|ALLOW_\w+|FORCE_BODY)"), re.compile(r"\bsanitizeHtml\s*\([^;]{0,200}allowedTags\s*:\s*(?:false|!1)")]),
    12: ("Framework trust hooks", [re.compile(r"\bv-html\b"), re.compile(r"\bbypassSecurityTrust\w*\s*\("), re.compile(r"\{@html\b"), re.compile(r"\bunsafeHTML\s*\(")]),
    13: ("Trusted Types and CSP", [re.compile(r"""createPolicy\s*\([^;]{0,120}create(?:HTML|Script|ScriptURL)\s*:\s*\(?\s*(\w+)\s*\)?\s*=>\s*\1\b""")]),
    14: ("Binding and template injection", [re.compile(r"\bng-bind-html\b|\$compile\s*\("), re.compile(r"\bHandlebars\.compile\s*\(\s*(?![\"'`])"), re.compile(r"\bx-html\b"), rx(r"""data-bind\s*=\s*["'][^"']{0,80}\bhtml\s*:"""), re.compile(r"\bVue\.compile\s*\(\s*(?![\"'`])"), re.compile(r"\bTemplate\.compile\s*\(|_\.template\s*\(\s*(?![\"'`])")]),
}
SECRET = re.compile(r"""\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{20,})\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----""")
RULES = (
    ("node-integration", "high", rf"\bnodeIntegration\s*:\s*{ON}", "A window can use Node.js directly", "Any script that lands in this window can run programs and read your files. Set nodeIntegration to false and move the work to a preload script."),
    ("node-integration-frames", "high", rf"\bnodeIntegration(?:InSubFrames|InWorker)\s*:\s*{ON}", "Frames or workers get Node.js", "Set nodeIntegrationInSubFrames and nodeIntegrationInWorker to false."),
    ("context-isolation-off", "high", rf"\bcontextIsolation\s*:\s*{OFF}", "Page scripts share a world with the preload script", "A page can tamper with the preload's objects. Set contextIsolation to true."),
    ("web-security-off", "high", rf"\bwebSecurity\s*:\s*{OFF}", "The same-origin policy is off", "Any page can read from any site. Remove webSecurity: false."),
    ("insecure-content", "high", rf"\ballowRunningInsecureContent\s*:\s*{ON}", "Scripts over plain HTTP are allowed", "Remove allowRunningInsecureContent."),
    ("remote-module", "high", rf"\benableRemoteModule\s*:\s*{ON}|require\s*\(\s*[\"']@electron/remote", "The remote module gives pages the main process", "Replace remote with narrow IPC handlers."),
    ("insecure-load", "high", r"""\.loadURL\s*\(\s*["'`]http://(?!localhost|127\.0\.0\.1)""", "The app loads a page over plain HTTP", "Anyone on the network can replace that page. Load it over HTTPS."),
    ("raw-bridge", "high", r"""exposeInMainWorld\s*\([^;]{0,240}(?:\{\s*ipcRenderer\b|ipcRenderer\s*:\s*\w*\.?ipcRenderer|\b(?:send|invoke|on)\s*:\s*\(?\s*\.\.\.\s*\w+\s*\)?\s*=>\s*\w*\.?ipcRenderer)""", "The preload hands pages the raw IPC channel", "The page can then call every handler in the app. Expose one function per action, each with a fixed channel name."),
    ("sandbox-off", "medium", rf"\bsandbox\s*:\s*{OFF}", "The renderer sandbox is off", "A browser bug in this window is not contained. Remove sandbox: false."),
    ("blink-features", "medium", r"\b(?:enableBlinkFeatures|experimentalFeatures)\s*:\s*(?:true|!0|[\"'`])", "Experimental browser features are on", "They are less tested. Remove them unless the app needs one."),
    ("open-external", "medium", r"""\bshell\.openExternal\s*\(\s*(?!["'`][^"'`$]*["'`]\s*\))""", "A variable URL reaches shell.openExternal", "A file: or custom-protocol link can start a program. Allow only https: after parsing the URL."),
    ("webview-node", "high", r"<webview[^>]{0,200}\bnodeintegration\b", "A webview tag has Node.js", "Remove the nodeintegration attribute."),
    ("webview-popups", "medium", r"<webview[^>]{0,200}\ballowpopups\b", "A webview can open new windows", "Remove allowpopups or handle new windows in the main process."),
    ("bypass-csp", "medium", rf"\bbypassCSP\s*:\s*{ON}", "A custom protocol skips the page's CSP", "Remove bypassCSP from registerSchemesAsPrivileged."),
    ("load-variable", "review", r"""\.loadURL\s*\(\s*(?!["'`])""", "A window loads a URL from a variable", "Check that an outside link cannot choose this URL."),
)
COMPILED = [(a, b, re.compile(c), d, e) for a, b, c, d, e in RULES]
LOOKS_LIKE_MAIN = re.compile(r"\bBrowserWindow\b|\bipcMain\b|require\(\s*[\"']electron[\"']")


LIBRARY = re.compile(r"(?:^|/)(?:jquery|lodash|underscore|react(?:-dom)?|vue|angular|moment|fabric|bootstrap|d3|three|highlight|marked|purify)(?:[.-][\w.-]*)?\.js$", re.I)


def is_vendor(name):
    name = name.replace("\\", "/")
    return "node_modules/" in name or name.startswith("vendor/") or "/vendor/" in name or bool(LIBRARY.search(name))


def commented(text, at):
    """True when the match sits on a line that starts with //."""
    return text[text.rfind("\n", 0, at) + 1:at].lstrip().startswith("//")


class Asar:
    """An app.asar, read in place. Files marked unpacked come from the folder beside it."""

    def __init__(self, path):
        self.path, self.entries = pathlib.Path(path), {}
        try:
            with open(path, "rb") as f:
                head = f.read(16)
                if len(head) < 16:
                    raise ValueError("too short")
                size, pickle_len, _, json_len = struct.unpack("<IIII", head)
                if size != 4 or json_len > self.path.stat().st_size or pickle_len > self.path.stat().st_size:
                    raise ValueError("bad header")
                tree = json.loads(f.read(json_len).decode("utf-8"))
            self.base = 8 + pickle_len
            stack = [("", tree)]
            while stack:
                prefix, node = stack.pop()
                for name, entry in node["files"].items():
                    full = f"{prefix}{name}"
                    if "files" in entry:
                        stack.append((full + "/", entry))
                    elif "size" in entry:
                        self.entries[full] = entry
        except (OSError, ValueError, KeyError, TypeError, AttributeError, struct.error) as e:
            raise Refused(f"{path} is not a readable asar file: {e}")

    label = property(lambda self: str(self.path))
    binary = None

    def names(self):
        return list(self.entries)

    def size(self, name):
        return int(self.entries[name].get("size", 0))

    def read(self, name):
        e = self.entries[name]
        if e.get("unpacked"):
            return (pathlib.Path(str(self.path) + ".unpacked") / name).read_bytes()
        with open(self.path, "rb") as f:
            f.seek(self.base + int(e["offset"]))
            return f.read(int(e["size"]))


class Folder:
    """Plain source or an unpacked app folder."""

    def __init__(self, path):
        self.path, self.files = pathlib.Path(path), {}
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in files:
                full = pathlib.Path(root) / f
                self.files[full.relative_to(path).as_posix()] = full

    label = property(lambda self: str(self.path))
    binary = None

    def names(self):
        return list(self.files)

    def size(self, name):
        return self.files[name].stat().st_size

    def read(self, name):
        return self.files[name].read_bytes()


def find_binary(folder):
    folder = pathlib.Path(folder)
    framework = folder / "Contents" / "Frameworks" / "Electron Framework.framework" / "Electron Framework"
    if framework.is_file():
        return framework
    try:
        items = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() not in (".dll", ".pak", ".dat", ".bin", ".json", ".txt", ".html", ".so", ".dylib", ".log", ".ini")]
    except OSError:
        return None
    for p in sorted(items, key=lambda p: -p.stat().st_size):
        if p.stat().st_size and read_fuses(p) is not None:
            return p
    return None


def read_fuses(path):
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            at = m.find(SENTINEL)
            if at < 0:
                return None
            at += len(SENTINEL)
            count = m[at + 1]
            states = m[at + 2:at + 2 + count]
    except (OSError, ValueError, IndexError):
        return None
    return {name: {0x31: True, 0x30: False}.get(st) for name, st in zip(FUSES, states)}


def open_target(path):
    p = pathlib.Path(path)
    if not p.exists():
        raise Refused(f"no such file or folder: {path}")
    if p.is_file():
        if p.suffix.lower() == ".asar":
            return Asar(p)
        if read_fuses(p) is not None:
            p = p.parent
        else:
            raise Refused(f"{path} is not an asar file or an Electron program")
    for res in (p / "resources", p / "Contents" / "Resources", p):
        if (res / "app.asar").is_file():
            t = Asar(res / "app.asar")
            t.binary = find_binary(p)
            return t
        if (res / "app").is_dir() and (res / "app" / "package.json").is_file():
            t = Folder(res / "app")
            t.binary = find_binary(p)
            return t
    t = Folder(p)
    if not [n for n in t.names() if pathlib.PurePosixPath(n).suffix in TEXT]:
        raise Refused(f"{path} has no app.asar and no source files to read")
    return t


def where(text, start, end):
    line = text.count("\n", 0, start) + 1
    a = max(start - 30, text.rfind("\n", 0, start) + 1)
    b = min(end + 70, a + SNIPPET)
    return line, " ".join(text[a:b].split())


def scan_text(name, text, vendor_cap=CAP_PER_RULE):
    """Sink matches for the 14 layers. A match is a place to read, not a confirmed bug."""
    hits = []
    for layer, (_, patterns) in LAYERS.items():
        seen = set()
        for pat in patterns:
            count = 0
            for m in pat.finditer(text):
                if m.start() in seen or commented(text, m.start()):
                    continue
                seen.add(m.start())
                count += 1
                if count <= vendor_cap:
                    line, snip = where(text, m.start(), m.end())
                    hits.append(dict(layer=layer, file=name, line=line, snippet=snip))
                else:
                    hits.append(dict(layer=layer, file=name, line=0, snippet="", capped=True))
    return hits


def mask(found):
    return found[:6] + "*" * 8


def audit(target, vendor=False):
    findings, layers, exclusions = [], {k: dict(title=v[0], matches=0) for k, v in LAYERS.items()}, []
    read = skipped_vendor = 0
    too_big = []
    has = dict(csp=False, nav=False, perm=False, main=False, html=False)
    pkg = load_pkg(target)
    seen = set()

    def add(rule_id, sev, title, why, file="", line=0, snippet=""):
        key = (rule_id, file, line)
        if key not in seen:
            seen.add(key)
            findings.append(dict(id=rule_id, severity=sev, title=title, why=why, file=file, line=line, snippet=snippet))

    for name in sorted(target.names()):
        suffix = pathlib.PurePosixPath(name).suffix.lower()
        if suffix not in TEXT:
            continue
        if is_vendor(name) and not vendor:
            skipped_vendor += 1
            continue
        if target.size(name) > MAX_FILE:
            too_big.append(name)
            continue
        try:
            text = target.read(name).decode("utf-8", "replace")
        except OSError:
            too_big.append(name)
            continue
        read += 1
        if suffix == ".json":
            continue
        for rule_id, sev, pat, title, why in COMPILED:
            for m in pat.finditer(text):
                if commented(text, m.start()) or (rule_id == "open-external" and ".protocol" in text[max(0, m.start() - 160):m.start()]):
                    continue
                line, snip = where(text, m.start(), m.end())
                add(rule_id, sev, title, why, name, line, snip)
        for m in list(SECRET.finditer(text))[:CAP_PER_RULE]:
            line = text.count("\n", 0, m.start()) + 1
            add("secret", "medium", "A key or password sits in the app's files", "Anyone with the app can read it. Move it to a server or the OS keychain, and replace this key.", name, line, mask(m.group(0)))
        for hit in scan_text(name, text):
            layers[hit["layer"]]["matches"] += 1
            if hit.get("capped"):
                continue
            add(f"layer-{hit['layer']}", "review", LAYERS[hit["layer"]][0], "Trace where this value comes from and whether it is cleaned for this context.", hit["file"], hit["line"], hit["snippet"])
        low = text.lower()
        if "content-security-policy" in low:
            has["csp"] = True
            for m in re.finditer(r"""content-security-policy[^>]{0,600}?'unsafe-(?:inline|eval)'""", low):
                line, snip = where(text, m.start(), m.end())
                add("weak-csp", "medium", "The CSP allows inline or eval scripts", "An injected script runs anyway. Remove unsafe-inline and unsafe-eval from script-src.", name, line, snip)
        if LOOKS_LIKE_MAIN.search(text):
            has["main"] = True
        has["nav"] = has["nav"] or "setWindowOpenHandler" in text or "will-navigate" in text
        has["perm"] = has["perm"] or "setPermissionRequestHandler" in text
        if suffix in (".html", ".htm"):
            has["html"] = True
    if has["html"] and not has["csp"]:
        add("no-csp", "medium", "No Content-Security-Policy was found", "Nothing limits what an injected script can load or run. Add a CSP to each page or response.")
    if has["main"] and not has["nav"]:
        add("no-nav-guard", "low", "No navigation or new-window guard was found", "A link could move a window to another site with the same access. Add will-navigate and setWindowOpenHandler handlers.")
    if has["main"] and not has["perm"]:
        add("no-permission-handler", "low", "No permission handler was found", "Sites shown in the app can get camera or location prompts by default. Add setPermissionRequestHandler.")

    fuses = read_fuses(target.binary) if target.binary else None
    if fuses:
        for fuse, value, rule, sev, title, why in (
            ("RunAsNode", True, "fuse-run-as-node", "medium", "The app can be run as plain Node.js", "Another program can use this signed binary to run its own code, through ELECTRON_RUN_AS_NODE. Turn the RunAsNode fuse off."),
            ("EnableNodeOptionsEnvironmentVariable", True, "fuse-node-options", "medium", "NODE_OPTIONS is honored", "An environment variable can load code into the app. Turn the fuse off."),
            ("EnableNodeCliInspectArguments", True, "fuse-inspect", "medium", "Debug flags are honored", "--inspect lets another program drive the app. Turn the fuse off."),
            ("EnableEmbeddedAsarIntegrityValidation", False, "fuse-asar-integrity", "low", "app.asar is not checked at startup", "Editing the file changes the app with no warning. Turn on asar integrity."),
            ("OnlyLoadAppFromAsar", False, "fuse-only-asar", "low", "The app can load from outside app.asar", "Turn on OnlyLoadAppFromAsar, or integrity checks can be skipped."),
        ):
            if fuses.get(fuse) is value:
                add(rule, sev, title, why, target.binary.name)
    else:
        exclusions.append("fuses: not checked, no Electron program was found beside this target")
    if skipped_vendor:
        exclusions.append(f"node_modules and vendor: {skipped_vendor} files skipped. Pass --vendor to read them")
    if too_big:
        exclusions.append(f"{len(too_big)} files could not be read or are over {MAX_FILE >> 20} MB: {', '.join(too_big[:5])}")
    ids = {f["id"] for f in findings}
    reach = "pc" if "node-integration" in ids else "bridge" if ids & {"raw-bridge", "context-isolation-off", "remote-module"} else "window"
    if reach == "pc":
        for f in findings:
            if f["id"].startswith("layer-") and f["id"] in ("layer-1", "layer-8"):
                f["severity"] = "high"
                f["why"] = "This window has Node.js, so script injection here means control of the PC. " + f["why"]
    findings.sort(key=lambda f: (ORDER[f["severity"]], f["id"] != "node-integration", f["id"], f["file"], f["line"]))
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ORDER}
    return dict(target=target.label, app=dict(name=pkg.get("productName") or pkg.get("name") or pathlib.Path(target.label).stem, version=pkg.get("version"), electron=electron_version(pkg, target)), reach=reach, findings=findings, counts=counts, layers=layers, fuses=fuses, exclusions=exclusions, files_read=read)


def load_pkg(target):
    try:
        data = json.loads(target.read("package.json").decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except (KeyError, OSError, ValueError):
        return {}


def electron_version(pkg, target):
    for group in ("devDependencies", "dependencies"):
        deps = pkg.get(group)
        if isinstance(deps, dict) and isinstance(deps.get("electron"), str):
            return deps["electron"].lstrip("^~")
    if target.binary and (target.binary.parent / "version").is_file():
        return (target.binary.parent / "version").read_text(encoding="utf-8", errors="replace").strip()[:20]
    return None


def build_map(target):
    """The app's skeleton, as a starting point for rebuilding it: pages, windows, IPC, menus, protocols."""
    pkg = load_pkg(target)
    out = dict(app=dict(name=pkg.get("productName") or pkg.get("name"), version=pkg.get("version"), main=pkg.get("main"), electron=electron_version(pkg, target)), pages=[], windows=[], ipc=set(), bridge=set(), menus=[], protocols=set(), native=[], dependencies={}, loads=set())
    for group in ("dependencies",):
        if isinstance(pkg.get(group), dict):
            out["dependencies"] = {k: str(v) for k, v in pkg[group].items()}
    for name in sorted(target.names()):
        suffix = pathlib.PurePosixPath(name).suffix.lower()
        if suffix == ".node":
            out["native"].append(name)
        if is_vendor(name) or suffix not in TEXT or suffix == ".json" or target.size(name) > MAX_FILE:
            continue
        if suffix in (".html", ".htm"):
            out["pages"].append(name)
            continue
        try:
            text = target.read(name).decode("utf-8", "replace")
        except OSError:
            continue
        out["ipc"].update(re.findall(r"""\bipc(?:Main|Renderer)\.(?:handle|handleOnce|on|once|invoke|send|sendSync)\s*\(\s*["'`]([^"'`]{1,100})["'`]""", text))
        out["bridge"].update(re.findall(r"""exposeInMainWorld\s*\(\s*["'`]([^"'`]{1,60})["'`]""", text))
        out["protocols"].update(re.findall(r"""setAsDefaultProtocolClient\s*\(\s*["'`]([^"'`]{1,60})["'`]""", text))
        out["loads"].update(re.findall(r"""\.load(?:URL|File)\s*\(\s*["'`]([^"'`]{1,200})["'`]""", text))
        for m in list(re.finditer(r"new\s+[\w.$]*BrowserWindow\s*\(\s*\{", text))[:40]:
            block = text[m.end():m.end() + 800]
            win = {}
            for key in ("width", "height", "minWidth", "minHeight"):
                v = re.search(rf"\b{key}\s*:\s*(\d+)", block)
                if v:
                    win[key] = int(v.group(1))
            t = re.search(r"""\btitle\s*:\s*["'`]([^"'`]{1,80})""", block)
            if t:
                win["title"] = t.group(1)
            out["windows"].append(dict(win, file=name))
        if LOOKS_LIKE_MAIN.search(text):
            for label in re.findall(r"""\blabel\s*:\s*["'`]([^"'`]{1,60})["'`]""", text):
                if label not in out["menus"]:
                    out["menus"].append(label)
    for key in ("ipc", "bridge", "protocols", "loads"):
        out[key] = sorted(out[key])
    return out


VERDICT = {"pc": "YES. A script injected into this app gets your whole PC.", "bridge": "PARTLY. A script injected into this app can reach past the page through its bridge.", "window": "NOT DIRECTLY. A script injected into this app stays inside its window, as far as this scan can see."}


def to_markdown(r):
    a, out = r["app"], []
    c = r["counts"]
    out += [f"# Electron audit: {a['name']}", "", f"Version {a['version'] or 'unknown'}, Electron {a['electron'] or 'unknown'}.", "", "> Static analysis only. A search match is not a confirmed vulnerability.", "", "## Executive Summary", "", f"**Can a bad web page reach your PC? {VERDICT[r['reach']]}**", "", f"High: {c['high']}. Medium: {c['medium']}. Low: {c['low']}. To review by hand: {c['review']}.", "", "## Audited paths", "", f"- `{r['target']}`, {r['files_read']} files read", "", "## Exclusions", ""]
    out += [f"- {e}" for e in r["exclusions"]] or ["- None"]
    for sev, head in (("high", "High Severity"), ("medium", "Medium Severity"), ("low", "Low Severity"), ("review", "Requires Manual Review")):
        items = [f for f in r["findings"] if f["severity"] == sev]
        out += ["", f"## {head}", ""]
        out += ["None."] if not items else []
        for f in items:
            place = f"`{f['file']}:{f['line']}`" if f["line"] else (f"`{f['file']}`" if f["file"] else "the whole app")
            out += [f"### {f['title']}", "", f"- **Where:** {place}", f"- **Why it matters:** {f['why']}"]
            if f["snippet"]:
                out += ["- **Code:**", "", "  ```text", "  " + f["snippet"].replace("`", "'"), "  ```"]
            out += [f"- **Rule:** `{f['id']}`. Status: not verified by running the app.", ""]
    out += ["## Fuses", ""]
    out += [f"- {k}: {v}" for k, v in r["fuses"].items()] if r["fuses"] else ["Not checked."]
    out += ["", "## Search Results Summary", "", "These are pattern matches, not confirmed vulnerabilities.", "", "| Layer | What it looks for | Matches |", "|---|---|---|"]
    out += [f"| {k} | {v['title']} | {v['matches']} |" for k, v in r["layers"].items()]
    return "\n".join(out) + "\n"


def to_card(r):
    colors = {"pc": "#e5484d", "bridge": "#f5a524", "window": "#30a46c"}
    word = {"pc": "Your whole PC", "bridge": "Past the page", "window": "Only its window"}
    e, c = html.escape, r["counts"]
    title = e(str(r["app"]["name"])[:40])
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="720" height="380" viewBox="0 0 720 380" font-family="Segoe UI,Helvetica,Arial,sans-serif">', '<rect width="720" height="380" rx="14" fill="#11151c"/>', f'<text x="36" y="58" font-size="26" font-weight="700" fill="#f2f4f8">{title}</text>', f'<text x="36" y="86" font-size="14" fill="#9aa3b2">Version {e(str(r["app"]["version"] or "unknown"))}, Electron {e(str(r["app"]["electron"] or "unknown"))}</text>', '<text x="36" y="132" font-size="15" fill="#9aa3b2">What an injected script can reach</text>', f'<text x="36" y="172" font-size="34" font-weight="700" fill="{colors[r["reach"]]}">{word[r["reach"]]}</text>']
    for i, (key, col) in enumerate((("high", "#e5484d"), ("medium", "#f5a524"), ("low", "#8b93a3"), ("review", "#5b8def"))):
        x = 36 + i * 166
        parts += [f'<rect x="{x}" y="204" width="150" height="86" rx="10" fill="#1b212c"/>', f'<text x="{x + 16}" y="248" font-size="32" font-weight="700" fill="{col}">{c[key]}</text>', f'<text x="{x + 16}" y="274" font-size="13" fill="#9aa3b2">{key if key != "review" else "to review"}</text>']
    parts += ['<text x="36" y="336" font-size="13" fill="#9aa3b2">Static scan. Matches are places to read, not confirmed bugs.</text>', '<text x="36" y="356" font-size="13" fill="#5f6878">electron-xray</text>', "</svg>"]
    return "\n".join(parts)


def print_report(r, full):
    a, c = r["app"], r["counts"]
    print(f"{a['name']} {a['version'] or ''}  Electron {a['electron'] or 'unknown'}  ({r['files_read']} files read)")
    print(f"\nCan a bad web page reach your PC?\n  {VERDICT[r['reach']]}\n")
    print(f"high {c['high']}   medium {c['medium']}   low {c['low']}   to review {c['review']}\n")
    groups = {}
    for f in r["findings"]:
        if f["severity"] != "review" or full:
            groups.setdefault((f["severity"], f["id"]), []).append(f)
    for (sev, _), items in groups.items():
        places = [f"{f['file']}:{f['line']}" if f["line"] else f["file"] or "whole app" for f in items]
        more = f" and {len(places) - 3} more" if len(places) > 3 else ""
        print(f"{sev.upper():7}{items[0]['title']}\n       {', '.join(places[:3])}{more}\n       {items[0]['why']}")
    if c["review"] and not full:
        top = [f"layer {k}: {v['matches']}" for k, v in r["layers"].items() if v["matches"]]
        print(f"\n{c['review']} places to read by hand ({', '.join(top[:6])}). Add --all or --report FILE to see them.")
    for e in r["exclusions"]:
        print(f"note: {e}")


def find_apps(roots):
    found = {}
    for root in roots:
        base = str(root)
        for here, dirs, files in os.walk(base):
            if here[len(base):].count(os.sep) > 5:
                dirs[:] = []
                continue
            if "app.asar" in files:
                dirs[:] = []
                found[pathlib.Path(here)] = None
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "$Recycle.Bin", "cache", "Cache")]
    rows = []
    for res in sorted(found):
        try:
            t = Asar(res / "app.asar")
        except Refused:
            continue
        pkg = load_pkg(t)
        rows.append((pkg.get("productName") or pkg.get("name") or res.parent.name, pkg.get("version") or "", str(res.parent)))
    return rows


def default_roots():
    env = os.environ.get
    roots = [env("ProgramFiles"), env("ProgramFiles(x86)"), env("LOCALAPPDATA"), "/Applications", str(pathlib.Path.home() / "Applications"), "/opt", "/usr/lib"]
    return [r for r in roots if r and os.path.isdir(r)]


def extract(target, out):
    out, wrote, refused = pathlib.Path(out).resolve(), 0, []
    for name in target.names():
        dest = (out / name.replace("\\", "/")).resolve()
        if out not in dest.parents:
            refused.append(name)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_bytes(target.read(name))
            wrote += 1
        except OSError as e:
            refused.append(f"{name} ({e})")
    return wrote, refused


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(prog="electron-xray", description=__doc__.splitlines()[0])
    ap.add_argument("--demo", action="store_true", help="audit the bundled, deliberately unsafe example")
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("audit", help="find the security holes")
    a.add_argument("target", help="an app folder, program, app.asar, or source folder")
    a.add_argument("--json", action="store_true"); a.add_argument("--all", action="store_true", help="also print every place to read by hand")
    a.add_argument("--report", metavar="FILE.md"); a.add_argument("--card", metavar="FILE.svg")
    a.add_argument("--vendor", action="store_true", help="also read node_modules")
    a.add_argument("--fail-on", choices=("high", "medium", "low"), help="exit 1 if a finding is this bad or worse")
    m = sub.add_parser("map", help="list its pages, windows, IPC channels, menus and protocols")
    m.add_argument("target"); m.add_argument("--json", action="store_true")
    x = sub.add_parser("extract", help="unpack app.asar into a folder")
    x.add_argument("target"); x.add_argument("-o", "--out", required=True)
    l = sub.add_parser("list", help="find Electron apps on this computer")
    l.add_argument("--root", action="append")
    args = ap.parse_args(argv)
    try:
        if args.demo:
            demo = pathlib.Path(__file__).resolve().parent / "examples" / "unsafe-notes"
            print_report(audit(open_target(demo)), False)
            return 0
        if args.cmd == "audit":
            r = audit(open_target(args.target), vendor=args.vendor)
            if args.report:
                pathlib.Path(args.report).write_text(to_markdown(r), encoding="utf-8")
            if args.card:
                pathlib.Path(args.card).write_text(to_card(r), encoding="utf-8")
            if args.json:
                print(json.dumps(r, indent=1, ensure_ascii=False, default=str))
            else:
                print_report(r, args.all)
            if args.fail_on and any(ORDER[f["severity"]] <= ORDER[args.fail_on] for f in r["findings"]):
                return 1
            return 0
        if args.cmd == "map":
            d = build_map(open_target(args.target))
            if args.json:
                print(json.dumps(d, indent=1, ensure_ascii=False))
            else:
                print_map(d)
            return 0
        if args.cmd == "extract":
            target = open_target(args.target)
            wrote, refused = extract(target, args.out)
            print(f"wrote {wrote} files to {args.out}")
            for name in refused:
                print(f"skipped {name}: it would land outside the folder or could not be written")
            return 0
        if args.cmd == "list":
            rows = find_apps(args.root or default_roots())
            for name, version, where_ in rows:
                print(f"{str(name)[:32]:<34}{str(version)[:14]:<16}{where_}")
            print(f"{len(rows)} Electron apps found")
            return 0
        ap.print_help()
        return 2
    except Refused as e:
        print(f"electron-xray: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"electron-xray: {e}", file=sys.stderr)
        return 2


def print_map(d):
    a = d["app"]
    print(f"{a['name']} {a['version'] or ''}  main: {a['main']}  Electron {a['electron'] or 'unknown'}")
    for head, items in (("Pages", d["pages"]), ("Loads", d["loads"]), ("IPC channels", d["ipc"]), ("Exposed to pages", d["bridge"]), ("Menus and labels", d["menus"][:60]), ("Link protocols", d["protocols"]), ("Native modules", d["native"])):
        print(f"\n{head} ({len(items)})")
        for item in items:
            print(f"  {item}")
    print(f"\nWindows ({len(d['windows'])})")
    for w in d["windows"]:
        print("  " + ", ".join(f"{k}={v}" for k, v in w.items()))
    print(f"\nDependencies ({len(d['dependencies'])})")
    for k, v in list(d["dependencies"].items())[:60]:
        print(f"  {k} {v}")


if __name__ == "__main__":
    sys.exit(main())
