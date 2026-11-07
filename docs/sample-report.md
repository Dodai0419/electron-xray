# Electron audit: Unsafe Notes

Version 1.4.0, Electron 28.2.0.

> Static analysis only. A search match is not a confirmed vulnerability.

## Executive Summary

**Can a bad web page reach your PC? YES. A script injected into this app gets your whole PC.**

High: 4. Medium: 3. Low: 2. To review by hand: 3.

## Audited paths

- `examples\unsafe-notes`, 4 files read

## Exclusions

- fuses: not checked, no Electron program was found beside this target

## High Severity

### Page scripts share a world with the preload script

- **Where:** `main.js:12`
- **Why it matters:** A page can tamper with the preload's objects. Set contextIsolation to true.
- **Code:**

  ```text
  ces: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false }, }); win.loadFile('index.ht
  ```
- **Rule:** `context-isolation-off`. Status: not verified by running the app.

### DOM and HTML injection

- **Where:** `renderer.js:6`
- **Why it matters:** This window has Node.js, so script injection here means control of the PC. Trace where this value comes from and whether it is cleaned for this context.
- **Code:**

  ```text
  cument.getElementById('note').innerHTML = marked(text); } window.addEventListener('message', (event) => show(even
  ```
- **Rule:** `layer-1`. Status: not verified by running the app.

### A window can use Node.js directly

- **Where:** `main.js:12`
- **Why it matters:** Any script that lands in this window can run programs and read your files. Set nodeIntegration to false and move the work to a preload script.
- **Code:**

  ```text
  webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false }, });
  ```
- **Rule:** `node-integration`. Status: not verified by running the app.

### The same-origin policy is off

- **Where:** `main.js:12`
- **Why it matters:** Any page can read from any site. Remove webSecurity: false.
- **Code:**

  ```text
  rue, contextIsolation: false, webSecurity: false, sandbox: false }, }); win.loadFile('index.html'); win.webConte
  ```
- **Rule:** `web-security-off`. Status: not verified by running the app.


## Medium Severity

### No Content-Security-Policy was found

- **Where:** the whole app
- **Why it matters:** Nothing limits what an injected script can load or run. Add a CSP to each page or response.
- **Rule:** `no-csp`. Status: not verified by running the app.

### A variable URL reaches shell.openExternal

- **Where:** `main.js:15`
- **Why it matters:** A file: or custom-protocol link can start a program. Allow only https: after parsing the URL.
- **Code:**

  ```text
  'new-window', (event, url) => shell.openExternal(url)); Menu.setApplicationMenu(Menu.buildFromTemplate([ { label:
  ```
- **Rule:** `open-external`. Status: not verified by running the app.

### The renderer sandbox is off

- **Where:** `main.js:12`
- **Why it matters:** A browser bug in this window is not contained. Remove sandbox: false.
- **Code:**

  ```text
  n: false, webSecurity: false, sandbox: false }, }); win.loadFile('index.html'); win.webContents.on('new-wind
  ```
- **Rule:** `sandbox-off`. Status: not verified by running the app.


## Low Severity

### No navigation or new-window guard was found

- **Where:** the whole app
- **Why it matters:** A link could move a window to another site with the same access. Add will-navigate and setWindowOpenHandler handlers.
- **Rule:** `no-nav-guard`. Status: not verified by running the app.

### No permission handler was found

- **Where:** the whole app
- **Why it matters:** Sites shown in the app can get camera or location prompts by default. Add setPermissionRequestHandler.
- **Rule:** `no-permission-handler`. Status: not verified by running the app.


## Requires Manual Review

### Markdown, sanitizers and mXSS

- **Where:** `renderer.js:6`
- **Why it matters:** Trace where this value comes from and whether it is cleaned for this context.
- **Code:**

  ```text
  ementById('note').innerHTML = marked(text); } window.addEventListener('message', (event) => show(event.data
  ```
- **Rule:** `layer-11`. Status: not verified by running the app.

### Untrusted sources and messaging

- **Where:** `renderer.js:8`
- **Why it matters:** Trace where this value comes from and whether it is cleaned for this context.
- **Code:**

  ```text
  window.addEventListener('message', (event) => show(event.data)); show(location.hash.slice(1));
  ```
- **Rule:** `layer-6`. Status: not verified by running the app.

### Untrusted sources and messaging

- **Where:** `renderer.js:9`
- **Why it matters:** Trace where this value comes from and whether it is cleaned for this context.
- **Code:**

  ```text
  show(location.hash.slice(1));
  ```
- **Rule:** `layer-6`. Status: not verified by running the app.

## Fuses

Not checked.

## Search Results Summary

These are pattern matches, not confirmed vulnerabilities.

| Layer | What it looks for | Matches |
|---|---|---|
| 1 | DOM and HTML injection | 1 |
| 2 | Attributes and event handlers | 0 |
| 3 | URLs and navigation | 0 |
| 4 | Configuration and JSON in script | 0 |
| 5 | Props spreading and gadget components | 0 |
| 6 | Untrusted sources and messaging | 2 |
| 7 | Prototype pollution | 0 |
| 8 | JavaScript execution | 0 |
| 9 | CSS and style injection | 0 |
| 10 | SVG, MathML and XML | 0 |
| 11 | Markdown, sanitizers and mXSS | 1 |
| 12 | Framework trust hooks | 0 |
| 13 | Trusted Types and CSP | 0 |
| 14 | Binding and template injection | 0 |
