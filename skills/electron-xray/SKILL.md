---
name: electron-xray
description: Use when the user asks whether an Electron desktop app is safe, wants a security or XSS audit of an installed app or a React, TypeScript or JavaScript codebase, or wants to see how an Electron app is built before rebuilding it. Reads app.asar and fuses without running the app.
---

# electron-xray

Reads an installed Electron app or a source folder and reports what an injected script could reach. Needs Python only. It never runs the app and sends nothing anywhere.

Use it only on apps the person has installed or may assess.

## Steps

1. Find the app with `list`, or use the path you were given.
2. Run `audit` with a report file.
3. Tell the person the one-line answer first.
4. Open the report. For each high and medium finding, read the code around it, and say whether it applies to a window that shows outside content.
5. For sinks under "Requires Manual Review", trace the value: where it comes from, what cleans it, and which context it lands in (HTML, attribute, URL, JS or CSS).
6. Separate confirmed issues from pattern matches in what you tell the person. Nothing here is verified until someone shows it working.

```bash
python electron_xray.py list
python electron_xray.py audit "PATH" --report xss-audit-report.md --card card.svg
python electron_xray.py audit "PATH" --json
python electron_xray.py map "PATH"
python electron_xray.py extract "PATH" -o unpacked
```

`PATH` can be an app folder, a program, an `app.asar`, a `.app` bundle or a source folder such as `src/`.

Exit codes: `0` success, `1` `--fail-on` was triggered, `2` refused or bad input.

## Reading the answer

| Answer | Meaning |
|---|---|
| Your whole PC | `nodeIntegration` is on in at least one window |
| Past the page | `contextIsolation` is off, the remote module is used, or the preload exposes raw IPC |
| Only its window | Nothing in this scan lets a script out of the page |

## Tracing a sink

- Hostname-only checks are not enough: `new URL("javascript://trusted.com/%0aalert(1)").hostname` is `trusted.com`.
- Substring checks fail: `url.includes("trusted.com")` passes `https://trusted.com.evil.com`.
- A sanitizer's output that is parsed or changed again before insertion can still be unsafe.
- Check the correct context. Cleaning for HTML does not make a value safe in a URL.

## Limits

No proof of exploit, no remote code, no CVE data, and settings built at run time will not match. A clean result is not proof of safety. Reports can contain code and paths from the app, so read them before sharing.
