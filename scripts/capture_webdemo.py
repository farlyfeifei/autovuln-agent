#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drive headless Edge over CDP to capture webdemo screenshots."""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

import websocket

EDGE = next(
    (p for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ) if os.path.exists(p)),
    None)
if EDGE is None:
    sys.exit("no Edge/Chrome found")
PORT = 9223
URL = os.environ.get("AV_WEBDEMO_URL", "http://127.0.0.1:8080/")
OUT_DIR = os.environ.get("AV_SHOT_DIR", os.path.join(os.getcwd(), "screenshots"))
os.makedirs(OUT_DIR, exist_ok=True)

# --- launch headless Edge with remote debugging ---
user_data = os.path.join(os.environ["TEMP"], "edge_cdp_prof")
proc = subprocess.Popen([
    EDGE, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    f"--remote-debugging-port={PORT}", f"--user-data-dir={user_data}",
    "--remote-allow-origins=*", "--window-size=1440,1000", "about:blank",
])

def http_json(path, tries=30):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=2) as r:
                return json.loads(r.read().decode())
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"CDP endpoint not reachable: {path}")

# --- find the page target's websocket ---
targets = http_json("/json")
page = next(t for t in targets if t.get("type") == "page")
ws_url = page["webSocketDebuggerUrl"]
ws = websocket.create_connection(ws_url, timeout=30)

_seq = 0
def send(method, params=None, timeout=15):
    global _seq
    _seq += 1
    mid = _seq
    msg = {"id": mid, "method": method}
    if params is not None:
        msg["params"] = params
    ws.send(json.dumps(msg))
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = json.loads(ws.recv())
        if resp.get("id") == mid:
            return resp
    raise TimeoutError(method)

def eval_js(expr):
    r = send("Runtime.evaluate", {"expression": expr, "returnByValue": True})
    return r.get("result", {}).get("result", {}).get("value")

def screenshot(name):
    r = send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
    data = r["result"]["data"]
    path = os.path.join(OUT_DIR, name)
    with open(path, "wb") as f:
        f.write(base64.b64decode(data))
    print(f"saved {path} ({os.path.getsize(path)/1024:.0f} KB)")
    return path

send("Page.enable")
send("Runtime.enable")
send("Page.navigate", {"url": URL})
time.sleep(2.0)   # let index.html load + SSE 'ready' render

print("status:", repr(eval_js("document.getElementById('status').textContent")))
screenshot("webdemo_idle.png")

# click start, then poll until run finishes
eval_js("document.getElementById('startBtn').click()")
for _ in range(100):
    status = eval_js("document.getElementById('status').textContent") or ""
    if "完成" in status or "错误" in status:
        break
    time.sleep(0.2)
time.sleep(0.8)
print("final status:", repr(status))
screenshot("webdemo_complete.png")

# extra: capture the table text for a machine-readable record
rows = eval_js("""JSON.stringify(Array.from(document.querySelectorAll('#tbody tr')).map(
    tr => Array.from(tr.children).map(td => td.textContent)))""")
print("table:", rows[:2000] if rows else "NONE")

ws.close()
proc.terminate()
print("done")
