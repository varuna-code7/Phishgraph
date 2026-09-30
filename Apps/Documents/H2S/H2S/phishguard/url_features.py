import re
from urllib.parse import urlparse
import tldextract

_ext = tldextract.TLDExtract(suffix_list_urls=())  # offline, uses bundled suffix list

URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
ANCHOR_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)

BRANDS = {
    "paypal": {"paypal.com"}, "google": {"google.com", "gmail.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"}, "amazon": {"amazon.com", "amazon.in"},
    "netflix": {"netflix.com"}, "facebook": {"facebook.com"},
    "instagram": {"instagram.com"}, "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"}, "hdfc": {"hdfcbank.com"}, "icici": {"icicibank.com"},
    "paytm": {"paytm.com"}, "irctc": {"irctc.co.in"}, "sbi": {"sbi.co.in", "onlinesbi.sbi"},
}
TRUSTED = set().union(*BRANDS.values()) | {"github.com", "wikipedia.org"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
SUS_TLDS = {"zip", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ru", "work",
            "support", "live", "icu", "cam", "co"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "$": "s"})


def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered(host):
    e = _ext(host)
    return e.registered_domain or host


def brand_imitated(text, reg):
    """Return brand name if `text` imitates a brand while `reg` isn't its official domain."""
    norm = text.lower().translate(LEET)
    toks = [t for t in re.split(r"[-.]", norm) if t]
    for b, official in BRANDS.items():
        if reg in official:
            continue
        if b in norm or (len(b) >= 5 and any(len(t) >= 5 and lev(t, b) <= 1 for t in toks)):
            return b
    return None


def analyze_url(url):
    reasons, s = [], 0.0
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host:
        return 0.0, [], ""
    e = _ext(host)
    reg = e.registered_domain or host
    if reg in TRUSTED:
        return 0.0, [], reg
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        s += .5; reasons.append("Link points to a raw IP address")
    if "xn--" in host:
        s += .4; reasons.append("Domain uses look-alike (punycode) characters")
    if e.suffix.split(".")[-1] in SUS_TLDS:
        s += .2; reasons.append(f"Uncommon top-level domain .{e.suffix}")
    if reg in SHORTENERS:
        s += .2; reasons.append("URL shortener hides the real destination")
    if e.subdomain and e.subdomain.count(".") >= 2:
        s += .15; reasons.append("Very deep subdomain chain")
    if "@" in p.netloc:
        s += .4; reasons.append("'@' in link hides the real host")
    if p.scheme == "http":
        s += .1; reasons.append("Link is not encrypted (http)")
    if len(url) > 100:
        s += .1; reasons.append("Unusually long URL")
    if e.domain.count("-") >= 2:
        s += .15; reasons.append("Domain stuffed with hyphens")
    b = brand_imitated(e.domain + "." + e.subdomain, reg)
    if b:
        s += .45; reasons.append(f"Domain imitates '{b}' but is not its official site")
    return min(s, 1.0), reasons, reg


def analyze_message(text):
    urls = list(dict.fromkeys(URL_RE.findall(text)))
    reasons, doms, scores = [], [], []
    for u in urls:
        sc, rs, reg = analyze_url(u)
        scores.append(sc)
        reasons += [f"{r} ({reg})" for r in rs]
        if reg and reg not in TRUSTED and reg not in doms:
            doms.append(reg)
    for href, label in ANCHOR_RE.findall(text):
        shown = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", re.sub("<[^>]+>", "", label).lower())
        real = registered(urlparse(href).hostname or "")
        if shown and real and registered(shown.group(0)) != real:
            scores.append(.6)
            reasons.append(f"Link text shows {shown.group(0)} but goes to {real}")
    score = 0.0
    if scores:
        score = min(1.0, max(scores) + 0.08 * (len(scores) - 1))
    return {"score": score, "reasons": list(dict.fromkeys(reasons)), "domains": doms}