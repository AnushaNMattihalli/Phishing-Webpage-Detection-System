# analyzer.py
import re
import socket
import ssl
import requests
import whois
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract

# Safe fetch constants
FETCH_TIMEOUT = 8
MAX_CONTENT_BYTES = 300_000  # limit body read

def is_ip_host(host):
    # if host is IPv4 or IPv6 literal
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        if host.startswith('[') and host.endswith(']'):
            return True
    return False

def get_domain_age_days(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None
        age_days = (datetime.datetime.utcnow() - created).days
        return age_days
    except Exception:
        return None

def get_ssl_info(hostname, port=443, timeout=6):
    info = {"valid": False, "issuer": None, "notAfter": None, "notBefore": None, "subject": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info['valid'] = True
                info['issuer'] = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else None
                info['subject'] = dict(x[0] for x in cert.get('subject', ())) if cert.get('subject') else None
                info['notBefore'] = cert.get('notBefore')
                info['notAfter'] = cert.get('notAfter')
    except Exception as e:
        info['error'] = str(e)
    return info

def safe_fetch(url):
    headers = {"User-Agent": "PhishDetect/1.0 (+https://example.local)"}  # benign UA
    try:
        r = requests.get(url, headers=headers, timeout=FETCH_TIMEOUT, allow_redirects=True, stream=True)
        content = b''
        for chunk in r.iter_content(4096):
            content += chunk
            if len(content) > MAX_CONTENT_BYTES:
                break
        text = ''
        try:
            text = content.decode(r.encoding or 'utf-8', errors='replace')
        except Exception:
            text = content.decode('utf-8', errors='replace')
        return {"status_code": r.status_code, "final_url": r.url, "history": [h.status_code for h in r.history], "text": text, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

# Heuristic checks
def analyze_page(url):
    parsed = urlparse(url)
    host = parsed.hostname or ''
    path = parsed.path or ''
    out = {"url": url, "host": host}
    # Basic URL heuristics
    out['is_ip'] = is_ip_host(host)
    out['url_length'] = len(url)
    out['suspicious_chars'] = bool(re.search(r'[@%\\\*\$!<>|]{1,}', url))
    out['punycode'] = host.startswith('xn--') if host else False
    ext = tldextract.extract(url)
    out['domain'] = ext.registered_domain
    out['subdomain'] = ext.subdomain
    # Fetch page
    fetched = safe_fetch(url)
    out['fetch'] = fetched
    if 'error' not in fetched:
        soup = BeautifulSoup(fetched['text'], 'html.parser')
        # forms
        forms = soup.find_all('form')
        out['forms_count'] = len(forms)
        out['forms_external_action'] = 0
        out['forms_with_password'] = 0
        for f in forms:
            action = f.get('action') or ''
            action_parsed = urlparse(action) if action and '//' in action else None
            if action_parsed and action_parsed.hostname and action_parsed.hostname != host:
                out['forms_external_action'] += 1
            if f.find('input', {'type': 'password'}):
                out['forms_with_password'] += 1
        # external resources count
        resources = 0
        external_resources = 0
        for tag in soup.find_all(['img','script','link','iframe']):
            src = tag.get('src') or tag.get('href') or ''
            if src:
                resources += 1
                if '//' in src:
                    src_host = urlparse(src if src.startswith('http') else 'http:' + src).hostname
                    if src_host and src_host != host:
                        external_resources += 1
        out['resources'] = resources
        out['external_resources'] = external_resources
        # meta refresh / iframe presence
        out['has_meta_refresh'] = bool(soup.find('meta', attrs={'http-equiv': lambda v: v and v.lower()=='refresh'}))
        out['iframes'] = len(soup.find_all('iframe'))
        out['page_title'] = (soup.title.string.strip() if soup.title and soup.title.string else '')
    else:
        out['forms_count'] = None
    # WHOIS
    domain_age = get_domain_age_days(out['domain']) if out['domain'] else None
    out['domain_age_days'] = domain_age
    # SSL
    ssl_info = None
    if parsed.scheme == 'https':
        ssl_info = get_ssl_info(host)
    else:
        try:
            # still try to get cert on port 443
            ssl_info = get_ssl_info(host)
        except Exception:
            ssl_info = None
    out['ssl'] = ssl_info

    # Scoring: weighted heuristics
    # Each check yields points (higher = more suspicious). We'll compute a percent risk 0..100.
    score = 0.0
    weight_sum = 0.0

    def add(weight, points):
        nonlocal score, weight_sum
        score += weight * points
        weight_sum += weight

    # Weight definitions (tunable)
    W_URL = 1.5
    W_WHOIS = 1.8
    W_SSL = 1.5
    W_PAGE = 2.0
    W_STATIC = 1.2

    # URL heuristics (0..1)
    url_flag = 0.0
    if out['is_ip']:
        url_flag += 1.0
    if out['punycode']:
        url_flag += 0.9
    if out['url_length'] > 75:
        url_flag += 0.6
    if out['suspicious_chars']:
        url_flag += 0.7
    # normalize to max 1.0
    url_flag = min(url_flag, 1.0)
    add(W_URL, url_flag)

    # WHOIS / domain age
    whois_flag = 0.0
    if domain_age is None:
        whois_flag += 0.5  # no whois info suspicious
    else:
        # new domains (< 180 days) suspicious
        if domain_age < 30:
            whois_flag += 1.0
        elif domain_age < 180:
            whois_flag += 0.7
        elif domain_age < 365:
            whois_flag += 0.4
        else:
            whois_flag += 0.0
    whois_flag = min(whois_flag, 1.0)
    add(W_WHOIS, whois_flag)

    # SSL checks
    ssl_flag = 0.0
    if ssl_info:
        if not ssl_info.get('valid'):
            ssl_flag += 1.0
        else:
            # check mismatch between cert subject CN and domain (simple)
            subj = ssl_info.get('subject') or {}
            commonName = subj.get('commonName') if subj else None
            if commonName and out['domain'] and out['domain'] not in commonName:
                ssl_flag += 0.6
    else:
        # no ssl info — treat as more suspicious for https pages
        if parsed.scheme == 'https':
            ssl_flag += 1.0
    ssl_flag = min(ssl_flag, 1.0)
    add(W_SSL, ssl_flag)

    # Page heuristics
    page_flag = 0.0
    if out.get('forms_with_password') and out.get('forms_with_password') > 0:
        page_flag += 1.0
    if out.get('forms_external_action') and out['forms_external_action'] > 0:
        page_flag += 0.9
    if out.get('has_meta_refresh'):
        page_flag += 0.6
    if out.get('iframes') and out['iframes'] > 0:
        page_flag += 0.5
    # proportion of external resources
    try:
        ratio = out['external_resources'] / max(out['resources'],1)
        if ratio > 0.7:
            page_flag += 0.6
        elif ratio > 0.4:
            page_flag += 0.3
    except Exception:
        pass
    page_flag = min(page_flag, 1.0)
    add(W_PAGE, page_flag)

    # Static heuristics: suspicious TLDs, subdomain trickery
    static_flag = 0.0
    tld = ext.suffix or ''
    suspicious_tlds = {'tk','ml','cf','gq'}  # high-abuse ccTLD examples
    if tld in suspicious_tlds:
        static_flag += 0.7
    if out.get('subdomain') and out['subdomain'].count('.') >= 1:
        # very long subdomain like bank.example.com.attacker.com
        static_flag += 0.4
    add(W_STATIC, min(static_flag,1.0))

    # Normalize final score to 0..100
    if weight_sum == 0:
        final_pct = 0.0
    else:
        normalized = score / weight_sum  # 0..1 but may exceed 1 if malicious — ensure clamp
        normalized = max(0.0, min(normalized, 1.0))
        final_pct = round(normalized * 100, 1)

    # Also provide breakdown with component percent contributions
    breakdown = {
        "url_component": round((W_URL * url_flag) / weight_sum * 100, 1) if weight_sum else 0,
        "whois_component": round((W_WHOIS * whois_flag) / weight_sum * 100, 1) if weight_sum else 0,
        "ssl_component": round((W_SSL * ssl_flag) / weight_sum * 100, 1) if weight_sum else 0,
        "page_component": round((W_PAGE * page_flag) / weight_sum * 100, 1) if weight_sum else 0,
        "static_component": round((W_STATIC * min(static_flag,1.0)) / weight_sum * 100, 1) if weight_sum else 0,
    }

    out['score'] = final_pct
    out['breakdown'] = breakdown
    out['internal_calc'] = {"raw_score": score, "weight_sum": weight_sum}
    return out
