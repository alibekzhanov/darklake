from django.shortcuts import render
from django.utils import timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urlunparse
import re
import socket
import ssl
import requests


def home(request):
    return render(request, 'main/home.html')


def features(request):
    return render(request, 'main/components/features.html')


def about(request):
    return render(request, 'main/components/about.html')


def support(request):
    return render(request, 'main/components/support.html')


# -----------------------------
# Helpers
# -----------------------------
def _normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Please enter a website URL.")

    if not re.match(r"^https?://", raw, flags=re.I):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")

    if not parsed.netloc:
        raise ValueError("Invalid URL. Please include a domain name.")

    cleaned = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    return cleaned


def _safe_get(url: str) -> requests.Response:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }

    session = requests.Session()

    retry = Retry(
        total=2,                # 2 повтора
        connect=2,
        read=2,
        backoff_factor=0.6,     # пауза между повторами
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # 1) пробуем HEAD быстро (иногда GET тяжелый)
    try:
        head = session.head(
            url,
            headers=headers,
            timeout=(4, 8),
            allow_redirects=True,
            verify=True,
        )
        # Если HEAD успешный — пробуем GET, но уже можем использовать final URL
        url = head.url or url
    except requests.RequestException:
        # Если HEAD не удался — просто идем на GET
        pass

    # 2) GET с чуть большим read timeout
    resp = session.get(
        url,
        headers=headers,
        timeout=(6, 25),       # было (4,10) → стало (6,25)
        allow_redirects=True,
        verify=True
    )
    return resp


def _extract_hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def _check_tls(hostname: str, port: int = 443) -> dict:
    result = {
        "ok": False,
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "not_before": None,
        "not_after": None,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["ok"] = True
                result["tls_version"] = ssock.version()

                cert = ssock.getpeercert()
                result["cert_subject"] = str(cert.get("subject", ""))[:160]
                result["cert_issuer"] = str(cert.get("issuer", ""))[:160]
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _detect_tech(headers: dict, html: str) -> list:
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    via = headers.get("Via", "")

    cloudflare_hint = (headers.get("Server", "") + headers.get("CF-RAY", "")).lower()
    proxy_cdn = "Cloudflare" if "cloudflare" in cloudflare_hint else (via or "Unknown")

    tech = {
        "Web Server": server or "Unknown",
        "X-Powered-By": powered or "Not disclosed",
        "Proxy / CDN": proxy_cdn,
        "CMS / Platform": "Unknown",
        "Frontend Signals": "Unknown",
    }

    html_l = (html or "").lower()

    # CMS hints
    if "wp-content" in html_l or "wordpress" in html_l:
        tech["CMS / Platform"] = "WordPress (detected)"
    elif "drupal" in html_l:
        tech["CMS / Platform"] = "Drupal (detected)"
    elif "shopify" in html_l:
        tech["CMS / Platform"] = "Shopify (detected)"
    elif "wix.com" in html_l:
        tech["CMS / Platform"] = "Wix (detected)"

    # Frontend hints
    signals = []
    if "__next_data__" in html_l or "next/script" in html_l:
        signals.append("Next.js")
    if "react" in html_l and ("data-reactroot" in html_l or "react-dom" in html_l):
        signals.append("React")
    if "vue" in html_l and ("data-v-" in html_l or "vuex" in html_l):
        signals.append("Vue")
    if "angular" in html_l and ("ng-version" in html_l or "angular.js" in html_l):
        signals.append("Angular")
    if "jquery" in html_l:
        signals.append("jQuery")

    tech["Frontend Signals"] = ", ".join(dict.fromkeys(signals)) if signals else "Unknown"
    return [{"label": k, "value": v} for k, v in tech.items()]


def _security_headers_findings(headers: dict) -> list:
    findings = []

    def add(sev, title, desc, evidence, reco):
        findings.append({
            "severity": sev,
            "severity_key": sev.lower(),
            "title": title,
            "description": desc,
            "evidence": evidence,
            "recommendation": reco
        })

    csp = headers.get("Content-Security-Policy", "")

    # Missing CSP
    if "Content-Security-Policy" not in headers:
        add(
            "Critical",
            "Missing Content-Security-Policy",
            "No CSP header detected. This increases exposure to script injection and data exfiltration.",
            "Content-Security-Policy: (missing)",
            "Implement a strict CSP and tighten it iteratively based on required sources."
        )

    # Missing HSTS
    if "Strict-Transport-Security" not in headers:
        add(
            "High",
            "Missing Strict-Transport-Security (HSTS)",
            "HSTS is not enabled. Users may be downgraded to HTTP in some scenarios.",
            "Strict-Transport-Security: (missing)",
            "Enable HSTS (start with a short max-age, then increase) and includeSubDomains if applicable."
        )

    # Clickjacking protection (FIXED LOGIC)
    xfo_missing = "X-Frame-Options" not in headers
    frame_ancestors_missing = ("frame-ancestors" not in (csp or ""))

    if xfo_missing and frame_ancestors_missing:
        add(
            "High",
            "Clickjacking protection not detected",
            "Neither X-Frame-Options nor CSP frame-ancestors directive was detected.",
            "X-Frame-Options: (missing)",
            "Set X-Frame-Options (DENY or SAMEORIGIN) or enforce CSP frame-ancestors."
        )

    # X-Content-Type-Options
    if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        add(
            "Medium",
            "X-Content-Type-Options not set to nosniff",
            "Missing or incorrect nosniff may allow MIME-type sniffing in some browsers.",
            f"X-Content-Type-Options: {headers.get('X-Content-Type-Options', '(missing)')}",
            "Set X-Content-Type-Options: nosniff."
        )

    # Referrer-Policy
    if "Referrer-Policy" not in headers:
        add(
            "Low",
            "Missing Referrer-Policy",
            "Referrer-Policy is not set, which may leak URLs and query parameters to third parties.",
            "Referrer-Policy: (missing)",
            "Set Referrer-Policy (e.g., strict-origin-when-cross-origin)."
        )

    return findings


def _tls_findings(tls_info: dict, is_https: bool) -> list:
    findings = []

    def add(sev, title, desc, evidence, reco):
        findings.append({
            "severity": sev,
            "severity_key": sev.lower(),
            "title": title,
            "description": desc,
            "evidence": evidence,
            "recommendation": reco
        })

    if not is_https:
        add(
            "Critical",
            "Site does not use HTTPS by default",
            "The provided URL uses HTTP. Traffic may be intercepted or modified in transit.",
            "Scheme: http",
            "Redirect all traffic to HTTPS and enforce HSTS."
        )
        return findings

    if not tls_info.get("ok"):
        add(
            "High",
            "TLS handshake failed",
            "Darklake could not complete a TLS handshake. The certificate or TLS configuration might be broken.",
            tls_info.get("error") or "TLS error",
            "Fix certificate chain / TLS configuration and ensure port 443 is reachable."
        )
        return findings

    tls_ver = tls_info.get("tls_version") or "Unknown"
    if tls_ver in ("TLSv1", "TLSv1.1"):
        add(
            "High",
            "Legacy TLS version negotiated",
            "A legacy TLS version was negotiated. This may indicate weak compatibility settings.",
            f"Negotiated: {tls_ver}",
            "Disable TLS 1.0/1.1 and enforce TLS 1.2+."
        )

    not_after = tls_info.get("not_after")
    if not_after:
        add(
            "Low",
            "Certificate details detected",
            "Certificate metadata was collected. Review expiry and issuer details.",
            f"notAfter: {not_after}",
            "Ensure certificate auto-renewal and monitor expiry to avoid outages."
        )

    return findings


def _score_and_metrics(findings: list) -> tuple[int, dict]:
    weights = {"critical": 18, "high": 10, "medium": 5, "low": 2}
    score = 0

    counts = {"severe": 0, "medium": 0, "low": 0, "total": 0}
    for f in findings:
        sev = f["severity_key"]
        score += weights.get(sev, 1)
        counts["total"] += 1
        if sev in ("critical", "high"):
            counts["severe"] += 1
        elif sev == "medium":
            counts["medium"] += 1
        else:
            counts["low"] += 1

    score = max(0, min(100, score))
    return score, counts


def _risk_level(score: int) -> tuple[str, str]:
    if score >= 70:
        return "High Risk", "high"
    if score >= 35:
        return "Medium Risk", "medium"
    return "Low Risk", "low"


def _build_stages(findings: list, tech_snapshot: list, tls_info: dict, is_https: bool) -> list:
    def stage(name, desc, key, issues_count):
        if issues_count == 0:
            status_key = "ok"
            status_label = "Completed"
        elif issues_count <= 2:
            status_key = "warning"
            status_label = "Completed — Issues Found"
        else:
            status_key = "critical"
            status_label = "Completed — Critical Issues"

        if key == "tls" and is_https and not tls_info.get("ok"):
            status_key, status_label = "critical", "Completed — Critical Issues"

        return {
            "name": name,
            "description": desc,
            "issues_count": issues_count,
            "status_key": status_key,
            "status_label": status_label,
        }

    headers_issues = sum(
        1 for f in findings
        if any(k in f["title"].lower() for k in ("content-security-policy", "hsts", "clickjacking", "x-content-type-options", "referrer-policy"))
    )
    tls_issues = sum(1 for f in findings if any(k in f["title"].lower() for k in ("tls", "https", "certificate")))
    recon_issues = sum(1 for f in findings if "header disclosed" in f["title"].lower())

    # tech stage issue count = detected meaningful signals
    meaningful = 0
    for t in tech_snapshot:
        v = (t.get("value") or "").strip().lower()
        if v and v not in ("unknown", "not disclosed"):
            meaningful += 1
    tech_issues = 1 if meaningful > 0 else 0

    passive_issues = max(0, len(findings) - (headers_issues + tls_issues + recon_issues))

    return [
        stage("Fingerprinting & Recon", "Extracts public signals: server identifiers, redirects, response metadata.", "recon", recon_issues),
        stage("Technology Stack Detection", "Infers technologies from headers and HTML patterns.", "tech", tech_issues),
        stage("Security Headers Analysis", "Checks essential HTTP security headers and common misconfigurations.", "headers", headers_issues),
        stage("SSL / TLS & Certificate Validation", "Collects certificate metadata and negotiated TLS version (best effort).", "tls", tls_issues),
        stage("Known Weaknesses (Passive)", "Highlights common weaknesses observable from public signals.", "passive", passive_issues),
    ]


# -----------------------------
# View
# -----------------------------
def analyze(request):
    raw_url = request.GET.get("url", "")

    target_url = None
    final_url = None
    hostname = None
    is_https = False
    html = ""
    headers = {}
    tls_info = {"ok": False}
    findings = []
    tech_snapshot = []

    try:
        target_url = _normalize_url(raw_url)
        parsed = urlparse(target_url)
        hostname = parsed.hostname or ""
        is_https = parsed.scheme == "https"

        # TLS можно проверить сразу (не зависит от requests.get)
        if hostname and is_https:
            tls_info = _check_tls(hostname)

        # Пытаемся получить сайт (может не успеть)
        try:
            resp = _safe_get(target_url)
            final_url = resp.url
            hostname = _extract_hostname(final_url) or hostname
            is_https = urlparse(final_url).scheme == "https"

            html = resp.text[:200_000] if resp.text else ""
            headers = dict(resp.headers) if resp.headers else {}
        except requests.RequestException as e:
            # НЕ падаем. Просто отмечаем, что HTML не получили
            findings.append({
                "severity": "Medium",
                "severity_key": "medium",
                "title": "Site content could not be fetched",
                "description": "Darklake could not download the HTML content within the time limits. TLS and basic checks may still be available.",
                "evidence": str(e)[:200],
                "recommendation": "Try again later, or test a lighter URL (homepage without heavy redirects) or increase timeouts."
            })

        # Если headers есть — делаем полноценные проверки
        if headers:
            tech_snapshot = _detect_tech(headers, html)
            findings.extend(_security_headers_findings(headers))

            if headers.get("Server"):
                findings.append({
                    "severity": "Low",
                    "severity_key": "low",
                    "title": "Server header disclosed",
                    "description": "Server header reveals implementation details that may help attackers fingerprint the stack.",
                    "evidence": f"Server: {headers.get('Server')}",
                    "recommendation": "Consider minimizing or standardizing the Server header where possible."
                })
            if headers.get("X-Powered-By"):
                findings.append({
                    "severity": "Low",
                    "severity_key": "low",
                    "title": "X-Powered-By header disclosed",
                    "description": "X-Powered-By reveals framework/runtime details and increases fingerprinting accuracy.",
                    "evidence": f"X-Powered-By: {headers.get('X-Powered-By')}",
                    "recommendation": "Remove or mask X-Powered-By header at the web server or application level."
                })
        else:
            # если headers нет — всё равно покажем tech_snapshot как Unknown
            tech_snapshot = [
                {"label": "Web Server", "value": "Unknown"},
                {"label": "X-Powered-By", "value": "Not disclosed"},
                {"label": "Proxy / CDN", "value": "Unknown"},
                {"label": "CMS / Platform", "value": "Unknown"},
                {"label": "Frontend Signals", "value": "Unknown"},
            ]

        # TLS findings добавляем всегда (если https)
        findings.extend(_tls_findings(tls_info, is_https))

        risk_score, counts = _score_and_metrics(findings)
        risk_level, risk_key = _risk_level(risk_score)

        risk_summary = (
            "Darklake performed passive analysis. "
            "Some sites may block automated requests or respond slowly; results may be partial. "
            "Prioritize transport security and missing security headers."
        )

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        top_findings = sorted(findings, key=lambda x: sev_rank.get(x["severity_key"], 9))[:4]

        stages = _build_stages(findings, tech_snapshot, tls_info, is_https)

        context = {
            "target_display": final_url or target_url,
            "scanned_at": timezone.now().strftime("%Y-%m-%d %H:%M"),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_level_key": risk_key,
            "risk_summary": risk_summary,
            "metrics": counts,
            "stages": stages,
            "tech_snapshot": tech_snapshot,
            "top_findings": top_findings,
        }

        allowed_tabs = {"overview", "tech", "vulns", "tls", "report"}
        active_tab = request.GET.get("tab", "overview")
        if active_tab not in allowed_tabs:
            active_tab = "overview"

        context.update({
            "findings": findings,
            "tls_info": tls_info,
            "active_tab": active_tab,
        })

        return render(request, "main/components/analysis_results.html", context)

    except ValueError as e:
        return render(request, "main/components/analysis_results.html", {"error": str(e)})
    except Exception as e:
        return render(request, "main/components/analysis_results.html", {"error": f"Unexpected error: {str(e)[:200]}"})

