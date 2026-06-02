from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urlunparse, urljoin

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

import ipaddress
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

    cleaned = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        "",
        parsed.query,
        "",
    ))

    return cleaned


def _extract_hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def _is_public_hostname(hostname: str) -> bool:
    if not hostname:
        return False

    blocked_hosts = {"localhost", "localhost.localdomain"}

    if hostname.lower() in blocked_hosts:
        return False

    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for item in resolved_ips:
        ip_raw = item[4][0]

        try:
            ip = ipaddress.ip_address(ip_raw)
        except ValueError:
            return False

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False

    return True


def _assert_public_url(url: str) -> None:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")

    if not _is_public_hostname(hostname):
        raise ValueError("Private, local, or internal addresses are not allowed.")


def _normalize_headers(headers) -> dict:
    return {str(k).lower(): str(v) for k, v in dict(headers or {}).items()}


def _safe_request_with_redirects(
    session: requests.Session,
    method: str,
    url: str,
    headers: dict,
    timeout: tuple,
    max_redirects: int = 6,
    stream: bool = False,
) -> requests.Response:
    current_url = url

    for _ in range(max_redirects + 1):
        _assert_public_url(current_url)

        resp = session.request(
            method=method,
            url=current_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=True,
            stream=stream,
        )

        if resp.is_redirect or resp.is_permanent_redirect:
            location = resp.headers.get("Location")

            if not location:
                return resp

            next_url = urljoin(current_url, location)
            _assert_public_url(next_url)
            current_url = next_url
            continue

        return resp

    raise requests.TooManyRedirects("Too many redirects.")


def _read_limited_text(resp: requests.Response, max_bytes: int = 200_000) -> str:
    content_type = resp.headers.get("Content-Type", "")

    if (
        "text/html" not in content_type
        and "application/xhtml+xml" not in content_type
        and content_type
    ):
        return ""

    chunks = []
    total = 0

    for chunk in resp.iter_content(chunk_size=8192, decode_unicode=False):
        if not chunk:
            continue

        remaining = max_bytes - total

        if remaining <= 0:
            break

        part = chunk[:remaining]
        chunks.append(part)
        total += len(part)

        if total >= max_bytes:
            break

    raw = b"".join(chunks)
    encoding = resp.encoding or "utf-8"

    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


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
        total=2,
        connect=2,
        read=2,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET"],
        raise_on_status=False,
    )

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    try:
        head = _safe_request_with_redirects(
            session=session,
            method="HEAD",
            url=url,
            headers=headers,
            timeout=(4, 8),
            stream=False,
        )

        if head.url:
            url = head.url

    except requests.RequestException:
        pass

    resp = _safe_request_with_redirects(
        session=session,
        method="GET",
        url=url,
        headers=headers,
        timeout=(6, 25),
        stream=True,
    )

    return resp


def _extract_cert_common_name(cert_part) -> str:
    if not cert_part:
        return "Unknown"

    try:
        for group in cert_part:
            for key, value in group:
                if key == "commonName":
                    return value
    except Exception:
        pass

    return str(cert_part)[:160]


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
        if not _is_public_hostname(hostname):
            raise ValueError("Private, local, or internal addresses are not allowed.")

        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["ok"] = True
                result["tls_version"] = ssock.version()

                cert = ssock.getpeercert()

                result["cert_subject"] = _extract_cert_common_name(cert.get("subject"))
                result["cert_issuer"] = _extract_cert_common_name(cert.get("issuer"))
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _normalize_proxy_cdn(headers: dict) -> str:
    server = headers.get("server", "")
    via = headers.get("via", "")
    cf_ray = headers.get("cf-ray", "")
    cf_cache = headers.get("cf-cache-status", "")

    combined = f"{server} {via} {cf_ray} {cf_cache}".lower()

    if "cloudflare" in combined or cf_ray or cf_cache:
        return "Cloudflare"

    if "heroku-router" in combined and "varnish" in combined:
        return "Heroku Router / Varnish"

    if "heroku-router" in combined:
        return "Heroku Router"

    if "varnish" in combined:
        return "Varnish"

    if via:
        return via

    return "Unknown"


def _add_tech_signal(bucket: dict, name: str, confidence: int, evidence: str) -> None:
    current = bucket.get(name)

    if not current or confidence > current["confidence"]:
        bucket[name] = {
            "confidence": confidence,
            "evidence": evidence,
        }


def _confidence_label(score: int) -> str:
    if score >= 3:
        return "High confidence"

    if score == 2:
        return "Medium confidence"

    return "Low confidence"


def _format_detected_stack(signals: dict, fallback: str = "Not confidently detected") -> str:
    if not signals:
        return fallback

    ordered = sorted(
        signals.items(),
        key=lambda item: item[1]["confidence"],
        reverse=True,
    )

    formatted = []

    for name, meta in ordered[:3]:
        formatted.append(f"{name} - {_confidence_label(meta['confidence'])}")

    return ", ".join(formatted)


def _collect_cookie_text(headers: dict) -> str:
    cookie_sources = []

    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie_sources.append(value)

    return " ".join(cookie_sources).lower()


def _detect_tech(headers: dict, html: str) -> list:
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    cookies = _collect_cookie_text(headers)

    html_l = (html or "").lower()
    combined = f"{html_l} {cookies} {server.lower()} {powered.lower()}"

    frontend = {}
    backend = {}
    platform = {}

    # Frontend framework detection
    if "__next_data__" in combined or "/_next/static/" in combined or "self.__next_f.push" in combined:
        _add_tech_signal(frontend, "Next.js", 3, "__NEXT_DATA__ or /_next/static/")
        _add_tech_signal(frontend, "React", 2, "Next.js is React-based")

    if "react-dom" in combined or "data-reactroot" in combined or "__react_devtools_global_hook__" in combined:
        _add_tech_signal(frontend, "React", 3, "react-dom/data-reactroot")

    if "__nuxt__" in combined or "/_nuxt/" in combined:
        _add_tech_signal(frontend, "Nuxt", 3, "__NUXT__ or /_nuxt/")
        _add_tech_signal(frontend, "Vue", 2, "Nuxt is Vue-based")

    if "vue.runtime" in combined or "__vue__" in combined or "data-v-" in combined:
        _add_tech_signal(frontend, "Vue", 3, "Vue runtime/data-v attributes")

    if "ng-version" in combined or "ng-app" in combined or "angular.js" in combined:
        _add_tech_signal(frontend, "Angular", 3, "ng-version/ng-app/angular.js")

    if "zone.js" in combined:
        _add_tech_signal(frontend, "Angular", 2, "zone.js")

    if "/_app/immutable/" in combined or "__svelte" in combined or "sveltekit" in combined:
        _add_tech_signal(frontend, "SvelteKit", 3, "_app/immutable or sveltekit")

    if "/@vite/client" in combined or "vite.svg" in combined:
        _add_tech_signal(frontend, "Vite", 3, "/@vite/client or vite.svg")

    if "__webpack_require__" in combined or "webpackjsonp" in combined or "chunk-vendors" in combined:
        _add_tech_signal(frontend, "Webpack", 2, "webpack runtime/chunk-vendors")

    if "jquery" in combined:
        _add_tech_signal(frontend, "jQuery", 2, "jquery detected")

    # Backend technology detection
    if powered:
        powered_l = powered.lower()

        if "express" in powered_l:
            _add_tech_signal(backend, "Express / Node.js", 3, "X-Powered-By: Express")
        elif "php" in powered_l:
            _add_tech_signal(backend, "PHP", 3, "X-Powered-By: PHP")
        elif "asp.net" in powered_l:
            _add_tech_signal(backend, "ASP.NET", 3, "X-Powered-By: ASP.NET")
        else:
            _add_tech_signal(backend, powered, 2, "X-Powered-By header")

    if "laravel_session" in combined or "xsrf-token" in combined:
        _add_tech_signal(backend, "Laravel", 3, "laravel_session/XSRF-TOKEN")

    if "csrftoken" in combined or "csrfmiddlewaretoken" in combined:
        _add_tech_signal(backend, "Django", 3, "csrftoken/csrfmiddlewaretoken")

    if "sessionid" in cookies and "django" not in combined:
        _add_tech_signal(backend, "Django-like session", 1, "sessionid cookie")

    if "_session_id" in combined or "rails-ujs" in combined or "csrf-param" in combined:
        _add_tech_signal(backend, "Ruby on Rails", 3, "_session_id/rails-ujs/csrf-param")

    if "connect.sid" in combined:
        _add_tech_signal(backend, "Express / Node.js", 3, "connect.sid cookie")

    if "phpsessid" in combined or ".php" in combined:
        _add_tech_signal(backend, "PHP", 2, "PHPSESSID or .php path")

    if "asp.net_sessionid" in combined or "__viewstate" in combined or ".aspx" in combined:
        _add_tech_signal(backend, "ASP.NET", 3, "ASP.NET_SessionId/__VIEWSTATE/.aspx")

    if "jsessionid" in combined:
        _add_tech_signal(backend, "Java / Spring", 2, "JSESSIONID cookie")

    if "heroku" in server.lower() and not backend:
        _add_tech_signal(backend, "Custom app on Heroku", 1, "Server: Heroku")

    # CMS / platform detection
    if "wp-content" in combined or "wp-includes" in combined or "/wp-json/" in combined:
        _add_tech_signal(platform, "WordPress", 3, "wp-content/wp-includes/wp-json")

    if "cdn.shopify.com" in combined or "shopify.theme" in combined or "myshopify.com" in combined:
        _add_tech_signal(platform, "Shopify", 3, "Shopify public assets")

    if "data-wf-page" in combined or "data-wf-site" in combined or "webflow.js" in combined:
        _add_tech_signal(platform, "Webflow", 3, "data-wf-page/data-wf-site/webflow.js")

    if "wixstatic.com" in combined or "x-seen-by" in combined:
        _add_tech_signal(platform, "Wix", 3, "wixstatic/X-Seen-By")

    if "drupalsettings" in combined or "/sites/default/" in combined or "x-drupal-cache" in combined:
        _add_tech_signal(platform, "Drupal", 3, "drupalSettings/sites/default")

    if "magento" in combined or "mage/cookies" in combined or "/static/frontend/" in combined:
        _add_tech_signal(platform, "Magento", 3, "Magento public assets")

    if not platform and backend:
        _add_tech_signal(platform, "Custom application", 1, "Backend/framework signals detected")

    tech = {
        "Hosting / Server": server or "Unknown",
        "Backend Technology": _format_detected_stack(backend, "Not confidently detected"),
        "Traffic Protection / CDN": _normalize_proxy_cdn(headers),
        "Website Platform": _format_detected_stack(platform, "Not confidently detected"),
        "Frontend Framework": _format_detected_stack(frontend, "Not confidently detected"),
    }

    return [{"label": k, "value": v} for k, v in tech.items()]


def _add_finding(findings: list, sev: str, title: str, desc: str, evidence: str, reco: str) -> None:
    findings.append({
        "severity": sev,
        "severity_key": sev.lower(),
        "title": title,
        "description": desc,
        "evidence": evidence,
        "recommendation": reco,
    })


def _security_headers_findings(headers: dict, is_https: bool) -> list:
    findings = []

    csp = headers.get("content-security-policy", "")

    if "content-security-policy" not in headers:
        _add_finding(
            findings,
            "High",
            "Missing Content-Security-Policy",
            "No CSP header detected. This increases exposure to script injection and data exfiltration if another weakness exists.",
            "Content-Security-Policy: (missing)",
            "Implement a strict CSP and tighten it iteratively based on required sources.",
        )
    else:
        csp_l = csp.lower()

        if "'unsafe-inline'" in csp_l or "unsafe-inline" in csp_l:
            _add_finding(
                findings,
                "Medium",
                "Content-Security-Policy allows unsafe-inline",
                "CSP is present, but unsafe-inline weakens protection against script injection.",
                "Content-Security-Policy contains unsafe-inline",
                "Avoid unsafe-inline where possible. Prefer nonces, hashes, or stricter script-src rules.",
            )

    if is_https and "strict-transport-security" not in headers:
        _add_finding(
            findings,
            "High",
            "Missing Strict-Transport-Security HSTS",
            "HSTS is not enabled. Users may be downgraded to HTTP in some scenarios.",
            "Strict-Transport-Security: (missing)",
            "Enable HSTS. Start with a short max-age, then increase it and includeSubDomains if applicable.",
        )

    xfo_missing = "x-frame-options" not in headers
    frame_ancestors_missing = "frame-ancestors" not in csp.lower()

    if xfo_missing and frame_ancestors_missing:
        _add_finding(
            findings,
            "Medium",
            "Clickjacking protection not detected",
            "Neither X-Frame-Options nor CSP frame-ancestors directive was detected.",
            "X-Frame-Options: (missing), CSP frame-ancestors: (missing)",
            "Set X-Frame-Options: DENY/SAMEORIGIN or enforce CSP frame-ancestors.",
        )

    if headers.get("x-content-type-options", "").lower() != "nosniff":
        _add_finding(
            findings,
            "Medium",
            "X-Content-Type-Options not set to nosniff",
            "Missing or incorrect nosniff may allow MIME-type sniffing in some browsers.",
            f"X-Content-Type-Options: {headers.get('x-content-type-options', '(missing)')}",
            "Set X-Content-Type-Options: nosniff.",
        )

    if "referrer-policy" not in headers:
        _add_finding(
            findings,
            "Low",
            "Missing Referrer-Policy",
            "Referrer-Policy is not set, which may leak URLs and query parameters to third parties.",
            "Referrer-Policy: (missing)",
            "Set Referrer-Policy, for example: strict-origin-when-cross-origin.",
        )

    if "permissions-policy" not in headers:
        _add_finding(
            findings,
            "Low",
            "Missing Permissions-Policy",
            "Permissions-Policy is not set. Browser features are not explicitly restricted.",
            "Permissions-Policy: (missing)",
            "Set Permissions-Policy to restrict unnecessary browser capabilities.",
        )

    return findings


def _tls_findings(tls_info: dict, is_https: bool) -> list:
    findings = []

    if not is_https:
        _add_finding(
            findings,
            "Critical",
            "Site does not use HTTPS by default",
            "The provided URL uses HTTP. Traffic may be intercepted or modified in transit.",
            "Scheme: http",
            "Redirect all traffic to HTTPS and enforce HSTS.",
        )
        return findings

    if not tls_info.get("ok"):
        _add_finding(
            findings,
            "High",
            "TLS handshake failed",
            "Darklake could not complete a TLS handshake. The certificate or TLS configuration might be broken.",
            tls_info.get("error") or "TLS error",
            "Fix certificate chain / TLS configuration and ensure port 443 is reachable.",
        )
        return findings

    tls_ver = tls_info.get("tls_version") or "Unknown"

    if tls_ver in ("TLSv1", "TLSv1.1"):
        _add_finding(
            findings,
            "High",
            "Legacy TLS version negotiated",
            "A legacy TLS version was negotiated. This may indicate weak compatibility settings.",
            f"Negotiated: {tls_ver}",
            "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
        )

    return findings


def _score_and_metrics(findings: list) -> tuple[int, dict]:
    weights = {
        "critical": 30,
        "high": 18,
        "medium": 8,
        "low": 3,
        "info": 0,
    }

    score = 0

    counts = {
        "total": 0,
        "severe": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for f in findings:
        sev = f.get("severity_key", "info")

        counts["total"] += 1
        score += weights.get(sev, 0)

        if sev in ("critical", "high"):
            counts["severe"] += 1
        elif sev == "medium":
            counts["medium"] += 1
        elif sev == "low":
            counts["low"] += 1
        else:
            counts["info"] += 1

    score = max(0, min(100, score))

    return score, counts


def _risk_level(score: int, findings: list) -> tuple[str, str]:
    has_critical = any(f.get("severity_key") == "critical" for f in findings)
    has_high = any(f.get("severity_key") == "high" for f in findings)
    medium_count = sum(1 for f in findings if f.get("severity_key") == "medium")

    if has_critical:
        return "High Risk", "high"

    if score >= 70:
        return "High Risk", "high"

    if has_high or score >= 35 or medium_count >= 3:
        return "Medium Risk", "medium"

    return "Low Risk", "low"


def _risk_summary(risk_level: str, counts: dict) -> str:
    if risk_level == "High Risk":
        return (
            "Darklake detected at least one serious issue that should be reviewed first. "
            "Prioritize severe findings before improving lower-impact hardening items."
        )

    if risk_level == "Medium Risk":
        return (
            "Darklake detected meaningful security hardening gaps. "
            "The site is not necessarily vulnerable, but the highlighted findings should be reviewed and prioritized."
        )

    if counts.get("total", 0) == 0:
        return (
            "Darklake did not detect notable passive security issues from the collected public signals. "
            "This does not replace deeper authenticated or active security testing."
        )

    return (
        "Darklake detected mostly low-impact or informational findings. "
        "Review them as hardening opportunities rather than immediate critical vulnerabilities."
    )


def _build_stages(findings: list, tech_snapshot: list, tls_info: dict, is_https: bool) -> list:
    def count_by_keywords(keywords):
        return sum(
            1 for f in findings
            if any(k in f.get("title", "").lower() for k in keywords)
            and f.get("severity_key") != "info"
        )

    def stage(name, desc, key, issues_count):
        if issues_count == 0:
            status_key = "ok"
            status_label = "Completed"
        elif issues_count <= 2:
            status_key = "warning"
            status_label = "Completed - Issues Found"
        else:
            status_key = "critical"
            status_label = "Completed - Multiple Issues"

        if key == "tls" and is_https and not tls_info.get("ok"):
            status_key = "critical"
            status_label = "Completed - TLS Issue"

        return {
            "name": name,
            "description": desc,
            "issues_count": issues_count,
            "status_key": status_key,
            "status_label": status_label,
        }

    headers_issues = count_by_keywords((
        "content-security-policy",
        "hsts",
        "clickjacking",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ))

    tls_issues = count_by_keywords(("tls", "https", "certificate"))
    recon_issues = count_by_keywords(("header disclosed", "powered-by"))

    passive_issues = max(
        0,
        sum(1 for f in findings if f.get("severity_key") != "info")
        - (headers_issues + tls_issues + recon_issues),
    )

    return [
        stage(
            "Fingerprinting & Recon",
            "Extracts public signals: server identifiers, redirects, and response metadata.",
            "recon",
            recon_issues,
        ),
        stage(
            "Technology Stack Detection",
            "Infers technologies from headers and HTML patterns.",
            "tech",
            0,
        ),
        stage(
            "Security Headers Analysis",
            "Checks essential HTTP security headers and common misconfigurations.",
            "headers",
            headers_issues,
        ),
        stage(
            "TLS & Certificate Validation",
            "Collects certificate metadata and negotiated TLS version.",
            "tls",
            tls_issues,
        ),
        stage(
            "Passive Weakness Review",
            "Highlights common weaknesses observable from public signals.",
            "passive",
            passive_issues,
        ),
    ]


def _unknown_tech_snapshot() -> list:
    return [
        {"label": "Hosting / Server", "value": "Unknown"},
        {"label": "Backend Technology", "value": "Not disclosed"},
        {"label": "Traffic Protection / CDN", "value": "Unknown"},
        {"label": "Website Platform", "value": "Not confidently detected"},
        {"label": "Frontend Framework", "value": "Not confidently detected"},
    ]


def _sort_findings(findings: list) -> list:
    sev_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    return sorted(
        findings,
        key=lambda x: sev_rank.get(x.get("severity_key", "info"), 9),
    )


def _build_analysis_context(raw_url: str, active_tab: str = "overview") -> dict:
    target_url = _normalize_url(raw_url)
    _assert_public_url(target_url)

    final_url = target_url
    hostname = _extract_hostname(target_url)
    is_https = urlparse(target_url).scheme == "https"

    html = ""
    headers = {}
    tls_info = {"ok": False}
    findings = []
    tech_snapshot = _unknown_tech_snapshot()

    try:
        resp = _safe_get(target_url)

        final_url = resp.url or target_url
        _assert_public_url(final_url)

        hostname = _extract_hostname(final_url) or hostname
        is_https = urlparse(final_url).scheme == "https"

        if hostname and is_https:
            tls_info = _check_tls(hostname)

        headers = _normalize_headers(resp.headers)
        html = _read_limited_text(resp, max_bytes=200_000)

    except requests.RequestException as e:
        if hostname and is_https:
            tls_info = _check_tls(hostname)

        _add_finding(
            findings,
            "Medium",
            "Site content could not be fetched",
            (
                "Darklake could not download the HTML content within the time limits. "
                "TLS and basic checks may still be available."
            ),
            str(e)[:200],
            "Try again later, test a lighter URL, or increase timeouts if this is your own system.",
        )

    if headers:
        tech_snapshot = _detect_tech(headers, html)
        findings.extend(_security_headers_findings(headers, is_https))

        if headers.get("server"):
            _add_finding(
                findings,
                "Info",
                "Server header disclosed",
                "Server header reveals implementation details that may help fingerprint the stack.",
                f"Server: {headers.get('server')}",
                "Optional: minimize or standardize the Server header where possible.",
            )

        if headers.get("x-powered-by"):
            _add_finding(
                findings,
                "Info",
                "X-Powered-By header disclosed",
                "X-Powered-By reveals framework/runtime details and increases fingerprinting accuracy.",
                f"X-Powered-By: {headers.get('x-powered-by')}",
                "Remove or mask X-Powered-By header at the web server or application level.",
            )

    findings.extend(_tls_findings(tls_info, is_https))
    findings = _sort_findings(findings)

    risk_score, counts = _score_and_metrics(findings)
    risk_level, risk_key = _risk_level(risk_score, findings)
    risk_summary = _risk_summary(risk_level, counts)

    top_findings = [
        f for f in findings
        if f.get("severity_key") != "info"
    ][:4]

    if not top_findings:
        top_findings = findings[:4]

    stages = _build_stages(findings, tech_snapshot, tls_info, is_https)

    allowed_tabs = {"overview", "tech", "findings", "tls", "report"}

    if active_tab not in allowed_tabs:
        active_tab = "overview"

    return {
        "query_url": target_url,
        "target_display": final_url or target_url,
        "target_host": hostname or "Unknown",
        "scanned_at": timezone.now().strftime("%Y-%m-%d %H:%M"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_level_key": risk_key,
        "risk_summary": risk_summary,
        "metrics": counts,
        "stages": stages,
        "tech_snapshot": tech_snapshot,
        "top_findings": top_findings,
        "findings": findings,
        "tls_info": tls_info,
        "active_tab": active_tab,
    }


def _safe_pdf_text(value) -> str:
    value = "" if value is None else str(value)

    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _build_pdf_report(context: dict) -> bytes:
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Darklake Security Report",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DarklakeTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#111111"),
        spaceAfter=10,
        alignment=TA_LEFT,
    )

    h2_style = ParagraphStyle(
        "DarklakeH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#111111"),
        spaceBefore=14,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "DarklakeNormal",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#222222"),
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "DarklakeSmall",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555"),
    )

    story = []

    target_display = context.get("target_display", "Unknown")
    target_host = context.get("target_host", "Unknown")
    scanned_at = context.get("scanned_at", "Unknown")
    risk_score = context.get("risk_score", 0)
    risk_level = context.get("risk_level", "Unknown")
    risk_summary = context.get("risk_summary", "")
    metrics = context.get("metrics", {})
    findings = context.get("findings", [])
    tech_snapshot = context.get("tech_snapshot", [])
    tls_info = context.get("tls_info", {})

    story.append(Paragraph("Darklake Security Report", title_style))
    story.append(Paragraph(f"<b>Target URL:</b> {_safe_pdf_text(target_display)}", normal_style))
    story.append(Paragraph(f"<b>Host:</b> {_safe_pdf_text(target_host)}", normal_style))
    story.append(Paragraph(f"<b>Scanned:</b> {_safe_pdf_text(scanned_at)}", normal_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Executive Summary", h2_style))
    story.append(Paragraph(
        f"<b>Risk score:</b> {_safe_pdf_text(risk_score)} / 100 - <b>{_safe_pdf_text(risk_level)}</b>",
        normal_style,
    ))
    story.append(Paragraph(_safe_pdf_text(risk_summary), normal_style))

    summary_data = [
        ["Total Findings", "Severe", "Medium", "Low", "Info"],
        [
            str(metrics.get("total", 0)),
            str(metrics.get("severe", 0)),
            str(metrics.get("medium", 0)),
            str(metrics.get("low", 0)),
            str(metrics.get("info", 0)),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[34 * mm, 30 * mm, 30 * mm, 30 * mm, 30 * mm],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d0d0")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f7f7f7")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(summary_table)

    story.append(Paragraph("Technology Snapshot", h2_style))

    tech_data = [["Category", "Detected Value"]]

    for item in tech_snapshot:
        tech_data.append([
            Paragraph(_safe_pdf_text(item.get("label", "")), small_style),
            Paragraph(_safe_pdf_text(item.get("value", "")), small_style),
        ])

    tech_table = Table(tech_data, colWidths=[48 * mm, 120 * mm])
    tech_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d0d0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tech_table)

    story.append(Paragraph("TLS & Certificate", h2_style))

    tls_table_data = [
        ["Field", "Value"],
        ["TLS OK", "Yes" if tls_info.get("ok") else "No"],
        ["TLS Version", tls_info.get("tls_version") or "Unknown"],
        ["Certificate Subject", tls_info.get("cert_subject") or "-"],
        ["Certificate Issuer", tls_info.get("cert_issuer") or "-"],
        ["Valid From", tls_info.get("not_before") or "-"],
        ["Valid Until", tls_info.get("not_after") or "-"],
    ]

    if tls_info.get("error"):
        tls_table_data.append(["TLS Error", tls_info.get("error")])

    tls_rows = [["Field", "Value"]]

    for row in tls_table_data[1:]:
        tls_rows.append([
            Paragraph(_safe_pdf_text(row[0]), small_style),
            Paragraph(_safe_pdf_text(row[1]), small_style),
        ])

    tls_table = Table(tls_rows, colWidths=[48 * mm, 120 * mm])
    tls_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d0d0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(tls_table)

    story.append(Paragraph("Findings Summary", h2_style))

    if findings:
        for index, finding in enumerate(findings, start=1):
            severity = finding.get("severity", "Info")
            title = finding.get("title", "Untitled finding")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            recommendation = finding.get("recommendation", "")

            story.append(Paragraph(
                f"<b>{index}. [{_safe_pdf_text(severity)}] {_safe_pdf_text(title)}</b>",
                normal_style,
            ))

            if description:
                story.append(Paragraph(
                    f"<b>Description:</b> {_safe_pdf_text(description)}",
                    small_style,
                ))

            if evidence:
                story.append(Paragraph(
                    f"<b>Evidence:</b> {_safe_pdf_text(evidence)}",
                    small_style,
                ))

            if recommendation:
                story.append(Paragraph(
                    f"<b>Recommendation:</b> {_safe_pdf_text(recommendation)}",
                    small_style,
                ))

            story.append(Spacer(1, 5))
    else:
        story.append(Paragraph("No findings were detected.", normal_style))

    story.append(Paragraph("Important Notes", h2_style))
    story.append(Paragraph(
        "This report is based on passive analysis only. It does not perform intrusive scanning, "
        "authentication checks, exploit validation, brute force testing, or active vulnerability exploitation. "
        "Use it as a prioritization layer before deeper testing.",
        normal_style,
    ))

    doc.build(story)

    pdf = buffer.getvalue()
    buffer.close()

    return pdf


def analyze(request):
    raw_url = request.GET.get("url", "")
    active_tab = request.GET.get("tab", "overview")

    try:
        context = _build_analysis_context(raw_url, active_tab)
        return render(request, "main/components/analysis_results.html", context)

    except ValueError as e:
        return render(request, "main/components/analysis_results.html", {
            "error": str(e),
            "active_tab": "overview",
        })

    except Exception as e:
        return render(request, "main/components/analysis_results.html", {
            "error": f"Unexpected error: {str(e)[:200]}",
            "active_tab": "overview",
        })


def download_report_pdf(request):
    raw_url = request.GET.get("url", "")

    try:
        context = _build_analysis_context(raw_url, active_tab="report")
        pdf = _build_pdf_report(context)

        host = context.get("target_host", "darklake-report")
        safe_host = re.sub(r"[^a-zA-Z0-9.-]+", "-", host).strip("-") or "darklake-report"

        response = HttpResponse(pdf, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="darklake-report-{safe_host}.pdf"'

        return response

    except ValueError as e:
        return HttpResponse(str(e), status=400, content_type="text/plain")

    except Exception as e:
        return HttpResponse(
            f"Could not generate PDF report: {str(e)[:200]}",
            status=500,
            content_type="text/plain",
        )