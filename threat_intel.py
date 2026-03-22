"""
Module Threat Intelligence: abuse.ch feeds + GitHub trending security repos.
"""

import logging
import requests
from datetime import datetime, timedelta, timezone
from html import escape

logger = logging.getLogger(__name__)

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"


# === ABUSE.CH FEEDS ===

def fetch_urlhaus_recent():
    """Recupere les URLs malveillantes recentes depuis URLhaus."""
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers={"User-Agent": UA},
            data={"limit": 10},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        urls = data.get("urls", [])

        results = []
        for u in urls[:5]:
            results.append({
                "url": u.get("url", ""),
                "threat": u.get("threat", "N/A"),
                "tags": u.get("tags", []),
                "host": u.get("host", ""),
                "date_added": u.get("date_added", ""),
                "status": u.get("url_status", ""),
            })
        logger.info("URLhaus: %d URLs malveillantes recentes", len(results))
        return results
    except Exception as e:
        logger.error("Erreur URLhaus: %s", e)
        return []


def fetch_threatfox_recent():
    """Recupere les IOC recents depuis ThreatFox."""
    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"User-Agent": UA},
            json={"query": "get_iocs", "days": 1},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        iocs = data.get("data", [])

        results = []
        for ioc in iocs[:5]:
            results.append({
                "ioc": ioc.get("ioc", ""),
                "ioc_type": ioc.get("ioc_type", ""),
                "threat_type": ioc.get("threat_type", ""),
                "malware": ioc.get("malware_printable", ""),
                "confidence": ioc.get("confidence_level", 0),
                "tags": ioc.get("tags", []),
                "reference": ioc.get("reference", ""),
            })
        logger.info("ThreatFox: %d IOC recents", len(results))
        return results
    except Exception as e:
        logger.error("Erreur ThreatFox: %s", e)
        return []


def fetch_malwarebazaar_recent():
    """Recupere les malwares recents depuis MalwareBazaar."""
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"User-Agent": UA},
            data={"query": "get_recent", "selector": "time"},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        samples = data.get("data", [])

        results = []
        for s in samples[:5]:
            results.append({
                "sha256": s.get("sha256_hash", ""),
                "filename": s.get("file_name", "N/A"),
                "file_type": s.get("file_type", ""),
                "signature": s.get("signature", "N/A"),
                "tags": s.get("tags", []),
                "delivery": s.get("delivery_method", ""),
            })
        logger.info("MalwareBazaar: %d samples recents", len(results))
        return results
    except Exception as e:
        logger.error("Erreur MalwareBazaar: %s", e)
        return []


def format_abuse_ch_digest():
    """Formate un digest des feeds abuse.ch."""
    urlhaus = fetch_urlhaus_recent()
    threatfox = fetch_threatfox_recent()
    malware = fetch_malwarebazaar_recent()

    if not urlhaus and not threatfox and not malware:
        return None

    lines = [
        "\U0001f6e1 <b>Threat Intel — abuse.ch</b>",
        "",
    ]

    if urlhaus:
        lines.append("\U0001f310 <b>URLhaus — URLs malveillantes</b>")
        for u in urlhaus[:3]:
            threat = escape(u["threat"])
            host = escape(u["host"])
            tags = ", ".join(u.get("tags") or [])
            lines.append(f"  \u2022 {host} — {threat}")
            if tags:
                lines.append(f"    Tags: {escape(tags)}")
        lines.append("")

    if threatfox:
        lines.append("\U0001f9a0 <b>ThreatFox — IOC</b>")
        for ioc in threatfox[:3]:
            malware_name = escape(ioc["malware"])
            ioc_type = escape(ioc["ioc_type"])
            ioc_val = escape(ioc["ioc"][:60])
            lines.append(f"  \u2022 {malware_name} ({ioc_type})")
            lines.append(f"    {ioc_val}")
        lines.append("")

    if malware:
        lines.append("\U0001f4a3 <b>MalwareBazaar — Samples</b>")
        for m in malware[:3]:
            sig = escape(m["signature"])
            ftype = escape(m["file_type"])
            fname = escape(m["filename"][:40])
            lines.append(f"  \u2022 {sig} — {ftype}")
            lines.append(f"    {fname}")
        lines.append("")

    lines.append('\U0001f517 <a href="https://urlhaus.abuse.ch">URLhaus</a> | '
                 '<a href="https://threatfox.abuse.ch">ThreatFox</a> | '
                 '<a href="https://bazaar.abuse.ch">MalwareBazaar</a>')

    return "\n".join(lines)


# === GITHUB TRENDING SECURITY ===

def fetch_github_trending_security():
    """Recupere les repos GitHub trending en securite."""
    try:
        # Utiliser l'API GitHub search pour les repos security crees/mis a jour recemment
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        params = {
            "q": f"topic:security topic:cybersecurity pushed:>{week_ago} stars:>50",
            "sort": "stars",
            "order": "desc",
            "per_page": 5,
        }
        response = requests.get(
            "https://api.github.com/search/repositories",
            params=params,
            headers={
                "User-Agent": UA,
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        repos = data.get("items", [])

        results = []
        for repo in repos[:5]:
            results.append({
                "name": repo.get("full_name", ""),
                "description": repo.get("description", ""),
                "stars": repo.get("stargazers_count", 0),
                "url": repo.get("html_url", ""),
                "language": repo.get("language", ""),
                "topics": repo.get("topics", []),
            })
        logger.info("GitHub trending: %d repos securite", len(results))
        return results
    except Exception as e:
        logger.error("Erreur GitHub trending: %s", e)
        return []


def format_github_trending():
    """Formate les repos GitHub trending securite."""
    repos = fetch_github_trending_security()
    if not repos:
        return None

    lines = [
        "\U0001f4bb <b>GitHub Trending — Securite</b>",
        "",
    ]

    for i, repo in enumerate(repos, 1):
        name = escape(repo["name"])
        desc = escape((repo["description"] or "")[:100])
        stars = repo["stars"]
        url = repo["url"]
        lang = escape(repo.get("language") or "")

        lines.append(f"<b>{i}.</b> <a href=\"{escape(url)}\">{name}</a> \u2b50 {stars}")
        if desc:
            lines.append(f"   {desc}")
        if lang:
            lines.append(f"   \U0001f4dd {lang}")
        lines.append("")

    return "\n".join(lines)
