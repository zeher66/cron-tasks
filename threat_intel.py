"""
Module Threat Intelligence: abuse.ch feeds + GitHub trending security repos + PoC monitor.
"""

import logging
import requests
from datetime import datetime, timedelta, timezone
from html import escape

from config import MY_STACK

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


# === POC MONITOR ===

# Mots-cles qui indiquent un VRAI PoC/exploit
POC_KEYWORDS = [
    "exploit", "poc", "proof of concept", "rce", "xss", "sqli",
    "injection", "bypass", "overflow", "shell", "reverse",
    "payload", "scanner", "detection", "vulnerability",
    "unauthenticated", "privilege escalation", "remote code",
    "dos", "denial of service", "lfi", "rfi", "ssrf", "deserialization",
]

# Mots-cles qui indiquent un FAUX positif (pas un vrai exploit)
POC_NOISE = [
    "homework", "assignment", "class project", "course", "tutorial",
    "learning", "study", "practice", "vectors implemented",
    "agent_dev", "database", "tracker", "list of", "collection",
    "awesome", "benchmark", "bench", "dataset",
]


def _is_real_poc(name, description):
    """Filtre les faux positifs — ne garde que les vrais PoC."""
    text = (name + " " + description).lower()

    # Rejeter si mot-cle de bruit
    if any(noise in text for noise in POC_NOISE):
        return False

    # Le nom doit contenir un vrai CVE ID (CVE-XXXX-XXXXX)
    import re
    has_cve_id = bool(re.search(r'cve-\d{4}-\d{4,}', text))

    # Si pas de CVE ID precis, rejeter
    if not has_cve_id:
        return False

    # Bonus si description contient des mots-cles d'exploit
    has_poc_keyword = any(kw in text for kw in POC_KEYWORDS)

    # Accepter si : CVE ID + (description OU keyword OU stars > 0)
    return has_cve_id and (has_poc_keyword or len(description) > 20)


def _translate_poc_description(desc):
    """Traduit et enrichit la description d'un PoC."""
    if not desc:
        return "Pas de description disponible"

    try:
        from deep_translator import GoogleTranslator
        translated = GoogleTranslator(source="auto", target="fr").translate(desc[:500])
        return translated or desc
    except Exception:
        return desc


def fetch_new_pocs():
    """Surveille GitHub pour les nouveaux repos PoC — filtre les faux positifs."""
    try:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        params = {
            "q": f"CVE- in:name created:{today}",
            "sort": "stars",
            "order": "desc",
            "per_page": 20,
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
        for repo in repos:
            name = repo.get("full_name", "")
            desc = repo.get("description", "") or ""
            stars = repo.get("stargazers_count", 0)

            # Filtrer les faux positifs
            if not _is_real_poc(name, desc):
                logger.debug("PoC filtre (faux positif): %s", name)
                continue

            # Extraire le CVE ID du nom
            import re
            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', name, re.IGNORECASE)
            cve_id = cve_match.group(1).upper() if cve_match else ""

            # Verifier si le PoC concerne notre stack
            text_lower = (name + " " + desc).lower()
            concerns_my_stack = any(tech.lower() in text_lower for tech in MY_STACK)

            results.append({
                "name": name,
                "description": desc,
                "stars": stars,
                "url": repo.get("html_url", ""),
                "language": repo.get("language", ""),
                "cve_id": cve_id,
                "concerns_my_stack": concerns_my_stack,
            })

        logger.info("PoC Monitor: %d vrais PoC (sur %d repos)", len(results), len(repos))
        return results
    except Exception as e:
        logger.error("Erreur PoC Monitor: %s", e)
        return []


def format_poc_alert(pocs):
    """Formate les alertes PoC — format unifie avec details."""
    if not pocs:
        return None

    lines = [
        "\U0001f534\U0001f534 <b>IMPORTANT</b> | \U0001f4a3 PoC / Exploit",
        "<code>" + "\u2588" * 7 + "\u2591" * 3 + "</code>",
        "",
        "\U0001f4f0 GitHub PoC Monitor",
        "",
        f"<b>{len(pocs)} nouveaux exploits publics detectes</b>",
        "",
    ]

    for poc in pocs[:6]:
        name = escape(poc["name"])
        desc = poc.get("description", "")
        desc_fr = _translate_poc_description(desc)
        desc_fr = escape(desc_fr[:150])
        stars = poc["stars"]
        url = poc["url"]
        cve_id = poc.get("cve_id", "")
        lang = escape(poc.get("language") or "")
        stack_tag = " \u26a1" if poc["concerns_my_stack"] else ""

        lines.append(f"\U0001f3af <b>{cve_id}</b>{stack_tag}")
        lines.append(f"\U0001f4d6 {desc_fr}")
        if lang:
            lines.append(f"\U0001f4dd Langage: {lang} | \u2b50 {stars}")
        lines.append(f'\U0001f517 <a href="{escape(url)}">Voir le PoC</a>')
        lines.append("")

    # Points cles
    lines.append("\U0001f511 <b>A retenir :</b>")
    lines.append(f"\u2022 {len(pocs)} nouveaux PoC publics aujourd'hui")
    stack_pocs = [p for p in pocs if p["concerns_my_stack"]]
    if stack_pocs:
        lines.append(f"\u2022 \u26a1 {len(stack_pocs)} concernent votre stack technique")
    lines.append("\u2022 Verifiez si vos systemes sont affectes")

    # Lien
    lines.append("")
    lines.append(f'\u27a1\ufe0f <a href="https://github.com/search?q=CVE-+in%3Aname&type=repositories&s=updated&o=desc">Voir tous les PoC</a>')

    return "\n".join(lines)


# === STACK FILTER ===

def check_stack_relevance(text):
    """Verifie si un texte concerne notre stack technique."""
    if not text:
        return False, []
    text_lower = text.lower()
    matched = [tech for tech in MY_STACK if tech.lower() in text_lower]
    return bool(matched), matched
