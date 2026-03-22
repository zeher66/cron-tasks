"""
Module de surveillance CVE via l'API NVD (National Vulnerability Database).
Interroge les CVE recentes critiques/hautes et les envoie sur Telegram.
100% gratuit, pas besoin de cle API (mais rate-limite a 5 req/30s).
"""

import logging
import requests
from datetime import datetime, timedelta, timezone
from html import escape

from config import REQUEST_TIMEOUT, USER_AGENT

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(hours=6, severity="CRITICAL"):
    """Recupere les CVE recentes depuis l'API NVD."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "cvssV3Severity": severity,
        "resultsPerPage": 20,
    }

    headers = {
        "User-Agent": USER_AGENT,
    }

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.RequestException as e:
        logger.error("Erreur API NVD: %s", e)
        return []


def parse_cve(vuln_item):
    """Parse un item CVE du NVD en format article."""
    cve = vuln_item.get("cve", {})
    cve_id = cve.get("id", "CVE-UNKNOWN")

    # Description (en anglais par defaut)
    descriptions = cve.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # Score CVSS
    cvss_score = None
    cvss_severity = None
    metrics = cve.get("metrics", {})

    # Essayer CVSS v3.1, puis v3.0, puis v4.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
            break

    # Produits affectes (CPE)
    affected = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                # Extraire le nom du produit du CPE
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    affected.append(f"{vendor}/{product}")

    # Limiter a 5 produits
    affected = list(set(affected))[:5]

    # References
    references = cve.get("references", [])
    ref_url = ""
    for ref in references:
        ref_url = ref.get("url", "")
        break

    # Date de publication
    published = cve.get("published", "")

    # URL NVD
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "affected": affected,
        "ref_url": ref_url,
        "nvd_url": nvd_url,
        "published": published,
    }


def _extract_attack_type(text):
    """Detecte le type d'attaque dans un texte."""
    text_lower = text.lower()
    attack_map = {
        "remote code execution": "\U0001f4bb Execution de code a distance",
        "buffer overflow": "\U0001f4a5 Debordement de tampon",
        "sql injection": "\U0001f489 Injection SQL",
        "privilege escalation": "\u2b06\ufe0f Escalade de privileges",
        "authentication bypass": "\U0001f513 Contournement d'authentification",
        "denial of service": "\U0001f6ab Deni de service",
        "cross-site scripting": "\U0001f310 XSS",
        "information disclosure": "\U0001f441 Fuite d'information",
        "debordement de tampon": "\U0001f4a5 Debordement de tampon",
        "execution de code": "\U0001f4bb Execution de code",
        "injection": "\U0001f489 Injection",
    }
    for pattern, label in attack_map.items():
        if pattern in text_lower:
            return label
    return ""


def _extract_key_points_from_text(text):
    """Extrait 2-3 points cles d'un texte."""
    import re
    if not text or len(text) < 50:
        return []
    sentences = re.split(r'(?<=[.!?])\s+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
    if len(sentences) <= 2:
        return []
    points = []
    for s in sentences:
        if 30 < len(s) < 150:
            if len(s) > 100:
                dot = s.find(",", 50)
                if dot > 0:
                    s = s[:dot]
            points.append(s)
        if len(points) >= 3:
            break
    return points


def format_cve_message(cve_data):
    """Formate un CVE — meme format que les articles."""
    cve_id = escape(cve_data["cve_id"])
    score = cve_data.get("cvss_score", "N/A")
    severity = cve_data.get("cvss_severity", "N/A")
    description = escape(cve_data.get("description", "Pas de description"))
    nvd_url = cve_data["nvd_url"]
    ref_url = cve_data.get("ref_url", "")

    # Header
    if severity == "CRITICAL":
        header = "\U0001f534\U0001f534\U0001f534 <b>CRITIQUE</b> | \u26a0\ufe0f CVE"
        bar = "\u2588" * 10
    elif severity == "HIGH":
        header = "\U0001f7e0\U0001f7e0 <b>HAUT</b> | \u26a0\ufe0f CVE"
        bar = "\u2588" * 7 + "\u2591" * 3
    else:
        header = "\U0001f7e1 <b>MOYEN</b> | \u26a0\ufe0f CVE"
        bar = "\u2588" * 5 + "\u2591" * 5

    affected = cve_data.get("affected", [])
    target = ", ".join(escape(a) for a in affected) if affected else "Non specifie"
    attack_type = _extract_attack_type(description)

    # Titre = CVE ID + CVSS + cible
    title = f"{cve_id} (CVSS {score}) — {target}"

    # Description detaillee
    if len(description) > 600:
        cut = description.find(".", 500)
        if cut > 0 and cut < 700:
            description = description[:cut + 1]
        else:
            description = description[:600].rstrip() + "..."

    # Points cles
    key_points = _extract_key_points_from_text(description)
    # Ajouter infos structurees
    if target != "Non specifie":
        key_points.insert(0, f"Cible : {target}")
    if attack_type:
        key_points.insert(1, f"Type : {attack_type}")
    key_points = key_points[:4]

    lines = [
        header,
        f"<code>{bar}</code>",
        "",
        f"\U0001f4f0 NVD",
        "",
        f"<b>{title}</b>",
        "",
        f"\U0001f4d6 {description}",
    ]

    if key_points:
        lines.append("")
        lines.append("\U0001f511 <b>A retenir :</b>")
        for p in key_points:
            lines.append(f"\u2022 {p}")

    # Liens
    lines.append("")
    from urllib.parse import quote
    translate_nvd = f"https://translate.google.com/translate?sl=en&tl=fr&u={quote(nvd_url)}"
    link_line = f'\u27a1\ufe0f <a href="{escape(translate_nvd)}">Lire en FR</a> | \U0001f517 <a href="{escape(nvd_url)}">Original EN</a>'
    if ref_url and ref_url != nvd_url:
        link_line += f' | <a href="{escape(ref_url)}">PoC</a>'
    lines.append(link_line)

    return "\n".join(lines)


def fetch_cisa_kev():
    """Recupere les CVE activement exploitees depuis le CISA KEV."""
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(kev_url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        # Filtrer les CVE ajoutees dans les dernieres 48h
        recent = []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=48)
        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded", "")
            try:
                dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if dt >= cutoff:
                    recent.append({
                        "cve_id": vuln.get("cveID", ""),
                        "description": vuln.get("shortDescription", ""),
                        "cvss_score": "N/A",
                        "cvss_severity": "CRITICAL",
                        "affected": [f"{vuln.get('vendorProject', '')}/{vuln.get('product', '')}"],
                        "ref_url": "",
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID', '')}",
                        "published": date_added,
                        "kev": True,
                    })
            except (ValueError, TypeError):
                continue

        logger.info("CISA KEV: %d CVE activement exploitees recentes", len(recent))
        return recent
    except requests.RequestException as e:
        logger.error("Erreur CISA KEV: %s", e)
        return []


def format_kev_message(cve_data):
    """Formate un CVE CISA KEV — exploitation active confirmee."""
    cve_id = escape(cve_data["cve_id"])
    description = escape(cve_data.get("description", ""))
    nvd_url = cve_data["nvd_url"]
    affected = cve_data.get("affected", [])
    target = ", ".join(escape(a) for a in affected) if affected else "Non specifie"

    title = f"{cve_id} — {target}"

    if len(description) > 600:
        cut = description.find(".", 500)
        if cut > 0 and cut < 700:
            description = description[:cut + 1]
        else:
            description = description[:600].rstrip() + "..."

    lines = [
        "\U0001f6a8\U0001f6a8\U0001f6a8 <b>CRITIQUE</b> | \U0001f525 Exploitation Active",
        "<code>\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588</code>",
        "",
        "\U0001f4f0 CISA KEV",
        "",
        f"<b>{title}</b>",
        "",
        f"\U0001f4d6 {description}",
        "",
        "\U0001f511 <b>A retenir :</b>",
        f"\u2022 Cible : {target}",
        "\u2022 Exploit utilise dans la nature",
        "\u2022 Action : Patcher IMMEDIATEMENT",
        "",
    ]

    from urllib.parse import quote
    translate_nvd = f"https://translate.google.com/translate?sl=en&tl=fr&u={quote(nvd_url)}"
    lines.append(f'\u27a1\ufe0f <a href="{escape(translate_nvd)}">Lire en FR</a> | \U0001f517 <a href="{escape(nvd_url)}">Original EN</a>')

    return "\n".join(lines)


def get_new_cves(hours=6):
    """Recupere et formate les nouvelles CVE critiques et hautes."""
    all_cves = []

    # CVE critiques (dernières X heures)
    critical = fetch_recent_cves(hours=hours, severity="CRITICAL")
    for vuln in critical:
        all_cves.append(parse_cve(vuln))

    # CVE hautes (dernières X heures)
    high = fetch_recent_cves(hours=hours, severity="HIGH")
    for vuln in high:
        all_cves.append(parse_cve(vuln))

    logger.info("CVE trouvees: %d critiques, %d hautes", len(critical), len(high))
    return all_cves


def get_kev_cves():
    """Recupere les CVE CISA KEV recentes."""
    return fetch_cisa_kev()
