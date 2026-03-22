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


def format_cve_message(cve_data):
    """Formate un CVE pour Telegram — lisible en 3 secondes."""
    cve_id = escape(cve_data["cve_id"])
    score = cve_data.get("cvss_score", "N/A")
    severity = cve_data.get("cvss_severity", "N/A")
    description = escape(cve_data.get("description", "Pas de description"))
    nvd_url = cve_data["nvd_url"]

    # Barre visuelle selon severite
    if severity == "CRITICAL":
        header = "\U0001f534\U0001f534\U0001f534 <b>CRITIQUE</b> \u2014 CVSS " + str(score)
        bar = "\u2588" * 10
    elif severity == "HIGH":
        header = "\U0001f7e0\U0001f7e0 <b>HAUT</b> \u2014 CVSS " + str(score)
        bar = "\u2588" * 7 + "\u2591" * 3
    else:
        header = "\U0001f7e1 <b>MOYEN</b> \u2014 CVSS " + str(score)
        bar = "\u2588" * 5 + "\u2591" * 5

    # Produits affectes
    affected = cve_data.get("affected", [])
    target = ", ".join(escape(a) for a in affected) if affected else "Non specifie"

    # Extraire le type d'attaque de la description
    attack_type = ""
    desc_lower = description.lower()
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
        if pattern in desc_lower:
            attack_type = label
            break

    # Tronquer la description a 2 phrases max
    if len(description) > 300:
        # Couper a la 2eme phrase
        first_dot = description.find(".", 0, 200)
        if first_dot > 0:
            second_dot = description.find(".", first_dot + 1, 350)
            if second_dot > 0:
                description = description[:second_dot + 1]
            else:
                description = description[:first_dot + 1]
        else:
            description = description[:300].rstrip() + "..."

    ref_url = cve_data.get("ref_url", "")

    lines = [
        header,
        f"<code>{bar}</code>",
        "",
        f"\U0001f3af <b>{cve_id}</b>",
        "",
        f"\U0001f4e6 <b>Cible :</b> {target}",
    ]

    if attack_type:
        lines.append(f"\u2694\ufe0f <b>Attaque :</b> {attack_type}")

    lines.extend([
        "",
        f"\U0001f4dd {description}",
        "",
        f'\U0001f517 <a href="{escape(nvd_url)}">NVD</a>',
    ])

    if ref_url and ref_url != nvd_url:
        lines[-1] += f' | <a href="{escape(ref_url)}">PoC / Details</a>'

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

    lines = [
        "\U0001f6a8\U0001f6a8\U0001f6a8 <b>EXPLOITATION ACTIVE</b>",
        "<code>\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588</code>",
        "",
        f"\U0001f3af <b>{cve_id}</b>",
        "",
        f"\U0001f4e6 <b>Cible :</b> {target}",
        f"\u26a0\ufe0f <b>Statut :</b> Exploit utilise dans la nature",
        "",
        f"\U0001f4dd {description}",
        "",
        f"\U0001f6e1\ufe0f <b>Action :</b> Patcher IMMEDIATEMENT",
        "",
        f'\U0001f517 <a href="{escape(nvd_url)}">NVD</a>',
    ]

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
