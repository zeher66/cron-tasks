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
    """Formate un CVE pour Telegram."""
    cve_id = escape(cve_data["cve_id"])
    score = cve_data.get("cvss_score", "N/A")
    severity = cve_data.get("cvss_severity", "N/A")
    description = escape(cve_data.get("description", "Pas de description"))
    nvd_url = cve_data["nvd_url"]

    # Emoji selon la severite
    if severity == "CRITICAL":
        emoji = "\U0001f534"  # 🔴
    elif severity == "HIGH":
        emoji = "\U0001f7e0"  # 🟠
    else:
        emoji = "\U0001f7e1"  # 🟡

    # Tronquer la description
    if len(description) > 500:
        description = description[:500]
        last_period = description.rfind(".")
        if last_period > 250:
            description = description[:last_period + 1]
        else:
            description = description.rstrip() + "..."

    lines = [
        f"{emoji} <b>CVE | {severity}</b> | CVSS {score}",
        "",
        f"\U0001f4cc <b>{cve_id}</b>",
        "",
        description,
        "",
    ]

    # Produits affectes
    affected = cve_data.get("affected", [])
    if affected:
        lines.append(f"\U0001f4e6 <b>Affecte:</b> {', '.join(escape(a) for a in affected)}")
        lines.append("")

    # Date
    published = cve_data.get("published", "")
    if published:
        try:
            dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            lines.append(f"\U0001f4c5 {dt.strftime('%d/%m/%Y %H:%M UTC')}")
        except (ValueError, TypeError):
            pass

    lines.append("")
    lines.append(f'\U0001f517 <a href="{escape(nvd_url)}">Voir sur NVD</a>')

    # Reference externe si disponible
    ref_url = cve_data.get("ref_url", "")
    if ref_url and ref_url != nvd_url:
        lines.append(f'\U0001f4ce <a href="{escape(ref_url)}">Reference</a>')

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
    """Formate un CVE CISA KEV pour Telegram."""
    cve_id = escape(cve_data["cve_id"])
    description = escape(cve_data.get("description", ""))
    nvd_url = cve_data["nvd_url"]
    affected = cve_data.get("affected", [])

    lines = [
        "\U0001f6a8 <b>CISA KEV | EXPLOITATION ACTIVE</b>",
        "",
        f"\U0001f4cc <b>{cve_id}</b>",
        "",
        description,
        "",
    ]

    if affected:
        lines.append(f"\U0001f4e6 <b>Affecte:</b> {', '.join(escape(a) for a in affected)}")
        lines.append("")

    lines.append(f'\U0001f517 <a href="{escape(nvd_url)}">Voir sur NVD</a>')

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
