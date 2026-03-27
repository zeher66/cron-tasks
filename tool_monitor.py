"""
Module de surveillance des nouveaux outils cyber sur GitHub.
Detecte les outils offensifs, defensifs et polyvalents.
Sauvegarde dans outils/type/categorie/nom.md
"""

import os
import re
import logging
import requests
import time
from datetime import datetime, timedelta, timezone
from html import escape
from zoneinfo import ZoneInfo

logger = logging.getLogger(__name__)

OUTILS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outils")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

# Categories d'outils
TOOL_CATEGORIES = {
    "offensif": {
        "scanner": ["scanner", "nuclei", "nmap", "masscan", "zmap", "rustscan"],
        "exploit-framework": ["exploit", "metasploit", "exploit framework", "exploitation"],
        "c2": ["c2", "command and control", "beacon", "sliver", "havoc", "mythic", "cobalt strike"],
        "password": ["password crack", "hashcat", "john the ripper", "hydra", "brute force password"],
        "osint": ["osint", "recon", "reconnaissance", "theharvester", "maltego", "spiderfoot"],
        "reverse-engineering": ["reverse engineering", "disassembler", "decompiler", "ghidra", "ida", "radare"],
        "forensic": ["forensic", "autopsy", "volatility", "memory analysis", "disk forensic"],
        "web-attack": ["web attack", "sqlmap", "xsstrike", "burp", "web exploit", "web pentest"],
        "network-attack": ["network attack", "responder", "bettercap", "arp spoof", "mitm tool"],
        "social-engineering": ["social engineering", "phishing tool", "gophish", "set toolkit"],
        "privilege-escalation": ["privilege escalation", "linpeas", "winpeas", "privesc"],
        "phishing": ["phishing", "evilginx", "modlishka", "credential harvest"],
        "bruteforce": ["bruteforce", "gobuster", "ffuf", "dirb", "dirbuster", "fuzzer url"],
        "fuzzing": ["fuzzing", "fuzzer", "afl", "boofuzz", "fuzz"],
        "payload-generator": ["payload", "msfvenom", "veil", "shellcode generator"],
        "post-exploitation": ["post exploitation", "mimikatz", "bloodhound", "sharphound", "lateral movement"],
        "wireless": ["wireless", "aircrack", "wifite", "wifi hack", "bluetooth hack"],
        "mobile": ["mobile pentest", "frida", "objection", "android hack", "ios hack"],
        "cloud-attack": ["cloud attack", "pacu", "scoutsuite", "aws exploit", "azure exploit"],
        "container-attack": ["container attack", "peirates", "deepce", "docker escape", "kubernetes exploit"],
    },
    "defensif": {
        "edr-xdr": ["edr", "xdr", "endpoint detection", "wazuh", "ossec", "velociraptor"],
        "siem-soc": ["siem", "soc", "elk", "splunk", "qradar", "security information"],
        "waf-firewall": ["waf", "firewall", "modsecurity", "bunkerweb", "web application firewall"],
        "hardening": ["hardening", "cis benchmark", "lynis", "security baseline", "system hardening"],
        "monitoring": ["monitoring", "grafana", "nagios", "zabbix", "prometheus", "alerting"],
        "backup": ["backup", "restic", "borgbackup", "disaster recovery"],
        "antivirus": ["antivirus", "clamav", "yara", "malware detection", "virus scanner"],
        "encryption": ["encryption", "gpg", "veracrypt", "age encryption", "cipher"],
        "identity": ["identity", "keycloak", "freeipa", "sso", "authentication server"],
        "incident-response": ["incident response", "thehive", "grr", "ir tool"],
        "threat-hunting": ["threat hunting", "misp", "opencti", "threat intelligence platform"],
        "log-analysis": ["log analysis", "graylog", "loki", "log parser"],
        "vulnerability-management": ["vulnerability management", "openvas", "nessus", "vulnerability scanner"],
        "patch-management": ["patch management", "wsus", "patch"],
        "dlp": ["dlp", "data loss prevention", "data leak"],
        "zero-trust": ["zero trust", "tailscale", "wireguard", "ztna"],
        "devsecops": ["devsecops", "trivy", "snyk", "sonarqube", "sast", "dast", "code security"],
        "container-security": ["container security", "falco", "aqua", "docker security"],
        "cloud-security": ["cloud security", "prowler", "cloudsploit", "cspm"],
        "email-security": ["email security", "rspamd", "spamassassin", "dmarc", "dkim"],
    },
    "polyvalent": {
        "analyse": ["analysis tool", "cyberchef", "wireshark", "packet analysis"],
        "automation": ["automation", "ansible", "n8n", "security automation"],
        "reporting": ["reporting", "dradis", "plextrac", "pentest report"],
        "network-tools": ["network tool", "netcat", "tcpdump", "ncat"],
        "dns-tools": ["dns tool", "dig", "dnsrecon", "dns enumeration"],
        "ssl-tls": ["ssl", "tls", "testssl", "sslscan", "certificate"],
        "api-security": ["api security", "postman", "api test", "api pentest"],
        "ctf": ["ctf", "capture the flag", "ctfd", "picoctf"],
        "lab": ["lab", "vulnhub", "dvwa", "hackable", "vulnerable machine"],
    },
}


def _detect_tool_category(name, description):
    """Detecte le type et la sous-categorie d'un outil."""
    text = (name + " " + description).lower()

    for tool_type, categories in TOOL_CATEGORIES.items():
        for cat, keywords in categories.items():
            if any(kw in text for kw in keywords):
                return tool_type, cat

    return "polyvalent", "autre"


def _ai_classify_tool(name, description):
    """L'IA classe l'outil si les mots-cles ne suffisent pas."""
    try:
        from ai_summarizer import is_ai_available, _call_groq
        if not is_ai_available():
            return None

        all_cats = []
        for tool_type, categories in TOOL_CATEGORIES.items():
            for cat in categories:
                all_cats.append(f"{tool_type}/{cat}")

        prompt = f"""Classe cet outil de cybersecurite.

Nom: {name}
Description: {description[:500]}

Categories possibles: {', '.join(all_cats[:30])}

Reponds avec EXACTEMENT ce format:
TYPE: [offensif/defensif/polyvalent]
CATEGORIE: [sous-categorie]
DESCRIPTION FR: [1-2 phrases en francais]"""

        response = _call_groq(prompt, max_tokens=200)
        if response:
            result = {"type": "polyvalent", "category": "autre", "desc_fr": ""}
            for line in response.split("\n"):
                line = line.strip()
                if line.startswith("TYPE:"):
                    t = line[5:].strip().lower()
                    if t in ("offensif", "defensif", "polyvalent"):
                        result["type"] = t
                elif line.startswith("CATEGORIE:"):
                    result["category"] = line[10:].strip().lower().replace(" ", "-")
                elif line.startswith("DESCRIPTION FR:"):
                    result["desc_fr"] = line[15:].strip()
            return result
    except Exception:
        pass
    return None


def save_tool(name, description, url, stars, language, tool_type=None, category=None):
    """Sauvegarde un outil dans le bon dossier."""
    if not tool_type or not category:
        tool_type, category = _detect_tool_category(name, description)

    # Si "autre", essayer avec l'IA
    if category == "autre":
        ai = _ai_classify_tool(name, description)
        if ai:
            tool_type = ai.get("type", tool_type)
            category = ai.get("category", category)
            if ai.get("desc_fr"):
                description = ai["desc_fr"] + "\n\n" + description

    # Verifier que la categorie existe
    if tool_type not in TOOL_CATEGORIES:
        tool_type = "polyvalent"
    if category not in TOOL_CATEGORIES.get(tool_type, {}):
        category = "autre"

    # Creer le dossier
    cat_dir = os.path.join(OUTILS_DIR, tool_type, category)
    os.makedirs(cat_dir, exist_ok=True)

    # Nom de fichier
    safe_name = re.sub(r'[^\w\-]', '-', name.replace("/", "-"))
    filepath = os.path.join(cat_dir, f"{safe_name}.md")

    # Ne jamais ecraser
    if os.path.exists(filepath):
        return filepath

    now = datetime.now(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y %H:%M")

    lines = [
        f"# {name}",
        "",
        f"**Date d'ajout:** {now}",
        f"**Type:** {tool_type.capitalize()}",
        f"**Categorie:** {category}",
        f"**Langage:** {language or 'Non specifie'}",
        f"**Etoiles:** {stars}",
        f"**Lien:** [{url}]({url})",
        "",
        "## Description",
        description[:500] if description else "Pas de description",
        "",
    ]

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logger.info("Outil sauvegarde: %s → %s/%s", name, tool_type, category)
        return filepath
    except Exception as e:
        logger.error("Erreur sauvegarde outil %s: %s", name, e)
        return None


def fetch_new_tools():
    """Recherche les nouveaux outils cyber sur GitHub."""
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")

    queries = [
        f"security tool in:name,description created:>{week_ago} stars:>10",
        f"pentest tool in:name,description created:>{week_ago} stars:>5",
        f"cybersecurity in:description created:>{week_ago} stars:>20",
        f"hacking tool in:name,description created:>{week_ago} stars:>5",
    ]

    all_repos = {}
    for query in queries:
        try:
            response = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": query, "sort": "stars", "order": "desc", "per_page": 10},
                headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"},
                timeout=15,
            )
            if response.status_code == 403:
                break
            response.raise_for_status()
            for repo in response.json().get("items", []):
                url = repo.get("html_url", "")
                if url not in all_repos:
                    all_repos[url] = repo
            time.sleep(2)
        except Exception as e:
            logger.warning("Erreur recherche outils: %s", e)

    results = []
    for repo in all_repos.values():
        name = repo.get("full_name", "")
        desc = repo.get("description", "") or ""
        stars = repo.get("stargazers_count", 0)
        lang = repo.get("language", "") or ""
        url = repo.get("html_url", "")

        results.append({
            "name": name,
            "description": desc,
            "stars": stars,
            "language": lang,
            "url": url,
        })

    results.sort(key=lambda x: -x["stars"])
    logger.info("Tool Monitor: %d nouveaux outils trouves", len(results))
    return results[:10]


def format_tools_alert(tools):
    """Formate l'alerte nouveaux outils pour Telegram."""
    if not tools:
        return None

    now = datetime.now(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y %H:%M")

    lines = [
        f"\U0001f527 <b>Nouveaux outils cyber</b> | \U0001f4c5 {now}",
        "",
    ]

    for tool in tools[:5]:
        name = escape(tool["name"])
        desc = escape((tool["description"] or "")[:100])
        stars = tool["stars"]
        url = tool["url"]
        lang = escape(tool.get("language") or "")

        tool_type, category = _detect_tool_category(tool["name"], tool["description"])
        type_emoji = {"offensif": "\U0001f534", "defensif": "\U0001f535", "polyvalent": "\U0001f7e1"}
        emoji = type_emoji.get(tool_type, "\U0001f7e1")

        lines.append(f"{emoji} <b>{name}</b> \u2b50 {stars}")
        lines.append(f"   {tool_type.capitalize()} | {category}")
        if desc:
            lines.append(f"   {desc}")
        if lang:
            lines.append(f"   \U0001f4dd {lang}")
        lines.append(f'   \U0001f517 <a href="{escape(url)}">GitHub</a>')
        lines.append("")

    return "\n".join(lines)
