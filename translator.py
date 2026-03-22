import logging
import re
from html import unescape

logger = logging.getLogger(__name__)

# Termes techniques a ne pas traduire
TECH_TERMS_PRESERVE = [
    "zero-day", "0day", "ransomware", "malware", "phishing",
    "backdoor", "rootkit", "spyware", "trojan", "botnet",
    "DDoS", "XSS", "SQL injection", "RCE", "CSRF",
    "buffer overflow", "heap overflow", "stack overflow",
    "APT", "C2", "C&C", "IOC", "YARA", "STIX", "TAXII",
    "EDR", "XDR", "SIEM", "SOC", "SOAR", "WAF", "IDS", "IPS",
    "CVE", "CVSS", "CWE", "MITRE ATT&CK", "OWASP",
    "Active Directory", "Kerberos", "NTLM", "LDAP",
    "Docker", "Kubernetes", "Terraform",
    "Nmap", "Metasploit", "Burp Suite", "Wireshark",
    "Ghidra", "IDA Pro", "Volatility", "Autopsy",
    "Cobalt Strike", "Mimikatz", "BloodHound",
    "Linux", "Windows", "macOS", "Android", "iOS",
]


def clean_html(text):
    """Nettoie le HTML d'un texte."""
    if text is None:
        return ""
    text = unescape(text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def translate_text(text, source_lang="en"):
    """Traduit un texte en francais avec deep-translator."""
    if not text or source_lang == "fr":
        return text

    text = clean_html(text)
    if not text:
        return ""

    try:
        from deep_translator import GoogleTranslator

        # Google Translate a une limite de 5000 caracteres
        max_chunk = 4500
        if len(text) <= max_chunk:
            translated = GoogleTranslator(source="en", target="fr").translate(text)
            return translated or text

        # Decouper en morceaux si trop long
        chunks = []
        remaining = text
        while remaining:
            if len(remaining) <= max_chunk:
                chunks.append(remaining)
                break
            split_pos = remaining.rfind(". ", 0, max_chunk)
            if split_pos == -1:
                split_pos = remaining.rfind(" ", 0, max_chunk)
            if split_pos == -1:
                split_pos = max_chunk
            chunks.append(remaining[:split_pos + 1])
            remaining = remaining[split_pos + 1:].strip()

        translated_chunks = []
        translator = GoogleTranslator(source="en", target="fr")
        for chunk in chunks:
            translated = translator.translate(chunk)
            translated_chunks.append(translated or chunk)

        return " ".join(translated_chunks)

    except ImportError:
        logger.warning("deep-translator non installe, traduction impossible")
        return text
    except Exception as e:
        logger.warning("Erreur traduction: %s", e)
        return text


def translate_title(title, source_lang="en"):
    """Traduit un titre en francais."""
    if not title or source_lang == "fr":
        return title
    return translate_text(title, source_lang)


def translate_article(article):
    """Traduit un article complet (titre + contenu) en francais."""
    lang = article.get("lang", "en")

    if lang == "fr":
        return article

    translated = article.copy()
    translated["title_fr"] = translate_title(article["title"], lang)
    translated["summary_fr"] = translate_text(article.get("content") or article.get("summary", ""), lang)
    return translated
