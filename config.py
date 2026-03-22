import os

# =============================================================================
# CONFIGURATION — Cyber Veille Telegram Bot
# =============================================================================

# --- Telegram ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_TOKEN_HERE")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE")

# --- Sources RSS ---
# Chaque source a : nom, url, categorie, langue, frequence (minutes)

FEEDS = [
    # === ALERTES & VULNERABILITES (30 min) ===
    {
        "name": "CERT-FR Alertes",
        "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "category": "alerte",
        "lang": "fr",
        "frequency": 30,
        "emoji": "\U0001f534",  # 🔴
    },
    {
        "name": "CERT-FR Avis",
        "url": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "category": "alerte",
        "lang": "fr",
        "frequency": 30,
        "emoji": "\U0001f534",
    },
    {
        "name": "CERT-FR CTI",
        "url": "https://www.cert.ssi.gouv.fr/cti/feed/",
        "category": "alerte",
        "lang": "fr",
        "frequency": 30,
        "emoji": "\U0001f534",
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "category": "alerte",
        "lang": "en",
        "frequency": 30,
        "emoji": "\U0001f534",
    },
    {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "category": "alerte",
        "lang": "en",
        "frequency": 30,
        "emoji": "\U0001f534",
    },

    # === CYBERATTAQUES & MENACES (2h) ===
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "cyberattaque",
        "lang": "en",
        "frequency": 120,
        "emoji": "\U0001f7e0",  # 🟠
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "cyberattaque",
        "lang": "en",
        "frequency": 120,
        "emoji": "\U0001f7e0",
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/feed",
        "category": "cyberattaque",
        "lang": "en",
        "frequency": 120,
        "emoji": "\U0001f7e0",
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "cyberattaque",
        "lang": "en",
        "frequency": 120,
        "emoji": "\U0001f7e0",
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
        "category": "cyberattaque",
        "lang": "en",
        "frequency": 120,
        "emoji": "\U0001f7e0",
    },
    {
        "name": "Zataz",
        "url": "https://www.zataz.com/feed/",
        "category": "cyberattaque",
        "lang": "fr",
        "frequency": 120,
        "emoji": "\U0001f7e0",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "cyberattaque",
        "lang": "en",
        "frequency": 120,
        "emoji": "\U0001f7e0",
    },

    # === OUTILS CYBER & INFORMATIQUE (4h) ===
    {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "category": "outil",
        "lang": "en",
        "frequency": 240,
        "emoji": "\U0001f535",  # 🔵
    },
    {
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "category": "outil",
        "lang": "en",
        "frequency": 240,
        "emoji": "\U0001f535",
    },
    {
        "name": "Naked Security (Sophos)",
        "url": "https://nakedsecurity.sophos.com/feed/",
        "category": "outil",
        "lang": "en",
        "frequency": 240,
        "emoji": "\U0001f535",
    },
    {
        "name": "Hackaday Security",
        "url": "https://hackaday.com/category/security-hacks/feed/",
        "category": "outil",
        "lang": "en",
        "frequency": 240,
        "emoji": "\U0001f535",
    },
    {
        "name": "SANS ISC",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "category": "outil",
        "lang": "en",
        "frequency": 240,
        "emoji": "\U0001f535",
    },

    # === VEILLE FR (2h) ===
    {
        "name": "Cybermalveillance.gouv.fr",
        "url": "https://www.cybermalveillance.gouv.fr/feed/rss2",
        "category": "veille_fr",
        "lang": "fr",
        "frequency": 120,
        "emoji": "\U0001f7e2",  # 🟢
    },
    {
        "name": "UnderNews",
        "url": "https://www.undernews.fr/feed",
        "category": "veille_fr",
        "lang": "fr",
        "frequency": 120,
        "emoji": "\U0001f7e2",
    },
    {
        "name": "Globalsecuritymag",
        "url": "https://www.globalsecuritymag.fr/feeds/rss",
        "category": "veille_fr",
        "lang": "fr",
        "frequency": 120,
        "emoji": "\U0001f7e2",
    },
]

# --- Mots-cles prioritaires ---
KEYWORDS_PRIORITY = [
    # Cyberattaques
    "ransomware", "zero-day", "0day", "breach", "leak", "APT",
    "malware", "phishing", "exploit", "botnet", "ddos", "trojan",
    "backdoor", "rootkit", "spyware", "wiper", "supply chain",
    "data breach", "cyberattaque", "fuite de donnees",
    # Vulnerabilites
    "cve-", "vulnerability", "patch", "critical", "rce",
    "remote code execution", "privilege escalation", "sql injection",
    "xss", "buffer overflow", "authentication bypass",
    # Cybersecurite
    "cert-fr", "cisa", "anssi", "encryption", "firewall",
    "edr", "soc", "siem", "threat intelligence", "incident response",
    # Outils
    "tool", "framework", "pentest", "scanner", "burp", "nmap",
    "metasploit", "wireshark", "kali", "osint", "ghidra", "ida",
    "reverse engineering", "forensic", "volatility", "autopsy",
    "nuclei", "subfinder", "httpx", "gobuster", "john", "hashcat",
    # Infra / IT
    "linux", "windows", "docker", "kubernetes", "cloud", "aws",
    "azure", "active directory", "vpn", "ssh", "tls", "ssl",
    # FR
    "france", "francais", "anssi", "cnil", "rgpd",
]

KEYWORDS_IGNORE = [
    "sponsor", "webinar", "advertisement", "promoted",
    "podcast episode", "job posting", "hiring", "career",
    "subscribe now", "sign up for", "free trial",
]

# --- Parametres ---
MAX_ARTICLE_AGE_HOURS = 48  # Ignorer les articles plus vieux que 48h
MAX_CONTENT_LENGTH = 500  # Longueur max du resume en caracteres
TELEGRAM_MAX_LENGTH = 4096  # Limite Telegram
REQUEST_TIMEOUT = 30  # Timeout HTTP en secondes
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
