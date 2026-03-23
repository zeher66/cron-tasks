import re
import random
import time
import json
import os
import feedparser
import logging
import requests
from datetime import datetime, timedelta, timezone
from time import mktime
from urllib.parse import urlparse

from trafilatura import fetch_url, extract

from config import (
    FEEDS,
    MAX_ARTICLE_AGE_HOURS,
    MAX_CONTENT_LENGTH,
    REQUEST_TIMEOUT,
    KEYWORDS_PRIORITY,
    KEYWORDS_IGNORE,
)

logger = logging.getLogger(__name__)

# --- Rotation User-Agent ---
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


def _get_ua():
    """Retourne un User-Agent aleatoire."""
    return random.choice(USER_AGENTS)


# --- Blacklist pour extraction de contenu (sites qui bloquent le scraping) ---
CONTENT_BLACKLIST = [
    "securityweek.com",
    "darkreading.com",
    "schneier.com",
]


def _is_blacklisted(url):
    """Verifie si un site bloque l'extraction de contenu."""
    domain = urlparse(url).netloc.lower()
    return any(bl in domain for bl in CONTENT_BLACKLIST)


# --- Suivi des sources (echecs, desactivation, redirect) ---
SOURCE_STATUS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "source_status.json")


def _load_source_status():
    """Charge le statut des sources."""
    if os.path.exists(SOURCE_STATUS_FILE):
        try:
            with open(SOURCE_STATUS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_source_status(status):
    """Sauvegarde le statut des sources."""
    try:
        with open(SOURCE_STATUS_FILE, "w") as f:
            json.dump(status, f, indent=2)
    except IOError as e:
        logger.warning("Impossible de sauvegarder source_status.json: %s", e)


def _record_success(status, name, url):
    """Enregistre un succes pour une source."""
    if name not in status:
        status[name] = {}
    status[name]["consecutive_failures"] = 0
    status[name]["last_success"] = datetime.now(timezone.utc).isoformat()
    status[name]["url"] = url
    status[name]["disabled"] = False


def _record_failure(status, name):
    """Enregistre un echec pour une source."""
    if name not in status:
        status[name] = {"consecutive_failures": 0}
    status[name]["consecutive_failures"] = status[name].get("consecutive_failures", 0) + 1
    status[name]["last_failure"] = datetime.now(timezone.utc).isoformat()


def _is_disabled(status, name):
    """Verifie si une source est desactivee (10+ echecs consecutifs)."""
    if name not in status:
        return False
    s = status[name]
    if s.get("disabled", False):
        # Reessayer 1x/jour
        last_fail = s.get("last_failure", "")
        if last_fail:
            try:
                dt = datetime.fromisoformat(last_fail)
                if datetime.now(timezone.utc) - dt > timedelta(hours=24):
                    logger.info("Reactivation test pour source desactivee: %s", name)
                    return False
            except (ValueError, TypeError):
                pass
        return True
    if s.get("consecutive_failures", 0) >= 10:
        s["disabled"] = True
        logger.warning("Source desactivee apres 10 echecs: %s", name)
        return True
    return False


def _get_dead_sources(status):
    """Retourne la liste des sources mortes (24h+ sans succes)."""
    dead = []
    for name, s in status.items():
        if s.get("disabled", False):
            dead.append(name)
        elif s.get("consecutive_failures", 0) >= 3:
            dead.append(name)
    return dead


# --- Parsing ---

def parse_date(entry):
    """Extrait la date de publication d'un article RSS."""
    for field in ("published_parsed", "updated_parsed"):
        parsed = entry.get(field)
        if parsed:
            try:
                return datetime.fromtimestamp(mktime(parsed), tz=timezone.utc)
            except (ValueError, OverflowError):
                continue
    return None


def is_too_old(pub_date):
    """Verifie si un article est trop vieux."""
    if pub_date is None:
        return False
    cutoff = datetime.now(timezone.utc) - timedelta(hours=MAX_ARTICLE_AGE_HOURS)
    return pub_date < cutoff


def should_ignore(title, summary):
    """Verifie si un article doit etre ignore."""
    text = (title + " " + summary).lower()
    return any(kw.lower() in text for kw in KEYWORDS_IGNORE)


def get_priority(title, summary):
    """Calcule le score de priorite d'un article."""
    text = (title + " " + summary).lower()
    return sum(1 for kw in KEYWORDS_PRIORITY if kw.lower() in text)


def get_severity(title, summary, category):
    """Determine la severite basee sur le contenu et la categorie."""
    text = (title + " " + summary).lower()

    # "critical" seul est trop vague — il faut un contexte securite
    critical_keywords = [
        "zero-day", "0day", "actively exploited",
        "critical vulnerability", "critical flaw", "critical bug",
        "critical rce", "critical patch", "critical security",
        "rce", "remote code execution",
        "cert-fr alerte", "urgence", "emergency patch",
        "exploitation active", "cisa kev", "exploited in the wild",
    ]
    high_keywords = [
        "ransomware", "breach", "leak", "apt", "backdoor", "wiper",
        "supply chain", "privilege escalation", "data breach",
    ]
    medium_keywords = [
        "vulnerability", "malware", "phishing", "trojan", "botnet",
        "cve-", "patch", "update", "critical",
    ]

    if any(kw in text for kw in critical_keywords):
        return "critique", "\U0001f534"
    if any(kw in text for kw in high_keywords):
        return "important", "\U0001f7e0"
    if any(kw in text for kw in medium_keywords):
        return "moyen", "\U0001f7e1"
    return "info", "\U0001f535"


# --- Extraction contenu ---

def extract_content(url):
    """Extrait le contenu complet, skip si blackliste."""
    if _is_blacklisted(url):
        return None

    try:
        from trafilatura.settings import use_config
        config = use_config()
        config.set("DEFAULT", "USER_AGENTS", _get_ua())

        downloaded = fetch_url(url, config=config)
        if downloaded is None:
            return None
        text = extract(
            downloaded,
            include_comments=False,
            include_tables=False,
            favor_precision=True,
            no_fallback=True,
        )
        return text
    except Exception as e:
        logger.warning("Erreur extraction contenu %s: %s", url, e)
        return None


def truncate_content(text, max_length=MAX_CONTENT_LENGTH):
    """Tronque le contenu proprement."""
    if text is None:
        return ""
    if len(text) <= max_length:
        return text
    truncated = text[:max_length]
    last_period = truncated.rfind(".")
    if last_period > max_length * 0.5:
        return truncated[:last_period + 1]
    last_space = truncated.rfind(" ")
    if last_space > 0:
        return truncated[:last_space] + "..."
    return truncated + "..."


# --- Reparation XML ---

def _fix_xml(raw_text):
    """Tente de reparer un XML malforme."""
    if not raw_text:
        return raw_text
    raw_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', raw_text)
    raw_text = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#)', '&amp;', raw_text)
    raw_text = re.sub(r'<br\s*>', '<br/>', raw_text)
    raw_text = re.sub(r'<hr\s*>', '<hr/>', raw_text)
    raw_text = re.sub(r'<img([^>]*?)(?<!/)>', r'<img\1/>', raw_text)
    return raw_text


def _extract_entries_regex(raw):
    """Extraction regex en dernier recours."""
    entries = []
    items = re.findall(r'<(?:item|entry)[\s>].*?</(?:item|entry)>', raw, re.DOTALL)
    for item in items:
        title_match = re.search(r'<title[^>]*>(.*?)</title>', item, re.DOTALL)
        link_match = re.search(r'<link[^>]*(?:href=["\']([^"\']+)["\']|>(.*?)</link>)', item, re.DOTALL)
        desc_match = re.search(r'<(?:description|summary|content)[^>]*>(.*?)</(?:description|summary|content)>', item, re.DOTALL)

        title = title_match.group(1).strip() if title_match else ""
        link = ""
        if link_match:
            link = (link_match.group(1) or link_match.group(2) or "").strip()
        summary = desc_match.group(1).strip() if desc_match else ""

        title = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', title)
        link = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', link)
        summary = re.sub(r'<!\[CDATA\[(.*?)\]\]>', r'\1', summary)

        if title and link:
            entry = feedparser.FeedParserDict()
            entry["title"] = title
            entry["link"] = link
            entry["summary"] = summary
            entries.append(entry)
    return entries


def _scrape_html_fallback(url):
    """Fallback: extraire les articles depuis la page HTML si RSS mort."""
    try:
        headers = {"User-Agent": _get_ua()}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        html = response.text

        # Chercher des liens d'articles avec des patterns courants
        entries = []
        base_domain = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Pattern: <a href="...">titre</a> dans des balises article/h2/h3
        article_links = re.findall(
            r'<(?:article|h[23])[^>]*>.*?<a\s+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            html, re.DOTALL
        )
        for link, title in article_links[:10]:
            title = re.sub(r'<[^>]+>', '', title).strip()
            if not link.startswith("http"):
                link = base_domain + link
            if title and len(title) > 10:
                entry = feedparser.FeedParserDict()
                entry["title"] = title
                entry["link"] = link
                entry["summary"] = ""
                entries.append(entry)

        if entries:
            logger.info("Fallback HTML: %d articles extraits de %s", len(entries), url)
        return entries
    except Exception as e:
        logger.warning("Fallback HTML echoue pour %s: %s", url, e)
        return []


def _auto_discover_feed(url):
    """Tente de decouvrir le flux RSS d'un site."""
    try:
        from trafilatura import feeds as tf_feeds
        feed_urls = tf_feeds.find_feed_urls(url)
        if feed_urls:
            logger.info("Auto-decouverte RSS pour %s: %s", url, feed_urls[0])
            return feed_urls[0]
    except Exception:
        pass

    # Essayer les chemins courants
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    common_paths = ["/feed", "/feed/", "/rss", "/rss.xml", "/atom.xml", "/feed.xml", "/index.xml"]
    for path in common_paths:
        try:
            test_url = base + path
            r = requests.head(test_url, headers={"User-Agent": _get_ua()}, timeout=10, allow_redirects=True)
            if r.status_code == 200 and ("xml" in r.headers.get("content-type", "") or "rss" in r.headers.get("content-type", "")):
                logger.info("Auto-decouverte RSS pour %s: %s", url, test_url)
                return test_url
        except Exception:
            continue
    return None


# --- Fetch principal ---

def _fetch_and_fix(url, name, status):
    """Telecharge un flux RSS avec retry, reparation, et fallback."""
    # Verifier si source desactivee
    if _is_disabled(status, name):
        logger.info("Source desactivee, skip: %s", name)
        return None

    headers = {"User-Agent": _get_ua()}

    for attempt in range(2):  # 2 tentatives max
        try:
            timeout = 15 if attempt == 0 else 20
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)

            # Detection redirect permanent (301) → mettre a jour l'URL
            if response.history:
                for r in response.history:
                    if r.status_code == 301:
                        new_url = response.url
                        if new_url != url:
                            logger.info("Redirect 301 detecte pour %s: %s → %s", name, url, new_url)
                            status.setdefault(name, {})["url"] = new_url

            response.raise_for_status()
            raw = response.text

            # Essai 1 : parser tel quel
            feed = feedparser.parse(raw)
            if not feed.bozo or feed.entries:
                _record_success(status, name, url)
                return feed

            # Essai 2 : reparer le XML
            fixed = _fix_xml(raw)
            feed = feedparser.parse(fixed)
            if feed.entries:
                logger.info("Reparation XML reussie pour %s", name)
                _record_success(status, name, url)
                return feed

            # Essai 3 : extraction regex
            entries = _extract_entries_regex(raw)
            if entries:
                logger.info("Extraction regex: %d articles pour %s", len(entries), name)
                _record_success(status, name, url)
                feed = feedparser.FeedParserDict()
                feed["entries"] = entries
                feed["bozo"] = False
                return feed

            # Si premiere tentative echoue, pas de retry pour XML malformed
            break

        except requests.RequestException as e:
            logger.warning("Tentative %d echouee pour %s: %s", attempt + 1, name, e)
            if attempt == 0:
                # Retry avec un User-Agent different
                headers = {"User-Agent": _get_ua()}
                time.sleep(2)
                continue
            break

    # Essai 4 : auto-decouvrir un nouveau flux RSS
    discovered_url = _auto_discover_feed(url)
    if discovered_url and discovered_url != url:
        try:
            response = requests.get(discovered_url, headers={"User-Agent": _get_ua()}, timeout=15)
            feed = feedparser.parse(response.text)
            if feed.entries:
                logger.info("Auto-decouverte reussie pour %s: %s", name, discovered_url)
                status.setdefault(name, {})["discovered_url"] = discovered_url
                _record_success(status, name, discovered_url)
                return feed
        except Exception:
            pass

    # Essai 5 : fallback scraping HTML
    site_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    entries = _scrape_html_fallback(site_url)
    if entries:
        _record_success(status, name, url)
        feed = feedparser.FeedParserDict()
        feed["entries"] = entries
        feed["bozo"] = False
        return feed

    _record_failure(status, name)
    return None


def fetch_feed(feed_config, status):
    """Scrape un flux RSS et retourne les nouveaux articles."""
    name = feed_config["name"]
    url = feed_config["url"]
    category = feed_config["category"]
    lang = feed_config["lang"]
    emoji = feed_config["emoji"]

    # Utiliser l'URL decouverte si disponible
    if name in status and "discovered_url" in status[name]:
        url = status[name]["discovered_url"]

    logger.info("Scraping: %s", name)

    feed = _fetch_and_fix(url, name, status)

    if feed is None or not hasattr(feed, 'entries') or not feed.entries:
        failures = status.get(name, {}).get("consecutive_failures", 0)
        if failures > 0:
            logger.warning("Source %s: %d echecs consecutifs", name, failures)
        return []

    articles = []
    for entry in feed.entries:
        title = entry.get("title", "").strip()
        link = entry.get("link", "").strip()
        summary = entry.get("summary", "").strip()

        if not title or not link:
            continue

        pub_date = parse_date(entry)
        if is_too_old(pub_date):
            continue

        if should_ignore(title, summary):
            continue

        severity, severity_emoji = get_severity(title, summary, category)
        priority = get_priority(title, summary)

        articles.append({
            "title": title,
            "url": link,
            "summary": summary,
            "source": name,
            "category": category,
            "lang": lang,
            "emoji": emoji,
            "severity": severity,
            "severity_emoji": severity_emoji,
            "priority": priority,
            "pub_date": pub_date.isoformat() if pub_date else None,
        })

    logger.info("%s: %d articles trouves", name, len(articles))
    return articles


def fetch_all_feeds():
    """Scrape tous les flux RSS."""
    status = _load_source_status()
    all_articles = []
    sources_active = 0

    for feed_config in FEEDS:
        articles = fetch_feed(feed_config, status)
        if articles:
            sources_active += 1
        all_articles.extend(articles)

    _save_source_status(status)

    severity_order = {"critique": 0, "important": 1, "moyen": 2, "info": 3}
    all_articles.sort(
        key=lambda a: (severity_order.get(a["severity"], 4), -a["priority"])
    )

    logger.info("Total: %d articles de %d sources actives", len(all_articles), sources_active)
    return all_articles, sources_active


def get_dead_sources():
    """Retourne la liste des sources mortes."""
    status = _load_source_status()
    return _get_dead_sources(status)
