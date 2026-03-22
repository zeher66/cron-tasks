import feedparser
import logging
from datetime import datetime, timedelta, timezone
from time import mktime

from trafilatura import fetch_url, extract

from config import (
    FEEDS,
    MAX_ARTICLE_AGE_HOURS,
    MAX_CONTENT_LENGTH,
    REQUEST_TIMEOUT,
    USER_AGENT,
    KEYWORDS_PRIORITY,
    KEYWORDS_IGNORE,
)

logger = logging.getLogger(__name__)


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
        return False  # En cas de doute, on le garde
    cutoff = datetime.now(timezone.utc) - timedelta(hours=MAX_ARTICLE_AGE_HOURS)
    return pub_date < cutoff


def should_ignore(title, summary):
    """Verifie si un article doit etre ignore (pub, spam, etc.)."""
    text = (title + " " + summary).lower()
    return any(kw.lower() in text for kw in KEYWORDS_IGNORE)


def get_priority(title, summary):
    """Calcule le score de priorite d'un article."""
    text = (title + " " + summary).lower()
    score = sum(1 for kw in KEYWORDS_PRIORITY if kw.lower() in text)
    return score


def get_severity(title, summary, category):
    """Determine la severite basee sur le contenu et la categorie."""
    text = (title + " " + summary).lower()

    critical_keywords = [
        "zero-day", "0day", "actively exploited", "critical", "rce",
        "remote code execution", "cert-fr alerte", "urgence",
        "exploitation active", "cisa kev",
    ]
    high_keywords = [
        "ransomware", "breach", "leak", "apt", "backdoor", "wiper",
        "supply chain", "privilege escalation", "data breach",
    ]
    medium_keywords = [
        "vulnerability", "malware", "phishing", "trojan", "botnet",
        "cve-", "patch", "update",
    ]

    if any(kw in text for kw in critical_keywords):
        return "critique", "\U0001f534"  # 🔴
    if any(kw in text for kw in high_keywords):
        return "important", "\U0001f7e0"  # 🟠
    if any(kw in text for kw in medium_keywords):
        return "moyen", "\U0001f7e1"  # 🟡
    return "info", "\U0001f535"  # 🔵


def extract_content(url):
    """Extrait le contenu complet d'un article depuis son URL."""
    try:
        downloaded = fetch_url(url)
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
    """Tronque le contenu a la longueur max en coupant proprement."""
    if text is None:
        return ""
    if len(text) <= max_length:
        return text
    # Couper au dernier point avant la limite
    truncated = text[:max_length]
    last_period = truncated.rfind(".")
    if last_period > max_length * 0.5:
        return truncated[:last_period + 1]
    # Sinon couper au dernier espace
    last_space = truncated.rfind(" ")
    if last_space > 0:
        return truncated[:last_space] + "..."
    return truncated + "..."


def fetch_feed(feed_config):
    """Scrape un flux RSS et retourne les nouveaux articles."""
    name = feed_config["name"]
    url = feed_config["url"]
    category = feed_config["category"]
    lang = feed_config["lang"]
    emoji = feed_config["emoji"]

    logger.info("Scraping: %s", name)

    try:
        feed = feedparser.parse(url, agent=USER_AGENT)
    except Exception as e:
        logger.error("Erreur parsing flux %s: %s", name, e)
        return []

    if feed.bozo and not feed.entries:
        logger.warning("Flux invalide ou vide: %s (%s)", name, feed.bozo_exception)
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
    """Scrape tous les flux RSS et retourne les articles tries par priorite."""
    all_articles = []
    sources_active = 0

    for feed_config in FEEDS:
        articles = fetch_feed(feed_config)
        if articles:
            sources_active += 1
        all_articles.extend(articles)

    # Trier par priorite (plus haute d'abord), puis par severite
    severity_order = {"critique": 0, "important": 1, "moyen": 2, "info": 3}
    all_articles.sort(
        key=lambda a: (severity_order.get(a["severity"], 4), -a["priority"])
    )

    logger.info("Total: %d articles de %d sources actives", len(all_articles), sources_active)
    return all_articles, sources_active
