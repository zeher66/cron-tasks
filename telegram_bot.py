import logging
import time
import requests
from html import escape

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_MAX_LENGTH, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

BASE_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"


def _send_request(method, data):
    """Envoie une requete a l'API Telegram."""
    url = f"{BASE_URL}/{method}"
    try:
        response = requests.post(url, json=data, timeout=REQUEST_TIMEOUT)
        result = response.json()

        if not result.get("ok"):
            error_code = result.get("error_code", 0)
            description = result.get("description", "")

            # Rate limit : attendre et reessayer
            if error_code == 429:
                retry_after = result.get("parameters", {}).get("retry_after", 30)
                logger.warning("Rate limit Telegram, attente %ds", retry_after)
                time.sleep(retry_after + 1)
                response = requests.post(url, json=data, timeout=REQUEST_TIMEOUT)
                return response.json()

            logger.error("Erreur Telegram API: %s", description)
            return None

        return result
    except requests.RequestException as e:
        logger.error("Erreur requete Telegram: %s", e)
        return None


def send_message(text, parse_mode="HTML", disable_preview=False, silent=False):
    """Envoie un message sur le canal Telegram."""
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_TOKEN_HERE":
        logger.error("Token Telegram non configure")
        return False
    if not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID_HERE":
        logger.error("Chat ID Telegram non configure")
        return False

    # Decouper si le message depasse la limite
    messages = split_message(text, TELEGRAM_MAX_LENGTH)

    for msg in messages:
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": msg,
            "parse_mode": parse_mode,
            "disable_web_page_preview": disable_preview,
            "disable_notification": silent,
        }
        result = _send_request("sendMessage", data)
        if result is None:
            return False
        if len(messages) > 1:
            time.sleep(1)

    return True


def split_message(text, max_length=4096):
    """Decoupe un message en morceaux respectant la limite Telegram."""
    if len(text) <= max_length:
        return [text]

    parts = []
    while text:
        if len(text) <= max_length:
            parts.append(text)
            break
        split_pos = text.rfind("\n", 0, max_length)
        if split_pos == -1 or split_pos < max_length * 0.3:
            split_pos = text.rfind(" ", 0, max_length)
        if split_pos == -1:
            split_pos = max_length
        parts.append(text[:split_pos])
        text = text[split_pos:].lstrip("\n")

    return parts


def format_article(article):
    """Formate un article pour Telegram en HTML."""
    severity_emoji = article.get("severity_emoji", "\U0001f535")
    severity = article.get("severity", "info").upper()
    source = escape(article.get("source", "Inconnu"))
    url = article.get("url", "")
    category = article.get("category", "")

    # Titre : traduit si disponible, sinon original
    title = article.get("title_fr") or article.get("title", "Sans titre")
    title = escape(title)

    # Contenu : traduit si disponible
    content = article.get("summary_fr") or article.get("content") or article.get("summary", "")
    content = escape(content)

    # Limiter la longueur du contenu
    if len(content) > 800:
        content = content[:800]
        last_period = content.rfind(".")
        if last_period > 400:
            content = content[:last_period + 1]
        else:
            content = content.rstrip() + "..."

    # Categorie en francais
    cat_labels = {
        "alerte": "\u26a0\ufe0f Alerte Securite",
        "0day": "\u2622\ufe0f 0-Day / Exploit",
        "cyberattaque": "\U0001f4a5 Cyberattaque",
        "outil": "\U0001f527 Outil Cyber",
        "veille_fr": "\U0001f1eb\U0001f1f7 Veille FR",
    }
    cat_label = cat_labels.get(category, category)

    # Date de publication (heure de Paris)
    pub_date = article.get("pub_date", "")
    if pub_date:
        try:
            from datetime import datetime
            from zoneinfo import ZoneInfo
            dt = datetime.fromisoformat(pub_date)
            dt_paris = dt.astimezone(ZoneInfo("Europe/Paris"))
            pub_date = dt_paris.strftime("%d/%m/%Y %H:%M")
        except (ValueError, TypeError):
            pub_date = ""

    # Construction du message
    lines = [
        f"{severity_emoji} <b>{severity}</b> | {cat_label}",
        "",
        f"\U0001f4cc <b>{title}</b>",
        "",
    ]

    if content:
        lines.append(content)
        lines.append("")

    lines.append(f"\U0001f4f0 Source: <b>{source}</b>")

    if pub_date:
        lines.append(f"\U0001f4c5 {pub_date}")

    lines.append("")
    lines.append(f'\U0001f517 <a href="{escape(url)}">Lire l\'article complet</a>')

    return "\n".join(lines)


def format_digest(articles):
    """Formate un digest de plusieurs articles."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    paris_tz = ZoneInfo("Europe/Paris")
    now = datetime.now(paris_tz).strftime("%d/%m/%Y %H:%M Paris")

    lines = [
        f"\U0001f4cb <b>Digest Cyber Veille — {now}</b>",
        "",
        f"\U0001f4e8 {len(articles)} nouvelles alertes",
        "\u2500" * 20,
        "",
    ]

    for i, article in enumerate(articles, 1):
        severity_emoji = article.get("severity_emoji", "\U0001f535")
        title = article.get("title_fr") or article.get("title", "Sans titre")
        title = escape(title)
        source = escape(article.get("source", ""))
        url = article.get("url", "")

        lines.append(f"{severity_emoji} <b>{i}. {title}</b>")
        lines.append(f"   \U0001f4f0 {source}")
        lines.append(f'   \U0001f517 <a href="{escape(url)}">Lire</a>')
        lines.append("")

    return "\n".join(lines)


def format_stats(stats):
    """Formate les statistiques quotidiennes."""
    if not stats:
        return None

    return (
        f"\U0001f4ca <b>Stats du jour — {stats['date']}</b>\n"
        f"\n"
        f"\u2022 {stats['articles_processed']} articles traites\n"
        f"\u2022 {stats['articles_sent']} envoyes\n"
        f"\u2022 {stats['duplicates_filtered']} doublons filtres\n"
        f"\u2022 Sources actives : {stats['sources_active']}/{stats['sources_total']}\n"
        f"\u2022 {stats['errors']} erreurs"
    )


def format_error(error_message):
    """Formate un message d'erreur."""
    return (
        f"\u26a0\ufe0f <b>Erreur Cyber Veille</b>\n"
        f"\n"
        f"{escape(str(error_message))}\n"
        f"\n"
        f"Le bot continue de fonctionner."
    )


def send_article(article):
    """Envoie un article formate sur Telegram."""
    message = format_article(article)
    return send_message(message)


def send_digest(articles):
    """Envoie un digest d'articles."""
    message = format_digest(articles)
    return send_message(message, disable_preview=True)


def send_stats(stats):
    """Envoie les statistiques quotidiennes."""
    message = format_stats(stats)
    if message:
        return send_message(message, disable_preview=True)
    return False


def send_error(error_message):
    """Envoie un rapport d'erreur."""
    message = format_error(error_message)
    return send_message(message, disable_preview=True)


def format_critical_alert(article):
    """Format special pour les alertes CRITICAL."""
    title = article.get("title_fr") or article.get("title", "Sans titre")
    title = escape(title)
    source = escape(article.get("source", "Inconnu"))
    url = article.get("url", "")
    content = article.get("summary_fr") or article.get("content") or article.get("summary", "")
    content = escape(content)
    if len(content) > 600:
        content = content[:600].rstrip() + "..."

    # Tag France
    france_tag = ""
    text_lower = (title + " " + content).lower()
    france_keywords = ["france", "français", "francais", "anssi", "cert-fr", "cnil", "rgpd", "paris", "french"]
    if any(kw in text_lower for kw in france_keywords):
        france_tag = " \U0001f1eb\U0001f1f7"

    lines = [
        "\U0001f6a8\U0001f6a8\U0001f6a8 <b>ALERTE CRITIQUE</b> \U0001f6a8\U0001f6a8\U0001f6a8",
        "",
        f"\U0001f4cc <b>{title}</b>{france_tag}",
        "",
        content,
        "",
        f"\U0001f4f0 Source: <b>{source}</b>",
        "",
        f'\U0001f517 <a href="{escape(url)}">Lire l\'article complet</a>',
    ]
    return "\n".join(lines)


def format_article_with_france_tag(article):
    """Format article avec tag France si pertinent."""
    message = format_article(article)

    # Verifier si l'article mentionne la France
    title = article.get("title_fr") or article.get("title", "")
    content = article.get("summary_fr") or article.get("content") or article.get("summary", "")
    text_lower = (title + " " + content).lower()

    france_keywords = ["france", "français", "francais", "anssi", "cert-fr", "cnil",
                       "rgpd", "paris", "french", "hexagone", "tricolore"]
    if any(kw in text_lower for kw in france_keywords):
        message = message.replace("</b>\n\n\U0001f4cc", "</b> \U0001f1eb\U0001f1f7\n\n\U0001f4cc", 1)

    return message


def format_health_check(stats, dead_sources, sources_total):
    """Formate le health check quotidien."""
    from datetime import datetime, timezone, timedelta
    paris_tz = timezone(timedelta(hours=1))
    now = datetime.now(paris_tz).strftime("%d/%m/%Y")

    lines = [
        f"\u2705 <b>Bot actif — {now}</b>",
        "",
    ]

    if stats:
        lines.append(f"\u2022 Articles envoyes aujourd'hui : {stats.get('articles_sent', 0)}")
        lines.append(f"\u2022 Doublons filtres : {stats.get('duplicates_filtered', 0)}")
        lines.append(f"\u2022 Sources actives : {stats.get('sources_active', 0)}/{sources_total}")
        lines.append(f"\u2022 Erreurs : {stats.get('errors', 0)}")
    else:
        lines.append(f"\u2022 Sources configurees : {sources_total}")

    if dead_sources:
        lines.append("")
        lines.append(f"\u26a0\ufe0f <b>Sources en panne ({len(dead_sources)}) :</b>")
        for src in dead_sources:
            lines.append(f"  \u2022 {escape(src)}")

    return "\n".join(lines)


def format_weekly_digest(week_stats):
    """Formate le digest hebdomadaire."""
    from datetime import datetime, timezone, timedelta
    paris_tz = timezone(timedelta(hours=1))
    now = datetime.now(paris_tz).strftime("%d/%m/%Y")

    lines = [
        f"\U0001f4cb <b>Digest Hebdomadaire — Semaine du {now}</b>",
        "",
        f"\u2022 Articles envoyes : {week_stats.get('total_sent', 0)}",
        f"\u2022 CVE critiques : {week_stats.get('critical_cves', 0)}",
        f"\u2022 Sources actives : {week_stats.get('avg_sources', 0)}",
        f"\u2022 Doublons filtres : {week_stats.get('total_duplicates', 0)}",
        "",
    ]

    top_sources = week_stats.get("top_sources", [])
    if top_sources:
        lines.append("<b>Top sources :</b>")
        for src, count in top_sources[:5]:
            lines.append(f"  \u2022 {escape(src)} : {count} articles")
        lines.append("")

    top_categories = week_stats.get("top_categories", [])
    if top_categories:
        lines.append("<b>Categories :</b>")
        cat_emojis = {"critique": "\U0001f534", "important": "\U0001f7e0", "moyen": "\U0001f7e1", "info": "\U0001f535"}
        for cat, count in top_categories:
            emoji = cat_emojis.get(cat, "")
            lines.append(f"  {emoji} {escape(cat.capitalize())} : {count}")

    return "\n".join(lines)


def send_critical_alert(article):
    """Envoie une alerte critique."""
    message = format_critical_alert(article)
    return send_message(message)


def send_health_check(stats, dead_sources, sources_total):
    """Envoie le health check."""
    message = format_health_check(stats, dead_sources, sources_total)
    return send_message(message, disable_preview=True)


def send_weekly_digest(week_stats):
    """Envoie le digest hebdomadaire."""
    message = format_weekly_digest(week_stats)
    return send_message(message, disable_preview=True)
