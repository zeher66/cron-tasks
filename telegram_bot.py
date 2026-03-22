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


def send_message(text, parse_mode="HTML", disable_preview=False):
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
        }
        result = _send_request("sendMessage", data)
        if result is None:
            return False
        # Pause entre les messages pour eviter le rate limit
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
            from datetime import datetime, timezone, timedelta
            dt = datetime.fromisoformat(pub_date)
            paris_offset = timedelta(hours=1)  # CET (UTC+1), CEST sera UTC+2
            dt_paris = dt.astimezone(timezone(paris_offset))
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
    from datetime import datetime, timezone, timedelta

    paris_tz = timezone(timedelta(hours=1))
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
