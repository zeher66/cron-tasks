import logging
import time
import requests
from html import escape

from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_CHAT_ID_CVE, TELEGRAM_CHAT_ID_0DAY, TELEGRAM_CHAT_ID_URGENT, TELEGRAM_MAX_LENGTH, REQUEST_TIMEOUT

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


def send_message(text, parse_mode="HTML", disable_preview=False, silent=False, channel="info"):
    """Envoie un message sur le canal Telegram appropriate."""
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_TOKEN_HERE":
        logger.error("Token Telegram non configure")
        return False

    # Choisir le canal
    if channel == "cve" and TELEGRAM_CHAT_ID_CVE:
        chat_id = TELEGRAM_CHAT_ID_CVE
    elif channel == "0day" and TELEGRAM_CHAT_ID_0DAY:
        chat_id = TELEGRAM_CHAT_ID_0DAY
    elif channel == "urgent" and TELEGRAM_CHAT_ID_URGENT:
        chat_id = TELEGRAM_CHAT_ID_URGENT
    else:
        chat_id = TELEGRAM_CHAT_ID

    if not chat_id or chat_id == "YOUR_CHAT_ID_HERE":
        logger.error("Chat ID Telegram non configure pour canal: %s", channel)
        return False

    # Decouper si le message depasse la limite
    messages = split_message(text, TELEGRAM_MAX_LENGTH)

    for msg in messages:
        data = {
            "chat_id": chat_id,
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


def _google_translate_url(url):
    """Genere un lien Google Translate pour un article anglais."""
    from urllib.parse import quote
    return f"https://translate.google.com/translate?sl=en&tl=fr&u={quote(url)}"


def format_article(article):
    """Formate un article pour Telegram — detail FR + resume + liens."""
    severity = article.get("severity", "info")
    source = escape(article.get("source", "Inconnu"))
    url = article.get("url", "")
    category = article.get("category", "")
    lang = article.get("lang", "en")

    # Header avec barre visuelle
    severity_headers = {
        "critique": ("\U0001f534\U0001f534\U0001f534 <b>CRITIQUE</b>", "\u2588" * 10),
        "important": ("\U0001f7e0\U0001f7e0 <b>IMPORTANT</b>", "\u2588" * 7 + "\u2591" * 3),
        "moyen": ("\U0001f7e1 <b>MOYEN</b>", "\u2588" * 5 + "\u2591" * 5),
        "info": ("\U0001f535 <b>INFO</b>", "\u2588" * 3 + "\u2591" * 7),
    }
    header, bar = severity_headers.get(severity, ("\U0001f535 <b>INFO</b>", "\u2591" * 10))

    # Categorie tag
    cat_tags = {
        "alerte": "\u26a0\ufe0f Alerte",
        "0day": "\u2622\ufe0f 0-Day",
        "cyberattaque": "\U0001f4a5 Attaque",
        "outil": "\U0001f527 Outil",
        "veille_fr": "\U0001f1eb\U0001f1f7 FR",
    }
    cat_tag = cat_tags.get(category, "")

    # Titre traduit
    title = article.get("title_fr") or article.get("title", "Sans titre")
    title = escape(title)

    # Description detaillee en francais
    detail = article.get("summary_fr") or article.get("content") or article.get("summary", "")
    detail = escape(detail)

    # Garder plus de texte pour le detail (IA = complet, sinon tronquer)
    has_ai = bool(article.get("ai_key_points"))
    max_detail = 1500 if has_ai else 600
    if len(detail) > max_detail:
        cut = detail.find(".", max_detail - 100)
        if cut > 0 and cut < max_detail + 100:
            detail = detail[:cut + 1]
        else:
            detail = detail[:max_detail].rstrip() + "..."

    # Points cles : IA si disponible, sinon extraction
    summary_points = article.get("ai_key_points") or _extract_key_points(detail)

    # Risque IA si disponible
    ai_risk = article.get("ai_risk", "")

    lines = [
        f"{header} | {cat_tag}",
        f"<code>{bar}</code>",
        "",
        f"\U0001f4f0 {source}",
        "",
        f"<b>{title}</b>",
    ]

    # Description detaillee
    if detail:
        lines.append("")
        lines.append(f"\U0001f4d6 {detail}")

    # Resume en points cles
    if summary_points:
        lines.append("")
        lines.append("\U0001f511 <b>A retenir :</b>")
        for point in summary_points:
            lines.append(f"\u2022 {escape(point)}")

    # Analyse de risque IA
    if ai_risk:
        lines.append("")
        lines.append(f"\U0001f6e1\ufe0f <b>Risque :</b> {escape(ai_risk)}")

    # Liens
    lines.append("")
    if lang != "fr":
        translate_url = _google_translate_url(url)
        lines.append(f'\u27a1\ufe0f <a href="{escape(translate_url)}">Lire en FR</a> | \U0001f517 <a href="{escape(url)}">Original EN</a>')
    else:
        lines.append(f'\u27a1\ufe0f <a href="{escape(url)}">Lire l\'article</a>')

    return "\n".join(lines)


def _extract_key_points(text):
    """Extrait 2-4 points cles d'un texte."""
    if not text or len(text) < 50:
        return []

    # Decouper en phrases
    import re
    sentences = re.split(r'(?<=[.!?])\s+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 20]

    if len(sentences) <= 2:
        return []

    # Garder les phrases les plus informatives (pas trop courtes, pas trop longues)
    points = []
    for s in sentences:
        if len(s) > 30 and len(s) < 150:
            # Raccourcir si besoin
            if len(s) > 100:
                dot = s.find(",", 50)
                if dot > 0:
                    s = s[:dot]
            points.append(s)
        if len(points) >= 3:
            break

    return points


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
    """Format special pour les alertes CRITICAL — meme format unifie."""
    title = article.get("title_fr") or article.get("title", "Sans titre")
    title = escape(title)
    source = escape(article.get("source", "Inconnu"))
    url = article.get("url", "")
    content = article.get("summary_fr") or article.get("content") or article.get("summary", "")
    content = escape(content)

    # Description detaillee (4-5 phrases)
    if len(content) > 600:
        cut = content.find(".", 500)
        if cut > 0 and cut < 700:
            content = content[:cut + 1]
        else:
            content = content[:600].rstrip() + "..."

    # Tag France
    france_tag = ""
    text_lower = (title + " " + content).lower()
    france_keywords = ["france", "français", "francais", "anssi", "cert-fr", "cnil", "rgpd", "paris", "french"]
    if any(kw in text_lower for kw in france_keywords):
        france_tag = " \U0001f1eb\U0001f1f7"

    # Custom alert tag
    custom_tag = ""
    custom_matches = article.get("custom_alert", [])
    if custom_matches:
        custom_tag = f"\U0001f514 <b>Alerte custom :</b> {', '.join(escape(str(m)) for m in custom_matches[:3])}"

    # Points cles : IA si disponible
    key_points = article.get("ai_key_points") or _extract_key_points(content)
    ai_risk = article.get("ai_risk", "")

    lines = [
        "\U0001f6a8\U0001f6a8\U0001f6a8 <b>CRITIQUE</b> | \U0001f4a5 Alerte",
        "<code>\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588</code>",
        "",
        f"\U0001f4f0 {source}",
        "",
        f"<b>{title}</b>{france_tag}",
        "",
        f"\U0001f4d6 {content}",
    ]

    if key_points:
        lines.append("")
        lines.append("\U0001f511 <b>A retenir :</b>")
        for p in key_points:
            lines.append(f"\u2022 {p}")

    if ai_risk:
        lines.append("")
        lines.append(f"\U0001f6e1\ufe0f <b>Risque :</b> {escape(ai_risk)}")

    if custom_tag:
        lines.append("")
        lines.append(custom_tag)

    # Liens
    lines.append("")
    lang = article.get("lang", "en")
    if lang != "fr":
        translate_url = _google_translate_url(url)
        lines.append(f'\u27a1\ufe0f <a href="{escape(translate_url)}">Lire en FR</a> | \U0001f517 <a href="{escape(url)}">Original EN</a>')
    else:
        lines.append(f'\u27a1\ufe0f <a href="{escape(url)}">Lire MAINTENANT</a>')

    return "\n".join(lines)


def format_article_with_france_tag(article):
    """Format article avec tag France si pertinent."""
    # Verifier si l'article mentionne la France AVANT le formatage
    title = article.get("title_fr") or article.get("title", "")
    content = article.get("summary_fr") or article.get("content") or article.get("summary", "")
    text_lower = (title + " " + content).lower()

    france_keywords = ["france", "français", "francais", "anssi", "cert-fr", "cnil",
                       "rgpd", "paris", "french", "hexagone", "tricolore"]
    is_france = any(kw in text_lower for kw in france_keywords)

    message = format_article(article)

    if is_france:
        # Inserer le tag apres le titre (qui est en <b>)
        # Chercher la fin du titre bold
        title_escaped = escape(article.get("title_fr") or article.get("title", ""))
        message = message.replace(
            f"<b>{title_escaped}</b>",
            f"<b>{title_escaped}</b> \U0001f1eb\U0001f1f7",
            1
        )

    return message


def format_health_check(stats, dead_sources, sources_total):
    """Formate le health check quotidien."""
    from datetime import datetime
    from zoneinfo import ZoneInfo
    now = datetime.now(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y")

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
    from datetime import datetime
    from zoneinfo import ZoneInfo
    now = datetime.now(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y")

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


def send_critical_alert(article, channel="info"):
    """Envoie une alerte critique."""
    message = format_critical_alert(article)
    return send_message(message, channel=channel)


def send_health_check(stats, dead_sources, sources_total):
    """Envoie le health check."""
    message = format_health_check(stats, dead_sources, sources_total)
    return send_message(message, disable_preview=True)


def send_weekly_digest(week_stats):
    """Envoie le digest hebdomadaire."""
    message = format_weekly_digest(week_stats)
    return send_message(message, disable_preview=True)
