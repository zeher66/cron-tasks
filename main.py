#!/usr/bin/env python3
"""
Cyber Veille — Bot de veille informationnelle cybersecurite
Scrape les flux RSS cyber, traduit en francais, envoie sur Telegram.
100% gratuit. Tourne sur GitHub Actions.
"""

import logging
import sys
import time

from config import FEEDS
from database import init_db, is_duplicate, mark_as_sent, update_stats, get_today_stats, cleanup_old_articles
from feeds import fetch_all_feeds, extract_content, truncate_content
from translator import translate_article, clean_html
from telegram_bot import send_article, send_digest, send_stats, send_error

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cyber-veille")


def process_articles():
    """Pipeline principal : scrape -> dedup -> extraction -> traduction -> envoi."""
    logger.info("=" * 50)
    logger.info("Demarrage de la veille cyber")
    logger.info("=" * 50)

    # Initialiser la base de donnees
    init_db()

    # Scraper tous les flux RSS
    articles, sources_active = fetch_all_feeds()
    sources_total = len(FEEDS)

    processed = 0
    sent = 0
    duplicates = 0
    errors = 0
    articles_to_send = []

    for article in articles:
        processed += 1
        title = article["title"]
        url = article["url"]
        source = article["source"]
        category = article["category"]

        # Verification doublons
        if is_duplicate(url, title):
            duplicates += 1
            logger.debug("Doublon ignore: %s", title[:60])
            continue

        # Extraction du contenu complet
        try:
            full_content = extract_content(url)
            if full_content:
                article["content"] = truncate_content(full_content)
            else:
                article["content"] = clean_html(article.get("summary", ""))
        except Exception as e:
            logger.warning("Erreur extraction %s: %s", url, e)
            article["content"] = clean_html(article.get("summary", ""))

        # Traduction en francais
        try:
            article = translate_article(article)
        except Exception as e:
            logger.warning("Erreur traduction %s: %s", title[:40], e)
            errors += 1

        articles_to_send.append(article)

    # Envoi sur Telegram
    for article in articles_to_send:
        try:
            success = send_article(article)
            if success:
                mark_as_sent(article["url"], article["title"], article["source"], article["category"])
                sent += 1
                logger.info("Envoye: [%s] %s", article["source"], article["title"][:60])
                # Pause entre les envois pour eviter le rate limit
                time.sleep(2)
            else:
                errors += 1
                logger.error("Echec envoi: %s", article["title"][:60])
        except Exception as e:
            errors += 1
            logger.error("Erreur envoi %s: %s", article["title"][:40], e)

    # Mise a jour des stats
    update_stats(processed, sent, duplicates, errors, sources_active, sources_total)

    # Log du resume
    logger.info("-" * 50)
    logger.info("Resume: %d traites | %d envoyes | %d doublons | %d erreurs", processed, sent, duplicates, errors)
    logger.info("Sources actives: %d/%d", sources_active, sources_total)
    logger.info("-" * 50)

    # Envoyer les stats si fin de journee (entre 22h et 23h UTC)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if now.hour == 22:
        stats = get_today_stats()
        if stats:
            send_stats(stats)
            logger.info("Stats quotidiennes envoyees")

    # Nettoyage des vieux articles (1x par jour a minuit)
    if now.hour == 0:
        cleanup_old_articles(days=30)

    # Envoyer un rapport d'erreur si beaucoup d'erreurs
    if errors > 5:
        send_error(f"{errors} erreurs detectees sur {processed} articles traites. Verifiez les logs.")

    return sent, errors


def main():
    """Point d'entree principal."""
    try:
        sent, errors = process_articles()
        logger.info("Veille terminee. %d articles envoyes, %d erreurs.", sent, errors)
        sys.exit(0 if errors == 0 else 1)
    except Exception as e:
        logger.critical("Erreur fatale: %s", e, exc_info=True)
        try:
            send_error(f"Erreur fatale: {e}")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
