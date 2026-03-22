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
from translator import translate_article, translate_text, clean_html
from telegram_bot import send_article, send_digest, send_stats, send_error, send_message
from cve_monitor import get_new_cves, format_cve_message, get_kev_cves, format_kev_message

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

    # === CVE Monitor (NVD API) ===
    logger.info("=" * 50)
    logger.info("Verification des nouvelles CVE critiques")
    logger.info("=" * 50)

    try:
        new_cves = get_new_cves(hours=6)
        cve_sent = 0
        for cve_data in new_cves:
            cve_id = cve_data["cve_id"]
            # Dedup CVE
            if is_duplicate(cve_data["nvd_url"], cve_id):
                duplicates += 1
                continue

            # Traduire la description en francais
            desc_fr = translate_text(cve_data.get("description", ""), "en")
            if desc_fr:
                cve_data["description"] = desc_fr

            message = format_cve_message(cve_data)
            if send_message(message):
                mark_as_sent(cve_data["nvd_url"], cve_id, "NVD", "cve")
                cve_sent += 1
                sent += 1
                logger.info("CVE envoye: %s (CVSS %s)", cve_id, cve_data.get("cvss_score", "N/A"))
                time.sleep(2)
            else:
                errors += 1

        logger.info("CVE: %d nouvelles envoyees", cve_sent)
    except Exception as e:
        logger.error("Erreur CVE monitor: %s", e)
        errors += 1

    # === CISA KEV (Exploitations actives) ===
    logger.info("=" * 50)
    logger.info("Verification CISA KEV (exploitations actives)")
    logger.info("=" * 50)

    try:
        kev_cves = get_kev_cves()
        kev_sent = 0
        for kev in kev_cves:
            cve_id = kev["cve_id"]
            if is_duplicate(kev["nvd_url"], cve_id):
                duplicates += 1
                continue

            # Traduire en francais
            desc_fr = translate_text(kev.get("description", ""), "en")
            if desc_fr:
                kev["description"] = desc_fr

            message = format_kev_message(kev)
            if send_message(message):
                mark_as_sent(kev["nvd_url"], cve_id, "CISA KEV", "kev")
                kev_sent += 1
                sent += 1
                logger.info("KEV envoye: %s", cve_id)
                time.sleep(2)
            else:
                errors += 1

        logger.info("CISA KEV: %d nouvelles envoyees", kev_sent)
    except Exception as e:
        logger.error("Erreur CISA KEV: %s", e)
        errors += 1

    # Mise a jour des stats
    update_stats(processed, sent, duplicates, errors, sources_active, sources_total)

    # Log du resume
    logger.info("-" * 50)
    logger.info("Resume: %d traites | %d envoyes | %d doublons | %d erreurs", processed, sent, duplicates, errors)
    logger.info("Sources actives: %d/%d", sources_active, sources_total)
    logger.info("-" * 50)

    # Envoyer les stats si fin de journee (22h heure de Paris = 21h UTC)
    from datetime import datetime, timezone, timedelta
    paris_tz = timezone(timedelta(hours=1))
    now = datetime.now(paris_tz)
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
