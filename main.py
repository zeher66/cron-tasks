#!/usr/bin/env python3
"""
Cyber Veille — Bot de veille informationnelle cybersecurite
100% gratuit. Tourne sur GitHub Actions.

Features:
- 26+ sources RSS (alertes, 0day, cyberattaques, outils, veille FR)
- CVE Monitor (NVD API) + CISA KEV
- Threat Intel (abuse.ch: URLhaus, ThreatFox, MalwareBazaar)
- GitHub trending security repos
- Traduction EN->FR automatique
- Anti-doublons triple niveau
- Auto-reparation XML + retry + rotation User-Agent
- Auto-desactivation/reactivation des sources mortes
- Alertes CRITICAL format special
- Tag France pour menaces francaises
- Health check quotidien (8h Paris)
- Digest hebdomadaire (dimanche 10h Paris)
- Export CSV mensuel
- Stats quotidiennes (22h Paris)
"""

import logging
import os
import sys
import time

from config import FEEDS
from database import (
    init_db, is_duplicate, mark_as_sent, update_stats,
    get_today_stats, get_week_stats, cleanup_old_articles, export_monthly_csv,
)
from feeds import fetch_all_feeds, extract_content, truncate_content, get_dead_sources
from translator import translate_article, translate_text, clean_html
from telegram_bot import (
    send_message, send_article, send_digest, send_stats, send_error,
    send_critical_alert, send_health_check, send_weekly_digest,
    format_article_with_france_tag,
)
from cve_monitor import get_new_cves, format_cve_message, get_kev_cves, format_kev_message
from threat_intel import format_abuse_ch_digest, format_github_trending

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cyber-veille")


def process_articles():
    """Pipeline principal."""
    logger.info("=" * 50)
    logger.info("Demarrage de la veille cyber")
    logger.info("=" * 50)

    init_db()

    # === RSS Feeds ===
    articles, sources_active = fetch_all_feeds()
    sources_total = len(FEEDS)

    processed = 0
    sent = 0
    duplicates = 0
    errors = 0

    for article in articles:
        processed += 1
        title = article["title"]
        url = article["url"]

        if is_duplicate(url, title):
            duplicates += 1
            continue

        # Extraction contenu
        try:
            full_content = extract_content(url)
            if full_content:
                article["content"] = truncate_content(full_content)
            else:
                article["content"] = clean_html(article.get("summary", ""))
        except Exception as e:
            logger.warning("Erreur extraction %s: %s", url, e)
            article["content"] = clean_html(article.get("summary", ""))

        # Traduction
        try:
            article = translate_article(article)
        except Exception as e:
            logger.warning("Erreur traduction: %s", e)
            errors += 1

        # Envoi : format special si CRITICAL
        try:
            if article.get("severity") == "critique":
                success = send_critical_alert(article)
            else:
                message = format_article_with_france_tag(article)
                success = send_message(message)

            if success:
                mark_as_sent(article["url"], article["title"], article["source"], article["category"])
                sent += 1
                logger.info("Envoye: [%s] %s", article["source"], article["title"][:60])
                time.sleep(2)
            else:
                errors += 1
        except Exception as e:
            errors += 1
            logger.error("Erreur envoi: %s", e)

    # === CVE Monitor ===
    logger.info("=" * 50)
    logger.info("Verification CVE critiques")
    logger.info("=" * 50)

    try:
        new_cves = get_new_cves(hours=6)
        for cve_data in new_cves:
            cve_id = cve_data["cve_id"]
            if is_duplicate(cve_data["nvd_url"], cve_id):
                duplicates += 1
                continue
            desc_fr = translate_text(cve_data.get("description", ""), "en")
            if desc_fr:
                cve_data["description"] = desc_fr
            message = format_cve_message(cve_data)
            if send_message(message):
                mark_as_sent(cve_data["nvd_url"], cve_id, "NVD", "cve")
                sent += 1
                logger.info("CVE envoye: %s (CVSS %s)", cve_id, cve_data.get("cvss_score", "N/A"))
                time.sleep(2)
            else:
                errors += 1
    except Exception as e:
        logger.error("Erreur CVE monitor: %s", e)
        errors += 1

    # === CISA KEV ===
    logger.info("=" * 50)
    logger.info("Verification CISA KEV")
    logger.info("=" * 50)

    try:
        kev_cves = get_kev_cves()
        for kev in kev_cves:
            cve_id = kev["cve_id"]
            if is_duplicate(kev["nvd_url"], cve_id):
                duplicates += 1
                continue
            desc_fr = translate_text(kev.get("description", ""), "en")
            if desc_fr:
                kev["description"] = desc_fr
            message = format_kev_message(kev)
            if send_message(message):
                mark_as_sent(kev["nvd_url"], cve_id, "CISA KEV", "kev")
                sent += 1
                logger.info("KEV envoye: %s", cve_id)
                time.sleep(2)
            else:
                errors += 1
    except Exception as e:
        logger.error("Erreur CISA KEV: %s", e)
        errors += 1

    # === Stats ===
    update_stats(processed, sent, duplicates, errors, sources_active, sources_total)

    logger.info("-" * 50)
    logger.info("Resume: %d traites | %d envoyes | %d doublons | %d erreurs",
                processed, sent, duplicates, errors)
    logger.info("Sources actives: %d/%d", sources_active, sources_total)
    logger.info("-" * 50)

    # === Actions horaires (basees sur l'heure de Paris) ===
    from datetime import datetime, timezone, timedelta
    paris_tz = timezone(timedelta(hours=1))
    now = datetime.now(paris_tz)

    # Health check quotidien (8h Paris)
    if now.hour == 8:
        logger.info("Envoi health check quotidien")
        stats = get_today_stats()
        dead = get_dead_sources()
        send_health_check(stats, dead, sources_total)

        # Alerte sources mortes
        if dead:
            send_error(f"Sources en panne depuis 24h+ : {', '.join(dead)}")

    # Stats quotidiennes (21h30 Paris)
    if now.hour == 21 and now.minute >= 30:
        stats = get_today_stats()
        if stats:
            send_stats(stats)
            logger.info("Stats quotidiennes envoyees")

    # Digest hebdomadaire (dimanche 10h Paris)
    if now.weekday() == 6 and now.hour == 10:
        logger.info("Envoi digest hebdomadaire")
        week_stats = get_week_stats()
        send_weekly_digest(week_stats)

    # Threat Intel abuse.ch (toutes les 6h : 6h, 12h, 18h, 0h)
    if now.hour in (0, 6, 12, 18):
        logger.info("Envoi threat intel abuse.ch")
        abuse_msg = format_abuse_ch_digest()
        if abuse_msg:
            send_message(abuse_msg, disable_preview=True)

    # GitHub trending (1x/jour a 9h Paris)
    if now.hour == 9:
        logger.info("Envoi GitHub trending security")
        gh_msg = format_github_trending()
        if gh_msg:
            send_message(gh_msg, disable_preview=True)

    # Export CSV mensuel (1er du mois a 7h)
    if now.day == 1 and now.hour == 7:
        logger.info("Export CSV mensuel")
        csv_data = export_monthly_csv()
        if csv_data:
            csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_mensuel.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(csv_data)
            logger.info("CSV exporte: %s", csv_path)

    # Nettoyage (minuit)
    if now.hour == 0:
        cleanup_old_articles(days=30)

    # Alerte erreurs
    if errors > 5:
        send_error(f"{errors} erreurs sur {processed} articles. Verifiez les logs.")

    return sent, errors


def main():
    """Point d'entree."""
    try:
        sent, errors = process_articles()
        logger.info("Veille terminee. %d envoyes, %d erreurs.", sent, errors)
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
