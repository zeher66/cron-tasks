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

from config import FEEDS, CUSTOM_ALERTS, NIGHT_MODE_START, NIGHT_MODE_END
from database import (
    init_db, is_duplicate, mark_as_sent, update_stats,
    get_today_stats, get_week_stats, cleanup_old_articles, export_monthly_csv,
    get_threat_trend,
)
from feeds import fetch_all_feeds, extract_content, truncate_content, get_dead_sources
from translator import translate_article, translate_text, clean_html
from telegram_bot import (
    send_message, send_stats, send_error,
    send_critical_alert, send_health_check, send_weekly_digest,
    format_article_with_france_tag,
)
from cve_monitor import get_new_cves, format_cve_message, get_kev_cves, format_kev_message
from threat_intel import format_abuse_ch_digest, format_github_trending, fetch_new_pocs, format_poc_alert, check_stack_relevance

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("cyber-veille")


def _is_night_mode():
    """Verifie si on est en mode nuit (23h-7h Paris)."""
    from datetime import datetime, timezone, timedelta
    from zoneinfo import ZoneInfo
    paris_tz = ZoneInfo("Europe/Paris")
    hour = datetime.now(paris_tz).hour
    if NIGHT_MODE_START > NIGHT_MODE_END:
        return hour >= NIGHT_MODE_START or hour < NIGHT_MODE_END
    return NIGHT_MODE_START <= hour < NIGHT_MODE_END


def _check_custom_alerts(text):
    """Verifie si un texte contient un mot-cle custom. Retourne les mots trouves."""
    if not CUSTOM_ALERTS or not text:
        return []
    text_lower = text.lower()
    return [kw for kw in CUSTOM_ALERTS if kw.lower() in text_lower]


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

        # Stack relevance check
        full_text = (article.get("title", "") + " " + article.get("content", "") + " " + article.get("summary", ""))
        is_relevant, matched_techs = check_stack_relevance(full_text)
        if is_relevant:
            article["stack_match"] = matched_techs

        # Custom alerts check
        custom_matches = _check_custom_alerts(full_text)

        # Envoi : format special si CRITICAL, silencieux si INFO ou mode nuit
        try:
            severity = article.get("severity", "info")
            night = _is_night_mode()

            # Mode nuit : tout silencieux sauf CRITICAL et custom alerts
            if night and severity != "critique" and not custom_matches:
                silent = True
            elif severity in ("info",):
                silent = True
            else:
                silent = False

            # Custom alert = forcer CRITICAL format
            if custom_matches:
                article["custom_alert"] = custom_matches
                success = send_critical_alert(article)
            elif severity == "critique":
                success = send_critical_alert(article)
            else:
                message = format_article_with_france_tag(article)
                if is_relevant:
                    techs_str = ", ".join(matched_techs[:3])
                    message += f"\n\u26a1 <b>Stack:</b> {techs_str}"
                success = send_message(message, silent=silent)

            if success:
                mark_as_sent(article["url"], article["title"], article["source"], article["category"])
                sent += 1
                tags = ""
                if is_relevant:
                    tags += " ⚡"
                if custom_matches:
                    tags += " 🔔"
                if night:
                    tags += " 🌙"
                logger.info("Envoye: [%s] %s%s", article["source"], article["title"][:60], tags)
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
    from zoneinfo import ZoneInfo
    paris_tz = ZoneInfo("Europe/Paris")
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

    # Digest hebdomadaire + tendance (dimanche 10h Paris)
    if now.weekday() == 6 and now.hour == 10:
        logger.info("Envoi digest hebdomadaire")
        week_stats = get_week_stats()
        send_weekly_digest(week_stats)

        # Tendance de menaces
        trend = get_threat_trend()
        if trend["this_week"] > 0 or trend["last_week"] > 0:
            art_arrow = "\u2b06\ufe0f" if trend["article_trend"] > 0 else "\u2b07\ufe0f" if trend["article_trend"] < 0 else "\u27a1\ufe0f"
            cve_arrow = "\u2b06\ufe0f" if trend["cve_trend"] > 0 else "\u2b07\ufe0f" if trend["cve_trend"] < 0 else "\u27a1\ufe0f"
            trend_msg = (
                f"\U0001f4c8 <b>Tendance des menaces</b>\n\n"
                f"{art_arrow} Articles: {trend['this_week']} cette semaine vs {trend['last_week']} la precedente ({trend['article_trend']:+d}%)\n"
                f"{cve_arrow} CVE: {trend['cve_this_week']} cette semaine vs {trend['cve_last_week']} la precedente ({trend['cve_trend']:+d}%)\n"
            )
            if abs(trend["article_trend"]) > 50:
                trend_msg += f"\n\u26a0\ufe0f <b>Variation importante detectee !</b>"
            send_message(trend_msg, disable_preview=True)

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

    # PoC Monitor (toutes les 4h : 8h, 12h, 16h, 20h)
    if now.hour in (8, 12, 16, 20):
        logger.info("PoC Monitor: verification nouveaux exploits")
        pocs = fetch_new_pocs()
        if pocs:
            # Filtrer les PoC deja envoyes
            new_pocs = []
            for poc in pocs:
                if not is_duplicate(poc["url"], poc["name"]):
                    new_pocs.append(poc)
                    mark_as_sent(poc["url"], poc["name"], "GitHub PoC", "poc")
            if new_pocs:
                poc_msg = format_poc_alert(new_pocs)
                if poc_msg:
                    # PoC concernant notre stack = sonore, sinon silencieux
                    has_stack = any(p["concerns_my_stack"] for p in new_pocs)
                    send_message(poc_msg, disable_preview=True, silent=not has_stack)

    # Resume quotidien condense (21h Paris)
    if now.hour == 21 and now.minute < 30:
        logger.info("Envoi resume quotidien condense")
        stats = get_today_stats()
        if stats and stats.get("articles_sent", 0) > 0:
            dead = get_dead_sources()
            lines = [
                f"\U0001f4cb <b>Resume du jour — {now.strftime('%d/%m/%Y')}</b>",
                "",
                f"\U0001f4e8 {stats['articles_sent']} articles envoyes",
                f"\U0001f6ab {stats['duplicates_filtered']} doublons filtres",
                f"\U0001f4e1 {stats['sources_active']}/{stats['sources_total']} sources actives",
            ]
            if stats['errors'] > 0:
                lines.append(f"\u26a0\ufe0f {stats['errors']} erreurs")
            if dead:
                lines.append(f"\U0001f6d1 Sources down: {', '.join(dead[:3])}")
            send_message("\n".join(lines), disable_preview=True, silent=True)

    # Export CSV hebdomadaire (dimanche 11h) + mensuel (1er du mois 7h)
    if now.weekday() == 6 and now.hour == 11:
        logger.info("Export CSV hebdomadaire")
        csv_data = export_monthly_csv()  # reutilise la meme fonction (30 derniers jours)
        if csv_data:
            week_label = now.strftime("%Y-W%W")
            csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"export_semaine_{week_label}.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(csv_data)
            logger.info("CSV hebdo exporte: %s", csv_path)

    if now.day == 1 and now.hour == 7:
        logger.info("Export CSV mensuel")
        csv_data = export_monthly_csv()
        if csv_data:
            month_label = now.strftime("%Y-%m")
            csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"export_mois_{month_label}.csv")
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write(csv_data)
            logger.info("CSV mensuel exporte: %s", csv_path)

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
