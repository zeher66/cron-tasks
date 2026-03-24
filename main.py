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
    get_threat_trend, get_today_important_articles, get_today_all_articles,
    export_weekly_csv,
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
from ai_summarizer import is_ai_available, summarize_article, summarize_cve, parse_ai_response, select_daily_important, parse_daily_selection

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


# Mots-cles d'urgence absolue
URGENCY_KEYWORDS = [
    "actively exploited", "exploitation active", "in the wild",
    "zero-day", "0day", "zero day",
    "cisa kev", "emergency patch", "correctif d'urgence",
    "wiper", "supply chain attack", "ransomware attack",
]


def _check_must_read(article, is_relevant, matched_techs, custom_matches, cvss_score=None):
    """Determine si un article est un 'A LIRE ABSOLUMENT'. Retourne (bool, raisons)."""
    reasons = []
    text = (article.get("title", "") + " " + article.get("content", "") + " " +
            article.get("summary", "") + " " + article.get("title_fr", "")).lower()

    # CVSS >= 9.0
    if cvss_score and cvss_score != "N/A":
        try:
            if float(cvss_score) >= 9.0:
                reasons.append(f"CVSS {cvss_score} (critique)")
        except (ValueError, TypeError):
            pass

    # Exploitation active
    if any(kw in text for kw in URGENCY_KEYWORDS):
        matched = [kw for kw in URGENCY_KEYWORDS if kw in text]
        reasons.append(f"Urgence: {matched[0]}")

    # Concerne ta stack
    if is_relevant and matched_techs:
        reasons.append(f"Concerne votre stack: {', '.join(matched_techs[:2])}")

    # Custom alerts
    if custom_matches:
        reasons.append(f"Alerte custom: {', '.join(custom_matches[:2])}")

    severity = article.get("severity", "info")

    # CRITIQUE + au moins 1 raison → MUST READ
    if severity == "critique" and len(reasons) >= 1:
        return True, reasons

    # IMPORTANT + au moins 2 raisons → MUST READ
    if severity == "important" and len(reasons) >= 2:
        return True, reasons

    # MOYEN ou INFO + concerne ta stack + urgence → MUST READ
    if severity in ("moyen", "info") and is_relevant and any(kw in text for kw in URGENCY_KEYWORDS):
        return True, reasons

    # N'importe quelle severite + custom alert → MUST READ
    if custom_matches:
        return True, reasons

    # N'importe quelle severite + CVSS >= 9.0 → MUST READ
    if cvss_score and cvss_score != "N/A":
        try:
            if float(cvss_score) >= 9.0:
                return True, reasons
        except (ValueError, TypeError):
            pass

    # Au moins 3 raisons combinées → MUST READ
    if len(reasons) >= 3:
        return True, reasons

    return False, reasons


def _format_must_read_banner(reasons, article=None):
    """Formate la banniere 'A LIRE ABSOLUMENT' avec explication detaillee."""
    lines = [
        "\u26a0\ufe0f\u26a0\ufe0f\u26a0\ufe0f <b>A LIRE ABSOLUMENT</b> \u26a0\ufe0f\u26a0\ufe0f\u26a0\ufe0f",
        "",
        "\U0001f4a2 <b>Pourquoi tu dois lire ca :</b>",
    ]

    for r in reasons:
        # Enrichir chaque raison avec une explication
        if "CVSS" in r:
            lines.append(f"\u2022 \U0001f534 {r} — score maximal, exploitation facile et impact total")
        elif "stack" in r.lower():
            techs = r.split(": ")[-1] if ": " in r else r
            lines.append(f"\u2022 \u26a1 {r} — cette faille/attaque cible directement des technologies que tu utilises")
        elif "urgence" in r.lower() or "exploit" in r.lower():
            lines.append(f"\u2022 \U0001f525 {r} — des attaquants exploitent activement cette faille en ce moment")
        elif "custom" in r.lower():
            lines.append(f"\u2022 \U0001f514 {r} — correspond a un de tes mots-cles de surveillance")
        else:
            lines.append(f"\u2022 {r}")

    # Ajouter le contexte de l'article si disponible
    if article:
        title = article.get("title_fr") or article.get("title", "")
        if title:
            lines.append("")
            lines.append(f"\U0001f4cc <b>{title[:100]}</b>")

    lines.append("")
    lines.append("\u2b07\ufe0f\u2b07\ufe0f\u2b07\ufe0f")
    return "\n".join(lines)


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

        # Resume IA (Groq) ou traduction Google (fallback)
        try:
            if is_ai_available():
                ai_response = summarize_article(
                    article["title"],
                    article.get("content") or article.get("summary", ""),
                    article["source"],
                    article.get("lang", "en"),
                )
                parsed = parse_ai_response(ai_response)
                if parsed:
                    # Filtrer les articles hors-sujet
                    if not parsed.get("pertinent", True):
                        logger.info("Filtre IA (hors-sujet): %s", article["title"][:60])
                        duplicates += 1
                        continue

                    article["title_fr"] = parsed["title"] or article["title"]
                    article["summary_fr"] = parsed["description"]
                    article["ai_key_points"] = parsed["key_points"]
                    article["ai_risk"] = parsed["risk"]

                    # Utiliser la severite IA si disponible
                    if parsed.get("ai_severity"):
                        article["severity"] = parsed["ai_severity"]
                        severity_emojis = {
                            "critique": "\U0001f534",
                            "important": "\U0001f7e0",
                            "moyen": "\U0001f7e1",
                            "info": "\U0001f535",
                        }
                        article["severity_emoji"] = severity_emojis.get(parsed["ai_severity"], "\U0001f535")
                else:
                    article = translate_article(article)
            else:
                article = translate_article(article)
        except Exception as e:
            logger.warning("Erreur IA/traduction: %s", e)
            try:
                article = translate_article(article)
            except Exception:
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

            # Verifier si "A LIRE ABSOLUMENT"
            must_read, must_reasons = _check_must_read(article, is_relevant, matched_techs, custom_matches)
            if must_read:
                banner = _format_must_read_banner(must_reasons, article)
                send_message(banner, silent=False, channel=channel)  # Toujours sonore
                time.sleep(1)

            # Determiner le canal
            cat = article.get("category", "")
            if cat in ("0day",):
                channel = "0day"
            elif cat in ("alerte",):
                channel = "cve"
            else:
                channel = "info"

            # Custom alert = forcer CRITICAL format
            if custom_matches:
                article["custom_alert"] = custom_matches
                success = send_critical_alert(article, channel=channel)
            elif severity == "critique":
                success = send_critical_alert(article, channel=channel)
            else:
                message = format_article_with_france_tag(article)
                if is_relevant:
                    techs_str = ", ".join(matched_techs[:3])
                    message += f"\n\u26a1 <b>Stack:</b> {techs_str}"
                success = send_message(message, silent=silent, channel=channel)

            if success:
                # Stocker le message formate pour le digest
                stored_msg = message if not custom_matches and severity != "critique" else format_article_with_france_tag(article)
                mark_as_sent(article["url"], article["title"], article["source"], article["category"],
                             severity=severity, message=stored_msg)
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
            # Resume IA ou traduction
            if is_ai_available():
                ai_resp = summarize_cve(
                    cve_id, cve_data.get("description", ""),
                    cve_data.get("cvss_score"), cve_data.get("affected", []),
                    cve_data.get("has_exploit", False),
                )
                parsed = parse_ai_response(ai_resp)
                if parsed:
                    cve_data["description"] = parsed["description"]
                    cve_data["ai_key_points"] = parsed["key_points"]
                    cve_data["ai_risk"] = parsed["risk"]
                else:
                    desc_fr = translate_text(cve_data.get("description", ""), "en")
                    if desc_fr:
                        cve_data["description"] = desc_fr
            else:
                desc_fr = translate_text(cve_data.get("description", ""), "en")
                if desc_fr:
                    cve_data["description"] = desc_fr

            # Verifier "A LIRE ABSOLUMENT" pour les CVE
            cvss = cve_data.get("cvss_score")
            cve_text_check = {"title": cve_id, "content": cve_data.get("description", ""),
                              "summary": "", "title_fr": "", "severity": "critique" if cve_data.get("cvss_severity") == "CRITICAL" else "important"}
            cve_relevant, cve_techs = check_stack_relevance(cve_data.get("description", ""))
            cve_must_read, cve_reasons = _check_must_read(cve_text_check, cve_relevant, cve_techs, [], cvss_score=cvss)
            if cve_must_read:
                banner = _format_must_read_banner(cve_reasons, cve_text_check)
                send_message(banner, silent=False, channel="cve")
                time.sleep(1)

            message = format_cve_message(cve_data)
            if send_message(message, channel="cve"):
                cve_sev = "critique" if cve_data.get("cvss_severity") == "CRITICAL" else "important"
                mark_as_sent(cve_data["nvd_url"], cve_id, "NVD", "cve", severity=cve_sev, message=message)
                sent += 1
                must_tag = " ⚠️MUST READ" if cve_must_read else ""
                logger.info("CVE envoye: %s (CVSS %s)%s", cve_id, cve_data.get("cvss_score", "N/A"), must_tag)
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
            if send_message(message, channel="cve"):
                mark_as_sent(kev["nvd_url"], cve_id, "CISA KEV", "kev", severity="critique", message=message)
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
    from datetime import datetime
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

    # Digest important du jour + stats (21h30 Paris)
    if now.hour == 21 and now.minute >= 30:
        logger.info("Envoi digest important du jour")

        all_articles = get_today_all_articles()

        if all_articles and is_ai_available():
            # L'IA decide quels articles sont importants
            articles_list = "\n".join(
                f"{a['id']}. [{a['severity'].upper()}] [{a['source']}] {a['title']}"
                for a in all_articles
            )
            ai_selection = select_daily_important(articles_list)
            parsed_sel = parse_daily_selection(ai_selection)

            if parsed_sel:
                selected_ids = parsed_sel["selected_ids"]
                daily_summary = parsed_sel["daily_summary"]
                priorities = parsed_sel["priorities"]

                # Header avec resume IA de la journee
                header_lines = [
                    f"\U0001f4cb <b>Digest du jour — {now.strftime('%d/%m/%Y')}</b>",
                    f"<code>\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588</code>",
                    "",
                    f"\U0001f4e8 <b>{len(selected_ids)} articles selectionnes par l'IA sur {len(all_articles)} du jour</b>",
                    "",
                ]

                if daily_summary:
                    header_lines.append(f"\U0001f4d6 <b>Resume de la journee :</b>")
                    header_lines.append(daily_summary)
                    header_lines.append("")

                if priorities:
                    header_lines.append("\U0001f3af <b>Top priorites :</b>")
                    for p in priorities[:3]:
                        header_lines.append(f"\u2022 {p}")
                    header_lines.append("")

                header_lines.append("\u2500" * 25)
                send_message("\n".join(header_lines), disable_preview=True, silent=True)
                time.sleep(1)

                # Envoyer les articles selectionnes par l'IA
                sent_digest = 0
                for a in all_articles:
                    if a["id"] in selected_ids and a.get("message"):
                        send_message(a["message"], disable_preview=True, silent=True)
                        sent_digest += 1
                        time.sleep(2)

                logger.info("Digest IA: %d articles selectionnes sur %d", sent_digest, len(all_articles))
            else:
                # Fallback si l'IA echoue : envoyer les critique + important
                important = get_today_important_articles()
                for art in important:
                    if art.get("message"):
                        send_message(art["message"], disable_preview=True, silent=True)
                        time.sleep(2)
        elif all_articles:
            # Pas d'IA : fallback
            important = get_today_important_articles()
            for art in important:
                if art.get("message"):
                    send_message(art["message"], disable_preview=True, silent=True)
                    time.sleep(2)

        # Stats
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

    # Threat Intel abuse.ch — desactive (API necessite un token maintenant)
    # if now.hour in (0, 6, 12, 18):
    #     abuse_msg = format_abuse_ch_digest()
    #     if abuse_msg:
    #         send_message(abuse_msg, disable_preview=True)

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
            if new_pocs:
                poc_msg = format_poc_alert(new_pocs)
                if poc_msg:
                    has_stack = any(p["concerns_my_stack"] for p in new_pocs)
                    success = send_message(poc_msg, disable_preview=True, silent=not has_stack, channel="0day")
                    # Marquer comme envoyes SEULEMENT apres envoi reussi
                    if success:
                        for poc in new_pocs:
                            mark_as_sent(poc["url"], poc["name"], "GitHub PoC", "poc")

    # (Resume quotidien integre dans le digest a 21h30)

    # Export CSV hebdomadaire (dimanche 11h) + mensuel (1er du mois 7h)
    if now.weekday() == 6 and now.hour == 11:
        logger.info("Export CSV hebdomadaire")
        csv_data = export_weekly_csv()
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
        sys.exit(1 if errors > 5 else 0)  # Seulement si beaucoup d'erreurs
    except Exception as e:
        logger.critical("Erreur fatale: %s", e, exc_info=True)
        try:
            send_error(f"Erreur fatale: {e}")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
