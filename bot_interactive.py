#!/usr/bin/env python3
"""
Bot Telegram interactif — tourne sur Render (Web Service).
Utilise les webhooks Telegram : Render dort et se reveille quand un message arrive.

Commandes:
/cve CVE-2026-XXXXX     → details d'une CVE
/search mot-cle          → chercher cybersecurite
/whois domaine.com       → info domaine/DNS
/list                    → lister les sources RSS
/ask question            → poser une question libre
/help                    → aide
"""

import os
import logging
import json
import time
import requests
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_API_KEY_2 = os.environ.get("GROQ_API_KEY_2", "")
CEREBRAS_API_KEY = os.environ.get("CEREBRAS_API_KEY", "")
SAMBANOVA_API_KEY = os.environ.get("SAMBANOVA_API_KEY", "")
TOGETHER_API_KEY = os.environ.get("TOGETHER_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
PORT = int(os.environ.get("PORT", 10000))
RENDER_URL = os.environ.get("RENDER_EXTERNAL_URL", "https://cron-tasks.onrender.com")

GITHUB_CONV_TOKEN = os.environ.get("GITHUB_CONV_TOKEN", "")
TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_DB_URL = "https://raw.githubusercontent.com/zeher66/cron-tasks/main/veille.db"
CONV_REPO = "zeher66/cyber-conv_bot_telegrame"
CONV_FILE = "conversations.json"


# --- Memoire conversations (GitHub prive) ---

_conv_cache = {}  # Cache en RAM : {chat_id: [messages]}
_conv_sha = ""    # SHA du fichier pour les updates


def _load_conversations():
    """Charge les conversations depuis le repo prive GitHub."""
    global _conv_cache, _conv_sha
    if not GITHUB_CONV_TOKEN:
        return

    try:
        response = requests.get(
            f"https://api.github.com/repos/{CONV_REPO}/contents/{CONV_FILE}",
            headers={
                "Authorization": f"Bearer {GITHUB_CONV_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            },
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            _conv_sha = data.get("sha", "")
            import base64
            content = base64.b64decode(data["content"]).decode("utf-8")
            _conv_cache = json.loads(content)
            logger.info("Conversations chargees: %d chats", len(_conv_cache))
        elif response.status_code == 404:
            _conv_cache = {}
            logger.info("Aucun historique de conversation")
    except Exception as e:
        logger.warning("Erreur chargement conversations: %s", e)


def _save_conversations():
    """Sauvegarde les conversations dans le repo prive GitHub."""
    global _conv_sha
    if not GITHUB_CONV_TOKEN:
        return

    try:
        import base64
        content = json.dumps(_conv_cache, ensure_ascii=False, indent=2)
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        data = {
            "message": "update conversations",
            "content": encoded,
        }
        if _conv_sha:
            data["sha"] = _conv_sha

        response = requests.put(
            f"https://api.github.com/repos/{CONV_REPO}/contents/{CONV_FILE}",
            headers={
                "Authorization": f"Bearer {GITHUB_CONV_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            },
            json=data,
            timeout=15,
        )
        if response.status_code in (200, 201):
            _conv_sha = response.json().get("content", {}).get("sha", "")
            logger.info("Conversations sauvegardees")
        else:
            logger.warning("Erreur sauvegarde conversations: %s", response.text[:200])
    except Exception as e:
        logger.warning("Erreur sauvegarde conversations: %s", e)


def _add_to_history(chat_id, role, content):
    """Ajoute un message a l'historique."""
    chat_key = str(chat_id)
    if chat_key not in _conv_cache:
        _conv_cache[chat_key] = []

    _conv_cache[chat_key].append({
        "role": role,
        "content": content[:500],  # Limiter la taille
    })

    # Garder les 20 derniers messages
    _conv_cache[chat_key] = _conv_cache[chat_key][-20:]


def _get_history(chat_id):
    """Recupere l'historique d'un chat."""
    return _conv_cache.get(str(chat_id), [])


# --- IA ---

def call_ai(prompt, max_tokens=1000, chat_id=None):
    """Appelle les providers IA en cascade."""
    providers = []

    # Cerebras en premier (pas utilise par la veille)
    if CEREBRAS_API_KEY:
        providers.append(("https://api.cerebras.ai/v1/chat/completions", CEREBRAS_API_KEY, "gpt-oss-120b"))

    # SambaNova (pas utilise par la veille)
    if SAMBANOVA_API_KEY:
        providers.append(("https://api.sambanova.ai/v1/chat/completions", SAMBANOVA_API_KEY, "Meta-Llama-3.3-70B-Instruct"))

    # Together AI (pas utilise par la veille)
    if TOGETHER_API_KEY:
        providers.append(("https://api.together.xyz/v1/chat/completions", TOGETHER_API_KEY, "meta-llama/Llama-3.3-70B-Instruct-Turbo"))

    # OpenRouter (utilise par la veille en fallback uniquement)
    if OPENROUTER_API_KEY:
        providers.append(("https://openrouter.ai/api/v1/chat/completions", OPENROUTER_API_KEY, "meta-llama/llama-3.3-70b-instruct:free"))

    # Groq en dernier (utilise en priorite par la veille)
    for key in [GROQ_API_KEY, GROQ_API_KEY_2]:
        if key:
            providers.append(("https://api.groq.com/openai/v1/chat/completions", key, "llama-3.3-70b-versatile"))

    # Contexte systeme avec date, stack, etc.
    from datetime import datetime as dt_now
    from zoneinfo import ZoneInfo
    now_paris = dt_now.now(ZoneInfo("Europe/Paris")).strftime("%d/%m/%Y %H:%M")

    try:
        from config import MY_STACK, FRANCE_KEYWORDS
        stack_str = ", ".join(MY_STACK[:15])
    except Exception:
        stack_str = "non configure"

    system_prompt = (
        f"Tu es un expert en cybersecurite. Tu reponds TOUJOURS et UNIQUEMENT en francais. "
        f"Tu es precis, concis et technique. Ne reponds JAMAIS en anglais. "
        f"PAS de markdown (** ## ```). Texte brut avec emojis. "
        f"Date actuelle: {now_paris}. "
        f"Stack technique de l'utilisateur: {stack_str}. "
        f"L'utilisateur vit en France."
    )

    # Construire les messages avec historique
    messages = [{"role": "system", "content": system_prompt}]
    if chat_id:
        history = _get_history(chat_id)
        for msg in history[-10:]:  # 10 derniers messages
            messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": prompt})

    for url, key, model in providers:
        try:
            response = requests.post(
                url,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
                timeout=30,
            )
            if response.status_code == 429:
                continue
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            continue

    return "Erreur: IA indisponible."


# --- Telegram ---

def _clean_markdown(text):
    """Nettoie le markdown de la reponse IA."""
    return text.replace("**", "").replace("##", "").replace("# ", "").replace("```", "")


def send_telegram(chat_id, text):
    """Envoie un message Telegram."""
    text = _clean_markdown(text)
    while text:
        chunk = text[:4096]
        text = text[4096:]
        try:
            requests.post(f"{TELEGRAM_API}/sendMessage", json={
                "chat_id": chat_id,
                "text": chunk,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }, timeout=15)
        except Exception as e:
            logger.error("Erreur envoi Telegram: %s", e)
        if text:
            time.sleep(1)


def setup_webhook():
    """Configure le webhook Telegram."""
    webhook_url = f"{RENDER_URL}/webhook"
    try:
        response = requests.post(f"{TELEGRAM_API}/setWebhook", json={
            "url": webhook_url,
        }, timeout=15)
        result = response.json()
        if result.get("ok"):
            logger.info("Webhook configure: %s", webhook_url)
        else:
            logger.error("Erreur webhook: %s", result)
    except Exception as e:
        logger.error("Erreur setup webhook: %s", e)


# --- DB ---

def get_today_articles():
    """Telecharge la DB depuis GitHub et recupere les articles du jour."""
    import sqlite3
    import tempfile
    from datetime import datetime, timezone

    try:
        response = requests.get(GITHUB_DB_URL, timeout=15)
        response.raise_for_status()

        # Ecrire en fichier temporaire
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.write(response.content)
        tmp.close()

        # Lire la DB
        conn = sqlite3.connect(tmp.name)
        cursor = conn.cursor()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT title, source, category, severity FROM articles WHERE sent_at >= ? ORDER BY sent_at DESC",
            (today,)
        )
        rows = cursor.fetchall()
        conn.close()

        # Supprimer le fichier temporaire
        os.unlink(tmp.name)

        return [{"title": r[0], "source": r[1], "category": r[2], "severity": r[3]} for r in rows]
    except Exception as e:
        logger.error("Erreur lecture DB: %s", e)
        return None


def get_week_articles():
    """Recupere les articles de la semaine."""
    import sqlite3
    import tempfile
    from datetime import datetime, timedelta, timezone

    try:
        response = requests.get(GITHUB_DB_URL, timeout=15)
        response.raise_for_status()

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.write(response.content)
        tmp.close()

        conn = sqlite3.connect(tmp.name)
        cursor = conn.cursor()
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT title, source, category, severity FROM articles WHERE sent_at >= ? ORDER BY sent_at DESC",
            (week_ago,)
        )
        rows = cursor.fetchall()
        conn.close()
        os.unlink(tmp.name)

        return [{"title": r[0], "source": r[1], "category": r[2], "severity": r[3]} for r in rows]
    except Exception as e:
        logger.error("Erreur lecture DB: %s", e)
        return None


# --- Commandes ---

def cmd_cve(chat_id, args):
    """Recherche les details d'une CVE."""
    if not args:
        send_telegram(chat_id, "Usage: /cve CVE-2026-XXXXX")
        return

    cve_id = args.upper()
    send_telegram(chat_id, f"\U0001f50d Recherche {cve_id}...")

    try:
        response = requests.get(f"{NVD_API}?cveId={cve_id}", timeout=15)
        data = response.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            send_telegram(chat_id, f"\u274c {cve_id} non trouve dans NVD.")
            return

        cve = vulns[0].get("cve", {})
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        score = "N/A"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                score = metrics[0].get("cvssData", {}).get("baseScore", "N/A")
                break

        ai_response = call_ai(
            f"Analyse cette CVE en francais de maniere detaillee:\n\n"
            f"CVE: {cve_id}\nCVSS: {score}\nDescription: {desc[:2000]}\n\n"
            f"Donne: description complete, produits affectes, impact, comment l'exploiter, que faire pour se proteger."
        )

        message = (
            f"\U0001f534 <b>{cve_id}</b> | CVSS {score}\n\n"
            f"{ai_response}\n\n"
            f'\U0001f517 <a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a>'
        )
        send_telegram(chat_id, message)

    except Exception as e:
        send_telegram(chat_id, f"\u274c Erreur: {e}")


def cmd_search(chat_id, args):
    """Recherche cybersecurite via l'IA."""
    if not args:
        send_telegram(chat_id, "Usage: /search ransomware 2026")
        return

    send_telegram(chat_id, f"\U0001f50d Recherche: {args}...")

    ai_response = call_ai(
        f"L'utilisateur cherche des informations sur: {args}\n\n"
        f"Donne une reponse detaillee et technique sur ce sujet en cybersecurite. "
        f"Inclure: definition, exemples recents, comment se proteger, outils recommandes."
    )

    send_telegram(chat_id, f"\U0001f50d <b>Recherche: {args}</b>\n\n{ai_response}")


def cmd_whois(chat_id, args):
    """Info sur un domaine."""
    if not args:
        send_telegram(chat_id, "Usage: /whois exemple.com")
        return

    domain = args.strip().lower()
    send_telegram(chat_id, f"\U0001f50d Whois {domain}...")

    try:
        ip = socket.gethostbyname(domain)

        ai_response = call_ai(
            f"Donne des informations de securite sur le domaine: {domain} (IP: {ip})\n\n"
            f"Inclure: informations generales, risques potentiels, recommandations de securite."
        )

        message = (
            f"\U0001f310 <b>Whois: {domain}</b>\n"
            f"\U0001f4cd IP: {ip}\n\n"
            f"{ai_response}"
        )
        send_telegram(chat_id, message)

    except socket.gaierror:
        send_telegram(chat_id, f"\u274c Domaine non resolu: {domain}")
    except Exception as e:
        send_telegram(chat_id, f"\u274c Erreur: {e}")


def cmd_list(chat_id):
    """Liste les sources RSS."""
    try:
        from config import FEEDS
        lines = ["\U0001f4e1 <b>Sources RSS actives:</b>\n"]
        for i, feed in enumerate(FEEDS, 1):
            lines.append(f"{i}. {feed['emoji']} {feed['name']}")
        send_telegram(chat_id, "\n".join(lines))
    except Exception:
        send_telegram(chat_id, "\u274c Impossible de lire la config.")


def get_month_articles():
    """Recupere les articles du mois."""
    import sqlite3
    import tempfile
    from datetime import datetime, timedelta, timezone

    try:
        response = requests.get(GITHUB_DB_URL, timeout=15)
        response.raise_for_status()

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.write(response.content)
        tmp.close()

        conn = sqlite3.connect(tmp.name)
        cursor = conn.cursor()
        month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT title, source, category, severity FROM articles WHERE sent_at >= ? ORDER BY sent_at DESC",
            (month_ago,)
        )
        rows = cursor.fetchall()
        conn.close()
        os.unlink(tmp.name)

        return [{"title": r[0], "source": r[1], "category": r[2], "severity": r[3]} for r in rows]
    except Exception as e:
        logger.error("Erreur lecture DB: %s", e)
        return None


def cmd_today(chat_id):
    """Articles importants du jour."""
    send_telegram(chat_id, "\U0001f50d Chargement des articles du jour...")

    articles = get_today_articles()
    if not articles:
        send_telegram(chat_id, "\u274c Impossible de recuperer les articles.")
        return

    if not articles:
        send_telegram(chat_id, "\U0001f4ed Aucun article aujourd'hui.")
        return

    # Preparer la liste pour l'IA
    articles_text = "\n".join(
        f"- [{a['severity'].upper()}] [{a['source']}] {a['title']}"
        for a in articles[:30]
    )

    ai_response = call_ai(
        f"Voici les {len(articles)} articles de cybersecurite recus aujourd'hui.\n\n"
        f"{articles_text}\n\n"
        f"Fais un resume STRUCTURE en francais avec EXACTEMENT ce format (utilise les emojis indiques):\n\n"
        f"📊 RESUME:\n[2-3 phrases resumant la journee globalement]\n\n"
        f"🔴 CRITIQUE:\n"
        f"1. 🚨 [titre] — [1 phrase: pourquoi c'est critique et que faire]\n\n"
        f"🟠 IMPORTANT:\n"
        f"1. ⚠️ [titre] — [1 phrase: impact et action]\n\n"
        f"🟡 A SURVEILLER:\n"
        f"1. 👁️ [titre] — [1 phrase courte]\n\n"
        f"Pas de blabla. Direct, technique, actionnable. PAS de markdown, PAS de ** ou #. Texte brut avec emojis.",
        max_tokens=1500,
    )

    # Nettoyer le markdown
    ai_response = ai_response.replace("**", "").replace("##", "").replace("# ", "")
    send_telegram(chat_id, f"\U0001f4cb <b>Resume du jour — {len(articles)} articles</b>\n\n{ai_response}")


def cmd_week(chat_id):
    """Resume de la semaine."""
    send_telegram(chat_id, "\U0001f50d Chargement des articles de la semaine...")

    articles = get_week_articles()
    if not articles:
        send_telegram(chat_id, "\u274c Impossible de recuperer les articles.")
        return

    articles_text = "\n".join(
        f"- [{a['severity'].upper()}] [{a['source']}] {a['title']}"
        for a in articles[:50]
    )

    ai_response = call_ai(
        f"Voici les {len(articles)} articles de cybersecurite de la semaine.\n\n"
        f"{articles_text}\n\n"
        f"Fais un resume STRUCTURE en francais avec EXACTEMENT ce format (utilise les emojis indiques):\n\n"
        f"📈 TENDANCES:\n[2-3 phrases sur les tendances de la semaine]\n\n"
        f"🔴 TOP MENACES:\n"
        f"1. 🚨 [titre] — [impact en 1 phrase]\n\n"
        f"⚠️ CVE CRITIQUES:\n"
        f"1. 🎯 [CVE-ID] — [produit + risque en 1 phrase]\n\n"
        f"🔑 A RETENIR:\n"
        f"- 💡 [point cle 1]\n"
        f"- 💡 [point cle 2]\n"
        f"- 💡 [point cle 3]\n\n"
        f"Direct et technique. PAS de markdown, PAS de ** ou #. Texte brut avec emojis.",
        max_tokens=1500,
    )

    ai_response = ai_response.replace("**", "").replace("##", "").replace("# ", "")
    send_telegram(chat_id, f"\U0001f4ca <b>Resume de la semaine — {len(articles)} articles</b>\n\n{ai_response}")


def cmd_month(chat_id):
    """Resume du mois."""
    send_telegram(chat_id, "\U0001f50d Chargement des articles du mois...")

    articles = get_month_articles()
    if not articles:
        send_telegram(chat_id, "\u274c Impossible de recuperer les articles.")
        return

    articles_text = "\n".join(
        f"- [{a['severity'].upper()}] [{a['source']}] {a['title']}"
        for a in articles[:60]
    )

    ai_response = call_ai(
        f"Voici les {len(articles)} articles de cybersecurite du mois.\n\n"
        f"{articles_text}\n\n"
        f"Fais un resume STRUCTURE en francais avec EXACTEMENT ce format (utilise les emojis indiques):\n\n"
        f"📊 BILAN:\n[3-4 phrases sur le mois en cybersecurite]\n\n"
        f"🏆 TOP 5 EVENEMENTS:\n"
        f"1. 🚨 [titre] — [impact]\n\n"
        f"🎭 GROUPES ACTIFS: [liste des groupes de hackers mentionnes]\n\n"
        f"📈 TENDANCES:\n"
        f"- 📌 [tendance 1]\n"
        f"- 📌 [tendance 2]\n"
        f"- 📌 [tendance 3]\n\n"
        f"🛡️ RECOMMANDATIONS:\n"
        f"- → [action 1]\n"
        f"- → [action 2]\n"
        f"- → [action 3]\n\n"
        f"Direct et technique. PAS de markdown, PAS de ** ou #. Texte brut avec emojis.",
        max_tokens=1500,
    )

    ai_response = ai_response.replace("**", "").replace("##", "").replace("# ", "")
    send_telegram(chat_id, f"\U0001f4c6 <b>Resume du mois — {len(articles)} articles</b>\n\n{ai_response}")


def cmd_shodan(chat_id, args):
    """Recherche Shodan sur une IP."""
    if not args:
        send_telegram(chat_id, "Usage: /shodan 8.8.8.8")
        return

    if not SHODAN_API_KEY:
        send_telegram(chat_id, "\u274c Shodan API non configuree.")
        return

    ip = args.strip()
    send_telegram(chat_id, f"\U0001f50d Scan Shodan: {ip}...")

    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
            timeout=15,
        )

        if response.status_code == 404:
            send_telegram(chat_id, f"\U0001f4ed Aucune donnee Shodan pour {ip}")
            return

        response.raise_for_status()
        data = response.json()

        org = data.get("org", "Inconnu")
        country = data.get("country_name", "Inconnu")
        city = data.get("city", "")
        isp = data.get("isp", "")
        os_name = data.get("os", "Inconnu")
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])

        lines = [
            f"\U0001f310 <b>Shodan: {ip}</b>",
            "",
            f"\U0001f3e2 Organisation: {org}",
            f"\U0001f4cd Pays: {country}" + (f" — {city}" if city else ""),
        ]

        if isp:
            lines.append(f"\U0001f4e1 FAI: {isp}")
        if os_name and os_name != "Inconnu":
            lines.append(f"\U0001f4bb OS: {os_name}")

        if ports:
            lines.append("")
            lines.append(f"<b>Ports ouverts ({len(ports)}) :</b>")
            for port in sorted(ports)[:15]:
                # Trouver le service
                service = ""
                for s in data.get("data", []):
                    if s.get("port") == port:
                        service = s.get("product", "") or s.get("_shodan", {}).get("module", "")
                        break
                warning = ""
                if port in (21, 23, 3306, 5432, 6379, 27017, 1433):
                    warning = " \U0001f534 expose !"
                elif port in (22, 3389):
                    warning = " \u26a0\ufe0f"
                lines.append(f"  \u2022 {port}" + (f" ({service})" if service else "") + warning)

        if vulns:
            lines.append("")
            lines.append(f"\U0001f534 <b>Vulnerabilites ({len(vulns)}) :</b>")
            for v in sorted(vulns)[:10]:
                lines.append(f"  \u2022 {v}")

        if not vulns:
            lines.append("")
            lines.append("\u2705 Aucune vulnerabilite connue")

        # Demander a l'IA d'analyser
        shodan_summary = f"IP: {ip}, Org: {org}, Pays: {country}, Ports: {ports[:10]}, Vulns: {vulns[:5]}"
        ai_analysis = call_ai(
            f"Analyse cette IP scannee par Shodan et donne des recommandations de securite:\n{shodan_summary}",
            max_tokens=500,
        )

        lines.append("")
        lines.append(f"\U0001f916 <b>Analyse IA :</b>")
        lines.append(ai_analysis)

        lines.append("")
        lines.append(f'\U0001f517 <a href="https://www.shodan.io/host/{ip}">Voir sur Shodan</a>')

        send_telegram(chat_id, "\n".join(lines))

    except Exception as e:
        send_telegram(chat_id, f"\u274c Erreur Shodan: {e}")


def cmd_scan(chat_id, args):
    """Scan complet d'une cible (domaine, IP ou URL)."""
    if not args:
        send_telegram(chat_id, "Usage: /scan exemple.com ou /scan 8.8.8.8 ou /scan https://exemple.com")
        return

    target = args.strip().lower()
    # Nettoyer l'URL
    target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    send_telegram(chat_id, f"\U0001f3af <b>Scan complet: {target}</b>\n\n\U0001f50d Analyse en cours...")

    results = []

    # 1. DNS
    try:
        ip = socket.gethostbyname(target)
        results.append(f"\U0001f4cd <b>DNS:</b> {target} \u2192 {ip}")
    except socket.gaierror:
        ip = target  # C'est peut-etre deja une IP
        results.append(f"\U0001f4cd <b>IP:</b> {ip}")

    # 2. Shodan
    shodan_data = {}
    if SHODAN_API_KEY:
        try:
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
                timeout=15,
            )
            if response.status_code == 200:
                shodan_data = response.json()

                org = shodan_data.get("org", "Inconnu")
                country = shodan_data.get("country_name", "Inconnu")
                city = shodan_data.get("city", "")
                isp = shodan_data.get("isp", "")
                ports = shodan_data.get("ports", [])
                vulns = shodan_data.get("vulns", [])

                results.append(f"\U0001f3e2 <b>Organisation:</b> {org}")
                results.append(f"\U0001f30d <b>Localisation:</b> {country}" + (f" — {city}" if city else ""))
                if isp:
                    results.append(f"\U0001f4e1 <b>FAI:</b> {isp}")

                if ports:
                    ports_str = ""
                    for port in sorted(ports)[:10]:
                        warning = ""
                        if port in (21, 23, 3306, 5432, 6379, 27017, 1433):
                            warning = " \U0001f534"
                        elif port in (22, 3389):
                            warning = " \u26a0\ufe0f"
                        ports_str += f"  \u2022 {port}{warning}\n"
                    results.append(f"\n\U0001f6aa <b>Ports ouverts ({len(ports)}):</b>\n{ports_str}")

                if vulns:
                    vulns_str = "\n".join(f"  \u2022 {v}" for v in sorted(vulns)[:10])
                    results.append(f"\U0001f534 <b>Vulnerabilites ({len(vulns)}):</b>\n{vulns_str}")
                else:
                    results.append("\u2705 Aucune vulnerabilite connue")

                # Technologies detectees
                techs = set()
                for s in shodan_data.get("data", []):
                    product = s.get("product", "")
                    if product:
                        techs.add(product)
                if techs:
                    results.append(f"\n\U0001f527 <b>Technologies:</b> {', '.join(list(techs)[:8])}")

            else:
                results.append("\U0001f4ed Aucune donnee Shodan pour cette IP")
        except Exception as e:
            results.append(f"\u26a0\ufe0f Shodan: {e}")

    # 3. SSL check
    try:
        import ssl
        import datetime
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(10)
            s.connect((target, 443))
            cert = s.getpeercert()
            expire = cert.get("notAfter", "")
            issuer = dict(x[0] for x in cert.get("issuer", []))
            issuer_name = issuer.get("organizationName", "Inconnu")
            results.append(f"\n\U0001f512 <b>SSL:</b> Valide \u2014 {issuer_name}")
            results.append(f"\U0001f4c5 <b>Expire:</b> {expire}")
    except Exception:
        results.append(f"\n\U0001f512 <b>SSL:</b> Non disponible ou invalide")

    # 4. Analyse IA
    scan_summary = "\n".join(results)
    ai_response = call_ai(
        f"Voici le resultat du scan de la cible {target}:\n\n{scan_summary}\n\n"
        f"Analyse cette cible et donne:\n"
        f"1. Niveau de risque global (Critique/Eleve/Moyen/Faible)\n"
        f"2. Les problemes de securite detectes\n"
        f"3. Les recommandations concretes pour securiser cette cible",
        max_tokens=800,
    )

    results.append(f"\n\U0001f916 <b>Analyse IA:</b>\n{ai_response}")
    results.append(f"\n\U0001f517 <a href=\"https://www.shodan.io/host/{ip}\">Shodan</a>")

    send_telegram(chat_id, "\n".join(results))


def cmd_tools(chat_id):
    """Derniers outils cyber detectes."""
    send_telegram(chat_id, "\U0001f50d Chargement des outils recents...")

    try:
        import sqlite3
        import tempfile
        from datetime import datetime, timedelta, timezone

        response = requests.get(GITHUB_DB_URL, timeout=15)
        response.raise_for_status()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.write(response.content)
        tmp.close()

        # Chercher les outils dans les articles recents
        conn = sqlite3.connect(tmp.name)
        cursor = conn.cursor()
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        cursor.execute(
            "SELECT title, source FROM articles WHERE sent_at >= ? AND (category = 'outil' OR title LIKE '%tool%' OR title LIKE '%outil%') ORDER BY sent_at DESC LIMIT 20",
            (week_ago,)
        )
        rows = cursor.fetchall()
        conn.close()
        os.unlink(tmp.name)

        if rows:
            tools_text = "\n".join(f"- [{r[1]}] {r[0]}" for r in rows)
            ai_resp = call_ai(
                f"Voici les outils et articles outils de la semaine:\n{tools_text}\n\n"
                f"Classe-les en: offensif, defensif, polyvalent. "
                f"Pour chaque outil, dis en 1 phrase ce qu'il fait et pourquoi c'est utile."
            )
            send_telegram(chat_id, f"\U0001f527 <b>Outils cyber recents</b>\n\n{ai_resp}")
        else:
            send_telegram(chat_id, "\U0001f4ed Aucun outil detecte cette semaine.")
    except Exception as e:
        send_telegram(chat_id, f"\u274c Erreur: {e}")


def cmd_exploit(chat_id, args):
    """Cherche un exploit/PoC pour une CVE."""
    if not args:
        send_telegram(chat_id, "Usage: /exploit CVE-2026-XXXXX")
        return

    cve_id = args.upper().strip()
    send_telegram(chat_id, f"\U0001f50d Recherche exploit pour {cve_id}...")

    # 1. Chercher sur GitHub
    try:
        response = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": f"{cve_id} in:name,description", "sort": "stars", "order": "desc", "per_page": 5},
            headers={"User-Agent": UA, "Accept": "application/vnd.github.v3+json"},
            timeout=15,
        )
        repos = response.json().get("items", []) if response.status_code == 200 else []
    except Exception:
        repos = []

    # 2. Chercher dans NVD
    nvd_desc = ""
    nvd_score = "N/A"
    try:
        response = requests.get(f"{NVD_API}?cveId={cve_id}", timeout=15)
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            cve = vulns[0].get("cve", {})
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    nvd_desc = d.get("value", "")
                    break
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    nvd_score = metrics[0].get("cvssData", {}).get("baseScore", "N/A")
                    break
    except Exception:
        pass

    # 3. Construire la reponse
    lines = [f"\U0001f4a3 <b>Exploit Search: {cve_id}</b>", ""]

    if nvd_desc:
        lines.append(f"CVSS: {nvd_score}")
        lines.append("")

    if repos:
        lines.append(f"\U0001f527 <b>{len(repos)} PoC trouves sur GitHub:</b>")
        lines.append("")
        for repo in repos[:5]:
            name = repo.get("full_name", "")
            desc = (repo.get("description", "") or "")[:80]
            stars = repo.get("stargazers_count", 0)
            url = repo.get("html_url", "")
            lines.append(f"\u2022 <a href=\"{url}\">{name}</a> \u2b50{stars}")
            if desc:
                lines.append(f"  {desc}")
            lines.append("")
    else:
        lines.append("\u274c Aucun PoC public trouve sur GitHub.")
        lines.append("")

    # 4. IA analyse
    if nvd_desc:
        ai_resp = call_ai(
            f"CVE: {cve_id}\nCVSS: {nvd_score}\nDescription: {nvd_desc[:1000]}\n"
            f"PoC disponibles: {len(repos)}\n\n"
            f"Analyse cette CVE: est-elle exploitable ? Comment ? Quels outils utiliser pour tester ?",
            max_tokens=800,
        )
        lines.append(f"\U0001f916 <b>Analyse IA:</b>")
        lines.append(ai_resp)

    lines.append("")
    lines.append(f'\U0001f517 <a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a> | <a href="https://www.exploit-db.com/search?cve={cve_id}">Exploit-DB</a>')

    send_telegram(chat_id, "\n".join(lines))


def cmd_help(chat_id):
    """Aide."""
    send_telegram(chat_id, (
        "\U0001f916 <b>Bot Cyber Veille — Commandes</b>\n\n"
        "/today \u2014 Resume des articles importants du jour\n"
        "/week \u2014 Resume de la semaine\n"
        "/month \u2014 Resume du mois\n"
        "/cve CVE-2026-XXXXX \u2014 Details d'une CVE\n"
        "/search mot-cle \u2014 Recherche cybersecurite\n"
        "/whois domaine.com \u2014 Info domaine/DNS\n"
        "/shodan IP \u2014 Scanner une IP (ports, vulns)\n"
        "/scan cible \u2014 Scan complet (domaine, IP ou URL)\n"
        "/exploit CVE-ID \u2014 Chercher un PoC/exploit\n"
        "/tools \u2014 Nouveaux outils cyber de la semaine\n"
        "/list \u2014 Lister les sources RSS\n"
        "/ask question \u2014 Poser une question libre\n"
        "/help \u2014 Cette aide\n\n"
        "\U0001f4a1 Tu peux aussi envoyer un message libre et l'IA repondra."
    ))


def cmd_ask(chat_id, args):
    """Question libre a l'IA avec contexte des articles recents."""
    if not args:
        send_telegram(chat_id, "Usage: /ask comment fonctionne un ransomware ?")
        return

    send_telegram(chat_id, "\U0001f914 Reflexion...")

    # Sauvegarder la question dans l'historique
    _add_to_history(chat_id, "user", args)

    # Chercher dans les articles recents pour donner du contexte
    context = ""
    try:
        articles = get_today_articles() or []
        if not articles:
            articles = get_week_articles() or []
        if not articles:
            articles = get_month_articles() or []

        if articles:
            question_lower = args.lower()
            words = [w for w in question_lower.split() if len(w) > 3]
            relevant = [a for a in articles if any(
                word in a["title"].lower() for word in words
            )]
            if relevant:
                context = "\n\nCONTEXTE - Articles recents sur ce sujet:\n"
                for a in relevant[:5]:
                    context += f"- [{a['severity'].upper()}] [{a['source']}] {a['title']}\n"
    except Exception:
        pass

    ai_response = call_ai(
        f"Question: {args}\n{context}\n"
        f"Si le contexte contient des articles pertinents, utilise-les pour donner une reponse precise et actuelle. "
        f"Sinon reponds avec tes connaissances generales. Sois precis et technique.",
        chat_id=chat_id,
    )

    # Sauvegarder la reponse dans l'historique
    _add_to_history(chat_id, "assistant", ai_response[:500])
    _save_conversations()

    send_telegram(chat_id, ai_response)


def handle_message(data):
    """Traite un message Telegram depuis le webhook."""
    message = data.get("message", {})
    chat_id = message.get("chat", {}).get("id")
    text = message.get("text", "").strip()

    if not chat_id or not text:
        return

    logger.info("Message de %s: %s", chat_id, text[:50])

    text_lower = text.lower()

    if text.startswith("/cve "):
        cmd_cve(chat_id, text[5:].strip())
    elif text.startswith("/search "):
        cmd_search(chat_id, text[8:].strip())
    elif text.startswith("/whois "):
        cmd_whois(chat_id, text[7:].strip())
    elif text.startswith("/shodan "):
        cmd_shodan(chat_id, text[8:].strip())
    elif text.startswith("/scan "):
        cmd_scan(chat_id, text[6:].strip())
    elif text.startswith("/exploit "):
        cmd_exploit(chat_id, text[9:].strip())
    elif text == "/tools":
        cmd_tools(chat_id)
    elif text == "/list":
        cmd_list(chat_id)
    elif text == "/today":
        cmd_today(chat_id)
    elif text == "/week":
        cmd_week(chat_id)
    elif text == "/month":
        cmd_month(chat_id)
    elif text == "/help" or text == "/start":
        cmd_help(chat_id)
    elif text.startswith("/ask "):
        cmd_ask(chat_id, text[5:].strip())
    elif any(kw in text_lower for kw in ["aujourd'hui", "du jour", "today", "ce matin", "ce soir", "important"]):
        cmd_today(chat_id)
    elif any(kw in text_lower for kw in ["semaine", "week", "cette semaine", "7 jours"]):
        cmd_week(chat_id)
    elif any(kw in text_lower for kw in ["mois", "month", "ce mois", "30 jours"]):
        cmd_month(chat_id)
    else:
        cmd_ask(chat_id, text)


# --- Web Server (webhook) ---

class WebhookHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Health check."""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        """Receive Telegram webhook."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)
            handle_message(data)
        except Exception as e:
            logger.error("Erreur webhook: %s", e)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass


# --- Main ---

def main():
    """Point d'entree — webhook mode."""
    logger.info("Bot interactif demarre (webhook mode)")

    if not TELEGRAM_BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN non configure")
        return

    # Charger les conversations depuis GitHub
    _load_conversations()

    # Configurer le webhook Telegram
    setup_webhook()

    # Demarrer le serveur web
    server = HTTPServer(("0.0.0.0", PORT), WebhookHandler)
    logger.info("Serveur webhook sur port %d", PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
