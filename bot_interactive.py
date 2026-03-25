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
PORT = int(os.environ.get("PORT", 10000))
RENDER_URL = os.environ.get("RENDER_EXTERNAL_URL", "https://cron-tasks.onrender.com")

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# --- IA ---

def call_ai(prompt, max_tokens=1000):
    """Appelle les providers IA en cascade."""
    providers = []

    # Groq
    for key in [GROQ_API_KEY, GROQ_API_KEY_2]:
        if key:
            providers.append(("https://api.groq.com/openai/v1/chat/completions", key, "llama-3.3-70b-versatile"))

    # Cerebras
    if CEREBRAS_API_KEY:
        providers.append(("https://api.cerebras.ai/v1/chat/completions", CEREBRAS_API_KEY, "llama-3.3-70b"))

    # SambaNova
    if SAMBANOVA_API_KEY:
        providers.append(("https://api.sambanova.ai/v1/chat/completions", SAMBANOVA_API_KEY, "Meta-Llama-3.3-70B-Instruct"))

    # Together AI
    if TOGETHER_API_KEY:
        providers.append(("https://api.together.xyz/v1/chat/completions", TOGETHER_API_KEY, "meta-llama/Llama-3.3-70B-Instruct-Turbo"))

    # OpenRouter
    if OPENROUTER_API_KEY:
        providers.append(("https://openrouter.ai/api/v1/chat/completions", OPENROUTER_API_KEY, "meta-llama/llama-3.3-70b-instruct:free"))

    for url, key, model in providers:
        try:
            response = requests.post(
                url,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "Tu es un expert en cybersecurite. Reponds en francais, de maniere precise et technique."},
                        {"role": "user", "content": prompt},
                    ],
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

def send_telegram(chat_id, text):
    """Envoie un message Telegram."""
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


def cmd_help(chat_id):
    """Aide."""
    send_telegram(chat_id, (
        "\U0001f916 <b>Bot Cyber Veille — Commandes</b>\n\n"
        "/cve CVE-2026-XXXXX \u2014 Details d'une CVE\n"
        "/search mot-cle \u2014 Recherche cybersecurite\n"
        "/whois domaine.com \u2014 Info domaine/DNS\n"
        "/list \u2014 Lister les sources RSS\n"
        "/ask question \u2014 Poser une question libre\n"
        "/help \u2014 Cette aide\n\n"
        "\U0001f4a1 Tu peux aussi envoyer un message libre et l'IA repondra."
    ))


def cmd_ask(chat_id, args):
    """Question libre a l'IA."""
    if not args:
        send_telegram(chat_id, "Usage: /ask comment fonctionne un ransomware ?")
        return

    send_telegram(chat_id, "\U0001f914 Reflexion...")
    ai_response = call_ai(args)
    send_telegram(chat_id, ai_response)


def handle_message(data):
    """Traite un message Telegram depuis le webhook."""
    message = data.get("message", {})
    chat_id = message.get("chat", {}).get("id")
    text = message.get("text", "").strip()

    if not chat_id or not text:
        return

    logger.info("Message de %s: %s", chat_id, text[:50])

    if text.startswith("/cve "):
        cmd_cve(chat_id, text[5:].strip())
    elif text.startswith("/search "):
        cmd_search(chat_id, text[8:].strip())
    elif text.startswith("/whois "):
        cmd_whois(chat_id, text[7:].strip())
    elif text == "/list":
        cmd_list(chat_id)
    elif text == "/help" or text == "/start":
        cmd_help(chat_id)
    elif text.startswith("/ask "):
        cmd_ask(chat_id, text[5:].strip())
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

    # Configurer le webhook Telegram
    setup_webhook()

    # Demarrer le serveur web
    server = HTTPServer(("0.0.0.0", PORT), WebhookHandler)
    logger.info("Serveur webhook sur port %d", PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
