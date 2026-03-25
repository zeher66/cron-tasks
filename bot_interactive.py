#!/usr/bin/env python3
"""
Bot Telegram interactif — tourne sur Render (Web Service).
Repond aux commandes en temps reel via l'IA.

Commandes:
/cve CVE-2026-XXXXX     → details d'une CVE
/search mot-cle          → chercher sur le web
/whois domaine.com       → info domaine/DNS
/list                    → lister les sources RSS
/help                    → aide
"""

import os
import logging
import time
import requests
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_API_KEY_2 = os.environ.get("GROQ_API_KEY_2", "")
CEREBRAS_API_KEY = os.environ.get("CEREBRAS_API_KEY", "")
SAMBANOVA_API_KEY = os.environ.get("SAMBANOVA_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
PORT = int(os.environ.get("PORT", 10000))

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- IA ---

def call_ai(prompt, max_tokens=1000):
    """Appelle Groq puis OpenRouter en fallback."""
    keys = [k for k in [GROQ_API_KEY, GROQ_API_KEY_2] if k]

    for key in keys:
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b-versatile",
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

    # Fallback Cerebras
    if CEREBRAS_API_KEY:
        try:
            response = requests.post(
                "https://api.cerebras.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {CEREBRAS_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b",
                    "messages": [
                        {"role": "system", "content": "Tu es un expert en cybersecurite. Reponds en francais."},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
                timeout=30,
            )
            if response.status_code != 429:
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

    # Fallback SambaNova
    if SAMBANOVA_API_KEY:
        try:
            response = requests.post(
                "https://api.sambanova.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {SAMBANOVA_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "Meta-Llama-3.3-70B-Instruct",
                    "messages": [
                        {"role": "system", "content": "Tu es un expert en cybersecurite. Reponds en francais."},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
                timeout=30,
            )
            if response.status_code != 429:
                response.raise_for_status()
                return response.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

    # Fallback OpenRouter
    if OPENROUTER_API_KEY:
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "meta-llama/llama-3.3-70b-instruct:free",
                    "messages": [
                        {"role": "system", "content": "Tu es un expert en cybersecurite. Reponds en francais."},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
                timeout=45,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

    return "Erreur: IA indisponible."


# --- Telegram ---

def send_telegram(chat_id, text):
    """Envoie un message Telegram."""
    # Decouper si trop long
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


def get_updates(offset=None):
    """Recupere les nouveaux messages."""
    try:
        params = {"timeout": 30}
        if offset:
            params["offset"] = offset
        response = requests.get(f"{TELEGRAM_API}/getUpdates", params=params, timeout=35)
        return response.json().get("result", [])
    except Exception:
        return []


# --- Commandes ---

def cmd_cve(chat_id, args):
    """Recherche les details d'une CVE."""
    if not args:
        send_telegram(chat_id, "Usage: /cve CVE-2026-XXXXX")
        return

    cve_id = args.upper()
    send_telegram(chat_id, f"🔍 Recherche {cve_id}...")

    try:
        response = requests.get(f"{NVD_API}?cveId={cve_id}", timeout=15)
        data = response.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            send_telegram(chat_id, f"❌ {cve_id} non trouve dans NVD.")
            return

        cve = vulns[0].get("cve", {})
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS
        score = "N/A"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                score = metrics[0].get("cvssData", {}).get("baseScore", "N/A")
                break

        # Demander a l'IA d'analyser
        ai_response = call_ai(
            f"Analyse cette CVE en francais de maniere detaillee:\n\n"
            f"CVE: {cve_id}\nCVSS: {score}\nDescription: {desc[:2000]}\n\n"
            f"Donne: description complete, produits affectes, impact, comment l'exploiter, que faire pour se proteger."
        )

        message = (
            f"🔴 <b>{cve_id}</b> | CVSS {score}\n\n"
            f"{ai_response}\n\n"
            f'🔗 <a href="https://nvd.nist.gov/vuln/detail/{cve_id}">NVD</a>'
        )
        send_telegram(chat_id, message)

    except Exception as e:
        send_telegram(chat_id, f"❌ Erreur: {e}")


def cmd_search(chat_id, args):
    """Recherche sur le web via l'IA."""
    if not args:
        send_telegram(chat_id, "Usage: /search ransomware 2026")
        return

    send_telegram(chat_id, f"🔍 Recherche: {args}...")

    ai_response = call_ai(
        f"L'utilisateur cherche des informations sur: {args}\n\n"
        f"Donne une reponse detaillee et technique sur ce sujet en cybersecurite. "
        f"Inclure: definition, exemples recents, comment se proteger, outils recommandes."
    )

    send_telegram(chat_id, f"🔍 <b>Recherche: {args}</b>\n\n{ai_response}")


def cmd_whois(chat_id, args):
    """Info sur un domaine."""
    if not args:
        send_telegram(chat_id, "Usage: /whois exemple.com")
        return

    domain = args.strip().lower()
    send_telegram(chat_id, f"🔍 Whois {domain}...")

    try:
        # DNS lookup
        import socket
        ip = socket.gethostbyname(domain)

        ai_response = call_ai(
            f"Donne des informations de securite sur le domaine: {domain} (IP: {ip})\n\n"
            f"Inclure: informations generales, risques potentiels, recommandations de securite."
        )

        message = (
            f"🌐 <b>Whois: {domain}</b>\n"
            f"📍 IP: {ip}\n\n"
            f"{ai_response}"
        )
        send_telegram(chat_id, message)

    except socket.gaierror:
        send_telegram(chat_id, f"❌ Domaine non resolu: {domain}")
    except Exception as e:
        send_telegram(chat_id, f"❌ Erreur: {e}")


def cmd_list(chat_id):
    """Liste les sources RSS."""
    try:
        from config import FEEDS
        lines = ["📡 <b>Sources RSS actives:</b>\n"]
        for i, feed in enumerate(FEEDS, 1):
            lines.append(f"{i}. {feed['emoji']} {feed['name']}")
        send_telegram(chat_id, "\n".join(lines))
    except Exception:
        send_telegram(chat_id, "❌ Impossible de lire la config.")


def cmd_help(chat_id):
    """Aide."""
    send_telegram(chat_id, (
        "🤖 <b>Bot Cyber Veille — Commandes</b>\n\n"
        "/cve CVE-2026-XXXXX — Details d'une CVE\n"
        "/search mot-cle — Recherche cybersecurite\n"
        "/whois domaine.com — Info domaine/DNS\n"
        "/list — Lister les sources RSS\n"
        "/ask question — Poser une question libre\n"
        "/help — Cette aide\n\n"
        "💡 Tu peux aussi envoyer un message libre et l'IA repondra."
    ))


def cmd_ask(chat_id, args):
    """Question libre a l'IA."""
    if not args:
        send_telegram(chat_id, "Usage: /ask comment fonctionne un ransomware ?")
        return

    send_telegram(chat_id, "🤔 Reflexion...")

    ai_response = call_ai(args)
    send_telegram(chat_id, ai_response)


def handle_message(update):
    """Traite un message Telegram."""
    message = update.get("message", {})
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
        # Message libre → l'IA repond
        cmd_ask(chat_id, text)


# --- Web Server (pour garder Render actif) ---

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # Pas de log pour les health checks


def start_web_server():
    """Demarre un serveur HTTP pour le health check Render."""
    server = HTTPServer(("0.0.0.0", PORT), HealthHandler)
    logger.info("Health server sur port %d", PORT)
    server.serve_forever()


# --- Self-ping (garder Render actif) ---

def self_ping():
    """Ping le service toutes les 4 minutes pour eviter le sleep."""
    render_url = os.environ.get("RENDER_EXTERNAL_URL", "")
    while True:
        time.sleep(240)  # 4 minutes
        if render_url:
            try:
                requests.get(render_url, timeout=10)
            except Exception:
                pass


# --- Main ---

def main():
    """Point d'entree — polling Telegram."""
    logger.info("Bot interactif demarre")

    if not TELEGRAM_BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN non configure")
        return

    # Demarrer le serveur web en background
    web_thread = Thread(target=start_web_server, daemon=True)
    web_thread.start()

    # Demarrer le self-ping en background
    ping_thread = Thread(target=self_ping, daemon=True)
    ping_thread.start()

    # Polling Telegram
    offset = None
    while True:
        try:
            updates = get_updates(offset)
            for update in updates:
                offset = update["update_id"] + 1
                handle_message(update)
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error("Erreur polling: %s", e)
            time.sleep(5)


if __name__ == "__main__":
    main()
