"""
Module IA — Resume intelligent avec Groq API (gratuit).
Utilise Llama 3.3 70B pour generer des resumes en francais de qualite.
Fallback sur la traduction Google si Groq est indisponible.
"""

import os
import logging
import requests

logger = logging.getLogger(__name__)

GROQ_API_KEYS = [
    os.environ.get("GROQ_API_KEY", ""),
    os.environ.get("GROQ_API_KEY_2", ""),
]
GROQ_API_KEYS = [k for k in GROQ_API_KEYS if k]  # Enlever les vides
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

# Index de la cle active (bascule si rate limit)
_current_key_index = 0


def is_ai_available():
    """Verifie si l'IA est configuree."""
    return bool(GROQ_API_KEYS)


def _call_groq(prompt, max_tokens=800):
    """Appelle l'API Groq avec fallback sur la 2e cle."""
    global _current_key_index

    if not GROQ_API_KEYS:
        return None

    # Essayer chaque cle
    for attempt in range(len(GROQ_API_KEYS)):
        key_index = (_current_key_index + attempt) % len(GROQ_API_KEYS)
        api_key = GROQ_API_KEYS[key_index]

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": GROQ_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Tu es un analyste expert en cybersecurite. "
                        "Tu reponds UNIQUEMENT en francais. "
                        "Tu es precis, concis et technique."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }

        try:
            response = requests.post(
                GROQ_API_URL, headers=headers, json=data, timeout=30
            )

            # Rate limit → basculer sur l'autre cle
            if response.status_code == 429:
                logger.warning("Groq rate limit sur cle %d, bascule sur cle %d",
                               key_index + 1, (key_index + 1) % len(GROQ_API_KEYS) + 1)
                _current_key_index = (key_index + 1) % len(GROQ_API_KEYS)
                continue

            response.raise_for_status()
            result = response.json()
            _current_key_index = key_index  # Garder la cle qui marche
            return result["choices"][0]["message"]["content"].strip()

        except requests.RequestException as e:
            logger.warning("Erreur Groq API (cle %d): %s", key_index + 1, e)
            continue
        except (KeyError, IndexError) as e:
            logger.warning("Erreur parsing reponse Groq: %s", e)
            return None

    logger.error("Toutes les cles Groq ont echoue")
    return None


def summarize_article(title, content, source, lang="en"):
    """Resume un article de cybersecurite en francais."""
    if not is_ai_available():
        return None

    # Tronquer le contenu pour rester dans les limites de tokens
    content_truncated = content[:3000] if content else ""

    prompt = f"""Analyse cet article et genere un resume structure en francais.

Source: {source}
Titre original: {title}
Langue: {lang}

Contenu:
{content_truncated}

Reponds avec EXACTEMENT ce format (pas de markdown, juste du texte brut):

PERTINENT: [OUI ou NON] - est-ce un article de cybersecurite, vulnerabilite, attaque, outil de securite, ou veille informatique ? (NON si c'est du marketing, promo, smartphone, sport, divertissement, etc.)

SEVERITE: [CRITIQUE/IMPORTANT/MOYEN/INFO] - basee sur l'impact reel (CRITIQUE = exploitation active ou RCE, IMPORTANT = menace reelle, MOYEN = vulnerabilite ou patch, INFO = actualite/outil)

TITRE: [titre traduit en francais, clair et accrocheur]

DESCRIPTION: [resume COMPLET et DETAILLE en 6-10 phrases. Le lecteur ne doit PAS avoir besoin de lire l'article original. Inclure: le contexte (qui, quoi, quand), les details techniques (comment l'attaque fonctionne, quelle faille, quel vecteur), les systemes/produits affectes avec versions, l'impact concret (nombre de victimes, donnees volees, acces obtenus), et les mesures prises ou recommandees. Utilise un langage clair et professionnel.]

POINTS CLES:
- [qui est affecte et combien]
- [comment l'attaque/faille fonctionne techniquement]
- [quel est l'impact concret]
- [quelle action prendre immediatement]
- [contexte supplementaire important]

RISQUE: [Critique/Eleve/Moyen/Faible] - [explication en 1-2 phrases de pourquoi ce niveau, avec les consequences possibles]"""

    return _call_groq(prompt, max_tokens=1200)


def summarize_cve(cve_id, description, cvss_score, affected, has_exploit=False):
    """Resume une CVE en francais avec analyse de risque."""
    if not is_ai_available():
        return None

    affected_str = ", ".join(affected) if affected else "Non specifie"
    exploit_info = "OUI - exploit public disponible" if has_exploit else "Non confirme"

    prompt = f"""Analyse cette vulnerabilite CVE et genere un resume en francais pour un analyste securite.

CVE: {cve_id}
CVSS: {cvss_score}
Produits affectes: {affected_str}
Exploit public: {exploit_info}

Description technique:
{description[:2000]}

Reponds avec EXACTEMENT ce format (pas de markdown, juste du texte brut):

TITRE: [CVE ID + description courte du probleme en francais]

DESCRIPTION: [explication COMPLETE en 6-10 phrases pour un analyste securite. Inclure: quel produit/version est affecte, quelle est la nature exacte de la faille (type, composant, fonction), comment un attaquant peut l'exploiter (vecteur d'attaque, conditions, authentification requise ou non), quel est l'impact concret (execution de code, vol de donnees, deni de service, escalade de privileges), si un exploit public existe, et quelle action corrective prendre (patch, workaround, mitigation).]

POINTS CLES:
- [produit et versions affectees]
- [type de faille et comment l'exploiter]
- [impact concret: ce qu'un attaquant peut faire]
- [exploit public disponible ou non]
- [action: patch/mise a jour/mitigation a appliquer]

RISQUE: [Critique/Eleve/Moyen/Faible] - [pourquoi, en tenant compte du CVSS, de l'exploit, et de la surface d'attaque]"""

    return _call_groq(prompt, max_tokens=1200)


def select_daily_important(articles_summary):
    """L'IA decide quels articles du jour sont importants a retenir."""
    if not is_ai_available() or not articles_summary:
        return None

    prompt = f"""Tu es un analyste cybersecurite senior. Voici la liste de TOUS les articles recus aujourd'hui.
Tu dois selectionner les articles les plus importants que l'utilisateur DOIT absolument connaitre.

Criteres de selection:
- Menaces actives et exploitees
- Vulnerabilites critiques sur des produits populaires
- Attaques en cours ou recentes
- Informations strategiques pour un professionnel de la securite
- Ignorer: les articles marketing, les news mineures, les outils sans impact direct

Liste des articles du jour:
{articles_summary}

Reponds avec EXACTEMENT ce format (pas de markdown):

SELECTION: [numeros des articles selectionnes, separes par des virgules, ex: 1,3,5,8]

RESUME JOURNEE: [resume en 3-4 phrases de la journee en cybersecurite: les tendances, les menaces principales, ce qu'il faut retenir]

PRIORITE 1: [numero] - [pourquoi c'est le plus important en 1 phrase]
PRIORITE 2: [numero] - [pourquoi en 1 phrase]
PRIORITE 3: [numero] - [pourquoi en 1 phrase]"""

    return _call_groq(prompt, max_tokens=600)


def parse_daily_selection(response):
    """Parse la reponse de selection quotidienne."""
    if not response:
        return None

    result = {
        "selected_ids": [],
        "daily_summary": "",
        "priorities": [],
    }

    for line in response.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("SELECTION:"):
            ids_str = line[10:].strip()
            try:
                result["selected_ids"] = [int(x.strip()) for x in ids_str.split(",") if x.strip().isdigit()]
            except ValueError:
                pass
        elif line.startswith("RESUME JOURNEE:"):
            result["daily_summary"] = line[15:].strip()
        elif line.startswith("PRIORITE"):
            result["priorities"].append(line.strip())

    return result if result["selected_ids"] else None


def parse_ai_response(response):
    """Parse la reponse structuree de l'IA."""
    if not response:
        return None

    result = {
        "title": "",
        "description": "",
        "key_points": [],
        "risk": "",
        "pertinent": True,
        "ai_severity": "",
    }

    current_section = None
    for line in response.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.startswith("PERTINENT:"):
            value = line[10:].strip().upper()
            result["pertinent"] = value.startswith("OUI")
            current_section = "pertinent"
        elif line.startswith("SEVERITE:"):
            value = line[9:].strip().upper()
            severity_map = {
                "CRITIQUE": "critique",
                "IMPORTANT": "important",
                "MOYEN": "moyen",
                "INFO": "info",
            }
            for key, val in severity_map.items():
                if key in value:
                    result["ai_severity"] = val
                    break
            current_section = "severite"
        elif line.startswith("TITRE:"):
            result["title"] = line[6:].strip()
            current_section = "title"
        elif line.startswith("DESCRIPTION:"):
            result["description"] = line[12:].strip()
            current_section = "description"
        elif line.startswith("POINTS CLES:"):
            current_section = "points"
        elif line.startswith("RISQUE:"):
            result["risk"] = line[7:].strip()
            current_section = "risk"
        elif current_section == "description" and not line.startswith("-"):
            result["description"] += " " + line
        elif current_section == "points" and line.startswith("- "):
            result["key_points"].append(line[2:].strip())
        elif current_section == "risk" and not line.startswith("-"):
            result["risk"] += " " + line

    # Nettoyer
    result["description"] = result["description"].strip()
    result["risk"] = result["risk"].strip()

    return result if result["title"] or result["description"] else None
