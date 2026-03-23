"""
Module IA — Resume intelligent avec Groq API (gratuit).
Utilise Llama 3.3 70B pour generer des resumes en francais de qualite.
Fallback sur la traduction Google si Groq est indisponible.
"""

import os
import logging
import requests

logger = logging.getLogger(__name__)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"


def is_ai_available():
    """Verifie si l'IA est configuree."""
    return bool(GROQ_API_KEY)


def _call_groq(prompt, max_tokens=800):
    """Appelle l'API Groq."""
    if not GROQ_API_KEY:
        return None

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
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
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"].strip()
    except requests.RequestException as e:
        logger.warning("Erreur Groq API: %s", e)
        return None
    except (KeyError, IndexError) as e:
        logger.warning("Erreur parsing reponse Groq: %s", e)
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
