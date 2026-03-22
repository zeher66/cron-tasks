# 🛡️ Cyber Veille — Bot Telegram automatisé

Bot de veille informationnelle cybersécurité qui tourne 24/7 gratuitement sur GitHub Actions.

## Fonctionnalités

- 📡 **20+ sources RSS** (CERT-FR, ANSSI, Hacker News, BleepingComputer, etc.)
- 🇫🇷 **Traduction automatique** EN→FR (Google Translate gratuit)
- 🔴🟠🟡🔵 **Catégorisation par sévérité** (critique, important, moyen, info)
- 🚫 **Anti-doublons** triple niveau (URL + titre + fenêtre temporelle)
- 📊 **Stats quotidiennes** automatiques
- ⚠️ **Alertes d'erreur** si le bot a des problèmes
- 🔒 **Sécurisé** (tokens dans GitHub Secrets)
- 💰 **100% gratuit** (GitHub Actions + Google Translate)

## Sources

| Catégorie | Sources |
|-----------|---------|
| 🔴 Alertes | CERT-FR Alertes, CERT-FR Avis, CERT-FR CTI, CISA, Exploit-DB |
| 🟠 Cyberattaques | The Hacker News, BleepingComputer, The Record, Dark Reading, SecurityWeek, Zataz, Krebs |
| 🔵 Outils | Schneier, PortSwigger, Packet Storm, Hackaday, Kali Linux |
| 🟢 Veille FR | ANSSI, UnderNews, LeMagIT |

## Déploiement (5 minutes)

### 1. Créer le bot Telegram

1. Ouvre Telegram → cherche **@BotFather**
2. Envoie `/newbot`
3. Choisis un nom et un username
4. Note le **token** (format : `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)
5. Crée un **canal** Telegram
6. Ajoute ton bot comme **administrateur** du canal
7. Envoie un message dans le canal
8. Va sur `https://api.telegram.org/bot<TON_TOKEN>/getUpdates`
9. Cherche `"chat":{"id":-100...}` → c'est ton **chat_id**

### 2. Déployer sur GitHub

1. **Fork** ce repo ou crée un nouveau repo public
2. Push le code dedans
3. Va dans **Settings** → **Secrets and variables** → **Actions**
4. Ajoute 2 secrets :
   - `TELEGRAM_BOT_TOKEN` = ton token du step 1
   - `TELEGRAM_CHAT_ID` = ton chat_id du step 1
5. Va dans **Actions** → active les workflows
6. C'est tout ! Le bot tourne toutes les 30 minutes.

### 3. Protéger le repo

1. **Settings** → **Branches** → **Add rule**
2. Branch name pattern : `main`
3. Coche : **Require a pull request before merging**
4. Coche : **Require approvals** (1)
5. Save

### 4. Test manuel

1. Va dans **Actions** → **Cyber Veille**
2. Clique **Run workflow** → **Run workflow**
3. Vérifie ton canal Telegram

## Structure

```
cyber-veille/
├── .github/workflows/veille.yml  # Cron GitHub Actions (30 min)
├── main.py                        # Orchestrateur principal
├── config.py                      # Sources RSS + configuration
├── feeds.py                       # Scraping RSS + extraction
├── translator.py                  # Traduction EN→FR
├── telegram_bot.py                # Envoi Telegram formaté
├── database.py                    # SQLite anti-doublons
├── requirements.txt               # Dépendances Python
├── .gitignore
└── veille.db                      # Base de données (auto-générée)
```

## Personnalisation

### Ajouter une source RSS

Dans `config.py`, ajoute dans la liste `FEEDS` :

```python
{
    "name": "Ma Source",
    "url": "https://example.com/feed.xml",
    "category": "cyberattaque",  # alerte, cyberattaque, outil, veille_fr
    "lang": "en",                # en ou fr
    "frequency": 120,            # minutes
    "emoji": "🟠",
},
```

### Modifier les mots-clés

Dans `config.py`, modifie `KEYWORDS_PRIORITY` et `KEYWORDS_IGNORE`.

## Sécurité

- ✅ Tokens dans GitHub Secrets (invisibles)
- ✅ Uniquement des GitHub Actions officielles
- ✅ Pas de `pull_request_target`
- ✅ Permissions minimales (`contents: write` uniquement)
- ✅ Pas d'action tierce
- ✅ Concurrency lock (pas d'exécution simultanée)
