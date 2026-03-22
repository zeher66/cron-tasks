import sqlite3
import hashlib
import os
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "veille.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_hash TEXT UNIQUE NOT NULL,
            title_hash TEXT NOT NULL,
            url TEXT NOT NULL,
            title TEXT NOT NULL,
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            sent_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            articles_processed INTEGER DEFAULT 0,
            articles_sent INTEGER DEFAULT 0,
            duplicates_filtered INTEGER DEFAULT 0,
            errors INTEGER DEFAULT 0,
            sources_active INTEGER DEFAULT 0,
            sources_total INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_url_hash ON articles(url_hash)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_title_hash ON articles(title_hash)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_sent_at ON articles(sent_at)
    """)
    conn.commit()
    conn.close()
    logger.info("Base de donnees initialisee: %s", DB_PATH)


def _hash(text):
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()


def is_duplicate(url, title):
    """Verifie si un article est un doublon (par URL ou par titre similaire)."""
    url_hash = _hash(url)
    title_hash = _hash(title)

    conn = get_connection()
    cursor = conn.cursor()

    # Niveau 1 : meme URL exacte
    cursor.execute("SELECT 1 FROM articles WHERE url_hash = ?", (url_hash,))
    if cursor.fetchone():
        conn.close()
        return True

    # Niveau 2 : meme titre (meme sujet sur une autre source)
    cursor.execute("SELECT 1 FROM articles WHERE title_hash = ?", (title_hash,))
    if cursor.fetchone():
        conn.close()
        return True

    conn.close()
    return False


def mark_as_sent(url, title, source, category):
    """Enregistre un article comme envoye."""
    url_hash = _hash(url)
    title_hash = _hash(title)
    now = datetime.now(timezone.utc).isoformat()

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO articles (url_hash, title_hash, url, title, source, category, sent_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (url_hash, title_hash, url, title, source, category, now),
        )
        conn.commit()
    except sqlite3.Error as e:
        logger.error("Erreur DB mark_as_sent: %s", e)
    finally:
        conn.close()


def cleanup_old_articles(days=30):
    """Supprime les articles de plus de X jours pour garder la DB legere."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM articles WHERE sent_at < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        logger.info("Nettoyage: %d anciens articles supprimes", deleted)
    return deleted


def update_stats(processed, sent, duplicates, errors, sources_active, sources_total):
    """Met a jour les statistiques du jour."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM stats WHERE date = ?", (today,))
    row = cursor.fetchone()

    if row:
        cursor.execute(
            "UPDATE stats SET "
            "articles_processed = articles_processed + ?, "
            "articles_sent = articles_sent + ?, "
            "duplicates_filtered = duplicates_filtered + ?, "
            "errors = errors + ?, "
            "sources_active = ?, "
            "sources_total = ? "
            "WHERE date = ?",
            (processed, sent, duplicates, errors, sources_active, sources_total, today),
        )
    else:
        cursor.execute(
            "INSERT INTO stats (date, articles_processed, articles_sent, duplicates_filtered, errors, sources_active, sources_total) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (today, processed, sent, duplicates, errors, sources_active, sources_total),
        )
    conn.commit()
    conn.close()


def get_today_stats():
    """Recupere les stats du jour."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM stats WHERE date = ?", (today,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "date": row[1],
            "articles_processed": row[2],
            "articles_sent": row[3],
            "duplicates_filtered": row[4],
            "errors": row[5],
            "sources_active": row[6],
            "sources_total": row[7],
        }
    return None


def get_week_stats():
    """Recupere les stats de la semaine."""
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT SUM(articles_sent), SUM(duplicates_filtered), AVG(sources_active) "
        "FROM stats WHERE date >= ?", (week_ago,)
    )
    row = cursor.fetchone()

    # Top sources de la semaine
    cursor.execute(
        "SELECT source, COUNT(*) as cnt FROM articles WHERE sent_at >= ? "
        "GROUP BY source ORDER BY cnt DESC LIMIT 5", (week_ago,)
    )
    top_sources = cursor.fetchall()

    # Top categories
    cursor.execute(
        "SELECT category, COUNT(*) as cnt FROM articles WHERE sent_at >= ? "
        "GROUP BY category ORDER BY cnt DESC", (week_ago,)
    )
    top_categories = cursor.fetchall()

    # CVE critiques
    cursor.execute(
        "SELECT COUNT(*) FROM articles WHERE sent_at >= ? AND category = 'cve'", (week_ago,)
    )
    cve_row = cursor.fetchone()

    conn.close()

    return {
        "total_sent": row[0] or 0 if row else 0,
        "total_duplicates": row[1] or 0 if row else 0,
        "avg_sources": int(row[2] or 0) if row else 0,
        "top_sources": top_sources,
        "top_categories": top_categories,
        "critical_cves": cve_row[0] if cve_row else 0,
    }


def export_monthly_csv():
    """Exporte les articles du mois en CSV."""
    import csv
    import io

    month_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT url, title, source, category, sent_at FROM articles WHERE sent_at >= ? ORDER BY sent_at DESC",
        (month_ago,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return None

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Titre", "Source", "Categorie", "Date"])
    for row in rows:
        writer.writerow(row)

    return output.getvalue()
