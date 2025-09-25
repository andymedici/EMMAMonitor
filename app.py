import os
import asyncio
import aiohttp
import feedparser
import sqlite3
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from contextlib import asynccontextmanager
import re
from urllib.parse import urljoin
import logging
from pathlib import Path
import json

# Configuration
EMMA_RSS_URL = "https://emma.msrb.org/rss/DisclosureSearch.aspx"
DATABASE_PATH = "emma_monitor.db"
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "alerts@yourdomain.com")
ALERT_EMAILS = os.getenv("ALERT_EMAILS", "").split(",") if os.getenv("ALERT_EMAILS") else []
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
RUN_INITIAL_SCAN = os.getenv("RUN_INITIAL_SCAN", "false").lower() == "true"

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SearchQuery:
    def __init__(self, query_id: int, name: str, query: str, search_type: str, active: bool = True, batch_name: str = ""):
        self.id = query_id
        self.name = name
        self.query = query
        self.search_type = search_type  # 'exact', 'all', 'any'
        self.active = active
        self.batch_name = batch_name
        self._compiled_pattern = None
    
    def matches(self, text: str) -> bool:
        if not text or not self.query:
            return False
        
        text_lower = text.lower()
        
        if self.search_type == 'exact':
            return self.query.lower() in text_lower
        
        elif self.search_type == 'all':  # AND logic
            terms = [t.strip().lower() for t in self.query.split(',') if t.strip()]
            return all(term in text_lower for term in terms)
        
        elif self.search_type == 'any':  # OR logic  
            terms = [t.strip().lower() for t in self.query.split(',') if t.strip()]
            return any(term in text_lower for term in terms)
        
        return False

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        
        # Disclosures table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS disclosures (
                id INTEGER PRIMARY KEY,
                guid TEXT UNIQUE,
                title TEXT,
                url TEXT,
                pub_date TEXT,
                content_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Search queries table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS search_queries (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                query TEXT NOT NULL,
                search_type TEXT NOT NULL CHECK(search_type IN ('exact', 'all', 'any')),
                active BOOLEAN DEFAULT 1,
                batch_name TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Matches table (links disclosures to search queries)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY,
                disclosure_id INTEGER,
                search_query_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (disclosure_id) REFERENCES disclosures (id),
                FOREIGN KEY (search_query_id) REFERENCES search_queries (id),
                UNIQUE(disclosure_id, search_query_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    async def save_search_query(self, name: str, query: str, search_type: str, batch_name: str = "") -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            INSERT INTO search_queries (name, query, search_type, batch_name)
            VALUES (?, ?, ?, ?)
        """, (name, query, search_type, batch_name))
        
        query_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return query_id
    
    async def get_search_queries(self, active_only: bool = True) -> List[SearchQuery]:
        conn = sqlite3.connect(self.db_path)
        
        where_clause = "WHERE active = 1" if active_only else ""
        cursor = conn.execute(f"""
            SELECT id, name, query, search_type, active, batch_name
            FROM search_queries {where_clause}
            ORDER BY batch_name, name
        """)
        
        queries = []
        for row in cursor:
            queries.append(SearchQuery(row[0], row[1], row[2], row[3], bool(row[4]), row[5]))
        
        conn.close()
        return queries
    
    async def update_search_query(self, query_id: int, name: str, query: str, search_type: str, 
                                 active: bool, batch_name: str = ""):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            UPDATE search_queries 
            SET name = ?, query = ?, search_type = ?, active = ?, batch_name = ?
            WHERE id = ?
        """, (name, query, search_type, active, batch_name, query_id))
        
        conn.commit()
        conn.close()
    
    async def delete_search_query(self, query_id: int):
        conn = sqlite3.connect(self.db_path)
        # Delete matches first due to foreign key
        conn.execute("DELETE FROM matches WHERE search_query_id = ?", (query_id,))
        conn.execute("DELETE FROM search_queries WHERE id = ?", (query_id,))
        conn.commit()
        conn.close()
    
    async def save_disclosure(self, guid: str, title: str, url: str, pub_date: str, content_summary: str = "") -> Optional[int]:
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("""
                INSERT OR IGNORE INTO disclosures 
                (guid, title, url, pub_date, content_summary)
                VALUES (?, ?, ?, ?, ?)
            """, (guid, title, url, pub_date, content_summary))
            
            if cursor.rowcount == 0:  # Already exists
                cursor = conn.execute("SELECT id FROM disclosures WHERE guid = ?", (guid,))
                disclosure_id = cursor.fetchone()[0]
            else:
                disclosure_id = cursor.lastrowid
            
            conn.commit()
            conn.close()
            return disclosure_id
        except Exception as e:
            conn.close()
            logger.error(f"Error saving disclosure: {e}")
            return None
    
    async def save_match(self, disclosure_id: int, search_query_id: int):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT OR IGNORE INTO matches (disclosure_id, search_query_id)
                VALUES (?, ?)
            """, (disclosure_id, search_query_id))
            conn.commit()
        except Exception as e:
            logger.error(f"Error saving match: {e}")
        finally:
            conn.close()
    
    async def get_recent_matches(self, days: int = 7) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cutoff = datetime.now() - timedelta(days=days)
        
        cursor = conn.execute("""
            SELECT d.guid, d.title, d.url, d.pub_date, d.content_summary, d.created_at,
                   GROUP_CONCAT(sq.name || ' (' || sq.search_type || ')') as matched_searches,
                   GROUP_CONCAT(sq.batch_name) as batch_names
            FROM disclosures d
            JOIN matches m ON d.id = m.disclosure_id
            JOIN search_queries sq ON m.search_query_id = sq.id
            WHERE d.created_at > ?
            GROUP BY d.id
            ORDER BY d.created_at DESC
        """, (cutoff.isoformat(),))
        
        results = []
        for row in cursor:
            results.append({
                'guid': row[0],
                'title': row[1],
                'url': row[2],
                'pub_date': row[3],
                'content_summary': row[4],
                'created_at': row[5],
                'matched_searches': row[6].split(',') if row[6] else [],
                'batch_names': list(set(row[7].split(',') if row[7] else []))
            })
        
        conn.close()
        return results
    
    async def search_disclosures(self, search_term: str, days: int = 30) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cutoff = datetime.now() - timedelta(days=days)
        
        cursor = conn.execute("""
            SELECT d.guid, d.title, d.url, d.pub_date, d.content_summary, d.created_at,
                   GROUP_CONCAT(sq.name || ' (' || sq.search_type || ')') as matched_searches,
                   GROUP_CONCAT(sq.batch_name) as batch_names
            FROM disclosures d
            LEFT JOIN matches m ON d.id = m.disclosure_id
            LEFT JOIN search_queries sq ON m.search_query_id = sq.id
            WHERE d.created_at > ? 
            AND (d.title LIKE ? OR d.content_summary LIKE ?)
            GROUP BY d.id
            ORDER BY d.created_at DESC
        """, (cutoff.isoformat(), f'%{search_term}%', f'%{search_term}%'))
        
        results = []
        for row in cursor:
            results.append({
                'guid': row[0],
                'title': row[1],
                'url': row[2],
                'pub_date': row[3],
                'content_summary': row[4],
                'created_at': row[5],
                'matched_searches': row[6].split(',') if row[6] else [],
                'batch_names': list(set(row[7].split(',') if row[7] else []))
            })
        
        conn.close()
        return results
    
    async def get_batches(self) -> List[str]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            SELECT DISTINCT batch_name 
            FROM search_queries 
            WHERE batch_name != '' AND active = 1
            ORDER BY batch_name
        """)
        batches = [row[0] for row in cursor if row[0]]
        conn.close()
        return batches
    
    async def cleanup_old(self, days: int) -> int:
        conn = sqlite3.connect(self.db_path)
        cutoff = datetime.now() - timedelta(days=days)
        
        # Delete old matches first
        conn.execute("""
            DELETE FROM matches WHERE disclosure_id IN (
                SELECT id FROM disclosures WHERE created_at < ?
            )
        """, (cutoff.isoformat(),))
        
        # Then delete old disclosures
        cursor = conn.execute("""
            DELETE FROM disclosures WHERE created_at < ?
        """, (cutoff.isoformat(),))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted

class EmmaScanner:
    def __init__(self, database: Database):
        self.db = database
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def fetch_document_content(self, url: str) -> str:
        """Attempt to fetch and extract text from document URL"""
        try:
            if not self.session:
                return ""
            
            async with self.session.get(url, timeout=30) as response:
                if response.status != 200:
                    return ""
                
                content_type = response.headers.get('content-type', '').lower()
                
                # Handle HTML/text content
                if 'html' in content_type or 'text' in content_type:
                    content = await response.text()
                    # Simple text extraction - remove HTML tags
                    text = re.sub(r'<[^>]+>', ' ', content)
                    text = re.sub(r'\s+', ' ', text).strip()
                    return text[:2000]  # Limit content length
                
                return ""
        except Exception as e:
            logger.warning(f"Failed to fetch document content from {url}: {e}")
            return ""
    
    async def scan_rss_feed(self) -> Dict[str, int]:
        """Scan EMMA RSS feed and run all active searches"""
        try:
            # Get all active search queries
            search_queries = await self.db.get_search_queries(active_only=True)
            
            if not search_queries:
                logger.info("No active search queries found")
                return {"processed": 0, "matches": 0}
            
            # Fetch RSS feed
            feed = feedparser.parse(EMMA_RSS_URL)
            
            if feed.bozo:
                logger.warning(f"RSS feed parsing warning: {feed.bozo_exception}")
            
            total_matches = 0
            processed = 0
            
            for entry in feed.entries[:50]:  # Limit to most recent 50 entries
                title = entry.get('title', '')
                url = entry.get('link', '')
                pub_date = entry.get('published', '')
                guid = entry.get('id', url)
                
                processed += 1
                
                # Fetch document content
                content = await self.fetch_document_content(url)
                content_summary = content[:300] + "..." if len(content) > 300 else content
                
                # Combine title and content for searching
                full_text = f"{title} {content}"
                
                # Save disclosure
                disclosure_id = await self.db.save_disclosure(guid, title, url, pub_date, content_summary)
                if disclosure_id is None:
                    continue  # Skip if already processed or error
                
                # Run all search queries against this disclosure
                matched_queries = []
                for query in search_queries:
                    if query.matches(full_text):
                        matched_queries.append(query)
                        await self.db.save_match(disclosure_id, query.id)
                
                if matched_queries:
                    total_matches += 1
                    logger.info(f"Disclosure '{title[:50]}...' matched {len(matched_queries)} queries")
            
            return {"processed": processed, "matches": total_matches}
            
        except Exception as e:
            logger.error(f"Error scanning RSS feed: {e}")
            return {"processed": 0, "matches": 0}

async def send_batch_digest(matches: List[Dict], recipients: List[str]):
    """Send email digest organized by batch"""
    if not matches or not recipients or not RESEND_API_KEY:
        return
    
    # Group matches by batch
    batches = {}
    for match in matches:
        for batch_name in match.get('batch_names', ['']):
            if batch_name not in batches:
                batches[batch_name] = []
            batches[batch_name].append(match)
    
    html = f"""
    <h2>EMMA Daily Digest — {len(matches)} total matches</h2>
    <p>Found {len(matches)} new municipal bond disclosures matching your saved searches.</p>
    """
    
    for batch_name, batch_matches in batches.items():
        batch_display = batch_name if batch_name else "Uncategorized"
        html += f"""
        <h3>📁 {batch_display} ({len(batch_matches)} matches)</h3>
        <ul>
        """
        
        for match in batch_matches:
            matched_searches = ', '.join(match.get('matched_searches', []))
            html += f"""
            <li style="margin-bottom: 15px;">
                <strong><a href='{match['url']}' target='_blank'>{match['title']}</a></strong><br>
                <small><strong>Matched searches:</strong> {matched_searches}</small><br>
                <small><strong>Published:</strong> {match['pub_date']}</small>
                {f"<br><small><strong>Preview:</strong> {match.get('content_summary', '')[:200]}...</small>" if match.get('content_summary') else ""}
            </li>
            """
        
        html += '</ul>'
    
    payload = {
        'from': FROM_EMAIL,
        'to': recipients,
        'subject': f'EMMA Daily Digest: {len(matches)} matches across {len(batches)} categories',
        'html': html
    }
    
    headers = {
        'Authorization': f'Bearer {RESEND_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            'https://api.resend.com/emails',
            json=payload,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        logger.info(f"Email sent successfully to {len(recipients)} recipients")
    except Exception as e:
        logger.error(f'Failed to send email: {e}')

# Database instance
db = Database(DATABASE_PATH)

async def daily_scan():
    """Perform daily EMMA scan"""
    logger.info(f'Starting EMMA scan at {datetime.utcnow().isoformat()}')
    
    async with EmmaScanner(db) as scanner:
        results = await scanner.scan_rss_feed()
        
        logger.info(f"Processed {results['processed']} entries, found {results['matches']} matches")
        
        # Send email if we have matches
        if results['matches'] > 0 and RESEND_API_KEY and FROM_EMAIL and ALERT_EMAILS:
            recent_matches = await db.get_recent_matches(days=1)  # Just today's matches
            if recent_matches:
                await send_batch_digest(recent_matches, ALERT_EMAILS)
    
    # Cleanup old records
    deleted = await db.cleanup_old(RETENTION_DAYS)
    if deleted > 0:
        logger.info(f'Cleaned up {deleted} old records')

# FastAPI setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        daily_scan,
        'cron',
        hour=9,  # Run at 9 AM UTC daily
        minute=0
    )
    scheduler.start()
    
    # Run initial scan if configured
    if RUN_INITIAL_SCAN:
        await daily_scan()
    
    yield
    
    # Shutdown
    scheduler.shutdown()

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    recent = await db.get_recent_matches(days=7)
    search_queries = await db.get_search_queries()
    batches = await db.get_batches()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "matches": recent,
        "search_queries": search_queries,
        "batches": batches,
        "query": None
    })

@app.post("/search", response_class=HTMLResponse)
async def search(request: Request, query: str = Form(...)):
    matches = await db.search_disclosures(query, days=30)
    search_queries = await db.get_search_queries()
    batches = await db.get_batches()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "matches": matches,
        "search_queries": search_queries,
        "batches": batches,
        "query": query
    })

@app.post("/add-search")
async def add_search(
    name: str = Form(...),
    query: str = Form(...),
    search_type: str = Form(...),
    batch_name: str = Form("")
):
    await db.save_search_query(name, query, search_type, batch_name)
    return RedirectResponse(url="/", status_code=303)

@app.post("/update-search/{query_id}")
async def update_search(
    query_id: int,
    name: str = Form(...),
    query: str = Form(...),
    search_type: str = Form(...),
    active: bool = Form(False),
    batch_name: str = Form("")
):
    await db.update_search_query(query_id, name, query, search_type, active, batch_name)
    return RedirectResponse(url="/", status_code=303)

@app.post("/delete-search/{query_id}")
async def delete_search(query_id: int):
    await db.delete_search_query(query_id)
    return RedirectResponse(url="/", status_code=303)

@app.get("/healthz")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/scan")
async def manual_scan():
    """Manual trigger for scanning (useful for testing)"""
    results = await daily_scan()
    return {"status": "scan completed", "results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False
    )
