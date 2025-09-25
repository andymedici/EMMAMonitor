import os
import asyncio
import aiohttp
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
import logging
from pathlib import Path
import json
import psutil
import time

# Add PDF parsing imports
try:
    import PyPDF2
    PDF_PARSING_AVAILABLE = True
except ImportError:
    PDF_PARSING_AVAILABLE = False

from bs4 import BeautifulSoup
import io

# Configuration
EMMA_SEARCH_URL = "https://emma.msrb.org/DisclosureSearch/Disclosures"
DATABASE_PATH = "emma_monitor.db"
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "alerts@yourdomain.com")
ALERT_EMAILS = os.getenv("ALERT_EMAILS", "").split(",") if os.getenv("ALERT_EMAILS") else []
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
RUN_INITIAL_SCAN = os.getenv("RUN_INITIAL_SCAN", "false").lower() == "true"

# Processing configuration - comprehensive approach
MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "0"))  # 0 = unlimited
MAX_DOCUMENTS_PER_SCAN = int(os.getenv("MAX_DOCUMENTS_PER_SCAN", "50"))
PROCESSING_MODE = os.getenv("PROCESSING_MODE", "thorough")  # fast, balanced, thorough

# Queue-based processing configuration
PEAK_PROCESSING_TIME_LIMIT = int(os.getenv("PEAK_TIME_LIMIT", "15"))  # minutes
LARGE_FILE_THRESHOLD_KB = int(os.getenv("LARGE_FILE_THRESHOLD", "2000"))  # 2MB
COMPLEX_DOC_PAGE_THRESHOLD = int(os.getenv("COMPLEX_PAGE_THRESHOLD", "50"))  # pages
MAX_PEAK_PROCESSING_ATTEMPTS = int(os.getenv("MAX_PEAK_ATTEMPTS", "3"))

# Resource monitoring configuration
ENABLE_RESOURCE_MONITORING = os.getenv("ENABLE_RESOURCE_MONITORING", "true").lower() == "true"
RESOURCE_LOG_INTERVAL = int(os.getenv("RESOURCE_LOG_INTERVAL", "30"))  # seconds
MEMORY_WARNING_THRESHOLD = int(os.getenv("MEMORY_WARNING_MB", "400"))  # MB
CPU_WARNING_THRESHOLD = int(os.getenv("CPU_WARNING_PERCENT", "80"))  # %

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ResourceMonitor:
    """Monitor system resources and track processing performance"""
    
    def __init__(self):
        self.start_time = None
        self.start_memory = None
        self.start_cpu = None
        self.processing_stats = {
            "documents_processed": 0,
            "total_processing_time": 0,
            "peak_memory_mb": 0,
            "peak_cpu_percent": 0,
            "documents_queued": 0,
            "processing_errors": 0,
            "avg_document_time": 0
        }
    
    def start_monitoring(self, operation_name: str = "processing"):
        """Start resource monitoring for an operation"""
        self.operation_name = operation_name
        self.start_time = time.time()
        
        # Get initial system state
        process = psutil.Process()
        self.start_memory = process.memory_info().rss / 1024 / 1024  # MB
        self.start_cpu = process.cpu_percent()
        
        logger.info(f"🔄 Starting {operation_name} | Memory: {self.start_memory:.1f}MB | CPU: {self.start_cpu:.1f}%")
        
        return {
            "start_time": self.start_time,
            "start_memory_mb": self.start_memory,
            "start_cpu_percent": self.start_cpu
        }
    
    def log_progress(self, documents_processed: int = 0, additional_info: str = ""):
        """Log current resource usage and progress"""
        if not self.start_time:
            return
        
        try:
            process = psutil.Process()
            current_memory = process.memory_info().rss / 1024 / 1024  # MB
            current_cpu = process.cpu_percent()
            elapsed_time = time.time() - self.start_time
            
            # Update peak stats
            self.processing_stats["peak_memory_mb"] = max(self.processing_stats["peak_memory_mb"], current_memory)
            self.processing_stats["peak_cpu_percent"] = max(self.processing_stats["peak_cpu_percent"], current_cpu)
            self.processing_stats["documents_processed"] = documents_processed
            
            # Log current state
            logger.info(f"📊 {self.operation_name} Progress: {documents_processed} docs | "
                       f"Memory: {current_memory:.1f}MB | CPU: {current_cpu:.1f}% | "
                       f"Time: {elapsed_time:.1f}s {additional_info}")
            
            # Check for resource warnings
            if current_memory > MEMORY_WARNING_THRESHOLD:
                logger.warning(f"⚠️ High memory usage: {current_memory:.1f}MB (threshold: {MEMORY_WARNING_THRESHOLD}MB)")
            
            if current_cpu > CPU_WARNING_THRESHOLD:
                logger.warning(f"⚠️ High CPU usage: {current_cpu:.1f}% (threshold: {CPU_WARNING_THRESHOLD}%)")
                
        except Exception as e:
            logger.warning(f"Resource monitoring error: {e}")
    
    def finish_monitoring(self) -> Dict:
        """Finish monitoring and return summary statistics"""
        if not self.start_time:
            return {}
        
        try:
            end_time = time.time()
            total_time = end_time - self.start_time
            
            process = psutil.Process()
            end_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            self.processing_stats["total_processing_time"] = total_time
            
            # Calculate averages
            if self.processing_stats["documents_processed"] > 0:
                self.processing_stats["avg_document_time"] = total_time / self.processing_stats["documents_processed"]
            
            memory_delta = end_memory - self.start_memory
            
            summary = {
                "operation": self.operation_name,
                "total_time_seconds": round(total_time, 1),
                "documents_processed": self.processing_stats["documents_processed"],
                "documents_queued": self.processing_stats["documents_queued"],
                "processing_errors": self.processing_stats["processing_errors"],
                "avg_time_per_document": round(self.processing_stats["avg_document_time"], 1),
                "memory_usage": {
                    "start_mb": round(self.start_memory, 1),
                    "peak_mb": round(self.processing_stats["peak_memory_mb"], 1),
                    "end_mb": round(end_memory, 1),
                    "delta_mb": round(memory_delta, 1)
                },
                "cpu_usage": {
                    "peak_percent": round(self.processing_stats["peak_cpu_percent"], 1)
                },
                "efficiency": {
                    "docs_per_minute": round(self.processing_stats["documents_processed"] / (total_time / 60), 1) if total_time > 0 else 0,
                    "mb_per_document": round(self.processing_stats["peak_memory_mb"] / max(self.processing_stats["documents_processed"], 1), 1)
                }
            }
            
            logger.info(f"✅ {self.operation_name} Complete: {summary['total_time_seconds']}s | "
                       f"{summary['documents_processed']} docs | "
                       f"Peak: {summary['memory_usage']['peak_mb']}MB | "
                       f"Avg: {summary['avg_time_per_document']}s/doc")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error finishing resource monitoring: {e}")
            return {"error": str(e)}

class ProcessingQueue:
    """Manages document processing queue with priority levels"""
    
    def __init__(self, database):
        self.db = database
    
    async def add_document(self, url: str, title: str, metadata: Dict, priority: int = 2) -> int:
        """Add document to processing queue
        Priority: 1=immediate (peak hours), 2=background (off-peak)
        """
        conn = sqlite3.connect(self.db.db_path)
        try:
            # Calculate scheduled time based on priority
            now = datetime.utcnow()
            if priority == 1:  # Immediate processing
                scheduled_for = now
            else:  # Background processing - schedule for next off-peak window
                # Schedule for 2 AM next day if after 2 AM, or 2 AM same day if before
                if now.hour >= 2:
                    scheduled_for = now.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
                else:
                    scheduled_for = now.replace(hour=2, minute=0, second=0, microsecond=0)
            
            cursor = conn.execute("""
                INSERT INTO processing_queue 
                (document_url, document_title, document_metadata, priority, status, scheduled_for)
                VALUES (?, ?, ?, ?, 'pending', ?)
            """, (url, title, json.dumps(metadata), priority, scheduled_for.isoformat()))
            
            queue_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f"📋 Queued document (priority {priority}): {title[:50]}... → scheduled for {scheduled_for.strftime('%H:%M')}")
            return queue_id
            
        except Exception as e:
            logger.error(f"Error adding document to queue: {e}")
            return 0
        finally:
            conn.close()
    
    async def get_ready_documents(self, priority: Optional[int] = None, limit: int = 20) -> List[Dict]:
        """Get documents ready for processing"""
        conn = sqlite3.connect(self.db.db_path)
        try:
            now = datetime.utcnow().isoformat()
            
            where_clause = "WHERE status = 'pending' AND scheduled_for <= ?"
            params = [now]
            
            if priority:
                where_clause += " AND priority = ?"
                params.append(priority)
            
            cursor = conn.execute(f"""
                SELECT id, document_url, document_title, document_metadata, priority, attempts, created_at
                FROM processing_queue
                {where_clause}
                ORDER BY priority ASC, created_at ASC
                LIMIT ?
            """, params + [limit])
            
            documents = []
            for row in cursor:
                documents.append({
                    "queue_id": row[0],
                    "url": row[1],
                    "title": row[2],
                    "metadata": json.loads(row[3]) if row[3] else {},
                    "priority": row[4],
                    "attempts": row[5],
                    "created_at": row[6]
                })
            
            return documents
            
        except Exception as e:
            logger.error(f"Error getting ready documents: {e}")
            return []
        finally:
            conn.close()
    
    async def mark_processing(self, queue_id: int):
        """Mark document as currently being processed"""
        conn = sqlite3.connect(self.db.db_path)
        try:
            conn.execute("""
                UPDATE processing_queue 
                SET status = 'processing', attempts = attempts + 1, started_at = ?
                WHERE id = ?
            """, (datetime.utcnow().isoformat(), queue_id))
            conn.commit()
        except Exception as e:
            logger.error(f"Error marking document as processing: {e}")
        finally:
            conn.close()
    
    async def mark_completed(self, queue_id: int):
        """Mark document as successfully processed"""
        conn = sqlite3.connect(self.db.db_path)
        try:
            conn.execute("""
                UPDATE processing_queue 
                SET status = 'completed', completed_at = ?
                WHERE id = ?
            """, (datetime.utcnow().isoformat(), queue_id))
            conn.commit()
        except Exception as e:
            logger.error(f"Error marking document as completed: {e}")
        finally:
            conn.close()
    
    async def mark_failed(self, queue_id: int, error_message: str = ""):
        """Mark document as failed and potentially reschedule"""
        conn = sqlite3.connect(self.db.db_path)
        try:
            cursor = conn.execute("SELECT attempts FROM processing_queue WHERE id = ?", (queue_id,))
            row = cursor.fetchone()
            
            if row and row[0] < 3:  # Retry up to 3 times
                # Reschedule for later (add exponential backoff)
                delay_hours = 2 ** row[0]  # 2, 4, 8 hours
                retry_time = datetime.utcnow() + timedelta(hours=delay_hours)
                
                conn.execute("""
                    UPDATE processing_queue 
                    SET status = 'pending', scheduled_for = ?, error_message = ?
                    WHERE id = ?
                """, (retry_time.isoformat(), error_message, queue_id))
                
                logger.info(f"🔄 Rescheduling failed document (attempt {row[0] + 1}) for {retry_time.strftime('%H:%M')}")
            else:
                # Give up after 3 attempts
                conn.execute("""
                    UPDATE processing_queue 
                    SET status = 'failed', error_message = ?
                    WHERE id = ?
                """, (error_message, queue_id))
                
                logger.warning(f"❌ Document permanently failed after 3 attempts: {error_message}")
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error marking document as failed: {e}")
        finally:
            conn.close()
    
    async def get_queue_stats(self) -> Dict:
        """Get current queue statistics"""
        conn = sqlite3.connect(self.db.db_path)
        try:
            cursor = conn.execute("""
                SELECT 
                    status,
                    priority,
                    COUNT(*) as count
                FROM processing_queue
                WHERE created_at > date('now', '-7 days')
                GROUP BY status, priority
            """)
            
            stats = {
                "pending_immediate": 0,
                "pending_background": 0,
                "processing": 0,
                "completed_today": 0,
                "failed": 0,
                "total_queued": 0
            }
            
            for row in cursor:
                status, priority, count = row
                if status == 'pending':
                    if priority == 1:
                        stats["pending_immediate"] += count
                    else:
                        stats["pending_background"] += count
                elif status == 'processing':
                    stats["processing"] += count
                elif status == 'completed':
                    stats["completed_today"] += count
                elif status == 'failed':
                    stats["failed"] += count
                
                stats["total_queued"] += count
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting queue stats: {e}")
            return {}
        finally:
            conn.close()

class SearchQuery:
    def __init__(self, query_id: int, name: str, query: str, search_type: str, active: bool = True, batch_name: str = ""):
        self.id = query_id
        self.name = name
        self.query = query
        self.search_type = search_type  # 'exact', 'all', 'any'
        self.active = active
        self.batch_name = batch_name
    
    def matches(self, text: str, page_info: List[Dict] = None) -> Dict:
        """Check if text matches this query and return detailed match locations"""
        if not text or not self.query:
            return {"matched": False}
        
        text_lower = text.lower()
        matched_terms = []
        match_locations = []
        
        # Split text into sentences for precise location tracking
        sentences = re.split(r'[.!?]+', text)
        
        if self.search_type == 'exact':
            query_lower = self.query.lower()
            if query_lower in text_lower:
                matched_terms.append(self.query)
                # Find all occurrences
                start = 0
                while True:
                    pos = text_lower.find(query_lower, start)
                    if pos == -1:
                        break
                    
                    # Find which sentence contains this match
                    sentence_info = self._find_sentence_and_page(pos, text, sentences, page_info)
                    
                    match_locations.append({
                        "term": self.query,
                        "sentence": sentence_info["sentence"],
                        "page_number": sentence_info["page_number"],
                        "context": sentence_info["context"],
                        "position_in_text": pos
                    })
                    start = pos + len(query_lower)
                    
                    # Limit to top 5 matches to avoid overwhelming results
                    if len(match_locations) >= 5:
                        break
        
        elif self.search_type == 'all':  # AND logic
            terms = [t.strip() for t in self.query.split(',') if t.strip()]
            terms_found = []
            
            for term in terms:
                term_lower = term.lower()
                if term_lower in text_lower:
                    terms_found.append(term)
                    # Find first occurrence of this term
                    pos = text_lower.find(term_lower)
                    sentence_info = self._find_sentence_and_page(pos, text, sentences, page_info)
                    
                    match_locations.append({
                        "term": term,
                        "sentence": sentence_info["sentence"],
                        "page_number": sentence_info["page_number"],
                        "context": sentence_info["context"],
                        "position_in_text": pos
                    })
            
            if len(terms_found) == len(terms):  # All terms found
                matched_terms = terms_found
            else:
                return {"matched": False}
        
        elif self.search_type == 'any':  # OR logic  
            terms = [t.strip() for t in self.query.split(',') if t.strip()]
            for term in terms:
                term_lower = term.lower()
                if term_lower in text_lower:
                    matched_terms.append(term)
                    # Find all occurrences of this term (up to 3 per term)
                    start = 0
                    term_matches = 0
                    while term_matches < 3:
                        pos = text_lower.find(term_lower, start)
                        if pos == -1:
                            break
                            
                        sentence_info = self._find_sentence_and_page(pos, text, sentences, page_info)
                        
                        match_locations.append({
                            "term": term,
                            "sentence": sentence_info["sentence"],
                            "page_number": sentence_info["page_number"],
                            "context": sentence_info["context"],
                            "position_in_text": pos
                        })
                        start = pos + len(term_lower)
                        term_matches += 1
        
        if matched_terms:
            # Sort by relevance (earlier in document = higher relevance)
            match_locations.sort(key=lambda x: x["position_in_text"])
            
            return {
                "matched": True,
                "matched_terms": list(set(matched_terms)),  # Remove duplicates
                "match_locations": match_locations,
                "total_matches": len(match_locations),
                "pages_with_matches": list(set([m["page_number"] for m in match_locations if m["page_number"]]))
            }
        
        return {"matched": False}
    
    def _find_sentence_and_page(self, position: int, full_text: str, sentences: List[str], page_info: List[Dict] = None) -> Dict:
        """Find which sentence and page contains a given character position"""
        
        # Find the sentence containing this position
        current_pos = 0
        sentence_text = ""
        sentence_number = 0
        
        for i, sentence in enumerate(sentences):
            sentence_len = len(sentence) + 1  # +1 for the delimiter
            if current_pos <= position < current_pos + sentence_len:
                sentence_text = sentence.strip()
                sentence_number = i + 1
                break
            current_pos += sentence_len
        
        # Find which page contains this position
        page_number = None
        if page_info:
            for page in page_info:
                if page["start_pos"] <= position < page["end_pos"]:
                    page_number = page["page_num"]
                    break
        
        # Create context (sentence + surrounding sentences)
        context_sentences = []
        start_idx = max(0, sentence_number - 1)
        end_idx = min(len(sentences), sentence_number + 2)
        
        for i in range(start_idx, end_idx):
            if i < len(sentences):
                context_sentences.append(sentences[i].strip())
        
        context = "... ".join(context_sentences)
        
        return {
            "sentence": sentence_text,
            "sentence_number": sentence_number,
            "page_number": page_number,
            "context": context[:300] + "..." if len(context) > 300 else context
        }

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        
        # Lightweight disclosures table - no full text content stored!
        conn.execute("""
            CREATE TABLE IF NOT EXISTS disclosures (
                id INTEGER PRIMARY KEY,
                guid TEXT UNIQUE,
                title TEXT,
                url TEXT,
                emma_direct_url TEXT,
                pub_date TEXT,
                issuer_name TEXT,
                document_type TEXT,
                file_size_kb INTEGER,
                pages_processed INTEGER,
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
        
        # Matches table with rich metadata but no full text
        conn.execute("""
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY,
                disclosure_id INTEGER,
                search_query_id INTEGER,
                matched_terms TEXT,  -- JSON array of matched terms
                match_locations TEXT,  -- JSON array of match contexts  
                total_matches INTEGER,
                relevance_score REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (disclosure_id) REFERENCES disclosures (id),
                FOREIGN KEY (search_query_id) REFERENCES search_queries (id),
                UNIQUE(disclosure_id, search_query_id)
            )
        """)
        
        # Processing queue table for off-peak processing
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processing_queue (
                id INTEGER PRIMARY KEY,
                document_url TEXT NOT NULL,
                document_title TEXT,
                document_metadata TEXT,  -- JSON
                priority INTEGER DEFAULT 2,  -- 1=immediate, 2=background
                status TEXT DEFAULT 'pending',  -- pending, processing, completed, failed
                attempts INTEGER DEFAULT 0,
                scheduled_for TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT
            )
        """)
        
        # Resource monitoring table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resource_logs (
                id INTEGER PRIMARY KEY,
                operation_type TEXT,  -- daily_scan, background_processing, etc.
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                duration_seconds REAL,
                documents_processed INTEGER,
                documents_queued INTEGER,
                peak_memory_mb REAL,
                peak_cpu_percent REAL,
                avg_time_per_document REAL,
                processing_errors INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    async def save_resource_log(self, resource_summary: Dict):
        """Save resource monitoring data"""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT INTO resource_logs 
                (operation_type, start_time, end_time, duration_seconds, documents_processed,
                 documents_queued, peak_memory_mb, peak_cpu_percent, avg_time_per_document, processing_errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                resource_summary.get("operation", "unknown"),
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
                resource_summary.get("total_time_seconds", 0),
                resource_summary.get("documents_processed", 0),
                resource_summary.get("documents_queued", 0),
                resource_summary.get("memory_usage", {}).get("peak_mb", 0),
                resource_summary.get("cpu_usage", {}).get("peak_percent", 0),
                resource_summary.get("avg_time_per_document", 0),
                resource_summary.get("processing_errors", 0)
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"Error saving resource log: {e}")
        finally:
            conn.close()
    
    async def get_resource_history(self, days: int = 7) -> List[Dict]:
        """Get resource usage history"""
        conn = sqlite3.connect(self.db_path)
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            cursor = conn.execute("""
                SELECT operation_type, duration_seconds, documents_processed, 
                       peak_memory_mb, peak_cpu_percent, avg_time_per_document, created_at
                FROM resource_logs
                WHERE created_at > ?
                ORDER BY created_at DESC
            """, (cutoff.isoformat(),))
            
            history = []
            for row in cursor:
                history.append({
                    "operation": row[0],
                    "duration": row[1],
                    "documents": row[2],
                    "peak_memory": row[3],
                    "peak_cpu": row[4],
                    "avg_time": row[5],
                    "timestamp": row[6]
                })
            
            return history
        except Exception as e:
            logger.error(f"Error getting resource history: {e}")
            return []
        finally:
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
    
    async def save_disclosure(self, guid: str, title: str, url: str, emma_direct_url: str, 
                             pub_date: str, issuer_name: str = "", document_type: str = "", 
                             file_size_kb: int = 0, pages_processed: int = 0) -> Optional[int]:
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.execute("""
                INSERT OR IGNORE INTO disclosures 
                (guid, title, url, emma_direct_url, pub_date, issuer_name, document_type, file_size_kb, pages_processed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (guid, title, url, emma_direct_url, pub_date, issuer_name, document_type, file_size_kb, pages_processed))
            
            if cursor.rowcount == 0:  # Already exists
                cursor = conn.execute("SELECT id FROM disclosures WHERE guid = ?", (guid,))
                row = cursor.fetchone()
                disclosure_id = row[0] if row else None
            else:
                disclosure_id = cursor.lastrowid
            
            conn.commit()
            conn.close()
            return disclosure_id
        except Exception as e:
            conn.close()
            logger.error(f"Error saving disclosure: {e}")
            return None
    
    async def save_match(self, disclosure_id: int, search_query_id: int, match_details: Dict):
        """Save match with detailed location information"""
        conn = sqlite3.connect(self.db_path)
        try:
            # Calculate relevance score based on number of matches and position
            relevance_score = 0.0
            if match_details.get("match_locations"):
                # Higher score for more matches and earlier positions
                relevance_score = min(100.0, 
                    len(match_details["match_locations"]) * 10 + 
                    (1000 - min(1000, match_details["match_locations"][0]["position_in_text"])) / 100
                )
            
            conn.execute("""
                INSERT OR REPLACE INTO matches 
                (disclosure_id, search_query_id, matched_terms, match_locations, total_matches, relevance_score)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                disclosure_id, 
                search_query_id, 
                json.dumps(match_details.get("matched_terms", [])),
                json.dumps(match_details.get("match_locations", [])),
                match_details.get("total_matches", 0),
                relevance_score
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"Error saving match: {e}")
        finally:
            conn.close()
    
    async def get_recent_matches(self, days: int = 7) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cutoff = datetime.now() - timedelta(days=days)
        
        cursor = conn.execute("""
            SELECT d.guid, d.title, d.url, d.emma_direct_url, d.pub_date, d.issuer_name, 
                   d.document_type, d.file_size_kb, d.pages_processed, d.created_at,
                   GROUP_CONCAT(sq.name) as search_names,
                   GROUP_CONCAT(sq.batch_name) as batch_names,
                   GROUP_CONCAT(m.matched_terms) as all_matched_terms,
                   GROUP_CONCAT(m.match_locations) as all_match_locations,
                   AVG(m.relevance_score) as avg_relevance_score,
                   GROUP_CONCAT(m.total_matches) as match_counts
            FROM disclosures d
            JOIN matches m ON d.id = m.disclosure_id
            JOIN search_queries sq ON m.search_query_id = sq.id
            WHERE d.created_at > ?
            GROUP BY d.id
            ORDER BY avg_relevance_score DESC, d.created_at DESC
        """, (cutoff.isoformat(),))
        
        results = []
        for row in cursor:
            # Parse match locations from all matched queries
            all_locations = []
            if row[13]:  # all_match_locations
                location_strings = row[13].split(',')
                for loc_str in location_strings:
                    try:
                        locations = json.loads(loc_str)
                        if isinstance(locations, list):
                            all_locations.extend(locations)
                    except:
                        continue
            
            # Parse matched terms
            all_terms = []
            if row[12]:  # all_matched_terms
                term_strings = row[12].split(',')
                for term_str in term_strings:
                    try:
                        terms = json.loads(term_str)
                        if isinstance(terms, list):
                            all_terms.extend(terms)
                    except:
                        continue
            
            results.append({
                'guid': row[0],
                'title': row[1],
                'url': row[2],
                'emma_direct_url': row[3],
                'pub_date': row[4],
                'issuer_name': row[5],
                'document_type': row[6],
                'file_size_kb': row[7],
                'pages_processed': row[8],
                'created_at': row[9],
                'matched_searches': row[10].split(',') if row[10] else [],
                'batch_names': list(set(row[11].split(',') if row[11] else [])),
                'matched_terms': list(set(all_terms)),
                'match_locations': all_locations[:10],  # Limit to top 10 locations for display
                'relevance_score': round(row[14] or 0.0, 1),
                'pages_with_matches': list(set([loc.get("page_number") for loc in all_locations if loc.get("page_number")]))
            })
        
        conn.close()
        return results
    
    async def search_disclosures(self, search_term: str, days: int = 30) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cutoff = datetime.now() - timedelta(days=days)
        
        cursor = conn.execute("""
            SELECT d.guid, d.title, d.url, d.emma_direct_url, d.pub_date, d.issuer_name,
                   d.document_type, d.file_size_kb, d.pages_processed, d.created_at,
                   GROUP_CONCAT(sq.name) as search_names,
                   GROUP_CONCAT(sq.batch_name) as batch_names,
                   GROUP_CONCAT(m.matched_terms) as all_matched_terms,
                   GROUP_CONCAT(m.match_locations) as all_match_locations,
                   AVG(m.relevance_score) as avg_relevance_score
            FROM disclosures d
            LEFT JOIN matches m ON d.id = m.disclosure_id
            LEFT JOIN search_queries sq ON m.search_query_id = sq.id
            WHERE d.created_at > ? 
            AND (d.title LIKE ? OR d.issuer_name LIKE ?)
            GROUP BY d.id
            ORDER BY avg_relevance_score DESC, d.created_at DESC
        """, (cutoff.isoformat(), f'%{search_term}%', f'%{search_term}%'))
        
        results = []
        for row in cursor:
            # Parse match data similar to get_recent_matches
            all_locations = []
            if row[13]:
                location_strings = row[13].split(',')
                for loc_str in location_strings:
                    try:
                        locations = json.loads(loc_str)
                        if isinstance(locations, list):
                            all_locations.extend(locations)
                    except:
                        continue
            
            all_terms = []
            if row[12]:
                term_strings = row[12].split(',')
                for term_str in term_strings:
                    try:
                        terms = json.loads(term_str)
                        if isinstance(terms, list):
                            all_terms.extend(terms)
                    except:
                        continue
            
            results.append({
                'guid': row[0],
                'title': row[1],
                'url': row[2],
                'emma_direct_url': row[3],
                'pub_date': row[4],
                'issuer_name': row[5],
                'document_type': row[6],
                'file_size_kb': row[7],
                'pages_processed': row[8],
                'created_at': row[9],
                'matched_searches': row[10].split(',') if row[10] else [],
                'batch_names': list(set(row[11].split(',') if row[11] else [])),
                'matched_terms': list(set(all_terms)),
                'match_locations': all_locations[:10],
                'relevance_score': round(row[14] or 0.0, 1) if row[14] else 0,
                'pages_with_matches': list(set([loc.get("page_number") for loc in all_locations if loc.get("page_number")]))
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
        
        # Delete old disclosures
        cursor = conn.execute("""
            DELETE FROM disclosures WHERE created_at < ?
        """, (cutoff.isoformat(),))
        
        # Cleanup old queue items
        conn.execute("""
            DELETE FROM processing_queue 
            WHERE status = 'completed' AND completed_at < ?
        """, (cutoff.isoformat(),))
        
        # Cleanup old resource logs (keep 30 days)
        resource_cutoff = datetime.now() - timedelta(days=30)
        conn.execute("""
            DELETE FROM resource_logs WHERE created_at < ?
        """, (resource_cutoff.isoformat(),))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted

class EmmaScanner:
    def __init__(self, database: Database):
        self.db = database
        self.session = None
        self.processing_queue = ProcessingQueue(database)
        self.resource_monitor = ResourceMonitor() if ENABLE_RESOURCE_MONITORING else None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def extract_pdf_text(self, pdf_content: bytes) -> Dict:
        """Extract text from PDF content with page tracking for precise match locations"""
        if not PDF_PARSING_AVAILABLE:
            return {"text": "", "page_info": []}
        
        try:
            pdf_file = io.BytesIO(pdf_content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            total_pages = len(pdf_reader.pages)
            
            # Determine pages to process
            if MAX_PDF_PAGES == 0:  # Process all pages
                max_pages = total_pages
                logger.debug(f"Processing all {total_pages} pages of PDF")
            else:
                max_pages = min(MAX_PDF_PAGES, total_pages)
                logger.debug(f"Processing {max_pages} of {total_pages} pages")
            
            # Processing mode determines which pages to extract
            if PROCESSING_MODE == "fast":
                page_range = list(range(min(5, max_pages)))
            elif PROCESSING_MODE == "thorough":
                page_range = list(range(max_pages))
                if total_pages > max_pages and MAX_PDF_PAGES > 0:
                    # Add strategic pages from rest of document
                    mid_page = total_pages // 2
                    end_pages = max(1, min(3, total_pages - max_pages))
                    page_range.extend([mid_page])
                    page_range.extend(list(range(total_pages - end_pages, total_pages)))
                    page_range = list(set(page_range))
                    page_range.sort()
            else:  # balanced
                page_range = list(range(max_pages))
            
            full_text = ""
            page_info = []
            pages_processed = 0
            
            for page_num in page_range:
                try:
                    if page_num < total_pages:
                        page = pdf_reader.pages[page_num]
                        page_text = page.extract_text()
                        
                        if page_text.strip():  # Only add non-empty pages
                            page_start_pos = len(full_text)
                            full_text += f"\n--- Page {page_num + 1} ---\n{page_text}\n"
                            page_end_pos = len(full_text)
                            
                            page_info.append({
                                "page_num": page_num + 1,
                                "start_pos": page_start_pos,
                                "end_pos": page_end_pos,
                                "text_length": len(page_text),
                                "page_text_preview": page_text[:200] + "..." if len(page_text) > 200 else page_text
                            })
                            
                            pages_processed += 1
                            
                except Exception as e:
                    logger.warning(f"Error extracting page {page_num + 1}: {e}")
                    continue
            
            # Clean up text
            full_text = re.sub(r'\s+', ' ', full_text).strip()
            
            logger.debug(f"Extracted {len(full_text)} characters from {pages_processed} pages")
            
            return {
                "text": full_text,
                "page_info": page_info,
                "pages_processed": pages_processed,
                "total_pages": total_pages
            }
            
        except Exception as e:
            logger.warning(f"Failed to extract PDF text: {e}")
            return {"text": "", "page_info": []}

    async def fetch_document_content(self, url: str) -> Dict:
        """Fetch and extract content from document URL with location tracking"""
        try:
            if not self.session:
                return {"text": "", "page_info": [], "file_size_kb": 0}
            
            async with self.session.get(url, timeout=60) as response:
                if response.status != 200:
                    return {"text": "", "page_info": [], "file_size_kb": 0}
                
                content_type = response.headers.get('content-type', '').lower()
                content = await response.read()
                file_size_kb = len(content) // 1024
                
                # Handle PDF content
                if 'pdf' in content_type:
                    pdf_result = await self.extract_pdf_text(content)
                    pdf_result["file_size_kb"] = file_size_kb
                    return pdf_result
                
                # Handle HTML/text content
                elif 'html' in content_type or 'text' in content_type:
                    text_content = content.decode('utf-8', errors='ignore')
                    clean_text = re.sub(r'<[^>]+>', ' ', text_content)
                    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                    
                    return {
                        "text": clean_text[:10000],  # Reasonable limit for HTML
                        "page_info": [{"page_num": 1, "start_pos": 0, "end_pos": len(clean_text)}],
                        "file_size_kb": file_size_kb
                    }
                
                return {"text": "", "page_info": [], "file_size_kb": file_size_kb}
                
        except Exception as e:
            logger.warning(f"Failed to fetch document content from {url}: {e}")
            return {"text": "", "page_info": [], "file_size_kb": 0}
    
    def should_process_immediately(self, title: str, estimated_size_kb: int, total_pages: int) -> bool:
        """Determine if document should be processed immediately or queued"""
        # Process immediately if:
        # 1. Small file and reasonable page count
        # 2. Or has priority keywords that suggest urgency
        
        if estimated_size_kb > LARGE_FILE_THRESHOLD_KB or total_pages > COMPLEX_DOC_PAGE_THRESHOLD:
            return False
        
        # Check for urgent keywords in title
        urgent_keywords = [
            "bankruptcy", "default", "emergency", "crisis", "investigation", "fraud",
            "downgrade", "negative", "rating action", "material event", "notice"
        ]
        
        title_lower = title.lower()
        return any(keyword in title_lower for keyword in urgent_keywords)
    
    async def scrape_emma_search(self) -> List[Dict]:
        """Scrape EMMA search results directly"""
        try:
            search_params = {
                'st': '1',  # Search type: continuing disclosures
                'sortdir': 'desc',  # Sort by newest first
                'perpage': '50'  # Limit results
            }
            
            async with self.session.get(EMMA_SEARCH_URL, params=search_params, timeout=30) as response:
                if response.status != 200:
                    logger.error(f"Failed to fetch EMMA search results: HTTP {response.status}")
                    return []
                
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')
                
                entries = []
                # Look for disclosure entries in the search results
                disclosure_rows = soup.find_all('tr', class_=['odd', 'even']) or soup.find_all('div', class_='disclosure-item')
                
                for row in disclosure_rows[:50]:  # Limit to 50 entries
                    try:
                        title_elem = row.find('a') or row.find('td', class_='title')
                        if not title_elem:
                            continue
                            
                        title = title_elem.get_text(strip=True) if hasattr(title_elem, 'get_text') else str(title_elem)
                        link = title_elem.get('href', '') if hasattr(title_elem, 'get') else ""
                        
                        if link and not link.startswith('http'):
                            link = f"https://emma.msrb.org{link}"
                        
                        # Extract date
                        date_elem = row.find('td', class_='date') or row.find('span', class_='date')
                        published = date_elem.get_text(strip=True) if date_elem else ""
                        
                        # Generate a unique ID
                        item_id = f"emma_{hash(f'{title}{link}{published}')}"
                        
                        entries.append({
                            'title': title,
                            'link': link,
                            'published': published,
                            'id': item_id
                        })
                        
                    except Exception as e:
                        logger.warning(f"Error parsing disclosure row: {e}")
                        continue
                
                logger.info(f"Scraped {len(entries)} disclosure entries from EMMA")
                return entries
                
        except Exception as e:
            logger.error(f"Error scraping EMMA search results: {e}")
            return []

    async def scan_with_priority_processing(self) -> Dict[str, int]:
        """Scan EMMA with priority-based processing and queuing"""
        if self.resource_monitor:
            self.resource_monitor.start_monitoring("priority_scan")
        
        try:
            # Get all active search queries
            search_queries = await self.db.get_search_queries(active_only=True)
            
            if not search_queries:
                logger.info("No active search queries found")
                return {"processed": 0, "matches": 0, "queued": 0}
            
            # Scrape EMMA for new documents
            logger.info("Fetching documents from EMMA...")
            entries = await self.scrape_emma_search()
            
            if not entries:
                logger.warning("No entries found from EMMA")
                return {"processed": 0, "matches": 0, "queued": 0}
            
            total_matches = 0
            processed_immediately = 0
            queued_for_later = 0
            total_text_extracted = 0
            processing_start_time = time.time()
            
            logger.info(f"Assessing {len(entries)} documents for priority processing...")
            
            for i, entry in enumerate(entries[:MAX_DOCUMENTS_PER_SCAN]):
                title = entry['title']
                url = entry['link']
                pub_date = entry['published']
                guid = entry['id']
                
                # Check if we should process immediately or queue
                should_process_now = self.should_process_immediately(title, 0, 0)  # Initial assessment
                
                # Check time budget - stop immediate processing if taking too long
                elapsed_minutes = (time.time() - processing_start_time) / 60
                if elapsed_minutes > PEAK_PROCESSING_TIME_LIMIT:
                    logger.info(f"⏰ Peak processing time limit reached ({PEAK_PROCESSING_TIME_LIMIT}m), queuing remaining documents")
                    should_process_now = False
                
                if should_process_now:
                    # Process immediately during peak hours
                    try:
                        logger.info(f"🔄 Immediate processing {processed_immediately + 1}: {title[:50]}...")
                        
                        if self.resource_monitor:
                            self.resource_monitor.log_progress(processed_immediately + 1, f"| Immediate processing")
                        
                        content_result = await self.fetch_document_content(url)
                        
                        # Re-assess based on actual file size and complexity
                        file_size_kb = content_result.get("file_size_kb", 0)
                        pages_processed = content_result.get("pages_processed", 0)
                        
                        # If document turns out to be complex, queue it instead
                        if file_size_kb > LARGE_FILE_THRESHOLD_KB or pages_processed > COMPLEX_DOC_PAGE_THRESHOLD:
                            logger.info(f"📋 Document larger than expected ({file_size_kb}KB, {pages_processed}p), queuing for background processing")
                            await self.processing_queue.add_document(url, title, {
                                "pub_date": pub_date,
                                "guid": guid,
                                "file_size_kb": file_size_kb,
                                "estimated_pages": pages_processed
                            }, priority=2)  # Background priority
                            queued_for_later += 1
                            continue
                        
                        full_text = content_result["text"]
                        page_info = content_result["page_info"]
                        total_text_extracted += len(full_text)
                        
                        # Process if we got meaningful content
                        if len(full_text) > 100:
                            # Save disclosure and run searches
                            emma_direct_url = url
                            issuer_name = self._extract_issuer_name(title, full_text)
                            document_type = self._extract_document_type(title, full_text)
                            
                            searchable_text = f"{title} {full_text}"
                            
                            disclosure_id = await self.db.save_disclosure(
                                guid, title, url, emma_direct_url, pub_date, 
                                issuer_name, document_type, file_size_kb, pages_processed
                            )
                            
                            if disclosure_id:
                                # Run search queries
                                matched_queries = []
                                for query in search_queries:
                                    match_result = query.matches(searchable_text, page_info)
                                    if match_result["matched"]:
                                        matched_queries.append(query)
                                        await self.db.save_match(disclosure_id, query.id, match_result)
                                
                                if matched_queries:
                                    total_matches += 1
                                    query_names = [q.name for q in matched_queries]
                                    pages_mentioned = set()
                                    for query in matched_queries:
                                        match_result = query.matches(searchable_text, page_info)
                                        pages_mentioned.update(match_result.get("pages_with_matches", []))
                                    
                                    logger.info(f"✅ IMMEDIATE MATCH: '{title[:50]}...' → {', '.join(query_names)}")
                                    if pages_mentioned:
                                        logger.info(f"   📄 Pages: {sorted(pages_mentioned)} | Size: {file_size_kb}KB")
                        
                        processed_immediately += 1
                        
                    except Exception as e:
                        logger.error(f"Error in immediate processing: {e}")
                        # Queue for retry during background processing
                        await self.processing_queue.add_document(url, title, {
                            "pub_date": pub_date,
                            "guid": guid,
                            "error": str(e)
                        }, priority=2)
                        queued_for_later += 1
                
                else:
                    # Queue for background processing
                    await self.processing_queue.add_document(url, title, {
                        "pub_date": pub_date,
                        "guid": guid
                    }, priority=2)  # Background priority
                    queued_for_later += 1
                    logger.debug(f"📋 Queued for background: {title[:50]}...")
            
            # Resource monitoring
            if self.resource_monitor:
                self.resource_monitor.processing_stats["documents_queued"] = queued_for_later
                summary = self.resource_monitor.finish_monitoring()
                await self.db.save_resource_log(summary)
            
            logger.info(f"Priority scan complete:")
            logger.info(f"  ⚡ Processed immediately: {processed_immediately}")
            logger.info(f"  📋 Queued for background: {queued_for_later}")
            logger.info(f"  🎯 Immediate matches found: {total_matches}")
            logger.info(f"  📊 Text extracted: {total_text_extracted:,} characters")
            
            return {
                "processed": processed_immediately,
                "matches": total_matches,
                "queued": queued_for_later,
                "total_text_extracted": total_text_extracted,
                "processing_time_minutes": round((time.time() - processing_start_time) / 60, 1)
            }
            
        except Exception as e:
            logger.error(f"Error in priority processing: {e}")
            if self.resource_monitor:
                self.resource_monitor.processing_stats["processing_errors"] += 1
                summary = self.resource_monitor.finish_monitoring()
                await self.db.save_resource_log(summary)
            
            return {"processed": 0, "matches": 0, "queued": 0}

    async def process_background_queue(self, max_items: int = 20) -> Dict[str, int]:
        """Process queued documents during off-peak hours"""
        if self.resource_monitor:
            self.resource_monitor.start_monitoring("background_processing")
        
        try:
            # Get documents ready for background processing
            ready_docs = await self.processing_queue.get_ready_documents(priority=2, limit=max_items)
            
            if not ready_docs:
                logger.info("No documents in background queue")
                return {"processed": 0, "matches": 0, "errors": 0}
            
            logger.info(f"🌙 Background processing: {len(ready_docs)} documents")
            
            # Get active search queries
            search_queries = await self.db.get_search_queries(active_only=True)
            if not search_queries:
                logger.info("No active search queries for background processing")
                return {"processed": 0, "matches": 0, "errors": 0}
            
            processed = 0
            matches = 0
            errors = 0
            total_text_extracted = 0
            
            for doc in ready_docs:
                try:
                    # Mark as processing
                    await self.processing_queue.mark_processing(doc["queue_id"])
                    
                    logger.info(f"🔄 Background processing: {doc['title'][:50]}...")
                    
                    # Process the document thoroughly
                    content_result = await self.fetch_document_content(doc["url"])
                    
                    full_text = content_result["text"]
                    page_info = content_result["page_info"]
                    file_size_kb = content_result.get("file_size_kb", 0)
                    pages_processed = content_result.get("pages_processed", 0)
                    total_text_extracted += len(full_text)
                    
                    if len(full_text) > 100:
                        # Save disclosure
                        metadata = doc.get("metadata", {})
                        emma_direct_url = doc["url"]
                        issuer_name = self._extract_issuer_name(doc["title"], full_text)
                        document_type = self._extract_document_type(doc["title"], full_text)
                        
                        searchable_text = f"{doc['title']} {full_text}"
                        
                        disclosure_id = await self.db.save_disclosure(
                            metadata.get("guid", f"bg_{doc['queue_id']}"), 
                            doc["title"], 
                            doc["url"], 
                            emma_direct_url, 
                            metadata.get("pub_date", ""),
                            issuer_name, 
                            document_type, 
                            file_size_kb, 
                            pages_processed
                        )
                        
                        if disclosure_id:
                            # Run search queries
                            matched_queries = []
                            for query in search_queries:
                                match_result = query.matches(searchable_text, page_info)
                                if match_result["matched"]:
                                    matched_queries.append(query)
                                    await self.db.save_match(disclosure_id, query.id, match_result)
                            
                            if matched_queries:
                                matches += 1
                                query_names = [q.name for q in matched_queries]
                                logger.info(f"✅ BACKGROUND MATCH: '{doc['title'][:50]}...' → {', '.join(query_names)}")
                    
                    # Mark as completed
                    await self.processing_queue.mark_completed(doc["queue_id"])
                    processed += 1
                    
                    if self.resource_monitor:
                        self.resource_monitor.log_progress(processed, f"| Background queue")
                    
                except Exception as e:
                    logger.error(f"Error in background processing: {e}")
                    await self.processing_queue.mark_failed(doc["queue_id"], str(e))
                    errors += 1
            
            # Resource monitoring
            if self.resource_monitor:
                self.resource_monitor.processing_stats["processing_errors"] = errors
                summary = self.resource_monitor.finish_monitoring()
                await self.db.save_resource_log(summary)
            
            logger.info(f"Background processing complete: {processed} docs, {matches} matches, {errors} errors")
            
            return {
                "processed": processed,
                "matches": matches,
                "errors": errors,
                "total_text_extracted": total_text_extracted
            }
            
        except Exception as e:
            logger.error(f"Error in background processing: {e}")
            return {"processed": 0, "matches": 0, "errors": 1}
    
    def _extract_issuer_name(self, title: str, content: str) -> str:
        """Extract issuer name from title or content"""
        if "city of" in title.lower():
            match = re.search(r'city of ([^,\-\n]+)', title.lower())
            if match:
                return f"City of {match.group(1).title()}"
        elif "county" in title.lower():
            match = re.search(r'([^,\-\n]+) county', title.lower())
            if match:
                return f"{match.group(1).title()} County"
        elif "state of" in title.lower():
            match = re.search(r'state of ([^,\-\n]+)', title.lower())
            if match:
                return f"State of {match.group(1).title()}"
        
        # Extract first meaningful part of title as fallback
        parts = title.split(' - ')
        if len(parts) > 1:
            return parts[0].strip()
        
        return ""
    
    def _extract_document_type(self, title: str, content: str) -> str:
        """Extract document type from title or content"""
        title_lower = title.lower()
        
        if "annual report" in title_lower or "cafr" in title_lower:
            return "Annual Financial Report"
        elif "budget" in title_lower:
            return "Budget Document"
        elif "audit" in title_lower:
            return "Audit Report"
        elif "rating" in title_lower:
            return "Rating Report"
        elif "official statement" in title_lower:
            return "Official Statement"
        elif "event notice" in title_lower or "material event" in title_lower:
            return "Material Event Notice"
        elif "continuing disclosure" in title_lower:
            return "Continuing Disclosure"
        
        return "Other"

async def send_batch_digest(matches: List[Dict], recipients: List[str]):
    """Send email digest organized by batch with detailed match information"""
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
    <h2>🏛️ EMMA Daily Digest — {len(matches)} total matches</h2>
    <p>Found {len(matches)} new municipal bond disclosures with precise keyword matches.</p>
    """
    
    for batch_name, batch_matches in batches.items():
        batch_display = batch_name if batch_name else "Uncategorized"
        html += f"""
        <h3>📁 {batch_display} ({len(batch_matches)} matches)</h3>
        """
        
        for match in batch_matches:
            matched_searches = ', '.join(match.get('matched_searches', []))
            matched_terms = ', '.join(match.get('matched_terms', []))
            pages_with_matches = match.get('pages_with_matches', [])
            
            html += f"""
            <div style="border: 1px solid #dee2e6; border-radius: 6px; padding: 15px; margin-bottom: 15px; background: #f8f9fa;">
                <h4 style="margin: 0 0 10px 0;">
                    <a href='{match['url']}' target='_blank' style="color: #2c5aa0; text-decoration: none;">
                        {match['title']}
                    </a>
                    {f" <span style='background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;'>Relevance: {match.get('relevance_score', 0)}%</span>" if match.get('relevance_score') else ""}
                </h4>
                
                <div style="font-size: 13px; color: #666; margin-bottom: 8px;">
                    <strong>Published:</strong> {match['pub_date']} | 
                    <strong>Matched searches:</strong> {matched_searches}
                    {f" | <strong>Issuer:</strong> {match['issuer_name']}" if match.get('issuer_name') else ""}
                    {f" | <strong>Type:</strong> {match['document_type']}" if match.get('document_type') else ""}
                </div>
                
                {f"<div style='margin-bottom: 8px;'><strong>Keywords found:</strong> <span style='background: #ffeaa7; padding: 2px 6px; border-radius: 3px; font-size: 12px;'>{matched_terms}</span></div>" if matched_terms else ""}
                
                {f"<div style='margin-bottom: 10px;'><strong>📄 Found on pages:</strong> {', '.join([f'<span style=\"background: #74b9ff; color: white; padding: 1px 4px; border-radius: 2px; font-size: 11px;\">Page {p}</span>' for p in sorted(pages_with_matches) if p])}</div>" if pages_with_matches else ""}
            """
            
            # Add top match locations
            if match.get('match_locations'):
                html += "<div style='margin-top: 10px;'><strong>🎯 Key Matches:</strong></div>"
                for i, location in enumerate(match['match_locations'][:2]):  # Top 2 matches in email
                    page_info = f" (Page {location['page_number']})" if location.get('page_number') else ""
                    html += f"""
                    <div style="background: white; padding: 8px; margin: 5px 0; border-left: 3px solid #74b9ff; font-size: 12px;">
                        <strong>{location['term']}</strong>{page_info}<br>
                        <em>"{location.get('sentence', location.get('context', ''))[:120]}..."</em>
                    </div>
                    """
                
                if len(match['match_locations']) > 2:
                    html += f"<div style='font-size: 11px; color: #666; margin-top: 5px;'>... and {len(match['match_locations']) - 2} more matches</div>"
            
            html += "</div>"
    
    html += """
    <div style="margin-top: 30px; padding: 15px; background: #e9ecef; border-radius: 6px; font-size: 12px; color: #666;">
        This digest shows precise keyword matches with page numbers and context. Click any link to view the full document on EMMA.
        <br><strong>System:</strong> Priority processing for immediate alerts + background queue for comprehensive coverage.
    </div>
    """
    
    payload = {
        'from': FROM_EMAIL,
        'to': recipients,
        'subject': f'EMMA Daily Digest: {len(matches)} matches with precise locations',
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

async def daily_peak_scan():
    """Perform daily peak-hour scan with priority processing"""
    logger.info(f'🌅 Starting daily peak scan at {datetime.utcnow().isoformat()}')
    logger.info(f'Processing mode: {PROCESSING_MODE} | Peak time limit: {PEAK_PROCESSING_TIME_LIMIT}m')
    
    if PDF_PARSING_AVAILABLE:
        logger.info("PDF text extraction enabled")
    else:
        logger.warning("PDF parsing not available - install PyPDF2 for full text search")
    
    async with EmmaScanner(db) as scanner:
        results = await scanner.scan_with_priority_processing()
        
        logger.info(f"Peak scan results: {results}")
        
        # Send email for immediate matches
        if results['matches'] > 0 and RESEND_API_KEY and FROM_EMAIL and ALERT_EMAILS:
            recent_matches = await db.get_recent_matches(days=1)  # Just today's matches
            if recent_matches:
                await send_batch_digest(recent_matches, ALERT_EMAILS)
    
    return results

async def background_processing():
    """Process background queue during off-peak hours"""
    logger.info(f'🌙 Starting background processing at {datetime.utcnow().isoformat()}')
    
    async with EmmaScanner(db) as scanner:
        results = await scanner.process_background_queue(max_items=30)
        
        logger.info(f"Background processing results: {results}")
        
        # Send additional email if background processing found matches
        if results['matches'] > 0 and RESEND_API_KEY and FROM_EMAIL and ALERT_EMAILS:
            recent_matches = await db.get_recent_matches(days=1)
            background_matches = [m for m in recent_matches if 'background' in str(m).lower()]
            if background_matches:
                # Send a separate digest for background finds
                subject_prefix = "EMMA Background Digest"
                await send_batch_digest(background_matches, ALERT_EMAILS)
    
    return results

async def cleanup_and_maintenance():
    """Daily cleanup and maintenance tasks"""
    logger.info(f'🧹 Starting cleanup at {datetime.utcnow().isoformat()}')
    
    # Cleanup old records
    deleted = await db.cleanup_old(RETENTION_DAYS)
    if deleted > 0:
        logger.info(f'Cleaned up {deleted} old records')
    
    # Get queue stats
    queue = ProcessingQueue(db)
    stats = await queue.get_queue_stats()
    logger.info(f"Queue stats: {stats}")
    
    return {"deleted_records": deleted, "queue_stats": stats}

# FastAPI setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    scheduler = AsyncIOScheduler()
    
    # Peak processing - 9 AM daily (when reporters start work)
    scheduler.add_job(
        daily_peak_scan,
        'cron',
        hour=9,
        minute=0,
        id='peak_scan'
    )
    
    # Background processing - 2 AM and 6 AM (off-peak hours)
    scheduler.add_job(
        background_processing,
        'cron',
        hour=2,
        minute=0,
        id='background_2am'
    )
    
    scheduler.add_job(
        background_processing,
        'cron',
        hour=6,
        minute=0,
        id='background_6am'
    )
    
    # Cleanup - 1 AM daily
    scheduler.add_job(
        cleanup_and_maintenance,
        'cron',
        hour=1,
        minute=0,
        id='daily_cleanup'
    )
    
    scheduler.start()
    logger.info("📅 Scheduler started with peak (9AM) and background (2AM, 6AM) processing")
    
    # Run initial scan if configured
    if RUN_INITIAL_SCAN:
        logger.info("🚀 Running initial scan...")
        await daily_peak_scan()
    
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
    return {
        "status": "ok", 
        "timestamp": datetime.utcnow().isoformat(),
        "pdf_parsing": PDF_PARSING_AVAILABLE,
        "scraping_enabled": True,
        "features": {
            "priority_processing": True,
            "background_queue": True,
            "resource_monitoring": ENABLE_RESOURCE_MONITORING,
            "page_level_precision": True,
            "sentence_level_context": True,
            "relevance_scoring": True,
            "lightweight_storage": True
        },
        "processing_config": {
            "peak_time_limit": f"{PEAK_PROCESSING_TIME_LIMIT} minutes",
            "large_file_threshold": f"{LARGE_FILE_THRESHOLD_KB}KB",
            "complex_doc_threshold": f"{COMPLEX_DOC_PAGE_THRESHOLD} pages",
            "processing_mode": PROCESSING_MODE,
            "max_documents_per_scan": MAX_DOCUMENTS_PER_SCAN
        }
    }

@app.get("/resource-stats")
async def get_resource_stats():
    """Get resource usage statistics"""
    history = await db.get_resource_history(days=7)
    queue = ProcessingQueue(db)
    queue_stats = await queue.get_queue_stats()
    
    # Calculate summary stats
    if history:
        avg_memory = sum(h.get("peak_memory", 0) for h in history) / len(history)
        avg_cpu = sum(h.get("peak_cpu", 0) for h in history) / len(history)
        avg_duration = sum(h.get("duration", 0) for h in history) / len(history)
        total_documents = sum(h.get("documents", 0) for h in history)
    else:
        avg_memory = avg_cpu = avg_duration = total_documents = 0
    
    return {
        "current_queue": queue_stats,
        "recent_performance": {
            "avg_peak_memory_mb": round(avg_memory, 1),
            "avg_peak_cpu_percent": round(avg_cpu, 1),
            "avg_duration_minutes": round(avg_duration / 60, 1),
            "total_documents_7days": total_documents,
            "avg_documents_per_day": round(total_documents / 7, 1)
        },
        "history": history[-10:],  # Last 10 operations
        "system_info": {
            "peak_time_limit": PEAK_PROCESSING_TIME_LIMIT,
            "large_file_threshold_kb": LARGE_FILE_THRESHOLD_KB,
            "resource_monitoring_enabled": ENABLE_RESOURCE_MONITORING
        }
    }

@app.get("/scan")
async def manual_peak_scan():
    """Manual trigger for peak processing scan"""
    results = await daily_peak_scan()
    return {
        "status": "peak scan completed", 
        "results": results,
        "note": "This runs priority processing with time limits"
    }

@app.get("/background-scan")
async def manual_background_scan():
    """Manual trigger for background processing"""
    results = await background_processing()
    return {
        "status": "background processing completed",
        "results": results,
        "note": "This processes queued documents thoroughly"
    }

@app.get("/queue-status")
async def get_queue_status():
    """Get current processing queue status"""
    queue = ProcessingQueue(db)
    stats = await queue.get_queue_stats()
    ready_docs = await queue.get_ready_documents(limit=5)
    
    return {
        "queue_stats": stats,
        "sample_ready_documents": [
            {
                "title": doc["title"][:50] + "..." if len(doc["title"]) > 50 else doc["title"],
                "priority": doc["priority"],
                "attempts": doc["attempts"],
                "created_at": doc["created_at"]
            }
            for doc in ready_docs
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False
    )
