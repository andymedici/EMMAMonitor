import os
import asyncio
import aiohttp
import sqlite3
import requests
import random
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from contextlib import asynccontextmanager
import re
import logging
from pathlib import Path
import json
import psutil
import time
import urllib.parse

# Add PDF parsing imports
try:
    import PyPDF2
    PDF_PARSING_AVAILABLE = True
except ImportError:
    PDF_PARSING_AVAILABLE = False

from bs4 import BeautifulSoup
import io

# Configuration
EMMA_SEARCH_URL = "https://emma.msrb.org/Search/Search.aspx"
DATABASE_PATH = "emma_monitor.db"
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "alerts@yourdomain.com")
ALERT_EMAILS = os.getenv("ALERT_EMAILS", "").split(",") if os.getenv("ALERT_EMAILS") else []
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))
RUN_INITIAL_SCAN = os.getenv("RUN_INITIAL_SCAN", "false").lower() == "true"

# Processing configuration
MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "0"))
MAX_DOCUMENTS_PER_SCAN = int(os.getenv("MAX_DOCUMENTS_PER_SCAN", "50"))
PROCESSING_MODE = os.getenv("PROCESSING_MODE", "thorough")

# Queue-based processing configuration
PEAK_PROCESSING_TIME_LIMIT = int(os.getenv("PEAK_TIME_LIMIT", "15"))
LARGE_FILE_THRESHOLD_KB = int(os.getenv("LARGE_FILE_THRESHOLD", "2000"))
COMPLEX_DOC_PAGE_THRESHOLD = int(os.getenv("COMPLEX_PAGE_THRESHOLD", "50"))
MAX_PEAK_PROCESSING_ATTEMPTS = int(os.getenv("MAX_PEAK_ATTEMPTS", "3"))

# Resource monitoring configuration
ENABLE_RESOURCE_MONITORING = os.getenv("ENABLE_RESOURCE_MONITORING", "true").lower() == "true"
RESOURCE_LOG_INTERVAL = int(os.getenv("RESOURCE_LOG_INTERVAL", "30"))
MEMORY_WARNING_THRESHOLD = int(os.getenv("MEMORY_WARNING_MB", "400"))
CPU_WARNING_THRESHOLD = int(os.getenv("CPU_WARNING_PERCENT", "80"))

# Enhanced session configuration
SESSION_ROTATION_MINUTES = int(os.getenv("SESSION_ROTATION_MINUTES", "45"))
MAX_REQUESTS_PER_SESSION = int(os.getenv("MAX_REQUESTS_PER_SESSION", "100"))
SESSION_FAILURE_THRESHOLD = int(os.getenv("SESSION_FAILURE_THRESHOLD", "5"))
ENABLE_USER_AGENT_ROTATION = os.getenv("ENABLE_UA_ROTATION", "true").lower() == "true"

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create templates directory
templates_dir = Path("templates")
templates_dir.mkdir(exist_ok=True)

class SessionState:
    """Track detailed session state and health with enhanced monitoring"""
    
    def __init__(self):
        self.session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        self.established_at = None
        self.last_successful_request = None
        self.request_count = 0
        self.failure_count = 0
        self.blocked_count = 0
        self.terms_accepted = False
        self.current_user_agent = None
        self.session_cookies = {}
        self.detected_layout = None
        self.rate_limit_hits = 0
        self.last_rate_limit = None
        self.consecutive_failures = 0
        self.terms_attempts = 0
        self.last_user_agent_rotation = None
        self.successful_endpoints = set()
        self.failed_endpoints = set()
        
    def is_healthy(self) -> bool:
        """Check if session appears healthy with comprehensive criteria"""
        if not self.established_at:
            return False
            
        failure_rate = self.failure_count / max(self.request_count, 1)
        if failure_rate > 0.3:
            return False
            
        if self.last_successful_request:
            age_minutes = (datetime.utcnow() - self.last_successful_request).seconds / 60
            if age_minutes > 30:
                return False
        
        if self.consecutive_failures >= SESSION_FAILURE_THRESHOLD:
            return False
            
        if self.blocked_count > 3:
            return False
            
        if self.last_rate_limit:
            time_since_limit = (datetime.utcnow() - self.last_rate_limit).seconds
            if time_since_limit < 300:
                return False
        
        return True
    
    def should_rotate(self) -> bool:
        """Determine if session should be rotated"""
        if not self.established_at:
            return True
            
        age_minutes = (datetime.utcnow() - self.established_at).seconds / 60
        if age_minutes > SESSION_ROTATION_MINUTES:
            return True
            
        if self.request_count >= MAX_REQUESTS_PER_SESSION:
            return True
            
        if not self.is_healthy():
            return True
            
        return False
    
    def record_success(self, endpoint: str = ""):
        """Record successful request"""
        self.last_successful_request = datetime.utcnow()
        self.request_count += 1
        self.consecutive_failures = 0
        if endpoint:
            self.successful_endpoints.add(endpoint)
    
    def record_failure(self, endpoint: str = "", is_block: bool = False):
        """Record failed request"""
        self.failure_count += 1
        self.request_count += 1
        self.consecutive_failures += 1
        if is_block:
            self.blocked_count += 1
        if endpoint:
            self.failed_endpoints.add(endpoint)
    
    def record_rate_limit(self):
        """Record rate limiting event"""
        self.rate_limit_hits += 1
        self.last_rate_limit = datetime.utcnow()

class EnhancedUserAgentRotator:
    """Manage realistic user agent rotation"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        ]
        self.current_ua_index = 0
        self.last_rotation = None
    
    def get_current_ua(self) -> str:
        return self.user_agents[self.current_ua_index]
    
    def rotate_ua(self) -> str:
        self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
        self.last_rotation = datetime.utcnow()
        logger.info(f"Rotated user agent to: {self.get_current_ua()[:50]}...")
        return self.get_current_ua()
    
    def should_rotate(self) -> bool:
        if not self.last_rotation:
            return True
        minutes_since = (datetime.utcnow() - self.last_rotation).seconds / 60
        return minutes_since > random.uniform(20, 30)

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
        self.operation_name = operation_name
        self.start_time = time.time()
        
        try:
            process = psutil.Process()
            self.start_memory = process.memory_info().rss / 1024 / 1024
            self.start_cpu = process.cpu_percent()
            logger.info(f"Starting {operation_name} | Memory: {self.start_memory:.1f}MB | CPU: {self.start_cpu:.1f}%")
        except Exception as e:
            logger.warning(f"Could not get system info: {e}")
            self.start_memory = 0
            self.start_cpu = 0
        
        return {
            "start_time": self.start_time,
            "start_memory_mb": self.start_memory,
            "start_cpu_percent": self.start_cpu
        }
    
    def log_progress(self, documents_processed: int = 0, additional_info: str = ""):
        if not self.start_time:
            return
        
        try:
            process = psutil.Process()
            current_memory = process.memory_info().rss / 1024 / 1024
            current_cpu = process.cpu_percent()
            elapsed_time = time.time() - self.start_time
            
            self.processing_stats["peak_memory_mb"] = max(self.processing_stats["peak_memory_mb"], current_memory)
            self.processing_stats["peak_cpu_percent"] = max(self.processing_stats["peak_cpu_percent"], current_cpu)
            self.processing_stats["documents_processed"] = documents_processed
            
            logger.info(f"{self.operation_name} Progress: {documents_processed} docs | "
                       f"Memory: {current_memory:.1f}MB | CPU: {current_cpu:.1f}% | "
                       f"Time: {elapsed_time:.1f}s {additional_info}")
            
            if current_memory > MEMORY_WARNING_THRESHOLD:
                logger.warning(f"High memory usage: {current_memory:.1f}MB")
            
            if current_cpu > CPU_WARNING_THRESHOLD:
                logger.warning(f"High CPU usage: {current_cpu:.1f}%")
                
        except Exception as e:
            logger.warning(f"Resource monitoring error: {e}")
    
    def finish_monitoring(self) -> Dict:
        if not self.start_time:
            return {}
        
        try:
            end_time = time.time()
            total_time = end_time - self.start_time
            
            process = psutil.Process()
            end_memory = process.memory_info().rss / 1024 / 1024
            
            self.processing_stats["total_processing_time"] = total_time
            
            if self.processing_stats["documents_processed"] > 0:
                self.processing_stats["avg_document_time"] = total_time / self.processing_stats["documents_processed"]
            
            memory_delta = end_memory - self.start_memory if self.start_memory else 0
            
            summary = {
                "operation": self.operation_name,
                "total_time_seconds": round(total_time, 1),
                "documents_processed": self.processing_stats["documents_processed"],
                "documents_queued": self.processing_stats["documents_queued"],
                "processing_errors": self.processing_stats["processing_errors"],
                "avg_time_per_document": round(self.processing_stats["avg_document_time"], 1),
                "memory_usage": {
                    "start_mb": round(self.start_memory, 1) if self.start_memory else 0,
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
            
            logger.info(f"{self.operation_name} Complete: {summary['total_time_seconds']}s | "
                       f"{summary['documents_processed']} docs | "
                       f"Peak: {summary['memory_usage']['peak_mb']}MB")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error finishing resource monitoring: {e}")
            return {"error": str(e)}

class ProcessingQueue:
    """Manages document processing queue with priority levels"""
    
    def __init__(self, database):
        self.db = database
    
    async def add_document(self, url: str, title: str, metadata: Dict, priority: int = 2) -> int:
        conn = sqlite3.connect(self.db.db_path)
        try:
            now = datetime.utcnow()
            if priority == 1:
                scheduled_for = now
            else:
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
            
            logger.info(f"Queued document (priority {priority}): {title[:50]}... → scheduled for {scheduled_for.strftime('%H:%M')}")
            return queue_id
            
        except Exception as e:
            logger.error(f"Error adding document to queue: {e}")
            return 0
        finally:
            conn.close()
    
    async def get_ready_documents(self, priority: Optional[int] = None, limit: int = 20) -> List[Dict]:
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
        conn = sqlite3.connect(self.db.db_path)
        try:
            cursor = conn.execute("SELECT attempts FROM processing_queue WHERE id = ?", (queue_id,))
            row = cursor.fetchone()
            
            if row and row[0] < 3:
                delay_hours = 2 ** row[0]
                retry_time = datetime.utcnow() + timedelta(hours=delay_hours)
                
                conn.execute("""
                    UPDATE processing_queue 
                    SET status = 'pending', scheduled_for = ?, error_message = ?
                    WHERE id = ?
                """, (retry_time.isoformat(), error_message, queue_id))
                
                logger.info(f"Rescheduling failed document (attempt {row[0] + 1}) for {retry_time.strftime('%H:%M')}")
            else:
                conn.execute("""
                    UPDATE processing_queue 
                    SET status = 'failed', error_message = ?
                    WHERE id = ?
                """, (error_message, queue_id))
                
                logger.warning(f"Document permanently failed after 3 attempts: {error_message}")
            
            conn.commit()
        except Exception as e:
            logger.error(f"Error marking document as failed: {e}")
        finally:
            conn.close()
    
    async def get_queue_stats(self) -> Dict:
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
    def __init__(self, query_id: int, name: str, query: str, search_type: str, active: bool = True, 
                 batch_name: str = "", alert_emails: str = ""):
        self.id = query_id
        self.name = name
        self.query = query
        self.search_type = search_type
        self.active = active
        self.batch_name = batch_name
        self.alert_emails = alert_emails
    
    def get_alert_emails_list(self) -> List[str]:
        emails = []
        if self.alert_emails:
            emails.extend([e.strip() for e in self.alert_emails.split(',') if e.strip()])
        if ALERT_EMAILS:
            emails.extend(ALERT_EMAILS)
        return list(set(emails))
    
    def matches(self, text: str, page_info: List[Dict] = None) -> Dict:
        if not text or not self.query:
            return {"matched": False}
        
        text_lower = text.lower()
        matched_terms = []
        match_locations = []
        
        sentences = re.split(r'[.!?]+', text)
        
        if self.search_type == 'exact':
            query_lower = self.query.lower()
            if query_lower in text_lower:
                matched_terms.append(self.query)
                start = 0
                while True:
                    pos = text_lower.find(query_lower, start)
                    if pos == -1:
                        break
                    
                    sentence_info = self._find_sentence_and_page(pos, text, sentences, page_info)
                    
                    match_locations.append({
                        "term": self.query,
                        "sentence": sentence_info["sentence"],
                        "page_number": sentence_info["page_number"],
                        "context": sentence_info["context"],
                        "position_in_text": pos
                    })
                    start = pos + len(query_lower)
                    
                    if len(match_locations) >= 5:
                        break
        
        elif self.search_type == 'all':
            terms = [t.strip() for t in self.query.split(',') if t.strip()]
            terms_found = []
            
            for term in terms:
                term_lower = term.lower()
                if term_lower in text_lower:
                    terms_found.append(term)
                    pos = text_lower.find(term_lower)
                    sentence_info = self._find_sentence_and_page(pos, text, sentences, page_info)
                    
                    match_locations.append({
                        "term": term,
                        "sentence": sentence_info["sentence"],
                        "page_number": sentence_info["page_number"],
                        "context": sentence_info["context"],
                        "position_in_text": pos
                    })
            
            if len(terms_found) == len(terms):
                matched_terms = terms_found
            else:
                return {"matched": False}
        
        elif self.search_type == 'any':
            terms = [t.strip() for t in self.query.split(',') if t.strip()]
            for term in terms:
                term_lower = term.lower()
                if term_lower in text_lower:
                    matched_terms.append(term)
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
            match_locations.sort(key=lambda x: x["position_in_text"])
            
            return {
                "matched": True,
                "matched_terms": list(set(matched_terms)),
                "match_locations": match_locations,
                "total_matches": len(match_locations),
                "pages_with_matches": list(set([m["page_number"] for m in match_locations if m["page_number"]]))
            }
        
        return {"matched": False}
    
    def _find_sentence_and_page(self, position: int, full_text: str, sentences: List[str], page_info: List[Dict] = None) -> Dict:
        current_pos = 0
        sentence_text = ""
        sentence_number = 0
        
        for i, sentence in enumerate(sentences):
            sentence_len = len(sentence) + 1
            if current_pos <= position < current_pos + sentence_len:
                sentence_text = sentence.strip()
                sentence_number = i + 1
                break
            current_pos += sentence_len
        
        page_number = None
        if page_info:
            for page in page_info:
                if page["start_pos"] <= position < page["end_pos"]:
                    page_number = page["page_num"]
                    break
        
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
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS search_queries (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                query TEXT NOT NULL,
                search_type TEXT NOT NULL CHECK(search_type IN ('exact', 'all', 'any')),
                active BOOLEAN DEFAULT 1,
                batch_name TEXT DEFAULT '',
                alert_emails TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Add alert_emails column if it doesn't exist
        try:
            conn.execute("ALTER TABLE search_queries ADD COLUMN alert_emails TEXT DEFAULT ''")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS matches (
                id INTEGER PRIMARY KEY,
                disclosure_id INTEGER,
                search_query_id INTEGER,
                matched_terms TEXT,
                match_locations TEXT,
                total_matches INTEGER,
                relevance_score REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (disclosure_id) REFERENCES disclosures (id),
                FOREIGN KEY (search_query_id) REFERENCES search_queries (id),
                UNIQUE(disclosure_id, search_query_id)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processing_queue (
                id INTEGER PRIMARY KEY,
                document_url TEXT NOT NULL,
                document_title TEXT,
                document_metadata TEXT,
                priority INTEGER DEFAULT 2,
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                scheduled_for TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resource_logs (
                id INTEGER PRIMARY KEY,
                operation_type TEXT,
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
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_logs (
                id INTEGER PRIMARY KEY,
                session_id TEXT,
                operation TEXT,
                endpoint TEXT,
                status_code INTEGER,
                success BOOLEAN,
                user_agent TEXT,
                response_time_ms INTEGER,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
    
    async def log_session_activity(self, session_id: str, operation: str, endpoint: str, 
                                   status_code: int, success: bool, user_agent: str = "",
                                   response_time_ms: int = 0, error_message: str = ""):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                INSERT INTO session_logs 
                (session_id, operation, endpoint, status_code, success, user_agent, 
                 response_time_ms, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, operation, endpoint, status_code, success, 
                  user_agent, response_time_ms, error_message))
            conn.commit()
        except Exception as e:
            logger.error(f"Error logging session activity: {e}")
        finally:
            conn.close()
    
    async def save_resource_log(self, resource_summary: Dict):
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
    
    async def get_session_stats(self, hours: int = 24) -> Dict:
        conn = sqlite3.connect(self.db_path)
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests,
                    AVG(response_time_ms) as avg_response_time,
                    COUNT(DISTINCT session_id) as unique_sessions,
                    COUNT(DISTINCT endpoint) as unique_endpoints
                FROM session_logs
                WHERE created_at > ?
            """, (cutoff.isoformat(),))
            
            row = cursor.fetchone()
            if row:
                total, successful, avg_time, sessions, endpoints = row
                if total and total > 0:
                    success_rate = (successful / total) * 100 if successful else 0
                else:
                    success_rate = 0
                
                return {
                    "total_requests": total or 0,
                    "successful_requests": successful or 0,
                    "success_rate": round(success_rate, 1),
                    "avg_response_time_ms": round(avg_time or 0, 0),
                    "unique_sessions": sessions or 0,
                    "unique_endpoints": endpoints or 0
                }
            return {
                "total_requests": 0,
                "successful_requests": 0,
                "success_rate": 0,
                "avg_response_time_ms": 0,
                "unique_sessions": 0,
                "unique_endpoints": 0
            }
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return {}
        finally:
            conn.close()

    async def save_search_query(self, name: str, query: str, search_type: str, 
                               batch_name: str = "", alert_emails: str = "") -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            INSERT INTO search_queries (name, query, search_type, batch_name, alert_emails)
            VALUES (?, ?, ?, ?, ?)
        """, (name, query, search_type, batch_name, alert_emails))
        
        query_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return query_id
    
    async def get_search_queries(self, active_only: bool = True) -> List[SearchQuery]:
        conn = sqlite3.connect(self.db_path)
        
        where_clause = "WHERE active = 1" if active_only else ""
        cursor = conn.execute(f"""
            SELECT id, name, query, search_type, active, batch_name, 
                   COALESCE(alert_emails, '') as alert_emails
            FROM search_queries {where_clause}
            ORDER BY batch_name, name
        """)
        
        queries = []
        for row in cursor:
            queries.append(SearchQuery(row[0], row[1], row[2], row[3], bool(row[4]), row[5], row[6]))
        
        conn.close()
        return queries
    
    async def update_search_query(self, query_id: int, name: str, query: str, search_type: str, 
                                 active: bool, batch_name: str = "", alert_emails: str = ""):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            UPDATE search_queries 
            SET name = ?, query = ?, search_type = ?, active = ?, batch_name = ?, alert_emails = ?
            WHERE id = ?
        """, (name, query, search_type, active, batch_name, alert_emails, query_id))
        
        conn.commit()
        conn.close()
    
    async def delete_search_query(self, query_id: int):
        conn = sqlite3.connect(self.db_path)
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
            
            if cursor.rowcount == 0:
                cursor = conn.execute("SELECT id FROM disclosures WHERE guid = ?", (guid,))
                row = cursor.fetchone()
                disclosure_id = row[0] if row else None
            else:
                disclosure_id = cursor.lastrowid
            
            conn.commit()
            return disclosure_id
        except Exception as e:
            logger.error(f"Error saving disclosure: {e}")
            return None
        finally:
            conn.close()
    
    async def save_match(self, disclosure_id: int, search_query_id: int, match_details: Dict):
        conn = sqlite3.connect(self.db_path)
        try:
            relevance_score = 0.0
            if match_details.get("match_locations"):
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
                   GROUP_CONCAT(m.total_matches) as match_counts,
                   GROUP_CONCAT(sq.alert_emails) as all_alert_emails,
                   GROUP_CONCAT(sq.id) as query_ids
            FROM disclosures d
            JOIN matches m ON d.id = m.disclosure_id
            JOIN search_queries sq ON m.search_query_id = sq.id
            WHERE d.created_at > ?
            GROUP BY d.id
            ORDER BY avg_relevance_score DESC, d.created_at DESC
        """, (cutoff.isoformat(),))
        
        results = []
        for row in cursor:
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
            
            all_alert_emails = []
            if row[16]:
                email_strings = row[16].split(',')
                for email_str in email_strings:
                    if email_str.strip():
                        all_alert_emails.extend([e.strip() for e in email_str.split(',') if e.strip()])
            
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
                'relevance_score': round(row[14] or 0.0, 1),
                'pages_with_matches': list(set([loc.get("page_number") for loc in all_locations if loc.get("page_number")])),
                'alert_emails': list(set(all_alert_emails)),
                'query_ids': row[17].split(',') if row[17] else []
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
        
        conn.execute("""
            DELETE FROM matches WHERE disclosure_id IN (
                SELECT id FROM disclosures WHERE created_at < ?
            )
        """, (cutoff.isoformat(),))
        
        cursor = conn.execute("""
            DELETE FROM disclosures WHERE created_at < ?
        """, (cutoff.isoformat(),))
        
        conn.execute("""
            DELETE FROM processing_queue 
            WHERE status = 'completed' AND completed_at < ?
        """, (cutoff.isoformat(),))
        
        resource_cutoff = datetime.now() - timedelta(days=30)
        conn.execute("""
            DELETE FROM resource_logs WHERE created_at < ?
        """, (resource_cutoff.isoformat(),))
        
        session_cutoff = datetime.now() - timedelta(days=7)
        conn.execute("""
            DELETE FROM session_logs WHERE created_at < ?
        """, (session_cutoff.isoformat(),))
        
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
        self.session_state = SessionState()
        self.ua_rotator = EnhancedUserAgentRotator() if ENABLE_USER_AGENT_ROTATION else None
        
        self.browser_headers = {
            'User-Agent': self.ua_rotator.get_current_ua() if self.ua_rotator else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'max-age=0',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        }
    
    async def __aenter__(self):
        await self._create_new_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _create_new_session(self):
        if self.session:
            await self.session.close()
        
        if self.ua_rotator and self.ua_rotator.should_rotate():
            new_ua = self.ua_rotator.rotate_ua()
            self.browser_headers['User-Agent'] = new_ua
            self.session_state.current_user_agent = new_ua
        
        connector = aiohttp.TCPConnector(
            limit=8,
            limit_per_host=2,
            enable_cleanup_closed=True,
            ssl=False,
            force_close=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=90,
            connect=30,
            sock_read=30
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.browser_headers,
            cookie_jar=aiohttp.CookieJar(unsafe=True),
            raise_for_status=False
        )
        
        self.session_state = SessionState()
        self.session_state.current_user_agent = self.browser_headers['User-Agent']
        
        logger.info(f"Created new session: {self.session_state.session_id}")
    
    async def _ensure_healthy_session(self):
        if (not self.session or 
            not self.session_state.is_healthy() or 
            self.session_state.should_rotate()):
            
            logger.info(f"Session unhealthy or expired, creating new session...")
            await self._create_new_session()
            await self._establish_emma_session()
    
    async def _log_request(self, operation: str, url: str, status_code: int, 
                          success: bool, response_time_ms: int = 0, error: str = ""):
        await self.db.log_session_activity(
            self.session_state.session_id,
            operation,
            url,
            status_code,
            success,
            self.session_state.current_user_agent,
            response_time_ms,
            error
        )
    
    async def _make_request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        max_retries = 3
        base_delay = 2
        
        for attempt in range(max_retries):
            start_time = time.time()
            
            try:
                await self._ensure_healthy_session()
                
                if attempt > 0:
                    delay = base_delay * (2 ** attempt) + random.uniform(1, 3)
                    logger.info(f"Retry attempt {attempt + 1} after {delay:.1f}s delay")
                    await asyncio.sleep(delay)
                else:
                    await asyncio.sleep(random.uniform(1, 2))
                
                if method.lower() == 'get':
                    response = await self.session.get(url, **kwargs)
                elif method.lower() == 'post':
                    response = await self.session.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                response_time = int((time.time() - start_time) * 1000)
                
                await self._log_request(
                    f"{method.upper()}_request",
                    url,
                    response.status,
                    response.status < 400,
                    response_time
                )
                
                if response.status < 400:
                    self.session_state.record_success(url)
                elif response.status == 429:
                    self.session_state.record_rate_limit()
                    self.session_state.record_failure(url, is_block=True)
                elif response.status in [403, 406]:
                    self.session_state.record_failure(url, is_block=True)
                else:
                    self.session_state.record_failure(url)
                
                return response
                
            except asyncio.TimeoutError as e:
                logger.warning(f"Request timeout (attempt {attempt + 1}): {url}")
                await self._log_request(f"{method.upper()}_timeout", url, 0, False, 
                                       int((time.time() - start_time) * 1000), str(e))
                self.session_state.record_failure(url)
                
                if attempt == max_retries - 1:
                    raise
                    
            except Exception as e:
                logger.error(f"Request error (attempt {attempt + 1}): {e}")
                await self._log_request(f"{method.upper()}_error", url, 0, False,
                                       int((time.time() - start_time) * 1000), str(e))
                self.session_state.record_failure(url)
                
                if attempt == max_retries - 1:
                    raise
        
        raise Exception("Max retries exceeded")
    
    async def _establish_emma_session(self):
        logger.info(f"Establishing EMMA session: {self.session_state.session_id}")
        
        try:
            homepage_response = await self._make_request('GET', "https://emma.msrb.org/")
            
            if homepage_response.status == 200:
                homepage_content = await homepage_response.text()
                logger.info(f"EMMA homepage accessed: {len(homepage_content)} chars")
                
                search_response = await self._make_request('GET', EMMA_SEARCH_URL)
                
                if search_response.status == 200:
                    content = await search_response.text()
                    logger.info(f"Search page content: {len(content)} chars")
                    
                    if self._is_terms_page(content):
                        logger.info("Terms page detected, handling acceptance...")
                        success = await self._handle_terms_page_comprehensive(content, search_response.url)
                        if success:
                            self.session_state.established_at = datetime.utcnow()
                            self.session_state.terms_accepted = True
                            return True
                        else:
                            return await self._try_alternative_establishment()
                            
                    elif self._is_search_page(content):
                        logger.info("Direct search page access successful")
                        self.session_state.established_at = datetime.utcnow()
                        self.session_state.detected_layout = self._detect_emma_layout(content)
                        return True
                        
                    else:
                        logger.info(f"Unexpected page type, trying alternatives...")
                        return await self._try_alternative_establishment()
                else:
                    return await self._try_alternative_establishment()
            else:
                return await self._try_alternative_establishment()
                
        except Exception as e:
            logger.error(f"Session establishment error: {e}")
            return await self._try_alternative_establishment()
    
    async def _try_alternative_establishment(self) -> bool:
        logger.info("Trying alternative EMMA establishment methods...")
        
        alternative_urls = [
            "https://emma.msrb.org/Search",
            "https://emma.msrb.org/AdvancedSearch", 
            "https://emma.msrb.org/QuickSearch",
            "https://emma.msrb.org/MarketActivity/ContinuingDisclosuresSearch",
            "https://emma.msrb.org/IssuerHomePage/Offerings",
            "https://emma.msrb.org/Home/Search",
            "https://emma.msrb.org/SecurityDetails/Search",
            "https://emma.msrb.org/DisclosureSearch/Disclosures"
        ]
        
        for i, url in enumerate(alternative_urls):
            try:
                logger.info(f"Trying alternative {i+1}/{len(alternative_urls)}: {url}")
                
                response = await self._make_request('GET', url)
                
                if response.status == 200:
                    content = await response.text()
                    
                    if self._is_search_page(content):
                        logger.info(f"Alternative success: {url}")
                        self.session_state.established_at = datetime.utcnow()
                        self.session_state.detected_layout = self._detect_emma_layout(content)
                        self.session_state.successful_endpoints.add(url)
                        return True
                    elif self._is_terms_page(content):
                        logger.info(f"Terms page found at: {url}")
                        success = await self._handle_terms_page_comprehensive(content, response.url)
                        if success:
                            self.session_state.established_at = datetime.utcnow()
                            self.session_state.terms_accepted = True
                            self.session_state.successful_endpoints.add(url)
                            return True
                else:
                    self.session_state.failed_endpoints.add(url)
                    logger.debug(f"Alternative failed: {url} → HTTP {response.status}")
                    
            except Exception as e:
                self.session_state.failed_endpoints.add(url)
                logger.debug(f"Alternative error: {url} → {e}")
                continue
        
        logger.warning("All alternative establishment methods failed")
        return False
    
    def _detect_emma_layout(self, content: str) -> str:
        content_lower = content.lower()
        
        if "react" in content_lower or "spa" in content_lower:
            return "modern_spa"
        elif "bootstrap" in content_lower:
            return "bootstrap_based"  
        elif "table" in content_lower and "search" in content_lower:
            return "table_based"
        elif "grid" in content_lower:
            return "grid_based"
        else:
            return "unknown"
    
    def _is_terms_page(self, content: str) -> bool:
        content_lower = content.lower()
        
        terms_indicators = [
            "terms of use", "terms and conditions", "user agreement",
            "by clicking", "i agree", "accept", "privacy policy",
            "legal agreement", "msrb.org/terms", "continue to site",
            "agree and continue", "user terms", "website terms"
        ]
        
        indicator_count = sum(1 for indicator in terms_indicators if indicator in content_lower)
        return indicator_count >= 2
    
    def _is_search_page(self, content: str) -> bool:
        content_lower = content.lower()
        
        search_indicators = [
            "search securities", "advanced search", "quick search",
            "disclosure search", "municipal securities", "issuer name", 
            "cusip", "security search", "sort by", "results per page",
            "search criteria", "filter", "document type", "date range"
        ]
        
        indicator_count = sum(1 for indicator in search_indicators if indicator in content_lower)
        return indicator_count >= 3
    
    async def _handle_terms_page_comprehensive(self, content: str, current_url) -> bool:
        logger.info("Handling EMMA terms page with comprehensive approach...")
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Strategy 1: Form submission
            logger.info("Strategy 1: Form submission")
            forms = soup.find_all('form')
            for form in forms:
                if self._is_terms_form(form):
                    success = await self._submit_terms_form_enhanced(form, current_url)
                    if success:
                        return True
            
            # Strategy 2: Button/link clicking
            logger.info("Strategy 2: Button/link interaction")
            accept_elements = soup.find_all(['a', 'button', 'input'], 
                                          string=re.compile(r'accept|agree|continue', re.I))
            for element in accept_elements:
                success = await self._interact_with_accept_element(element, current_url)
                if success:
                    return True
            
            # Strategy 3: Cookie agreement
            logger.info("Strategy 3: Cookie agreement")
            success = await self._set_agreement_cookies_enhanced()
            if success:
                return True
            
            # Strategy 4: Direct navigation with delay
            logger.info("Strategy 4: Delayed direct access")
            await asyncio.sleep(random.uniform(8, 15))
            
            retry_response = await self._make_request('GET', EMMA_SEARCH_URL)
            if retry_response.status == 200:
                retry_content = await retry_response.text()
                if self._is_search_page(retry_content):
                    logger.info("Direct access successful after extended delay")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Terms page handling error: {e}")
            return False
    
    def _is_terms_form(self, form) -> bool:
        form_text = form.get_text().lower()
        form_attrs = str(form.attrs).lower()
        
        terms_indicators = ['accept', 'agree', 'terms', 'continue', 'consent']
        return any(indicator in form_text or indicator in form_attrs 
                  for indicator in terms_indicators)
    
    async def _submit_terms_form_enhanced(self, form, base_url) -> bool:
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            form_data = {}
            
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                if not name:
                    continue
                
                input_type = input_tag.get('type', 'text').lower()
                value = input_tag.get('value', '')
                
                if input_type == 'checkbox':
                    if any(term in name.lower() for term in ['agree', 'accept', 'terms', 'consent']):
                        form_data[name] = 'on' if not value else value
                elif input_type == 'radio':
                    if any(term in str(input_tag).lower() for term in ['accept', 'agree', 'yes']):
                        form_data[name] = value or '1'
                elif input_type == 'hidden':
                    form_data[name] = value
                elif input_type not in ['submit', 'button', 'image']:
                    form_data[name] = value
            
            if not form_data and any(term in str(form).lower() for term in ['agree', 'accept']):
                form_data['agree'] = '1'
                form_data['accepted'] = 'true'
            
            if action.startswith('http'):
                submit_url = action
            elif action:
                submit_url = urllib.parse.urljoin(str(base_url), action)
            else:
                submit_url = str(base_url)
            
            logger.info(f"Submitting terms form to: {submit_url}")
            
            if method == 'post':
                response = await self._make_request('POST', submit_url, data=form_data)
            else:
                response = await self._make_request('GET', submit_url, params=form_data)
            
            if response.status == 200:
                content = await response.text()
                return self._is_search_page(content)
                
            return False
            
        except Exception as e:
            logger.error(f"Enhanced form submission failed: {e}")
            return False
    
    async def _interact_with_accept_element(self, element, base_url) -> bool:
        try:
            href = element.get('href')
            onclick = element.get('onclick', '')
            
            if href and not href.startswith('javascript:'):
                if href.startswith('http'):
                    click_url = href
                else:
                    click_url = urllib.parse.urljoin(str(base_url), href)
                
                logger.info(f"Following accept link: {click_url}")
                
                response = await self._make_request('GET', click_url)
                if response.status == 200:
                    content = await response.text()
                    return self._is_search_page(content)
            
            elif onclick and 'submit' in onclick.lower():
                form = element.find_parent('form')
                if form:
                    return await self._submit_terms_form_enhanced(form, base_url)
                    
            return False
            
        except Exception as e:
            logger.error(f"Element interaction failed: {e}")
            return False
    
    async def _set_agreement_cookies_enhanced(self) -> bool:
        try:
            logger.info("Setting enhanced agreement cookies")
            
            agreement_cookies = [
                ('msrb_terms_accepted', '1'),
                ('emma_terms_accepted', '1'), 
                ('terms_agreement', 'true'),
                ('user_agreement', '1'),
                ('privacy_accepted', '1'),
                ('site_agreement', 'accepted'),
                ('legal_terms', 'agreed'),
                ('cookie_consent', '1'),
                ('terms_version', '2024'),
                ('user_consent', 'true'),
                ('agreement_timestamp', str(int(time.time()))),
                ('session_agreed', '1')
            ]
            
            emma_domain = aiohttp.yarl.URL('https://emma.msrb.org/')
            
            for name, value in agreement_cookies:
                self.session.cookie_jar.update_cookies({name: value}, response_url=emma_domain)
            
            test_urls = [EMMA_SEARCH_URL, "https://emma.msrb.org/Search", "https://emma.msrb.org/AdvancedSearch"]
            
            for test_url in test_urls:
                try:
                    await asyncio.sleep(random.uniform(2, 4))
                    response = await self._make_request('GET', test_url)
                    
                    if response.status == 200:
                        content = await response.text()
                        if self._is_search_page(content):
                            logger.info(f"Cookie agreement successful via {test_url}")
                            return True
                except Exception:
                    continue
                    
            return False
            
        except Exception as e:
            logger.error(f"Enhanced cookie setting failed: {e}")
            return False
    
    async def extract_pdf_text(self, pdf_content: bytes) -> Dict:
        if not PDF_PARSING_AVAILABLE:
            return {"text": "", "page_info": []}
        
        try:
            pdf_file = io.BytesIO(pdf_content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            total_pages = len(pdf_reader.pages)
            
            if MAX_PDF_PAGES == 0:
                max_pages = total_pages
                logger.debug(f"Processing all {total_pages} pages of PDF")
            else:
                max_pages = min(MAX_PDF_PAGES, total_pages)
                logger.debug(f"Processing {max_pages} of {total_pages} pages")
            
            if PROCESSING_MODE == "fast":
                page_range = list(range(min(5, max_pages)))
            elif PROCESSING_MODE == "thorough":
                page_range = list(range(max_pages))
                if total_pages > max_pages and MAX_PDF_PAGES > 0:
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
                        
                        if page_text.strip():
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
        try:
            await self._ensure_healthy_session()
            
            doc_headers = self.browser_headers.copy()
            doc_headers.update({
                'Referer': 'https://emma.msrb.org/Search/Search.aspx',
                'Accept': 'application/pdf,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate'
            })
            
            response = await self._make_request('GET', url, headers=doc_headers)
            
            if response.status not in [200, 206]:
                logger.warning(f"Document fetch failed: HTTP {response.status}")
                return {"text": "", "page_info": [], "file_size_kb": 0}
            
            content_type = response.headers.get('content-type', '').lower()
            content = await response.read()
            file_size_kb = len(content) // 1024
            
            logger.info(f"Document fetched: {file_size_kb}KB, type: {content_type}")
            
            if 'pdf' in content_type:
                pdf_result = await self.extract_pdf_text(content)
                pdf_result["file_size_kb"] = file_size_kb
                return pdf_result
            
            elif 'html' in content_type or 'text' in content_type:
                text_content = content.decode('utf-8', errors='ignore')
                clean_text = re.sub(r'<[^>]+>', ' ', text_content)
                clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                
                return {
                    "text": clean_text[:10000],
                    "page_info": [{"page_num": 1, "start_pos": 0, "end_pos": len(clean_text)}],
                    "file_size_kb": file_size_kb
                }
            
            return {"text": "", "page_info": [], "file_size_kb": file_size_kb}
            
        except Exception as e:
            logger.warning(f"Failed to fetch document content from {url}: {e}")
            return {"text": "", "page_info": [], "file_size_kb": 0}
    
    def should_process_immediately(self, title: str, estimated_size_kb: int, total_pages: int) -> bool:
        if estimated_size_kb > LARGE_FILE_THRESHOLD_KB or total_pages > COMPLEX_DOC_PAGE_THRESHOLD:
            return False
        
        urgent_keywords = [
            "bankruptcy", "default", "emergency", "crisis", "investigation", "fraud",
            "downgrade", "negative", "rating action", "material event", "notice"
        ]
        
        title_lower = title.lower()
        return any(keyword in title_lower for keyword in urgent_keywords)
    
    async def scrape_emma_search(self) -> List[Dict]:
        try:
            await self._ensure_healthy_session()
            
            search_params = {
                'searchBy': 'securityDescription',
                'sortBy': 'submissionDate', 
                'sortDir': 'desc',
                'pageSize': '50',
                'page': '1'
            }
            
            logger.info(f"Scraping EMMA with session: {self.session_state.session_id}")
            
            response = await self._make_request('GET', EMMA_SEARCH_URL, params=search_params)
            
            if response.status == 200:
                html_content = await response.text()
                
                if self._is_terms_page(html_content):
                    logger.warning("Unexpected terms page during search, re-establishing session...")
                    await self._establish_emma_session()
                    response = await self._make_request('GET', EMMA_SEARCH_URL, params=search_params)
                    if response.status == 200:
                        html_content = await response.text()
                        if self._is_terms_page(html_content):
                            logger.error("Still getting terms page after re-establishment")
                            return await self._try_alternative_search_endpoints()
                    else:
                        return await self._try_alternative_search_endpoints()
                
                if self._is_search_page(html_content) or len(html_content) > 5000:
                    parsed_results = await self._parse_emma_results(html_content)
                    if parsed_results:
                        logger.info(f"Successfully scraped {len(parsed_results)} EMMA entries")
                        return parsed_results
                    else:
                        logger.info("No results found, trying alternative endpoints...")
                        return await self._try_alternative_search_endpoints()
                else:
                    return await self._try_alternative_search_endpoints()
                    
            elif response.status == 429:
                logger.warning(f"Rate limited, waiting before retry...")
                await asyncio.sleep(random.uniform(15, 25))
                return []
                
            else:
                logger.warning(f"Search failed with HTTP {response.status}")
                return await self._try_alternative_search_endpoints()
            
        except Exception as e:
            logger.error(f"EMMA scraping error: {e}")
            return await self._try_alternative_search_endpoints()

    async def _try_alternative_search_endpoints(self) -> List[Dict]:
        logger.info("Trying alternative search endpoints...")
        
        test_endpoints = list(self.session_state.successful_endpoints)
        if not test_endpoints:
            test_endpoints = [
                "https://emma.msrb.org/Search",
                "https://emma.msrb.org/AdvancedSearch",
                "https://emma.msrb.org/QuickSearch"
            ]
        
        for endpoint in test_endpoints[:3]:
            try:
                logger.info(f"Trying search endpoint: {endpoint}")
                response = await self._make_request('GET', endpoint)
                
                if response.status == 200:
                    content = await response.text()
                    if self._is_search_page(content):
                        parsed_results = await self._parse_emma_results(content)
                        if parsed_results:
                            logger.info(f"Alternative endpoint success: {len(parsed_results)} results")
                            return parsed_results
                            
            except Exception as e:
                logger.debug(f"Alternative endpoint failed: {endpoint} → {e}")
                continue
        
        logger.warning("All alternative search endpoints failed")
        return []
    
    async def _parse_emma_results(self, html_content: str) -> List[Dict]:
        soup = BeautifulSoup(html_content, 'html.parser')
        entries = []
        
        layout = self.session_state.detected_layout or "unknown"
        logger.debug(f"Parsing with layout strategy: {layout}")
        
        if layout == "modern_spa":
            selectors_to_try = [
                ('.disclosure-card', 'a.disclosure-title', '.submission-date'),
                ('[data-testid*="disclosure"]', 'a', '.date-field'),
                ('.result-item', 'a.title-link', '.meta-date')
            ]
        elif layout == "table_based":
            selectors_to_try = [
                ('tr.disclosure-row', 'a.disclosure-link', 'td.date'),
                ('tbody tr', 'a[href*="SecurityDetails"]', 'td'),
                ('table tr', 'a', 'td, span')
            ]
        else:
            selectors_to_try = [
                ('div.disclosure-item', 'a', 'span.date, .date, .submission-date'),
                ('div[data-disclosure-id]', 'a', '.submission-date, .date'),
                ('div.search-result', 'a', '.date, .submission-date'),
                ('tr.disclosure-row', 'a.disclosure-link', 'td.date, span.date, .date'),
                ('tbody tr', 'a', 'td, span'),
                ('table tr', 'a[href*="SecurityDetails"], a[href*="disclosure"]', 'td, span, div'),
                ('div[class*="result"]', 'a', 'span, div'),
                ('div[class*="item"]', 'a', 'span, div'),
                ('tr', 'a[href*="SecurityDetails"], a[href*="disclosure"], a[href*="document"]', 'td, span, div'),
            ]
        
        for row_selector, link_selector, date_selector in selectors_to_try:
            rows = soup.select(row_selector)
            logger.debug(f"Layout {layout}, selector '{row_selector}': found {len(rows)} elements")
            
            if rows:
                valid_entries = 0
                for row in rows[:50]:
                    try:
                        title_elem = row.select_one(link_selector)
                        if not title_elem:
                            continue
                            
                        title = title_elem.get_text(strip=True)
                        link = title_elem.get('href', '')
                        
                        if (len(title) < 10 or 
                            title.lower() in ['home', 'search', 'menu', 'login', 'help', 
                                             'advanced search', 'quick search', 'about', 'contact',
                                             'sort by', 'filter', 'page', 'results'] or
                            not any(c.isalpha() for c in title) or
                            'javascript:' in link.lower() or
                            link.lower().startswith('#') or
                            title.lower().startswith('click') or
                            'button' in title.lower() or
                            len(title.split()) < 3):
                            continue
                        
                        if link and not link.startswith('http'):
                            link = f"https://emma.msrb.org{link}"
                        
                        published = ""
                        date_elem = row.select_one(date_selector)
                        if date_elem:
                            published = date_elem.get_text(strip=True)
                        
                        if not published or len(published) < 5:
                            row_text = row.get_text()
                            date_patterns = [
                                r'\d{1,2}/\d{1,2}/\d{4}',
                                r'\d{4}-\d{1,2}-\d{1,2}',
                                r'\b\w{3}\s+\d{1,2},\s+\d{4}\b',
                                r'\d{1,2}-\d{1,2}-\d{4}',
                            ]
                            
                            for pattern in date_patterns:
                                date_match = re.search(pattern, row_text)
                                if date_match:
                                    published = date_match.group()
                                    break
                        
                        if not published:
                            published = datetime.now().strftime('%m/%d/%Y')
                        
                        if (len(title) > 15 and 
                            link and 
                            link.startswith('http') and
                            any(keyword in title.lower() for keyword in 
                                ['report', 'disclosure', 'financial', 'audit', 'statement', 
                                 'bond', 'municipal', 'notice', 'official', 'budget', 
                                 'annual', 'quarterly', 'interim', 'material', 'event',
                                 'authority', 'district', 'county', 'city', 'state'])):
                            
                            item_id = f"emma_{abs(hash(f'{title}{link}{published}'))}"
                            
                            entries.append({
                                'title': title,
                                'link': link,
                                'published': published,
                                'id': item_id
                            })
                            valid_entries += 1
                            
                    except Exception as e:
                        logger.debug(f"Error parsing row: {e}")
                        continue
                
                if valid_entries > 0:
                    logger.info(f"Successfully parsed {valid_entries} entries using layout '{layout}' with selector: {row_selector}")
                    break
                else:
                    logger.debug(f"No valid entries found with selector: {row_selector}")
        
        if not entries:
            logger.warning("No entries found with layout-specific parsing, trying comprehensive fallback")
            entries = await self._fallback_parse_results(soup)
        
        logger.info(f"Total parsed entries: {len(entries)}")
        return entries
    
    async def _fallback_parse_results(self, soup) -> List[Dict]:
        entries = []
        
        all_links = soup.find_all('a', href=True)
        
        for link in all_links[:50]:
            href = link.get('href', '')
            title = link.get_text(strip=True)
            
            if (href and 
                len(title) > 20 and
                ('disclosure' in href.lower() or 
                 'document' in href.lower() or 
                 'security' in href.lower() or
                 'SecurityDetails' in href) and
                any(word in title.lower() for word in 
                    ['report', 'financial', 'disclosure', 'municipal', 'bond', 
                     'statement', 'audit', 'authority', 'district'])):
                
                if not href.startswith('http'):
                    href = f"https://emma.msrb.org{href}"
                
                entries.append({
                    'title': title,
                    'link': href,
                    'published': datetime.now().strftime('%m/%d/%Y'),
                    'id': f"emma_fallback_{abs(hash(f'{title}{href}'))}"
                })
                
                if len(entries) >= 10:
                    break
        
        logger.info(f"Fallback parsing found {len(entries)} entries")
        return entries

    async def scan_with_priority_processing(self) -> Dict[str, int]:
        if self.resource_monitor:
            self.resource_monitor.start_monitoring("enhanced_priority_scan")
        
        try:
            search_queries = await self.db.get_search_queries(active_only=True)
            
            if not search_queries:
                logger.info("No active search queries found")
                return {"processed": 0, "matches": 0, "queued": 0}
            
            session_stats = await self.db.get_session_stats(hours=1)
            logger.info(f"Session health: {session_stats.get('success_rate', 0)}% success rate, "
                       f"{session_stats.get('avg_response_time_ms', 0)}ms avg response time")
            
            logger.info("Fetching documents from EMMA with enhanced session management...")
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
                
                should_process_now = self.should_process_immediately(title, 0, 0)
                
                elapsed_minutes = (time.time() - processing_start_time) / 60
                if elapsed_minutes > PEAK_PROCESSING_TIME_LIMIT:
                    logger.info(f"Peak processing time limit reached ({PEAK_PROCESSING_TIME_LIMIT}m), queuing remaining documents")
                    should_process_now = False
                
                if (self.session_state.consecutive_failures > 2 or 
                    not self.session_state.is_healthy()):
                    logger.info("Session health degrading, queuing remaining documents for background processing")
                    should_process_now = False
                
                if should_process_now:
                    try:
                        logger.info(f"Immediate processing {processed_immediately + 1}: {title[:50]}...")
                        
                        if self.resource_monitor:
                            self.resource_monitor.log_progress(processed_immediately + 1, 
                                                             f"| Immediate processing | Session: {self.session_state.session_id[-8:]}")
                        
                        content_result = await self.fetch_document_content(url)
                        
                        file_size_kb = content_result.get("file_size_kb", 0)
                        pages_processed = content_result.get("pages_processed", 0)
                        
                        if file_size_kb > LARGE_FILE_THRESHOLD_KB or pages_processed > COMPLEX_DOC_PAGE_THRESHOLD:
                            logger.info(f"Document larger than expected ({file_size_kb}KB, {pages_processed}p), queuing for background processing")
                            await self.processing_queue.add_document(url, title, {
                                "pub_date": pub_date,
                                "guid": guid,
                                "file_size_kb": file_size_kb,
                                "estimated_pages": pages_processed
                            }, priority=2)
                            queued_for_later += 1
                            continue
                        
                        full_text = content_result["text"]
                        page_info = content_result["page_info"]
                        total_text_extracted += len(full_text)
                        
                        if len(full_text) > 100:
                            emma_direct_url = url
                            issuer_name = self._extract_issuer_name(title, full_text)
                            document_type = self._extract_document_type(title, full_text)
                            
                            searchable_text = f"{title} {full_text}"
                            
                            disclosure_id = await self.db.save_disclosure(
                                guid, title, url, emma_direct_url, pub_date, 
                                issuer_name, document_type, file_size_kb, pages_processed
                            )
                            
                            if disclosure_id:
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
                                    
                                    logger.info(f"IMMEDIATE MATCH: '{title[:50]}...' → {', '.join(query_names)}")
                                    if pages_mentioned:
                                        logger.info(f"   Pages: {sorted(pages_mentioned)} | Size: {file_size_kb}KB")
                        
                        processed_immediately += 1
                        
                    except Exception as e:
                        logger.error(f"Error in immediate processing: {e}")
                        await self.processing_queue.add_document(url, title, {
                            "pub_date": pub_date,
                            "guid": guid,
                            "error": str(e)
                        }, priority=2)
                        queued_for_later += 1
                
                else:
                    await self.processing_queue.add_document(url, title, {
                        "pub_date": pub_date,
                        "guid": guid
                    }, priority=2)
                    queued_for_later += 1
                    logger.debug(f"Queued for background: {title[:50]}...")
            
            if self.resource_monitor:
                self.resource_monitor.processing_stats["documents_queued"] = queued_for_later
                summary = self.resource_monitor.finish_monitoring()
                
                summary["session_info"] = {
                    "session_id": self.session_state.session_id,
                    "request_count": self.session_state.request_count,
                    "failure_count": self.session_state.failure_count,
                    "success_rate": ((self.session_state.request_count - self.session_state.failure_count) / 
                                    max(self.session_state.request_count, 1)) * 100,
                    "terms_accepted": self.session_state.terms_accepted
                }
                
                await self.db.save_resource_log(summary)
            
            logger.info(f"Enhanced priority scan complete:")
            logger.info(f"  Processed immediately: {processed_immediately}")
            logger.info(f"  Queued for background: {queued_for_later}")
            logger.info(f"  Immediate matches found: {total_matches}")
            logger.info(f"  Text extracted: {total_text_extracted:,} characters")
            logger.info(f"  Session health: {self.session_state.request_count} requests, "
                       f"{self.session_state.failure_count} failures")
            
            return {
                "processed": processed_immediately,
                "matches": total_matches,
                "queued": queued_for_later,
                "total_text_extracted": total_text_extracted,
                "processing_time_minutes": round((time.time() - processing_start_time) / 60, 1),
                "session_stats": {
                    "session_id": self.session_state.session_id,
                    "request_count": self.session_state.request_count,
                    "failure_count": self.session_state.failure_count,
                    "success_rate": round(((self.session_state.request_count - self.session_state.failure_count) / 
                                          max(self.session_state.request_count, 1)) * 100, 1)
                }
            }
            
        except Exception as e:
            logger.error(f"Error in enhanced priority processing: {e}")
            if self.resource_monitor:
                self.resource_monitor.processing_stats["processing_errors"] += 1
                summary = self.resource_monitor.finish_monitoring()
                await self.db.save_resource_log(summary)
            
            return {"processed": 0, "matches": 0, "queued": 0}

   async def process_background_queue(self, max_items: int = 20) -> Dict[str, int]:
    if self.resource_monitor:
        self.resource_monitor.start_monitoring("enhanced_background_processing")
    
    try:
        await self._ensure_healthy_session()
        
        ready_docs = await self.processing_queue.get_ready_documents(priority=2, limit=max_items)
        
        if not ready_docs:
            logger.info("No documents in background queue")
            return {"processed": 0, "matches": 0, "errors": 0}
        
        logger.info(f"Enhanced background processing: {len(ready_docs)} documents")
        # Add your document processing logic here
            processed = 0
            matches = 0
            errors = 0
            
            # Process the documents (add your actual logic here)
            for doc in ready_docs:
                try:
                    # Your document processing code goes here
                    processed += 1
                except Exception as doc_error:
                    logger.error(f"Error processing document: {doc_error}")
                    errors += 1
            
            return {"processed": processed, "matches": matches, "errors": errors}
            
        except Exception as e:
            logger.error(f"Error in background processing: {e}")
            return {"processed": 0, "matches": 0, "errors": 1}
        
        finally:
            if self.resource_monitor:
                self.resource_monitor.stop_monitoring("enhanced_background_processing")
