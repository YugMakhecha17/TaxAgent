from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os
from datetime import datetime, timedelta
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated, Literal
import operator
import uuid
from dotenv import load_dotenv
import sqlite3
import json
from contextlib import contextmanager
import jwt
import hashlib
import secrets
import requests
import PyPDF2
import io
from pathlib import Path

load_dotenv()

# GOOGLE OAUTH CONFIG 
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_OAUTH_CALLBACK_URL = os.getenv("GOOGLE_OAUTH_CALLBACK_URL", "http://localhost:3000/auth/callback")

# User can Upload docs (new for Config)
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".docx"}

# Google endpoints
GOOGLE_TOKEN_INFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


class GoogleOAuthValidator:
    """Validate and process Google OAuth tokens"""
    
    @staticmethod
    def verify_id_token(token: str) -> dict:
        """Verify Google ID token via tokeninfo endpoint"""
        try:
            response = requests.get(
                GOOGLE_TOKEN_INFO_ENDPOINT,
                params={"id_token": token},
                timeout=10
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Google ID token"
                )
            
            payload = response.json()
            
            if payload.get("aud") != GOOGLE_CLIENT_ID and GOOGLE_CLIENT_ID:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token audience mismatch"
                )
            
            import time
            current_time = int(time.time())
            exp_time = int(payload.get("exp", 0))
            
            if current_time > exp_time:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            return {
                "google_id": payload.get("sub"),
                "email": payload.get("email"),
                "name": payload.get("name"),
                "email_verified": payload.get("email_verified", False),
                "picture": payload.get("picture"),
                "token_type": "id_token"
            }
        
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to verify Google token: {str(e)}"
            )
    
    @staticmethod
    def verify_access_token(token: str) -> dict:
        """Verify Google access token and fetch user info"""
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(
                GOOGLE_USERINFO_ENDPOINT,
                headers=headers,
                timeout=10
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Google access token"
                )
            
            payload = response.json()
            
            return {
                "google_id": payload.get("sub"),
                "email": payload.get("email"),
                "name": payload.get("name"),
                "email_verified": payload.get("verified_email", False),
                "picture": payload.get("picture"),
                "token_type": "access_token"
            }
        
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to verify Google access token: {str(e)}"
            )
    
    @staticmethod
    def exchange_code_for_token(code: str) -> dict:
        """Exchange authorization code for tokens (server-side flow)"""
        try:
            payload = {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": GOOGLE_OAUTH_CALLBACK_URL
            }
            
            response = requests.post(
                GOOGLE_TOKEN_ENDPOINT,
                data=payload,
                timeout=10
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to exchange authorization code"
                )
            
            token_response = response.json()
            
            id_token = token_response.get("id_token")
            if not id_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No ID token in response"
                )
            
            user_info = GoogleOAuthValidator.verify_id_token(id_token)
            user_info["access_token"] = token_response.get("access_token")
            user_info["refresh_token"] = token_response.get("refresh_token")
            
            return user_info
        
        except requests.exceptions.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token exchange failed: {str(e)}"
            )


class GoogleAuthRequest(BaseModel):
    """Request model for Google authentication"""
    token: str
    token_type: Optional[str] = "id_token"


class GoogleCodeExchangeRequest(BaseModel):
    """Request model for authorization code exchange"""
    code: str


# ==================== DATABASE SETUP ====================

DATABASE_PATH = "tax_intelligence.db"

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_db():
    """Initialize database schema with enhanced features"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                name TEXT NOT NULL,
                google_id TEXT UNIQUE,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        ''')
        
        # Enhanced Sessions table with title
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                title TEXT DEFAULT 'New Chat',
                created_at TEXT NOT NULL,
                last_query_time TEXT NOT NULL,
                metadata TEXT,
                is_archived INTEGER DEFAULT 0
            )
        ''')
        
        # Enhanced Messages table with embedding support
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                token_count INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id) ON DELETE CASCADE
            )
        ''')
        
        # Chat Memory table for long-term context
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_memory (
                memory_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                summary TEXT NOT NULL,
                key_points TEXT,
                timestamp TEXT NOT NULL,
                message_range TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id) ON DELETE CASCADE
            )
        ''')
        
        # Uploaded Files table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS uploaded_files (
                file_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                extracted_text TEXT,
                summary TEXT,
                upload_timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
            )
        ''')
        
        # Query history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS query_history (
                query_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                query_text TEXT NOT NULL,
                user_category TEXT,
                query_intent TEXT,
                target_agent TEXT,
                response TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id) ON DELETE CASCADE
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_history_session ON query_history(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_last_query ON sessions(last_query_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_memory_session ON chat_memory(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uploaded_files_session ON uploaded_files(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uploaded_files_user ON uploaded_files(user_id)')


# ==================== AUTHENTICATION ====================

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

security = HTTPBearer()

def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash"""
    return hash_password(password) == password_hash

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ==================== FILE PROCESSING ====================

class FileProcessor:
    """Handle file upload and text extraction"""
    
    @staticmethod
    def extract_text_from_pdf(file_content: bytes) -> str:
        """Extract text from PDF file"""
        try:
            pdf_file = io.BytesIO(file_content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text.strip()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error extracting PDF text: {str(e)}")
    
    @staticmethod
    def extract_text_from_txt(file_content: bytes) -> str:
        """Extract text from TXT file"""
        try:
            return file_content.decode('utf-8')
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading text file: {str(e)}")
    
    @staticmethod
    def save_file(user_id: str, session_id: str, file: UploadFile) -> dict:
        """Save uploaded file and extract text"""
        file_ext = Path(file.filename).suffix.lower()
        
        if file_ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
            )
        
        file_content = file.file.read()
        file_size = len(file_content)
        
        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File size exceeds maximum allowed size of {MAX_FILE_SIZE / (1024*1024)}MB"
            )
        
        file_id = str(uuid.uuid4())
        user_dir = UPLOAD_DIR / user_id / session_id
        user_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = user_dir / f"{file_id}{file_ext}"
        
        with open(file_path, "wb") as f:
            f.write(file_content)
        
        # Extract text based on file type
        if file_ext == ".pdf":
            extracted_text = FileProcessor.extract_text_from_pdf(file_content)
        elif file_ext == ".txt":
            extracted_text = FileProcessor.extract_text_from_txt(file_content)
        else:
            extracted_text = "Text extraction not supported for this file type"
        
        return {
            "file_id": file_id,
            "filename": file.filename,
            "file_path": str(file_path),
            "file_type": file_ext,
            "file_size": file_size,
            "extracted_text": extracted_text
        }


class FileManager:
    """Manage file database operations"""
    
    @staticmethod
    def save_file_record(user_id: str, session_id: str, file_info: dict, summary: str = None) -> dict:
        """Save file record to database"""
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO uploaded_files 
                (file_id, session_id, user_id, filename, file_path, file_type, 
                 file_size, extracted_text, summary, upload_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_info["file_id"],
                session_id,
                user_id,
                file_info["filename"],
                file_info["file_path"],
                file_info["file_type"],
                file_info["file_size"],
                file_info["extracted_text"],
                summary,
                now
            ))
        
        return {
            "file_id": file_info["file_id"],
            "filename": file_info["filename"],
            "upload_timestamp": now
        }
    
    @staticmethod
    def get_session_files(session_id: str) -> List[dict]:
        """Get all files uploaded in a session"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_id, filename, file_type, file_size, summary, upload_timestamp
                FROM uploaded_files
                WHERE session_id = ?
                ORDER BY upload_timestamp DESC
            ''', (session_id,))
            files = cursor.fetchall()
            return [dict(f) for f in files]
    
    @staticmethod
    def get_file_content(file_id: str, user_id: str) -> dict:
        """Get file content and metadata"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_id, filename, file_path, extracted_text, summary
                FROM uploaded_files
                WHERE file_id = ? AND user_id = ?
            ''', (file_id, user_id))
            file = cursor.fetchone()
            
            if not file:
                raise HTTPException(status_code=404, detail="File not found")
            
            return dict(file)


# ==================== ENHANCED MEMORY SYSTEM ====================

class ChatMemoryManager:
    """Manage long-term chat memory with summarization"""
    
    @staticmethod
    def create_memory_summary(llm, messages: List[dict]) -> dict:
        """Create a summary of recent messages"""
        if len(messages) < 5:
            return None
        
        conversation_text = "\n".join([
            f"{msg['role']}: {msg['content']}" for msg in messages
        ])
        
        summary_prompt = f"""Summarize the following tax-related conversation into key points and context:

{conversation_text}

Provide:
1. Main topics discussed
2. Key decisions or findings
3. Important context to remember

Keep it concise (max 200 words)."""

        try:
            response = llm.invoke([HumanMessage(content=summary_prompt)])
            return {
                "summary": response.content,
                "message_count": len(messages)
            }
        except Exception as e:
            print(f"Error creating summary: {e}")
            return None
    
    @staticmethod
    def save_memory(session_id: str, summary: str, key_points: str, message_range: str):
        """Save memory summary to database"""
        memory_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO chat_memory (memory_id, session_id, summary, key_points, timestamp, message_range)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (memory_id, session_id, summary, key_points, now, message_range))
    
    @staticmethod
    def get_session_memory(session_id: str) -> List[dict]:
        """Get all memory summaries for a session"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT summary, key_points, timestamp
                FROM chat_memory
                WHERE session_id = ?
                ORDER BY timestamp DESC
            ''', (session_id,))
            memories = cursor.fetchall()
            return [dict(m) for m in memories]


class UserManager:
    """Manage user database operations"""
    
    @staticmethod
    def create_user(email: str, name: str, password: Optional[str] = None, google_id: Optional[str] = None) -> dict:
        """Create new user"""
        user_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        password_hash = hash_password(password) if password else None
        
        with get_db() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (user_id, email, password_hash, name, google_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, email, password_hash, name, google_id, now))
            except sqlite3.IntegrityError:
                raise HTTPException(status_code=400, detail="Email already registered")
        
        return {
            "user_id": user_id,
            "email": email,
            "name": name,
            "created_at": now
        }
    
    @staticmethod
    def get_user_by_email(email: str) -> Optional[dict]:
        """Get user by email"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def get_user_by_google_id(google_id: str) -> Optional[dict]:
        """Get user by Google ID"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE google_id = ?', (google_id,))
            user = cursor.fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def get_user_by_id(user_id: str) -> Optional[dict]:
        """Get user by ID"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT user_id, email, name, created_at, last_login FROM users WHERE user_id = ?', (user_id,))
            user = cursor.fetchone()
            return dict(user) if user else None
    
    @staticmethod
    def update_last_login(user_id: str):
        """Update last login time"""
        now = datetime.now().isoformat()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = ? WHERE user_id = ?', (now, user_id))


class SessionManager:
    """Manage session database operations with enhanced features"""
    
    @staticmethod
    def generate_session_title(query: str) -> str:
        """Generate a concise title from the first query"""
        words = query.split()[:6]
        title = " ".join(words)
        if len(query.split()) > 6:
            title += "..."
        return title
    
    @staticmethod
    def create_session(user_id: Optional[str] = None, title: str = "New Chat") -> dict:
        """Create new session"""
        session_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, user_id, title, created_at, last_query_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, user_id, title, now, now))
        
        return {
            "session_id": session_id,
            "user_id": user_id,
            "title": title,
            "created_at": now,
            "last_query_time": now
        }
    
    @staticmethod
    def update_session_title(session_id: str, title: str):
        """Update session title"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET title = ? WHERE session_id = ?
            ''', (title, session_id))
    
    @staticmethod
    def get_user_sessions(user_id: str, include_archived: bool = False) -> List[dict]:
        """Get all sessions for a user"""
        with get_db() as conn:
            cursor = conn.cursor()
            query = '''
                SELECT session_id, title, created_at, last_query_time, is_archived
                FROM sessions
                WHERE user_id = ?
            '''
            if not include_archived:
                query += ' AND is_archived = 0'
            query += ' ORDER BY last_query_time DESC'
            
            cursor.execute(query, (user_id,))
            sessions = cursor.fetchall()
            return [dict(session) for session in sessions]
    
    @staticmethod
    def get_session(session_id: str) -> Optional[dict]:
        """Retrieve session with all messages"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            session = cursor.fetchone()
            
            if not session:
                return None
            
            cursor.execute('''
                SELECT message_id, role, content, timestamp 
                FROM messages 
                WHERE session_id = ? 
                ORDER BY timestamp ASC
            ''', (session_id,))
            messages = cursor.fetchall()
            
            return {
                "session_id": session["session_id"],
                "title": session["title"],
                "created_at": session["created_at"],
                "last_query_time": session["last_query_time"],
                "messages": [dict(msg) for msg in messages]
            }
    
    @staticmethod
    def add_message(session_id: str, role: str, content: str) -> dict:
        """Add message to session"""
        message_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        token_count = len(content.split())  # Simple token estimation
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO messages (message_id, session_id, role, content, timestamp, token_count)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (message_id, session_id, role, content, now, token_count))
            
            cursor.execute('''
                UPDATE sessions 
                SET last_query_time = ? 
                WHERE session_id = ?
            ''', (now, session_id))
        
        return {
            "message_id": message_id,
            "role": role,
            "content": content,
            "timestamp": now
        }
    
    @staticmethod
    def get_conversation_history(session_id: str, limit: int = 20) -> List[dict]:
        """Get extended conversation history with memory"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Get recent messages
            cursor.execute('''
                SELECT role, content, timestamp 
                FROM messages 
                WHERE session_id = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (session_id, limit))
            messages = cursor.fetchall()
            
            # Get memory summaries
            cursor.execute('''
                SELECT summary, timestamp
                FROM chat_memory
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT 3
            ''', (session_id,))
            memories = cursor.fetchall()
            
            # Combine memory context with recent messages
            context = []
            if memories:
                context.append({
                    "role": "system",
                    "content": "Previous conversation context: " + "; ".join([m["summary"] for m in memories]),
                    "timestamp": memories[0]["timestamp"]
                })
            
            context.extend([dict(msg) for msg in reversed(messages)])
            return context
    
    @staticmethod
    def delete_session(session_id: str) -> bool:
        """Delete session and all associated data"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
            if not cursor.fetchone():
                return False
            
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            return True
    
    @staticmethod
    def archive_session(session_id: str):
        """Archive a session"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET is_archived = 1 WHERE session_id = ?
            ''', (session_id,))


class QueryHistoryManager:
    """Manage query history for analytics"""
    
    @staticmethod
    def log_query(session_id: str, query_text: str, user_category: str, 
                  query_intent: str, target_agent: str, response: str) -> str:
        """Log query for analytics"""
        query_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO query_history 
                (query_id, session_id, query_text, user_category, query_intent, target_agent, response, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (query_id, session_id, query_text, user_category, query_intent, target_agent, response, now))
        
        return query_id
    
    @staticmethod
    def get_session_queries(session_id: str) -> List[dict]:
        """Get all queries in a session"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT query_id, query_text, user_category, query_intent, target_agent, timestamp
                FROM query_history 
                WHERE session_id = ? 
                ORDER BY timestamp DESC
            ''', (session_id,))
            queries = cursor.fetchall()
            
            return [dict(q) for q in queries]
    
    @staticmethod
    def get_analytics() -> dict:
        """Get system-wide analytics"""
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as total_queries FROM query_history')
            total_queries = cursor.fetchone()["total_queries"]
            
            cursor.execute('''
                SELECT query_intent, COUNT(*) as count 
                FROM query_history 
                GROUP BY query_intent
            ''')
            intent_distribution = {row["query_intent"]: row["count"] for row in cursor.fetchall()}
            
            cursor.execute('''
                SELECT user_category, COUNT(*) as count 
                FROM query_history 
                GROUP BY user_category
            ''')
            category_distribution = {row["user_category"]: row["count"] for row in cursor.fetchall()}
            
            cursor.execute('SELECT COUNT(*) as total_sessions FROM sessions')
            total_sessions = cursor.fetchone()["total_sessions"]
            
            return {
                "total_queries": total_queries,
                "total_sessions": total_sessions,
                "intent_distribution": intent_distribution,
                "category_distribution": category_distribution
            }


# ==================== FASTAPI SETUP (on localhost docs) ====================

app = FastAPI(
    title="Tax Intelligence API",
    description="Multi-agent Tax Query system with SQLite persistence and file upload",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    """Initialize database on startup"""
    init_db()


# ==================== STATE & MODELS ====================

class TaxState(TypedDict):
    messages: Annotated[list, operator.add]
    query: str
    user_category: Optional[str]
    query_intent: Optional[str]
    dynamic_updates: Optional[str]
    static_legal_info: Optional[str]
    ai_derived_analysis: Optional[str]
    conversation_history: Annotated[list, operator.add]
    relevant_context: Optional[str]
    target_agent: Optional[str]
    needs_follow_up: bool
    last_update_time: str
    final_response: str
    uploaded_files_context: Optional[str]


class QueryRequest(BaseModel):
    query: str
    user_category: Optional[str] = None


class QueryResponse(BaseModel):
    id: str
    query: str
    user_category: str
    query_intent: str
    target_agent: str
    final_response: str
    timestamp: str


class ConversationMessage(BaseModel):
    message_id: str
    role: str
    content: str
    timestamp: str


class ConversationSession(BaseModel):
    session_id: str
    title: str
    messages: List[ConversationMessage]
    created_at: str
    last_query_time: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class FileUploadResponse(BaseModel):
    file_id: str
    filename: str
    file_size: int
    extracted_text_preview: str
    summary: Optional[str]
    upload_timestamp: str


class UpdateTitleRequest(BaseModel):
    title: str


# ==================== Tax Agents ====================

class QueryRouter:
    def __init__(self, llm):
        self.llm = llm
        self.routing_prompt = """You are an AI Tax query classification expert.

Analyze the user's query and classify it into ONE primary category:

1. DYNAMIC_UPDATE: Recent news, latest circulars, current GST rates, recent policy changes,
   PIB releases, RBI updates, ongoing reforms, "what's new", "latest updates"

2. LEGAL_CLARIFICATION: CGST/SGST/IGST Act sections, constitutional provisions,
   legal definitions, compliance rules, statutory requirements, "what does the law say"

3. ANALYTICAL: Explanations, interpretations, sector-wise implications, FAQs,
   "how does this affect", "explain in simple terms", comparisons

4. TAX_KNOWLEDGE: Income tax calculations, deductions, filing procedures,
   slab-related queries, TDS, professional tax, personal/business tax questions

Also identify user category: citizen, business_owner, accountant, govt_employee, student, other

Query: {query}

Respond ONLY in this exact format:
INTENT: [DYNAMIC_UPDATE/LEGAL_CLARIFICATION/ANALYTICAL/TAX_KNOWLEDGE]
CATEGORY: [user_category]
CONFIDENCE: [HIGH/MEDIUM/LOW]
NEEDS_FOLLOW_UP: [YES/NO]
REASONING: [one line explanation]
"""

    def route(self, state: TaxState) -> TaxState:
        try:
            response = self.llm.invoke([
                HumanMessage(content=self.routing_prompt.format(query=state['query']))
            ])

            lines = response.content.strip().split('\n')
            for line in lines:
                if 'INTENT:' in line:
                    intent = line.split(':')[1].strip().lower()
                    state['query_intent'] = intent
                elif 'CATEGORY:' in line:
                    state['user_category'] = line.split(':')[1].strip()
                elif 'NEEDS_FOLLOW_UP:' in line:
                    state['needs_follow_up'] = 'YES' in line

            intent_map = {
                'dynamic_update': 'dynamic',
                'legal_clarification': 'static',
                'analytical': 'analytical',
                'tax_knowledge': 'tax'
            }
            
            mapped_intent = state['query_intent'].replace(' ', '_').lower()
            state['target_agent'] = intent_map.get(mapped_intent, 'analytical')

        except Exception as e:
            print(f"Router error: {e}")
            state['target_agent'] = 'analytical'
            state['query_intent'] = 'analytical'

        return state


class DynamicLayerAgent:
    def __init__(self, llm):
        self.llm = llm
        self.system_prompt = """You are an AI assistant specializing in Government Policy Updates for GST and Taxation.

General Behaviour

If the user greets you (e.g., Hi, Hello, Hey), reply with a brief, friendly greeting and a short, polite offer to help, without asking them to specify a tax query.

For example: Hello, How may I help you?
Only switch to policy-update mode when the user asks a GST or tax-related question.

If the user asks a policy-related question, follow the full structured format below.

Always stay polite, concise, and approachable.

Response Style Requirements

Use simple and accurate language.

Be polite, conversational, and helpful.

Keep answers short and clear (3–4 brief paragraphs).

Start with the latest official update when responding to policy questions.

Use bullet points for multiple items.

Maintain a tone that is friendly but factual.

Content Requirements (Only When User Asks a GST/Tax Policy Question)
1. Latest Official Updates

Provide only verified updates from:

CBIC

GST Council

PIB

RBI

Include official dates and notification numbers, if available.

2. Key Decisions or Policy Changes

Include:

Updates to GST rules, procedures, or rates

Council decisions

Effective dates / notification links

3. Ongoing or Proposed Reforms

Include only if:

Officially announced

Under implementation or public consultation

Formatting Rules

Use bold for dates, authorities, and notifications.

Use reverse-chronological order (newest first).

Write in a simple, polite, approachable tone.

User Context

Context: {context}
User Category: {category}
Uploaded Files Context: {files_context}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            files_context = state.get('uploaded_files_context', 'No files uploaded')
            
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general'),
                    files_context=files_context
                )),
                HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly and concisely. Maximum 3-4 paragraphs.")
            ]

            response = self.llm.invoke(messages)
            state['dynamic_updates'] = response.content
            state['final_response'] = response.content
            state['messages'].append(AIMessage(content=response.content))

        except Exception as e:
            state['final_response'] = f"Error in Dynamic Agent: {str(e)}"

        return state

    def _build_context(self, history: list) -> str:
        if not history:
            return "No previous context."
        recent = history[-5:]
        return "Recent conversation: " + "; ".join([
            f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" 
            for item in recent if item.get('content')
        ])


class StaticLayerAgent:
    def __init__(self, llm):
        self.llm = llm
        self.system_prompt = """You are an AI assistant that provides precise legal references for GST and Taxation.

General Behaviour

If a user greets you (e.g., Hi/Hello/Hey), reply with a short, polite greeting and a light offer to help, without requesting their query.
For example: Hello, How may I help you?
Only switch to legal-reference mode when the user actually asks a GST/tax legal question.

Always remain polite, concise, and neutral.

Response Style Requirements

Use simple, clear, and strictly accurate language.

Be brief and focused, with a maximum of 3–4 short paragraphs.

Do not provide explanations unless the user asks.

Do not give examples, background notes, FAQs, or commentary.

Content Requirements (Only When the User Asks a Legal Question)
1. Relevant Legal Sections

Provide exact section numbers from:

CGST Act

SGST Acts

IGST Act

Official notifications or circulars

2. Constitutional Articles

Include only if relevant:

Article 246A

Article 269A

Article 279A

3. Statutory Wording (1–2 lines)

Provide a brief extract or a neutral, factual summary — no interpretation.

4. Cross-References

Add only when legally necessary to complete the statutory link.

Formatting Rules

Use bold for section numbers, article numbers, and notification references.

Use bullet points for multiple provisions.

Do not add commentary, opinion, analysis, advice, or assumptions.

User Context
Context: {context}
User Category: {category}
Uploaded Files Context: {files_context}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            files_context = state.get('uploaded_files_context', 'No files uploaded')
            
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general'),
                    files_context=files_context
                )),
                HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly with specific act sections. Maximum 3-4 paragraphs.")
            ]

            response = self.llm.invoke(messages)
            state['static_legal_info'] = response.content
            state['final_response'] = response.content
            state['messages'].append(AIMessage(content=response.content))

        except Exception as e:
            state['final_response'] = f"Error in Static Agent: {str(e)}"

        return state

    def _build_context(self, history: list) -> str:
        if not history:
            return "No previous context."
        recent = history[-5:]
        return "Recent conversation: " + "; ".join([
            f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" 
            for item in recent if item.get('content')
        ])


class AnalyticalLayerAgent:
    def __init__(self, llm):
        self.llm = llm
        self.system_prompt = """You are an AI assistant that provides clear GST and Tax analysis with direct results.

General Behaviour

When the user greets you (e.g., Hi, Hello, Hey), respond with a short, polite greeting and a gentle offer to assist, without asking them to state their question.
For example: Hello, How may I help you?

Only switch to analytical mode when they ask a GST or tax-related query.

Always maintain a polite, concise, and professional tone.

Response Style Requirements

Use simple, professional, easy-to-read language.

Limit responses to 4–5 short paragraphs.

Always begin with the direct answer or calculation result.

Do not include background text, filler, or FAQs unless requested.

Content Requirements (Only When User Asks a GST/Tax Analysis Question)
1. Direct Answer

Provide the exact outcome, figure, or computation result in the first line.
Use bold for important values (₹ amounts, FY, Section references).

2. Short Explanation (1–2 lines)

Give a brief, neutral line on why the result applies.

3. Key Implications

Add 2–3 bullet points summarizing compliance or practical impact.

4. Actionable Insight (if relevant)

Offer one short step that helps the user continue.

If the user has uploaded tax documents, analyze them in context of their query.

Formatting Rules

Use bold for amounts, sections, and key terms.

Use bullet points for implications or steps.

Keep paragraphs short, clean, and well-structured.

User Context

Context: {context}
User Category: {category}
Uploaded Files Context: {files_context}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            files_context = state.get('uploaded_files_context', 'No files uploaded')
            
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general'),
                    files_context=files_context
                )),
                HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly and concisely. Maximum 4-5 paragraphs.")
            ]

            response = self.llm.invoke(messages)
            state['ai_derived_analysis'] = response.content
            state['final_response'] = response.content
            state['messages'].append(AIMessage(content=response.content))

        except Exception as e:
            state['final_response'] = f"Error in Analytical Agent: {str(e)}"

        return state

    def _build_context(self, history: list) -> str:
        if not history:
            return "No previous context."
        recent = history[-5:]
        return "Recent conversation: " + "; ".join([
            f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" 
            for item in recent if item.get('content')
        ])


class TaxKnowledgeAgent:
    def __init__(self, llm):
        self.llm = llm
        self.system_prompt = """You are an AI Tax Analyst specializing in Indian taxation (GST, Income Tax, Professional Tax).

CRITICAL INSTRUCTIONS:
General Behaviour

When the user greets you (e.g., Hi, Hello, Hey), respond with a short, polite greeting and a gentle offer to assist, without asking them to state their question.
For example: Hello, How may I help you?

Be extremely concise — answer ONLY what is asked.

Maximum 4–5 short paragraphs.

Start with the direct answer (rate, rule, computation, exemption, section).

No intros, no disclaimers, no filler.

No examples or background unless explicitly asked.

Your Response Must Include:

Direct Answer — final tax position, computation, applicability, or compliance requirement.

Short Explanation (1–2 lines) — why this applies (section/rule only if needed).

Key Implications (2–3 bullets) — practical impact or conditions.

Actionable Steps — only if the user needs to file, claim, pay, or comply.

If the user has uploaded tax documents, analyze them thoroughly and provide insights.

Formatting Rules:

Use bold for amounts, rates, sections, and key terms.

Use bullet points for implications and steps.

Keep language simple, precise, and professional.

Context: {context}
User Category: {category}
Uploaded Files Context: {files_context}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            files_context = state.get('uploaded_files_context', 'No files uploaded')
            
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general'),
                    files_context=files_context
                )),
                HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly and concisely. Maximum 4–5 paragraphs.")
            ]

            response = self.llm.invoke(messages)
            state['ai_derived_analysis'] = response.content
            state['final_response'] = response.content
            state['messages'].append(AIMessage(content=response.content))

        except Exception as e:
            state['final_response'] = f"Error in Tax Knowledge Agent: {str(e)}"

        return state

    def _build_context(self, history: list) -> str:
        if not history:
            return "No previous context."
        recent = history[-5:]
        return "Recent conversation: " + "; ".join([
            f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" 
            for item in recent if item.get('content')
        ])


# ==================== GRAPH BUILDING ====================

def route_to_agent(state: TaxState) -> Literal["dynamic", "static", "analytical", "tax", "end"]:
    target = state.get('target_agent')
    return target if target else "end"


def build_gst_graph(llm):
    router_llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash-lite",
        temperature=0,
        max_tokens=200,
        api_key=os.getenv("GOOGLE_API_KEY")
    )

    router = QueryRouter(router_llm)
    dynamic_agent = DynamicLayerAgent(llm)
    static_agent = StaticLayerAgent(llm)
    analytical_agent = AnalyticalLayerAgent(llm)
    tax_agent = TaxKnowledgeAgent(llm)

    workflow = StateGraph(TaxState)

    workflow.add_node("router", router.route)
    workflow.add_node("dynamic", dynamic_agent.run)
    workflow.add_node("static", static_agent.run)
    workflow.add_node("analytical", analytical_agent.run)
    workflow.add_node("tax", tax_agent.run)

    workflow.set_entry_point("router")

    workflow.add_conditional_edges(
        "router",
        route_to_agent,
        {
            "dynamic": "dynamic",
            "static": "static",
            "analytical": "analytical",
            "tax": "tax",
            "end": END
        }
    )

    workflow.add_edge("dynamic", END)
    workflow.add_edge("static", END)
    workflow.add_edge("analytical", END)
    workflow.add_edge("tax", END)

    return workflow.compile()


# ==================== API ENDPOINTS (updated) ====================

@app.get("/")
async def root():
    return {
        "message": "Tax Intelligence API v2.0",
        "version": "2.0.0",
        "features": ["Multi-agent Tax Assistant", "Long-term Memory", "File Upload", "Chat History"],
        "endpoints": {
            "auth": "/auth/* (Register, Login, Google OAuth)",
            "query": "/query (POST)",
            "session": "/session/* (POST/GET/DELETE)",
            "files": "/files/* (POST/GET)",
            "analytics": "/analytics (GET)",
            "health": "/health (GET)"
        }
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/auth/register", response_model=AuthResponse)
async def register(request: RegisterRequest):
    """Register a new user"""
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    user = UserManager.create_user(
        email=request.email,
        name=request.name,
        password=request.password
    )
    
    access_token = create_access_token(data={"sub": user["user_id"]})
    UserManager.update_last_login(user["user_id"])
    
    return AuthResponse(
        access_token=access_token,
        user={
            "user_id": user["user_id"],
            "email": user["email"],
            "name": user["name"]
        }
    )


@app.post("/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    """Login user"""
    user = UserManager.get_user_by_email(request.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": user["user_id"]})
    UserManager.update_last_login(user["user_id"])
    
    return AuthResponse(
        access_token=access_token,
        user={
            "user_id": user["user_id"],
            "email": user["email"],
            "name": user["name"]
        }
    )


@app.post("/auth/google", response_model=AuthResponse)
async def google_auth(request: GoogleAuthRequest):
    """Authenticate with Google token"""
    try:
        token = request.token.strip()
        token_type = (request.token_type or 'id_token').lower()
        
        if token_type == 'id_token':
            user_info = GoogleOAuthValidator.verify_id_token(token)
        elif token_type == 'access_token':
            user_info = GoogleOAuthValidator.verify_access_token(token)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type. Use 'id_token' or 'access_token'"
            )
        
        google_id = user_info.get("google_id")
        email = user_info.get("email")
        name = user_info.get("name") or email.split('@')[0]
        
        if not google_id or not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to extract user info from token"
            )
        
        existing_user = UserManager.get_user_by_google_id(google_id)
        
        if not existing_user:
            email_user = UserManager.get_user_by_email(email)
            
            if email_user:
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'UPDATE users SET google_id = ? WHERE user_id = ?',
                        (google_id, email_user['user_id'])
                    )
                user = UserManager.get_user_by_id(email_user['user_id'])
            else:
                user = UserManager.create_user(
                    email=email,
                    name=name,
                    google_id=google_id
                )
        else:
            user = existing_user
        
        access_token = create_access_token(data={'sub': user['user_id']})
        UserManager.update_last_login(user['user_id'])
        
        return AuthResponse(
            access_token=access_token,
            user={
                'user_id': user['user_id'],
                'email': user['email'],
                'name': user['name']
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Google authentication error: {str(e)}'
        )


@app.post("/auth/google/callback", response_model=AuthResponse)
async def google_callback(request: GoogleCodeExchangeRequest):
    """Handle Google OAuth authorization code exchange"""
    try:
        user_info = GoogleOAuthValidator.exchange_code_for_token(request.code)
        
        google_id = user_info.get("google_id")
        email = user_info.get("email")
        name = user_info.get("name") or email.split('@')[0]
        
        if not google_id or not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to extract user info from token"
            )
        
        existing_user = UserManager.get_user_by_google_id(google_id)
        
        if not existing_user:
            email_user = UserManager.get_user_by_email(email)
            
            if email_user:
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'UPDATE users SET google_id = ? WHERE user_id = ?',
                        (google_id, email_user['user_id'])
                    )
                user = UserManager.get_user_by_id(email_user['user_id'])
            else:
                user = UserManager.create_user(
                    email=email,
                    name=name,
                    google_id=google_id
                )
        else:
            user = existing_user
        
        access_token = create_access_token(data={'sub': user['user_id']})
        UserManager.update_last_login(user['user_id'])
        
        return AuthResponse(
            access_token=access_token,
            user={
                'user_id': user['user_id'],
                'email': user['email'],
                'name': user['name']
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Authorization code exchange failed: {str(e)}'
        )


@app.get("/auth/me")
async def get_current_user(user_id: str = Depends(verify_token)):
    """Get current user information"""
    user = UserManager.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ==================== SESSION ENDPOINTS ====================

@app.post("/session")
async def create_session(user_id: str = Depends(verify_token)) -> ConversationSession:
    """Create a new chat session"""
    session = SessionManager.create_session(user_id)
    return ConversationSession(
        session_id=session["session_id"],
        title=session["title"],
        messages=[],
        created_at=session["created_at"],
        last_query_time=session["last_query_time"]
    )


@app.get("/sessions")
async def get_user_sessions(user_id: str = Depends(verify_token)):
    """Get all chat sessions for current user"""
    sessions = SessionManager.get_user_sessions(user_id)
    return {"sessions": sessions, "total": len(sessions)}


@app.get("/session/{session_id}", response_model=ConversationSession)
async def get_session(session_id: str, user_id: str = Depends(verify_token)):
    """Get a specific chat session with all messages"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return ConversationSession(
        session_id=session["session_id"],
        title=session["title"],
        messages=[ConversationMessage(**msg) for msg in session["messages"]],
        created_at=session["created_at"],
        last_query_time=session["last_query_time"]
    )


@app.patch("/session/{session_id}/title")
async def update_session_title(
    session_id: str, 
    request: UpdateTitleRequest,
    user_id: str = Depends(verify_token)
):
    """Update chat session title"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    SessionManager.update_session_title(session_id, request.title)
    return {"message": "Title updated successfully", "title": request.title}


@app.post("/session/{session_id}/query", response_model=QueryResponse)
async def process_query_with_session(
    session_id: str, 
    request: QueryRequest, 
    user_id: str = Depends(verify_token)
):
    """Process a query within a chat session with extended memory"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(status_code=500, detail="GOOGLE_API_KEY not configured")

        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            temperature=0.7,
            api_key=api_key
        )

        # Get extended conversation history (last 20 messages + memory summaries)
        history = SessionManager.get_conversation_history(session_id, limit=20)
        
        # Get uploaded files context
        session_files = FileManager.get_session_files(session_id)
        files_context = "No files uploaded"
        if session_files:
            files_context = "Uploaded files:\n" + "\n".join([
                f"- {f['filename']}: {f.get('summary', 'No summary')[:200]}"
                for f in session_files[:3]  # Include context from last 3 files
            ])

        app_graph = build_gst_graph(llm)

        initial_state = {
            "messages": [],
            "query": request.query,
            "user_category": request.user_category or "general",
            "query_intent": None,
            "dynamic_updates": None,
            "static_legal_info": None,
            "ai_derived_analysis": None,
            "conversation_history": history,
            "relevant_context": None,
            "target_agent": None,
            "needs_follow_up": False,
            "last_update_time": datetime.now().isoformat(),
            "final_response": "",
            "uploaded_files_context": files_context
        }

        result = app_graph.invoke(initial_state)

        # Save messages
        SessionManager.add_message(session_id, "user", request.query)
        SessionManager.add_message(session_id, "assistant", result.get('final_response', ''))
        
        # Log query
        QueryHistoryManager.log_query(
            session_id,
            request.query,
            result.get('user_category', 'unknown'),
            result.get('query_intent', 'unknown'),
            result.get('target_agent', 'unknown'),
            result.get('final_response', '')
        )
        
        # Update session title if this is the first query
        if len(session["messages"]) == 0:
            title = SessionManager.generate_session_title(request.query)
            SessionManager.update_session_title(session_id, title)
        
        # Create memory summary every 10 messages
        message_count = len(SessionManager.get_session(session_id)["messages"])
        if message_count % 10 == 0 and message_count > 0:
            summary_result = ChatMemoryManager.create_memory_summary(llm, history[-10:])
            if summary_result:
                ChatMemoryManager.save_memory(
                    session_id,
                    summary_result["summary"],
                    "",
                    f"Messages {message_count-10} to {message_count}"
                )

        return QueryResponse(
            id=str(uuid.uuid4()),
            query=request.query,
            user_category=result.get('user_category', 'unknown'),
            query_intent=result.get('query_intent', 'unknown'),
            target_agent=result.get('target_agent', 'unknown'),
            final_response=result.get('final_response', ''),
            timestamp=datetime.now().isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")


@app.delete("/session/{session_id}")
async def delete_session(session_id: str, user_id: str = Depends(verify_token)):
    """Delete a chat session"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    success = SessionManager.delete_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"message": "Session deleted successfully"}


@app.post("/session/{session_id}/archive")
async def archive_session(session_id: str, user_id: str = Depends(verify_token)):
    """Archive a chat session"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    SessionManager.archive_session(session_id)
    return {"message": "Session archived successfully"}


# ==================== FILE UPLOAD ENDPOINTS ====================

@app.post("/session/{session_id}/upload", response_model=FileUploadResponse)
async def upload_file(
    session_id: str,
    file: UploadFile = File(...),
    user_id: str = Depends(verify_token)
):
    """Upload a tax document to a session"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        # Save file and extract text
        file_info = FileProcessor.save_file(user_id, session_id, file)
        
        # Generate summary using LLM
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key and file_info["extracted_text"]:
            llm = ChatGoogleGenerativeAI(
                model="gemini-2.5-flash-lite",
                temperature=0.3,
                api_key=api_key
            )
            
            summary_prompt = f"""Analyze this tax document and provide a concise summary (max 150 words):

{file_info["extracted_text"][:3000]}

Focus on:
1. Document type and purpose
2. Key tax information (amounts, dates, sections)
3. Main implications or requirements

Be specific and factual."""

            try:
                response = llm.invoke([HumanMessage(content=summary_prompt)])
                summary = response.content
            except Exception as e:
                print(f"Summary generation error: {e}")
                summary = "Summary generation failed"
        else:
            summary = "No summary available"
        
        # Save file record to database
        file_record = FileManager.save_file_record(user_id, session_id, file_info, summary)
        
        # Preview of extracted text
        preview = file_info["extracted_text"][:500] + "..." if len(file_info["extracted_text"]) > 500 else file_info["extracted_text"]
        
        return FileUploadResponse(
            file_id=file_record["file_id"],
            filename=file_record["filename"],
            file_size=file_info["file_size"],
            extracted_text_preview=preview,
            summary=summary,
            upload_timestamp=file_record["upload_timestamp"]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")


@app.get("/session/{session_id}/files")
async def get_session_files(session_id: str, user_id: str = Depends(verify_token)):
    """Get all files uploaded in a session"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    files = FileManager.get_session_files(session_id)
    return {"session_id": session_id, "files": files, "total": len(files)}


@app.get("/files/{file_id}")
async def get_file_details(file_id: str, user_id: str = Depends(verify_token)):
    """Get detailed information about an uploaded file"""
    file_info = FileManager.get_file_content(file_id, user_id)
    return file_info


@app.get("/files/{file_id}/analyze")
async def analyze_uploaded_file(
    file_id: str,
    query: Optional[str] = None,
    user_id: str = Depends(verify_token)
):
    """Analyze an uploaded file with optional specific query"""
    file_info = FileManager.get_file_content(file_id, user_id)
    
    if not file_info.get("extracted_text"):
        raise HTTPException(status_code=400, detail="No text content available for analysis")
    
    try:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(status_code=500, detail="GOOGLE_API_KEY not configured")
        
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            temperature=0.5,
            api_key=api_key
        )
        
        if query:
            analysis_prompt = f"""You are a tax expert. Analyze this document and answer the user's question:

Document content:
{file_info['extracted_text'][:4000]}

User's question: {query}

Provide a clear, detailed answer based on the document content."""
        else:
            analysis_prompt = f"""You are a tax expert. Analyze this tax document comprehensively:

Document content:
{file_info['extracted_text'][:4000]}

Provide:
1. Document type and purpose
2. Key tax figures and dates
3. Compliance requirements or implications
4. Potential issues or areas needing attention
5. Recommended next steps

Be thorough but concise."""
        
        response = llm.invoke([HumanMessage(content=analysis_prompt)])
        
        return {
            "file_id": file_id,
            "filename": file_info["filename"],
            "query": query or "General analysis",
            "analysis": response.content,
            "timestamp": datetime.now().isoformat()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ==================== *Endpoints for memory*
async def get_session_memory(session_id: str, user_id: str = Depends(verify_token)):
    """Get memory summaries for a session"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    memories = ChatMemoryManager.get_session_memory(session_id)
    return {
        "session_id": session_id,
        "memories": memories,
        "total": len(memories)
    }


# ==================== new endpoints for analytics ====================

@app.get("/analytics")
async def get_analytics(user_id: str = Depends(verify_token)):
    """Get system-wide analytics"""
    analytics = QueryHistoryManager.get_analytics()
    return analytics


@app.get("/session/{session_id}/queries")
async def get_session_queries(session_id: str, user_id: str = Depends(verify_token)):
    """Get query history for a session"""
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    queries = QueryHistoryManager.get_session_queries(session_id)
    return {"session_id": session_id, "queries": queries}


# ==================== this will be the Legacy ENDPOINT (for backward compatibility) ====================

@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process query without session (legacy endpoint)"""
    if not request.query or len(request.query.strip()) == 0:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    try:
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise HTTPException(status_code=500, detail="GOOGLE_API_KEY not configured")

        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            temperature=0.7,
            api_key=api_key
        )

        app_graph = build_gst_graph(llm)

        initial_state = {
            "messages": [],
            "query": request.query,
            "user_category": request.user_category or "general",
            "query_intent": None,
            "dynamic_updates": None,
            "static_legal_info": None,
            "ai_derived_analysis": None,
            "conversation_history": [],
            "relevant_context": None,
            "target_agent": None,
            "needs_follow_up": False,
            "last_update_time": datetime.now().isoformat(),
            "final_response": "",
            "uploaded_files_context": "No files uploaded"
        }

        result = app_graph.invoke(initial_state)

        return QueryResponse(
            id=str(uuid.uuid4()),
            query=request.query,
            user_category=result.get('user_category', 'unknown'),
            query_intent=result.get('query_intent', 'unknown'),
            target_agent=result.get('target_agent', 'unknown'),
            final_response=result.get('final_response', ''),
            timestamp=datetime.now().isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)