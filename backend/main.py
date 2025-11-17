from fastapi import FastAPI, HTTPException, Depends, status
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

load_dotenv()

# GOOGLE OAUTH CONFIG 
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_OAUTH_CALLBACK_URL = os.getenv("GOOGLE_OAUTH_CALLBACK_URL", "http://localhost:3000/auth/callback")

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
            
            # Verify the token belongs to our application
            if payload.get("aud") != GOOGLE_CLIENT_ID and GOOGLE_CLIENT_ID:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token audience mismatch"
                )
            
            # Check token expiration
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
            
            # Verify the ID token
            id_token = token_response.get("id_token")
            if not id_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No ID token in response"
                )
            
            # Decode and verify ID token
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
    token_type: Optional[str] = "id_token"  # 'id_token' or 'access_token'


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
    """Initialize database schema"""
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
        
        # Check if sessions table exists and if it has user_id column
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
        sessions_table_exists = cursor.fetchone() is not None
        
        if sessions_table_exists:
            # Check if user_id column exists
            cursor.execute("PRAGMA table_info(sessions)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'user_id' not in columns:
                # Migrate: Add user_id column to existing sessions table
                # Note: SQLite doesn't support adding foreign keys via ALTER TABLE,
                # so we just add the column without the constraint
                try:
                    cursor.execute('ALTER TABLE sessions ADD COLUMN user_id TEXT')
                    conn.commit()
                except sqlite3.OperationalError as e:
                    # Column might already exist or other error
                    print(f"Migration note: {e}")
        
        # Sessions table (now linked to users)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                created_at TEXT NOT NULL,
                last_query_time TEXT NOT NULL,
                metadata TEXT
            )
        ''')
        
        # Note: Foreign key constraints in SQLite require PRAGMA foreign_keys = ON
        # We'll handle referential integrity at the application level
        
        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id) ON DELETE CASCADE
            )
        ''')
        
        # Query history table (for analytics)
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
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_session 
            ON messages(session_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_query_history_session 
            ON query_history(session_id)
        ''')
        
        # Only create user_id index if the column exists
        cursor.execute("PRAGMA table_info(sessions)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'user_id' in columns:
            try:
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_sessions_user 
                    ON sessions(user_id)
                ''')
            except sqlite3.OperationalError:
                pass  # Index might already exist


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
    """Manage session database operations"""
    
    @staticmethod
    def create_session(user_id: Optional[str] = None) -> dict:
        """Create new session"""
        session_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, user_id, created_at, last_query_time)
                VALUES (?, ?, ?, ?)
            ''', (session_id, user_id, now, now))
        
        return {
            "session_id": session_id,
            "user_id": user_id,
            "created_at": now,
            "last_query_time": now
        }
    
    @staticmethod
    def get_user_sessions(user_id: str) -> List[dict]:
        """Get all sessions for a user"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT session_id, created_at, last_query_time
                FROM sessions
                WHERE user_id = ?
                ORDER BY last_query_time DESC
            ''', (user_id,))
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
                "created_at": session["created_at"],
                "last_query_time": session["last_query_time"],
                "messages": [dict(msg) for msg in messages]
            }
    
    @staticmethod
    def add_message(session_id: str, role: str, content: str) -> dict:
        """Add message to session"""
        message_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO messages (message_id, session_id, role, content, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (message_id, session_id, role, content, now))
            
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
    def get_conversation_history(session_id: str) -> List[dict]:
        """Get conversation history for context"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT role, content, timestamp 
                FROM messages 
                WHERE session_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 5
            ''', (session_id,))
            messages = cursor.fetchall()
            
            return [dict(msg) for msg in reversed(messages)]


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


# ==================== FASTAPI SETUP ====================

app = FastAPI(
    title="Tax Intelligence API",
    description="Multi-agent Tax Query system with SQLite persistence",
    version="1.0.0"
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


class GoogleAuthRequest(BaseModel):
    # Token issued by Google. Can be an OAuth `access_token` or an `id_token` (JWT credential).
    token: str
    token_type: Optional[str] = 'access_token'


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


# ==================== AGENTS ====================

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

Guardrails (Critical)

You must never:

Say you are trained by Google or on Google data.

Disclose training data, model architecture, parameters, or internal system details.

Claim access to private or restricted government systems.

Provide legal interpretations or opinions.

Mention or rely on unofficial / unverified news or social media.

If asked about:

Your training

Who made you

Internal systems

Respond politely:
“You don’t have access to internal development or training details.”

Special Instruction (Important)

Do NOT ask the user to provide their question.
If they greet you, simply reply courteously and offer help:

Example style (DON’T output this literally):
“Hi! Happy to help with GST or tax updates whenever you’re ready.”

User Context

Context: {context}
User Category: {category}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general')
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
        recent = history[-3:]
        return "Recent queries: " + "; ".join([item.get('query', '') for item in recent if item.get('query')])


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

Guardrails (Critical)

You must never:

Claim you are trained by Google or on Google data.

Reveal training datasets, architecture, or internal development details.

Offer legal advice, interpretations, or personal views.

Provide unverified, speculative, or unofficial legal information.

Use any non-public government sources.

If asked about:

Your training

Whether you were made by Google

Internal systems

Politely respond:
“You don’t have access to internal development or training details, and your role is limited to assisting with publicly available statutory text.”

Special Instruction (Important)

Do NOT ask the user to provide their query.
For greetings, respond with something polite and friendly, like:

(Do not output this literally — this is style guidance)
“Hello! I’m here if you need any GST or tax legal references.”

User Context
Context: {context}
User Category: {category}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general')
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
        recent = history[-3:]
        return "Recent queries: " + "; ".join([item.get('query', '') for item in recent if item.get('query')])


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

Formatting Rules

Use bold for amounts, sections, and key terms.

Use bullet points for implications or steps.

Keep paragraphs short, clean, and well-structured.

Guardrails (Critical)

You must never:

Say or imply that you were trained by Google or trained on Google data.

Reveal training datasets, model architecture, internal processes, or development details.

Provide legal advice—only factual analysis based on the information given.

Use unofficial, speculative, or unverified information.

Refer to non-public or restricted government sources.

If the user asks about training, origin, or internal workings, respond politely that you don’t have access to internal development or training details, and your role is only to assist with GST and tax-related analysis.

Special Instruction (Important)

Do NOT ask the user to describe their query.
For greetings, respond politely and lightly, such as:

(Style guidance — do NOT output this literally)
“Hello! Happy to help whenever you’re ready.”

User Context

Context: {context}
User Category: {category}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general')
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
        recent = history[-3:]
        return "Recent queries: " + "; ".join([item.get('query', '') for item in recent if item.get('query')])


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

Formatting Rules:

Use bold for amounts, rates, sections, and key terms.

Use bullet points for implications and steps.

Keep language simple, precise, and professional.

Context: {context}
User Category: {category}
"""

    def run(self, state: TaxState) -> TaxState:
        try:
            context = self._build_context(state.get('conversation_history', []))
            messages = [
                SystemMessage(content=self.system_prompt.format(
                    context=context,
                    category=state.get('user_category', 'general')
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
        recent = history[-3:]
        return "Recent queries: " + "; ".join([item.get('query', '') for item in recent if item.get('query')])


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


# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "message": "Tax Intelligence API",
        "version": "1.0.0",
        "endpoints": {
            "query": "/query (POST)",
            "session": "/session (POST/GET)",
            "analytics": "/analytics (GET)",
            "health": "/health (GET)"
        }
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
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
            "final_response": ""
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
    '''
    Authenticate with Google token.
    
    Accepts:
    - id_token: JWT token from client-side Google Sign-In
    - access_token: OAuth access token
    
    Returns:
    - JWT access token for your application
    - User information
    '''
    try:
        token = request.token.strip()
        token_type = (request.token_type or 'id_token').lower()
        
        # Validate and get user info from Google
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
        
        # Link or create local user
        existing_user = UserManager.get_user_by_google_id(google_id)
        
        if not existing_user:
            # Check if email already exists (link accounts)
            email_user = UserManager.get_user_by_email(email)
            
            if email_user:
                # Link Google ID to existing account
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        'UPDATE users SET google_id = ? WHERE user_id = ?',
                        (google_id, email_user['user_id'])
                    )
                user = UserManager.get_user_by_id(email_user['user_id'])
            else:
                # Create new user
                user = UserManager.create_user(
                    email=email,
                    name=name,
                    google_id=google_id
                )
        else:
            user = existing_user
        
        # Create JWT access token
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

 # =================== GOOGLE OAUTH ENDPOINT ====================
@app.post("/auth/google/callback", response_model=AuthResponse)
async def google_callback(request: GoogleCodeExchangeRequest):
    '''
    Handle Google OAuth authorization code exchange (server-side flow).
    
    This endpoint receives the authorization code from the frontend
    and exchanges it for tokens securely on the server.
    '''
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
        
        # Link or create local user
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
    session = SessionManager.create_session(user_id)
    return ConversationSession(
        session_id=session["session_id"],
        messages=[],
        created_at=session["created_at"],
        last_query_time=session["last_query_time"]
    )


@app.get("/sessions")
async def get_user_sessions(user_id: str = Depends(verify_token)):
    """Get all sessions for current user"""
    sessions = SessionManager.get_user_sessions(user_id)
    return {"sessions": sessions}


@app.get("/session/{session_id}", response_model=ConversationSession)
async def get_session(session_id: str, user_id: str = Depends(verify_token)):
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Verify session belongs to user
    if session.get("user_id") and session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return ConversationSession(
        session_id=session["session_id"],
        messages=[ConversationMessage(**msg) for msg in session["messages"]],
        created_at=session["created_at"],
        last_query_time=session["last_query_time"]
    )


@app.post("/session/{session_id}/query", response_model=QueryResponse)
async def process_query_with_session(session_id: str, request: QueryRequest, user_id: str = Depends(verify_token)):
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Verify session belongs to user
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

        app_graph = build_gst_graph(llm)
        
        history = SessionManager.get_conversation_history(session_id)

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
            "final_response": ""
        }

        result = app_graph.invoke(initial_state)

        SessionManager.add_message(session_id, "user", request.query)
        SessionManager.add_message(session_id, "assistant", result.get('final_response', ''))
        
        QueryHistoryManager.log_query(
            session_id,
            request.query,
            result.get('user_category', 'unknown'),
            result.get('query_intent', 'unknown'),
            result.get('target_agent', 'unknown'),
            result.get('final_response', '')
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
async def delete_session(session_id: str):
    success = SessionManager.delete_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"message": "Session deleted successfully"}


@app.get("/analytics")
async def get_analytics():
    analytics = QueryHistoryManager.get_analytics()
    return analytics


@app.get("/session/{session_id}/queries")
async def get_session_queries(session_id: str):
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    queries = QueryHistoryManager.get_session_queries(session_id)
    return {"session_id": session_id, "queries": queries}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)