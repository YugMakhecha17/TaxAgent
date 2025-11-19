from fastapi import FastAPI, HTTPException, status, UploadFile, File, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List, TypedDict, Annotated, Literal
from datetime import datetime, timedelta
import sqlite3, json, uuid, hashlib, secrets, os, io, operator, requests, jwt
from contextlib import contextmanager
from pathlib import Path
from dotenv import load_dotenv
import PyPDF2
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.graph import StateGraph, END

load_dotenv()

GOOGLE_CLIENT_ID      = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET  = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_OAUTH_CALLBACK_URL = os.getenv("GOOGLE_OAUTH_CALLBACK_URL", "http://localhost:3000/auth/callback")
GOOGLE_TOKEN_INFO_ENDPOINT   = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_USERINFO_ENDPOINT     = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_TOKEN_ENDPOINT        = "https://oauth2.googleapis.com/token"

UPLOAD_DIR  = Path("uploads"); UPLOAD_DIR.mkdir(exist_ok=True)
MAX_FILE_SIZE      = 10 * 1024 * 1024   # 10 MB
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".docx"}

SECRET_KEY   = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM    = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

DATABASE_PATH = "tax_intelligence.db"

security = HTTPBearer()


@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _table_exists(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None

def _column_exists(conn, table: str, col: str) -> bool:
    return col in {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

def migrate_schema():
    """Add any missing columns without losing data."""
    with get_db() as conn:
        
        if not _column_exists(conn, "sessions", "title"):
            conn.execute("ALTER TABLE sessions ADD COLUMN title TEXT DEFAULT 'New Chat'")
        if not _column_exists(conn, "sessions", "is_archived"):
            conn.execute("ALTER TABLE sessions ADD COLUMN is_archived INTEGER DEFAULT 0")

        if not _column_exists(conn, "messages", "token_count"):
            conn.execute("ALTER TABLE messages ADD COLUMN token_count INTEGER DEFAULT 0")

        if not _column_exists(conn, "users", "google_id"):
            conn.execute("ALTER TABLE users ADD COLUMN google_id TEXT UNIQUE")

def init_db():
    with get_db() as conn:
        # USERS
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                name          TEXT NOT NULL,
                google_id     TEXT UNIQUE,
                created_at    TEXT NOT NULL,
                last_login    TEXT
            )
        """)
        # SESSIONS
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id      TEXT PRIMARY KEY,
                user_id         TEXT,
                title           TEXT DEFAULT 'New Chat',
                created_at      TEXT NOT NULL,
                last_query_time TEXT NOT NULL,
                metadata        TEXT,
                is_archived     INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        # MESSAGES
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                message_id  TEXT PRIMARY KEY,
                session_id  TEXT NOT NULL,
                role        TEXT NOT NULL,
                content     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                token_count INTEGER DEFAULT 0,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        # CHAT MEMORY
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_memory (
                memory_id     TEXT PRIMARY KEY,
                session_id    TEXT NOT NULL,
                summary       TEXT NOT NULL,
                key_points    TEXT,
                timestamp     TEXT NOT NULL,
                message_range TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        # UPLOADED FILES
        conn.execute("""
            CREATE TABLE IF NOT EXISTS uploaded_files (
                file_id           TEXT PRIMARY KEY,
                session_id        TEXT NOT NULL,
                user_id           TEXT NOT NULL,
                filename          TEXT NOT NULL,
                file_path         TEXT NOT NULL,
                file_type         TEXT NOT NULL,
                file_size         INTEGER NOT NULL,
                extracted_text    TEXT,
                summary           TEXT,
                upload_timestamp  TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
                FOREIGN KEY(user_id)   REFERENCES users(user_id)   ON DELETE CASCADE
            )
        """)
        # HISTORY of queries
        conn.execute("""
            CREATE TABLE IF NOT EXISTS query_history (
                query_id      TEXT PRIMARY KEY,
                session_id    TEXT NOT NULL,
                query_text    TEXT NOT NULL,
                user_category TEXT,
                query_intent  TEXT,
                target_agent  TEXT,
                response      TEXT NOT NULL,
                timestamp     TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            )
        """)
        # INDEXES for performance
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_messages_session   ON messages(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user      ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_last_query ON sessions(last_query_time)",
            "CREATE INDEX IF NOT EXISTS idx_chat_memory_session ON chat_memory(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_uploaded_files_session ON uploaded_files(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_uploaded_files_user    ON uploaded_files(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_query_history_session  ON query_history(session_id)",
        ]:
            conn.execute(idx_sql)


app = FastAPI(
    title="Tax Intelligence API",
    description="Multi-agent Tax Query system with SQLite persistence and file upload",
    version="2.0.1"
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
    init_db()
    migrate_schema()   # <- ensures title column (and any future ones) exist


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def create_access_token(data: dict, expires: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid: str = payload.get("sub")
        if not uid:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return uid
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid credentials")


class GoogleOAuthValidator:
    @staticmethod
    def verify_id_token(token: str) -> dict:
        r = requests.get(GOOGLE_TOKEN_INFO_ENDPOINT, params={"id_token": token}, timeout=10)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google ID token")
        p = r.json()
        if p.get("aud") != GOOGLE_CLIENT_ID and GOOGLE_CLIENT_ID:
            raise HTTPException(status_code=401, detail="Token audience mismatch")
        import time
        if int(time.time()) > int(p.get("exp", 0)):
            raise HTTPException(status_code=401, detail="Token expired")
        return {
            "google_id": p.get("sub"),
            "email": p.get("email"),
            "name": p.get("name"),
            "email_verified": p.get("email_verified", False),
            "picture": p.get("picture"),
            "token_type": "id_token"
        }

    @staticmethod
    def verify_access_token(token: str) -> dict:
        r = requests.get(GOOGLE_USERINFO_ENDPOINT, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google access token")
        p = r.json()
        return {
            "google_id": p.get("sub"),
            "email": p.get("email"),
            "name": p.get("name"),
            "email_verified": p.get("verified_email", False),
            "picture": p.get("picture"),
            "token_type": "access_token"
        }

    @staticmethod
    def exchange_code_for_token(code: str) -> dict:
        payload = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_OAUTH_CALLBACK_URL
        }
        r = requests.post(GOOGLE_TOKEN_ENDPOINT, data=payload, timeout=10)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Failed to exchange code")
        t = r.json()
        id_token = t.get("id_token")
        if not id_token:
            raise HTTPException(status_code=400, detail="No ID token in response")
        user_info = GoogleOAuthValidator.verify_id_token(id_token)
        user_info["access_token"] = t.get("access_token")
        user_info["refresh_token"] = t.get("refresh_token")
        return user_info

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

class GoogleAuthRequest(BaseModel):
    token: str
    token_type: Optional[str] = "id_token"

class GoogleCodeExchangeRequest(BaseModel):
    code: str

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

class UpdateTitleRequest(BaseModel):
    title: str

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

class FileUploadResponse(BaseModel):
    file_id: str
    filename: str
    file_size: int
    extracted_text_preview: str
    summary: Optional[str]
    upload_timestamp: str

class UserManager:
    @staticmethod
    def create_user(email: str, name: str, password: Optional[str] = None, google_id: Optional[str] = None) -> dict:
        uid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        phash = hash_password(password) if password else None
        with get_db() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (user_id, email, password_hash, name, google_id, created_at) VALUES (?,?,?,?,?,?)",
                    (uid, email, phash, name, google_id, now)
                )
            except sqlite3.IntegrityError:
                raise HTTPException(status_code=400, detail="Email already registered")
        return {"user_id": uid, "email": email, "name": name, "created_at": now}

    @staticmethod
    def get_user_by_email(email: str) -> Optional[dict]:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_user_by_google_id(gid: str) -> Optional[dict]:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE google_id=?", (gid,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_user_by_id(uid: str) -> Optional[dict]:
        with get_db() as conn:
            row = conn.execute(
                "SELECT user_id, email, name, created_at, last_login FROM users WHERE user_id=?", (uid,)
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update_last_login(uid: str):
        with get_db() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE user_id=?", (datetime.now().isoformat(), uid))

class SessionManager:
    @staticmethod
    def generate_session_title(query: str) -> str:
        words = query.split()[:6]
        title = " ".join(words)
        return title + "..." if len(query.split()) > 6 else title

    @staticmethod
    def create_session(uid: Optional[str] = None, title: str = "New Chat") -> dict:
        sid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, user_id, title, created_at, last_query_time) VALUES (?,?,?,?,?)",
                (sid, uid, title, now, now)
            )
        return {"session_id": sid, "user_id": uid, "title": title, "created_at": now, "last_query_time": now}

    @staticmethod
    def get_user_sessions(uid: str, include_archived: bool = False) -> List[dict]:
        with get_db() as conn:
            sql = "SELECT session_id, title, created_at, last_query_time, is_archived FROM sessions WHERE user_id=?"
            if not include_archived:
                sql += " AND is_archived=0"
            sql += " ORDER BY last_query_time DESC"
            rows = conn.execute(sql, (uid,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_session(sid: str) -> Optional[dict]:
        with get_db() as conn:
            sess = conn.execute("SELECT * FROM sessions WHERE session_id=?", (sid,)).fetchone()
            if not sess:
                return None
            msgs = conn.execute(
                "SELECT message_id, role, content, timestamp FROM messages WHERE session_id=? ORDER BY timestamp ASC", (sid,)
            ).fetchall()
            return {
                "session_id": sess["session_id"],
                "user_id": sess["user_id"],
                "title": sess["title"],
                "created_at": sess["created_at"],
                "last_query_time": sess["last_query_time"],
                "messages": [dict(m) for m in msgs]
            }

    @staticmethod
    def add_message(sid: str, role: str, content: str) -> dict:
        mid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO messages (message_id, session_id, role, content, timestamp, token_count) VALUES (?,?,?,?,?,?)",
                (mid, sid, role, content, now, len(content.split()))
            )
            conn.execute("UPDATE sessions SET last_query_time=? WHERE session_id=?", (now, sid))
        return {"message_id": mid, "role": role, "content": content, "timestamp": now}

    @staticmethod
    def update_session_title(sid: str, title: str):
        with get_db() as conn:
            conn.execute("UPDATE sessions SET title=? WHERE session_id=?", (title, sid))

    @staticmethod
    def delete_session(sid: str) -> bool:
        with get_db() as conn:
            cur = conn.execute("SELECT 1 FROM sessions WHERE session_id=?", (sid,))
            if not cur.fetchone():
                return False
            conn.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
            return True

    @staticmethod
    def archive_session(sid: str):
        with get_db() as conn:
            conn.execute("UPDATE sessions SET is_archived=1 WHERE session_id=?", (sid,))


class FileProcessor:
    @staticmethod
    def extract_text_from_pdf(content: bytes) -> str:
        try:
            reader = PyPDF2.PdfReader(io.BytesIO(content))
            return "\n".join(page.extract_text() or "" for page in reader.pages).strip()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"PDF extraction failed: {e}")

    @staticmethod
    def extract_text_from_txt(content: bytes) -> str:
        try:
            return content.decode("utf-8")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Text read failed: {e}")

    @staticmethod
    def save_file(uid: str, sid: str, file: UploadFile) -> dict:
        ext = Path(file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"Allowed types: {', '.join(ALLOWED_EXTENSIONS)}")
        content = file.file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")
        fid = str(uuid.uuid4())
        user_dir = UPLOAD_DIR / uid / sid
        user_dir.mkdir(parents=True, exist_ok=True)
        file_path = user_dir / f"{fid}{ext}"
        file_path.write_bytes(content)
        text = (
            FileProcessor.extract_text_from_pdf(content) if ext == ".pdf" else
            FileProcessor.extract_text_from_txt(content) if ext == ".txt" else
            "Text extraction not supported for this file type"
        )
        return {
            "file_id": fid,
            "filename": file.filename,
            "file_path": str(file_path),
            "file_type": ext,
            "file_size": len(content),
            "extracted_text": text
        }

class FileManager:
    @staticmethod
    def save_file_record(uid: str, sid: str, info: dict, summary: Optional[str] = None) -> dict:
        now = datetime.now().isoformat()
        with get_db() as conn:
            conn.execute(
                """INSERT INTO uploaded_files
                   (file_id, session_id, user_id, filename, file_path, file_type, file_size, extracted_text, summary, upload_timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (info["file_id"], sid, uid, info["filename"], info["file_path"], info["file_type"],
                 info["file_size"], info["extracted_text"], summary, now)
            )
        return {"file_id": info["file_id"], "filename": info["filename"], "upload_timestamp": now}

    @staticmethod
    def get_session_files(sid: str) -> List[dict]:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT file_id, filename, file_type, file_size, summary, upload_timestamp FROM uploaded_files WHERE session_id=? ORDER BY upload_timestamp DESC",
                (sid,)
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_file_content(fid: str, uid: str) -> dict:
        with get_db() as conn:
            row = conn.execute(
                "SELECT file_id, filename, file_path, extracted_text, summary FROM uploaded_files WHERE file_id=? AND user_id=?", (fid, uid)
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="File not found")
            return dict(row)


class ChatMemoryManager:
    @staticmethod
    def save_memory(sid: str, summary: str, key_points: str, msg_range: str):
        mid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO chat_memory (memory_id, session_id, summary, key_points, timestamp, message_range) VALUES (?,?,?,?,?,?)",
                (mid, sid, summary, key_points, now, msg_range)
            )

    @staticmethod
    def get_session_memory(sid: str) -> List[dict]:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT summary, key_points, timestamp FROM chat_memory WHERE session_id=? ORDER BY timestamp DESC", (sid,)
            ).fetchall()
            return [dict(r) for r in rows]


class QueryHistoryManager:
    @staticmethod
    def log_query(sid: str, query_text: str, user_cat: str, intent: str, agent: str, response: str) -> str:
        qid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with get_db() as conn:
            conn.execute(
                """INSERT INTO query_history
                   (query_id, session_id, query_text, user_category, query_intent, target_agent, response, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (qid, sid, query_text, user_cat, intent, agent, response, now)
            )
        return qid

    @staticmethod
    def get_session_queries(sid: str) -> List[dict]:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT query_id, query_text, user_category, query_intent, target_agent, timestamp FROM query_history WHERE session_id=? ORDER BY timestamp DESC",
                (sid,)
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_analytics() -> dict:
        with get_db() as conn:
            total_queries = conn.execute("SELECT COUNT(*) as c FROM query_history").fetchone()["c"]
            total_sessions = conn.execute("SELECT COUNT(*) as c FROM sessions").fetchone()["c"]
            intent_dist = {row["query_intent"]: row["c"] for row in conn.execute(
                "SELECT query_intent, COUNT(*) as c FROM query_history GROUP BY query_intent"
            ).fetchall()}
            cat_dist = {row["user_category"]: row["c"] for row in conn.execute(
                "SELECT user_category, COUNT(*) as c FROM query_history GROUP BY user_category"
            ).fetchall()}
            return {
                "total_queries": total_queries,
                "total_sessions": total_sessions,
                "intent_distribution": intent_dist,
                "category_distribution": cat_dist
            }

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

# router for classification of different queries, it will invoke an agent to classify the query
class QueryRouter:
    def __init__(self, llm):
        self.llm = llm
        self.prompt = """You are an AI Tax query classification expert.
Analyze the user's query and classify it into ONE primary category:

1. DYNAMIC_UPDATE: Recent news, latest circulars, current GST rates, policy changes, PIB releases, RBI updates, ongoing reforms, "what's new", "latest updates"
2. LEGAL_CLARIFICATION: CGST/SGST/IGST Act sections, constitutional provisions, legal definitions, compliance rules, statutory requirements, "what does the law say"
3. ANALYTICAL: Explanations, interpretations, sector-wise implications, FAQs, "how does this affect", "explain in simple terms", comparisons
4. TAX_KNOWLEDGE: Income tax calculations, deductions, filing procedures, slab-related queries, TDS, professional tax, personal/business tax questions

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
            response = self.llm.invoke([HumanMessage(content=self.prompt.format(query=state["query"]))])
            for line in response.content.strip().splitlines():
                if "INTENT:" in line:
                    state["query_intent"] = line.split(":", 1)[1].strip().lower().replace(" ", "_")
                elif "CATEGORY:" in line:
                    state["user_category"] = line.split(":", 1)[1].strip()
                elif "NEEDS_FOLLOW_UP:" in line:
                    state["needs_follow_up"] = "YES" in line
            intent_map = {"dynamic_update": "dynamic", "legal_clarification": "static",
                          "analytical": "analytical", "tax_knowledge": "tax"}
            state["target_agent"] = intent_map.get(state.get("query_intent", "analytical"), "analytical")
        except Exception as e:
            print("Router error:", e)
            state["target_agent"] = "analytical"
            state["query_intent"] = "analytical"
        return state

class DynamicLayerAgent:
    def __init__(self, llm):
        self.llm = llm
        self.sys = """You are an AI assistant specializing in Government Policy Updates for GST and Taxation.

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
        context = self._build_context(state.get("conversation_history", []))
        files_context = state.get("uploaded_files_context", "No files uploaded")
        messages = [
            SystemMessage(content=self.sys.format(context=context, category=state.get("user_category", "general"), files_context=files_context)),
            HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly and concisely. Maximum 3-4 paragraphs.")
        ]
        response = self.llm.invoke(messages)
        state["dynamic_updates"] = response.content
        state["final_response"] = response.content
        state["messages"].append(AIMessage(content=response.content))
        return state

    def _build_context(self, hist: list) -> str:
        if not hist:
            return "No previous context."
        recent = hist[-5:]
        return "Recent: " + "; ".join(f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" for item in recent if item.get("content"))

class StaticLayerAgent:
    def __init__(self, llm):
        self.llm = llm
        self.sys = """You are an AI assistant that provides precise legal references for GST and Taxation.

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
        context = self._build_context(state.get("conversation_history", []))
        files_context = state.get("uploaded_files_context", "No files uploaded")
        messages = [
            SystemMessage(content=self.sys.format(context=context, category=state.get("user_category", "general"), files_context=files_context)),
            HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly with specific act sections. Maximum 3-4 paragraphs.")
        ]
        response = self.llm.invoke(messages)
        state["static_legal_info"] = response.content
        state["final_response"] = response.content
        state["messages"].append(AIMessage(content=response.content))
        return state

    def _build_context(self, hist: list) -> str:
        if not hist:
            return "No previous context."
        recent = hist[-5:]
        return "Recent: " + "; ".join(f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" for item in recent if item.get("content"))

class AnalyticalLayerAgent:
    def __init__(self, llm):
        self.llm = llm
        self.sys = """You are an AI assistant that provides clear GST and Tax analysis with direct results.

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
        context = self._build_context(state.get("conversation_history", []))
        files_context = state.get("uploaded_files_context", "No files uploaded")
        messages = [
            SystemMessage(content=self.sys.format(context=context, category=state.get("user_category", "general"), files_context=files_context)),
            HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly and concisely. Maximum 4-5 paragraphs.")
        ]
        response = self.llm.invoke(messages)
        state["ai_derived_analysis"] = response.content
        state["final_response"] = response.content
        state["messages"].append(AIMessage(content=response.content))
        return state

    def _build_context(self, hist: list) -> str:
        if not hist:
            return "No previous context."
        recent = hist[-5:]
        return "Recent: " + "; ".join(f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" for item in recent if item.get("content"))

class TaxKnowledgeAgent:
    def __init__(self, llm):
        self.llm = llm
        self.sys = """You are an AI Tax Analyst specializing in Indian taxation (GST, Income Tax, Professional Tax).

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
Uploaded Files Context: {files_context}"""

    def run(self, state: TaxState) -> TaxState:
        context = self._build_context(state.get("conversation_history", []))
        files_context = state.get("uploaded_files_context", "No files uploaded")
        messages = [
            SystemMessage(content=self.sys.format(context=context, category=state.get("user_category", "general"), files_context=files_context)),
            HumanMessage(content=f"Query: {state['query']}\n\nAnswer directly and concisely. Maximum 4–5 paragraphs.")
        ]
        response = self.llm.invoke(messages)
        state["ai_derived_analysis"] = response.content
        state["final_response"] = response.content
        state["messages"].append(AIMessage(content=response.content))
        return state

    def _build_context(self, hist: list) -> str:
        if not hist:
            return "No previous context."
        recent = hist[-5:]
        return "Recent: " + "; ".join(f"{item.get('role', 'unknown')}: {item.get('content', '')[:100]}" for item in recent if item.get("content"))


def route_to_agent(state: TaxState) -> Literal["dynamic", "static", "analytical", "tax", "end"]:
    return state.get("target_agent", "end")

def build_gst_graph(llm):
    router_llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash-lite", temperature=0, max_tokens=200, api_key=os.getenv("GOOGLE_API_KEY"))
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
    workflow.add_conditional_edges("router", route_to_agent, {
        "dynamic": "dynamic", "static": "static", "analytical": "analytical", "tax": "tax", "end": END
    })
    workflow.add_edge("dynamic", END)
    workflow.add_edge("static", END)
    workflow.add_edge("analytical", END)
    workflow.add_edge("tax", END)
    return workflow.compile()


@app.get("/")
async def root():
    return {"message": "Tax Intelligence API v2.0.1", "version": "2.0.1"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/auth/register", response_model=AuthResponse)
async def register(req: RegisterRequest):
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")
    user = UserManager.create_user(email=req.email, name=req.name, password=req.password)
    token = create_access_token(data={"sub": user["user_id"]})
    UserManager.update_last_login(user["user_id"])
    return AuthResponse(access_token=token, user={"user_id": user["user_id"], "email": user["email"], "name": user["name"]})

@app.post("/auth/login", response_model=AuthResponse)
async def login(req: LoginRequest):
    user = UserManager.get_user_by_email(req.email)
    if not user or not user.get("password_hash") or user["password_hash"] != hash_password(req.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": user["user_id"]})
    UserManager.update_last_login(user["user_id"])
    return AuthResponse(access_token=token, user={"user_id": user["user_id"], "email": user["email"], "name": user["name"]})

@app.post("/auth/google", response_model=AuthResponse)
async def google_auth(req: GoogleAuthRequest):
    user_info = (
        GoogleOAuthValidator.verify_id_token(req.token) if req.token_type == "id_token" else
        GoogleOAuthValidator.verify_access_token(req.token)
    )
    gid, email, name = user_info["google_id"], user_info["email"], user_info["name"] or user_info["email"].split("@")[0]
    user = UserManager.get_user_by_google_id(gid) or UserManager.get_user_by_email(email)
    if not user:
        user = UserManager.create_user(email=email, name=name, google_id=gid)
    elif not user.get("google_id"):
        with get_db() as conn:
            conn.execute("UPDATE users SET google_id=? WHERE user_id=?", (gid, user["user_id"]))
    token = create_access_token(data={"sub": user["user_id"]})
    UserManager.update_last_login(user["user_id"])
    return AuthResponse(access_token=token, user={"user_id": user["user_id"], "email": user["email"], "name": user["name"]})

@app.get("/auth/me")
async def me(uid: str = Depends(verify_token)):
    user = UserManager.get_user_by_id(uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# SESSIONS
@app.post("/session", response_model=ConversationSession)
async def create_session(uid: str = Depends(verify_token)):
    sess = SessionManager.create_session(uid)
    return ConversationSession(
        session_id=sess["session_id"],
        title=sess["title"],
        messages=[],
        created_at=sess["created_at"],
        last_query_time=sess["last_query_time"]
    )

@app.get("/sessions")
async def list_sessions(uid: str = Depends(verify_token)):
    sessions = SessionManager.get_user_sessions(uid)
    return {"sessions": sessions, "total": len(sessions)}

@app.get("/session/{sid}", response_model=ConversationSession)
async def get_session(sid: str, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    return ConversationSession(
        session_id=sess["session_id"],
        title=sess["title"],
        messages=[ConversationMessage(**m) for m in sess["messages"]],
        created_at=sess["created_at"],
        last_query_time=sess["last_query_time"]
    )

@app.patch("/session/{sid}/title")
async def update_title(sid: str, req: UpdateTitleRequest, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    SessionManager.update_session_title(sid, req.title)
    return {"message": "Title updated", "title": req.title}

@app.delete("/session/{sid}")
async def delete_session(sid: str, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    SessionManager.delete_session(sid)
    return {"message": "Session deleted"}

@app.post("/session/{sid}/archive")
async def archive_session(sid: str, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    SessionManager.archive_session(sid)
    return {"message": "Session archived"}

# ----------  QUERY  ----------
@app.post("/session/{sid}/query", response_model=QueryResponse)
async def session_query(sid: str, req: QueryRequest, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GOOGLE_API_KEY not configured")
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.7, api_key=api_key)

    history = []
    # keep context of the last 20 messages
    if sess["messages"]:
        history = [{"role": m["role"], "content": m["content"]} for m in sess["messages"][-20:]]
    files_context = "No files uploaded"
    files = FileManager.get_session_files(sid)
    if files:
        files_context = "Uploaded files:\n" + "\n".join(f"- {f['filename']}: {f.get('summary', 'No summary')[:200]}" for f in files[:3])

    graph = build_gst_graph(llm)
    initial_state = {
        "messages": [],
        "query": req.query,
        "user_category": req.user_category or "general",
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
    result = graph.invoke(initial_state)

    SessionManager.add_message(sid, "user", req.query)
    SessionManager.add_message(sid, "assistant", result.get("final_response", ""))
    QueryHistoryManager.log_query(sid, req.query, result.get("user_category", "unknown"),
                                  result.get("query_intent", "unknown"), result.get("target_agent", "unknown"),
                                  result.get("final_response", ""))
    # this will update title of the chat on the first query
    if len(sess["messages"]) == 0:
        SessionManager.update_session_title(sid, SessionManager.generate_session_title(req.query))

    return QueryResponse(
        id=str(uuid.uuid4()),
        query=req.query,
        user_category=result.get("user_category", "unknown"),
        query_intent=result.get("query_intent", "unknown"),
        target_agent=result.get("target_agent", "unknown"),
        final_response=result.get("final_response", ""),
        timestamp=datetime.now().isoformat()
    )

# new file upload endpoint
@app.post("/session/{sid}/upload", response_model=FileUploadResponse)
async def upload_file(sid: str, file: UploadFile = File(...), uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    info = FileProcessor.save_file(uid, sid, file)
    api_key = os.getenv("GOOGLE_API_KEY")
    summary = "No summary"
    if api_key and info["extracted_text"]:
        llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash-lite", temperature=0.3, api_key=api_key)
        prompt = f"Analyse this tax document and provide a concise summary (max 150 words):\n{info['extracted_text'][:3000]}"
        try:
            summary = llm.invoke([HumanMessage(content=prompt)]).content
        except Exception as e:
            print("Summary generation error:", e)
    rec = FileManager.save_file_record(uid, sid, info, summary)
    preview = info["extracted_text"][:500] + "..." if len(info["extracted_text"]) > 500 else info["extracted_text"]
    return FileUploadResponse(
        file_id=rec["file_id"],
        filename=rec["filename"],
        file_size=info["file_size"],
        extracted_text_preview=preview,
        summary=summary,
        upload_timestamp=rec["upload_timestamp"]
    )

@app.get("/session/{sid}/files")
async def list_files(sid: str, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    files = FileManager.get_session_files(sid)
    return {"session_id": sid, "files": files, "total": len(files)}

@app.get("/files/{fid}")
async def file_details(fid: str, uid: str = Depends(verify_token)):
    return FileManager.get_file_content(fid, uid)

# Fastapi ANALYTICS
@app.get("/analytics")
async def analytics(uid: str = Depends(verify_token)):
    return QueryHistoryManager.get_analytics()

@app.get("/session/{sid}/queries")
async def session_queries(sid: str, uid: str = Depends(verify_token)):
    sess = SessionManager.get_session(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    if sess.get("user_id") and sess["user_id"] != uid:
        raise HTTPException(status_code=403, detail="Access denied")
    queries = QueryHistoryManager.get_session_queries(sid)
    return {"session_id": sid, "queries": queries}

# Original query endpoint for legacy support 
@app.post("/query", response_model=QueryResponse)
async def legacy_query(req: QueryRequest):
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GOOGLE_API_KEY not configured")
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.7, api_key=api_key)
    graph = build_gst_graph(llm)
    initial_state = {
        "messages": [],
        "query": req.query,
        "user_category": req.user_category or "general",
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
    result = graph.invoke(initial_state)
    return QueryResponse(
        id=str(uuid.uuid4()),
        query=req.query,
        user_category=result.get("user_category", "unknown"),
        query_intent=result.get("query_intent", "unknown"),
        target_agent=result.get("target_agent", "unknown"),
        final_response=result.get("final_response", ""),
        timestamp=datetime.now().isoformat()
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)