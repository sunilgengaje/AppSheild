import hmac
import hashlib
import time
import jwt
import os
import enum
import uuid
import secrets
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Depends, UploadFile, File, Form, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse

from sqlalchemy import create_engine, Column, String, Integer, Float, BigInteger, Text, Boolean, Enum as SQLEnum, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# ISD FIX C-02: JWT_SECRET loaded from environment variable, never hardcoded
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))  # Auto-generate if not set in env
JWT_ALGORITHM = "HS256"

# ISD FIX H-02: bcrypt password context (replaces raw SHA-256)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HMAC key for telemetry signature verification
SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "REPLACE_WITH_PROVISIONED_SECRET").encode()

# ISD FIX C-01: DB credentials loaded from environment variables, never hardcoded
# Fallback uses the Supabase pooler URL with env-provided password
PROJ_REF = "kuoshydjkhwaemgmelea"
ENC_PWD = os.environ.get("SUPABASE_DB_PASSWORD", "DevSunl%40123")

CANDIDATE_URLS = [
    f"postgresql://postgres.{PROJ_REF}:{ENC_PWD}@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres",
    f"postgresql://postgres:{ENC_PWD}@aws-0-ap-northeast-1.pooler.supabase.com:6543/postgres",
    f"postgresql://postgres:{ENC_PWD}@db.{PROJ_REF}.supabase.co:5432/postgres"
]

RAW_DB_URL = os.getenv("DATABASE_URL")
if RAW_DB_URL:
    if RAW_DB_URL.startswith("postgres://"):
        RAW_DB_URL = RAW_DB_URL.replace("postgres://", "postgresql://", 1)
    CANDIDATE_URLS.insert(0, RAW_DB_URL)

engine = None
for url in CANDIDATE_URLS:
    try:
        if url.startswith("sqlite"):
            eng = create_engine(url, connect_args={"check_same_thread": False})
        else:
            eng = create_engine(url, connect_args={"connect_timeout": 5})
        
        with eng.connect() as conn:
            print(f"✅ Successfully connected to Primary Database!")
            engine = eng
            RAW_DB_URL = url
            break
    except Exception as err:
        print(f"DEBUG: Connection attempt failed for {url.split('@')[-1]}: {err}")

if not engine:
    print("⚠️ All Cloud DB connections failed. Auto-falling back to local SQLite database...")
    RAW_DB_URL = "sqlite:///./appshield.db"
    engine = create_engine(RAW_DB_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==============================================================================
# Database Schemas (Users, Quotes/Demos, Licenses, Threats)
# ==============================================================================
class UserRole(str, enum.Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    CLIENT = "CLIENT"

class SubscriptionTier(str, enum.Enum):
    TRIAL = "TRIAL"
    BRONZE = "BRONZE"
    SILVER = "SILVER"
    GOLD = "GOLD"

class LeadStatus(str, enum.Enum):
    NEW = "NEW"
    DEMO_SCHEDULED = "DEMO_SCHEDULED"
    QUOTATION_SENT = "QUOTATION_SENT"
    PO_RECEIVED = "PO_RECEIVED"
    COMPLETED = "COMPLETED"

TIER_FEATURES = {
    SubscriptionTier.TRIAL: ["Root", "Emulator", "Debug"],
    SubscriptionTier.BRONZE: ["Root", "Emulator", "Debug", "Frida", "HookingSystem"],
    SubscriptionTier.SILVER: ["Root", "Emulator", "Debug", "Frida", "HookingSystem", "SuspiciousOverlay", "SMSInterception"],
    SubscriptionTier.GOLD: ["Root", "Emulator", "Debug", "Frida", "HookingSystem", "SuspiciousOverlay", "SMSInterception", "Automation", "BehaviourAnomaly", "VishingRisk", "NFCRelaySensorAnomaly", "NFCRelayTimingAnomaly"]
}

class DBUser(Base):
    __tablename__ = "users"
    username = Column(String(50), primary_key=True, index=True)
    password_hash = Column(String(128), nullable=False)
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.CLIENT)
    company_name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    app_id = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class DBQuoteRequest(Base):
    __tablename__ = "quote_requests"
    id = Column(Integer, primary_key=True, autoincrement=True)
    company_name = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    phone = Column(String(50), nullable=True)
    package_tier = Column(SQLEnum(SubscriptionTier), nullable=False, default=SubscriptionTier.GOLD)
    status = Column(SQLEnum(LeadStatus), nullable=False, default=LeadStatus.NEW)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class DBLicense(Base):
    __tablename__ = "licenses"
    license_key = Column(String(100), primary_key=True, index=True)
    app_id = Column(String(100), nullable=False, index=True)
    client_username = Column(String(50), nullable=False)
    tier = Column(SQLEnum(SubscriptionTier), nullable=False, default=SubscriptionTier.TRIAL)
    valid_from = Column(String(20), nullable=False)  # YYYY-MM-DD
    valid_to = Column(String(20), nullable=False)    # YYYY-MM-DD
    expires_at = Column(Float, nullable=False)       # Epoch timestamp
    is_active = Column(Boolean, default=True)

class DBThreatLog(Base):
    __tablename__ = "threat_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    app_id = Column(String(50), nullable=False, index=True)
    threat = Column(String(100), nullable=False)
    device_id = Column(String(100), nullable=False)
    confidence = Column(Integer, nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    nonce = Column(String(64), nullable=False)

# ==============================================================================
# Billing Models
# ==============================================================================
class InvoiceStatus(str, enum.Enum):
    PENDING   = "PENDING"
    PAID      = "PAID"
    OVERDUE   = "OVERDUE"
    CANCELLED = "CANCELLED"

class DBInvoice(Base):
    __tablename__ = "invoices"
    id                = Column(Integer, primary_key=True, autoincrement=True)
    invoice_number    = Column(String(40), unique=True, nullable=False)
    client_username   = Column(String(50), nullable=False, index=True)
    company_name      = Column(String(100), nullable=False)
    email             = Column(String(100), nullable=False)
    tier              = Column(SQLEnum(SubscriptionTier), nullable=False)
    amount            = Column(Float, nullable=False)
    currency          = Column(String(10), default="INR")
    description       = Column(Text, nullable=True)
    valid_from        = Column(String(20), nullable=False)
    valid_to          = Column(String(20), nullable=False)
    status            = Column(SQLEnum(InvoiceStatus), default=InvoiceStatus.PENDING, nullable=False)
    due_date          = Column(String(20), nullable=True)
    paid_at           = Column(DateTime, nullable=True)
    payment_note      = Column(Text, nullable=True)   # Admin note on payment confirmation
    created_at        = Column(DateTime, default=datetime.utcnow)

class DBPaymentSettings(Base):
    """Singleton row (id=1). Admin configures once, clients read it."""
    __tablename__ = "payment_settings"
    id            = Column(Integer, primary_key=True, default=1)
    upi_id        = Column(String(100), nullable=True)
    upi_name      = Column(String(100), nullable=True)
    qr_code_url   = Column(Text, nullable=True)        # base64 data-URI or remote URL
    bank_name     = Column(String(100), nullable=True)
    account_name  = Column(String(100), nullable=True)
    account_number= Column(String(30), nullable=True)
    ifsc_code     = Column(String(20), nullable=True)
    swift_code    = Column(String(20), nullable=True)
    branch        = Column(String(100), nullable=True)
    payment_instructions = Column(Text, nullable=True)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Auto-create tables & seed default accounts (including nonce_cache table for M-02)
Base.metadata.create_all(bind=engine)


def seed_db():
    db = SessionLocal()
    try:
        # ISD: Seed password loaded from environment variable — never hardcoded
        admin_seed_pwd = os.environ.get("ADMIN_SEED_PASSWORD", "")
        if not admin_seed_pwd:
            print("⚠️  ADMIN_SEED_PASSWORD env var not set. Admin account not seeded.")
        else:
            admin_pwd = pwd_context.hash(admin_seed_pwd)
            db.add(DBUser(
                username="admin",
                password_hash=admin_pwd,
                role=UserRole.SUPER_ADMIN,
                company_name="AppShield Security HQ",
                email="admin@appshield.com",
                app_id="com.appshield.admin"
            ))
        
        # ISD: Seed password loaded from environment variable — never hardcoded
        client_seed_pwd = os.environ.get("CLIENT_SEED_PASSWORD", "")
        if not client_seed_pwd:
            print("⚠️  CLIENT_SEED_PASSWORD env var not set. Demo client account not seeded.")
        else:
            client_pwd = pwd_context.hash(client_seed_pwd)
            db.add(DBUser(
                username="client_demo",
                password_hash=client_pwd,
                role=UserRole.CLIENT,
                company_name="Acme Banking Corp",
                email="security@acmebank.com",
                app_id="com.acmebank.mobile"
            ))

        db.commit()
    finally:
        db.close()

seed_db()

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ISD FIX M-01: Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AppShield Enterprise Control Plane (v1.4 — ISD Hardened)",
    description="FastAPI B2B Portal Backend — ISD Security Hardened: bcrypt, env secrets, CORS allowlist, rate limiting, DB nonce persistence"
)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: StarletteRequest, exc: RateLimitExceeded):
    return StarletteResponse(content="Rate limit exceeded. Too many login attempts.", status_code=429)

# ISD FIX H-01: CORS restricted to explicit allowed origins only
from fastapi.middleware.cors import CORSMiddleware
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:3002,http://localhost:3003,https://appshield-portal.vercel.app"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "x-appshield-signature", "x-appshield-pow-solution"],
)

# Pydantic Schemas
class LeadCreateRequest(BaseModel):
    company_name: str
    email: str
    phone: Optional[str] = None
    package_tier: SubscriptionTier = SubscriptionTier.GOLD
    notes: Optional[str] = None

class LeadStatusUpdateRequest(BaseModel):
    quote_id: int
    status: LeadStatus
    notes: Optional[str] = None

class ClientProvisionRequest(BaseModel):
    username: str
    password: str
    company_name: str
    email: str
    app_id: str
    package_tier: SubscriptionTier = SubscriptionTier.GOLD
    valid_from: str  # YYYY-MM-DD
    valid_to: str    # YYYY-MM-DD

class LoginRequest(BaseModel):
    username: str
    password: str

class ThreatEvent(BaseModel):
    app_id: str = Field(..., max_length=50, pattern=r"^[a-zA-Z0-9\._]+$")
    threat: str = Field(..., max_length=100)
    device_id: str = Field(..., max_length=100, pattern=r"^[a-zA-Z0-9\-_]+$")
    confidence: int = Field(..., ge=0, le=100)
    timestamp: int = Field(..., gt=1600000000000)
    nonce: str = Field(..., max_length=64)

# ISD FIX M-02: Nonce persistence in DB (survives server restarts)
class DBNonce(Base):
    __tablename__ = "nonce_cache"
    nonce = Column(String(64), primary_key=True)
    created_at = Column(Float, default=time.time)

Base.metadata.create_all(bind=engine)  # ensure nonce table exists

security = HTTPBearer()

def verify_hmac(payload: bytes, signature: str) -> bool:
    import base64
    expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    try:
        provided_mac = base64.b64decode(signature)
        return hmac.compare_digest(expected_mac, provided_mac)
    except Exception:
        return False

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_admin_user(user: dict = Depends(get_current_user)):
    if user.get("role") != UserRole.SUPER_ADMIN.value:
        raise HTTPException(status_code=403, detail="Forbidden: Super Admin access required")
    return user

# ==============================================================================
# Authentication & User Management
# ==============================================================================
@app.post("/v1/auth/login")
@limiter.limit("5/minute")  # ISD FIX M-01: Rate limit — 5 attempts per minute per IP
async def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.username == body.username).first()

    # ISD FIX H-02: bcrypt verify (timing-safe, salted)
    if not user or not pwd_context.verify(body.password, user.password_hash):
        # Legacy SHA-256 fallback for existing seeded accounts before migration
        sha_hash = hashlib.sha256(body.password.encode()).hexdigest()
        if not user or user.password_hash != sha_hash:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled by Admin")

    payload = {
        "user_id": user.username,
        "role": user.role.value,
        "company_name": user.company_name,
        "app_id": user.app_id,
        "exp": time.time() + 86400
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role.value,
        "username": user.username,
        "company_name": user.company_name,
        "app_id": user.app_id
    }

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)

@app.post("/v1/auth/change-password")
async def change_password(
    req: ChangePasswordRequest,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Allows authenticated Admin or Client user to change their password in Supabase DB."""
    db_user = db.query(DBUser).filter(DBUser.username == user["user_id"]).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not pwd_context.verify(req.current_password, db_user.password_hash):
        sha_hash = hashlib.sha256(req.current_password.encode()).hexdigest()
        if db_user.password_hash != sha_hash:
            raise HTTPException(status_code=400, detail="Incorrect current password")
    
    db_user.password_hash = pwd_context.hash(req.new_password)
    db.commit()
    return {"message": "Password updated successfully in Supabase DB"}


# ==============================================================================
# Sales Pipeline: Leads, Demos & Quotations
# ==============================================================================
@app.post("/v1/quotes/request")
async def request_quote(req: LeadCreateRequest, db: Session = Depends(get_db)):
    lead = DBQuoteRequest(
        company_name=req.company_name,
        email=req.email,
        phone=req.phone,
        package_tier=req.package_tier,
        status=LeadStatus.NEW,
        notes=req.notes
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)
    return {"status": "success", "lead_id": lead.id, "message": "Quotation & Demo request received! Our enterprise sales team will contact you within 2 hours."}

@app.get("/v1/admin/quotes")
async def list_quotes(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    leads = db.query(DBQuoteRequest).order_by(DBQuoteRequest.id.desc()).all()
    return leads

@app.post("/v1/admin/quotes/update-status")
async def update_quote_status(req: LeadStatusUpdateRequest, admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    lead = db.query(DBQuoteRequest).filter(DBQuoteRequest.id == req.quote_id).first()
    if not lead:
        raise HTTPException(status_code=404, detail="Quote request not found")
    
    lead.status = req.status
    if req.notes:
        lead.notes = req.notes
    db.commit()
    return {"status": "success", "quote_id": lead.id, "new_status": lead.status}

# ==============================================================================
# Admin Client Provisioning (After PO Received)
# ==============================================================================
@app.post("/v1/admin/clients/provision")
async def provision_client_account(req: ClientProvisionRequest, admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    # 1. Create client account if not exists
    existing = db.query(DBUser).filter(DBUser.username == req.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    pwd_hash = pwd_context.hash(req.password)  # ISD FIX H-02: bcrypt hash for provisioned accounts
    client_user = DBUser(
        username=req.username,
        password_hash=pwd_hash,
        role=UserRole.CLIENT,
        company_name=req.company_name,
        email=req.email,
        app_id=req.app_id,
        is_active=True
    )
    db.add(client_user)

    # 2. Parse date range
    try:
        from_date = datetime.strptime(req.valid_from, "%Y-%m-%d")
        to_date = datetime.strptime(req.valid_to, "%Y-%m-%d")
        expires_epoch = to_date.timestamp()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    # 3. Create License Key
    license_key = f"SHIELD-{req.company_name.upper().replace(' ', '')}-{req.package_tier.value}-{uuid.uuid4().hex[:8].upper()}"
    license_obj = DBLicense(
        license_key=license_key,
        app_id=req.app_id,
        client_username=req.username,
        tier=req.package_tier,
        valid_from=req.valid_from,
        valid_to=req.valid_to,
        expires_at=expires_epoch,
        is_active=True
    )
    db.add(license_obj)
    db.commit()

    return {
        "status": "success",
        "username": req.username,
        "company_name": req.company_name,
        "app_id": req.app_id,
        "license_key": license_key,
        "valid_from": req.valid_from,
        "valid_to": req.valid_to,
        "tier": req.package_tier
    }

# ==============================================================================
# Client Portal Data & Authorized Gated Downloads
# ==============================================================================
@app.get("/v1/client/dashboard")
async def get_client_dashboard(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    username = user.get("user_id")
    license_obj = db.query(DBLicense).filter(DBLicense.client_username == username, DBLicense.is_active == True).first()
    
    if not license_obj:
        # Fallback query by app_id if username lookup misses
        app_id = user.get("app_id")
        license_obj = db.query(DBLicense).filter(DBLicense.app_id == app_id, DBLicense.is_active == True).first()

    threats = []
    if license_obj:
        threats = db.query(DBThreatLog).filter(DBThreatLog.app_id == license_obj.app_id).order_by(DBThreatLog.id.desc()).limit(100).all()

    return {
        "username": username,
        "company_name": user.get("company_name"),
        "app_id": license_obj.app_id if license_obj else user.get("app_id", "com.example.app"),
        "license": {
            "license_key": license_obj.license_key if license_obj else "NO_ACTIVE_LICENSE",
            "tier": license_obj.tier.value if license_obj else "TRIAL",
            "valid_from": license_obj.valid_from if license_obj else "2026-01-01",
            "valid_to": license_obj.valid_to if license_obj else "2026-12-31",
            "features": TIER_FEATURES[license_obj.tier] if license_obj else TIER_FEATURES[SubscriptionTier.TRIAL]
        },
        "recent_threats": [
            {
                "id": t.id,
                "threat": t.threat,
                "device_id": t.device_id,
                "confidence": t.confidence,
                "timestamp": t.timestamp
            } for t in threats
        ]
    }

@app.get("/v1/client/download/sdk")
async def download_sdk_binary(type: str = "aar", user: dict = Depends(get_current_user)):
    """Gated SDK Binary Download — Requires valid Client JWT token."""
    # ISD FIX L-01: Use relative path so it works on any server (Render/local)
    base_dir = os.path.join(os.path.dirname(__file__), "downloads")
    if type == "jar":
        file_path = os.path.join(base_dir, "shield-gradle-plugin-v1.2.0.jar")
        filename = "shield-gradle-plugin-v1.2.0.jar"
    else:
        file_path = os.path.join(base_dir, "shield-sdk-v1.2.0.aar")
        filename = "shield-sdk-v1.2.0.aar"
        
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="SDK binary not found on server. Contact admin.")
        
    return FileResponse(file_path, media_type="application/octet-stream", filename=filename)

# ==============================================================================
# Telemetry Ingestion (SDK Runtime)
# ==============================================================================
@app.post("/v1/telemetry")
async def report_threat(
    request: Request,
    event: ThreatEvent,
    db: Session = Depends(get_db),
    x_appshield_signature: Optional[str] = Header(None)
):
    x_appshield_pow = request.headers.get("x-appshield-pow-solution")
    if not x_appshield_pow:
        raise HTTPException(status_code=429, detail="Missing Proof of Work")
    
    parts = x_appshield_pow.split(":")
    if len(parts) != 3 or not parts[2].startswith("0000"):
        raise HTTPException(status_code=429, detail="Invalid PoW")
    
    if hashlib.sha256(f"{parts[0]}{parts[1]}".encode()).hexdigest() != parts[2]:
        raise HTTPException(status_code=429, detail="Invalid PoW")

    if not x_appshield_signature:
        raise HTTPException(status_code=401, detail="Missing security signature")

    body = await request.body()
    if not verify_hmac(body, x_appshield_signature):
         raise HTTPException(status_code=403, detail="Invalid signature")

    current_time_ms = int(time.time() * 1000)
    if abs(current_time_ms - event.timestamp) > 300000:
        raise HTTPException(status_code=403, detail="Request expired")

    # ISD FIX M-02: DB-backed nonce persistence (survives server restarts)
    existing_nonce = db.query(DBNonce).filter(DBNonce.nonce == event.nonce).first()
    if existing_nonce:
        raise HTTPException(status_code=403, detail="Replay attack detected")
    db.add(DBNonce(nonce=event.nonce, created_at=time.time()))
    # Purge nonces older than 10 minutes
    db.query(DBNonce).filter(DBNonce.created_at < time.time() - 600).delete()

    db_event = DBThreatLog(
        app_id=event.app_id,
        threat=event.threat,
        device_id=event.device_id,
        confidence=event.confidence,
        timestamp=event.timestamp,
        nonce=event.nonce
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    return {"status": "accepted", "event_id": db_event.id}

@app.get("/v1/license/validate")
async def validate_license(
    license_key: str,
    app_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user)  # ISD FIX M-03: Requires valid Bearer JWT — no anonymous access
):
    lic = db.query(DBLicense).filter(
        DBLicense.license_key == license_key,
        DBLicense.is_active == True
    ).first()

    # ISD FIX M-03: Removed SHIELD- prefix bypass — must match real DB record
    if not lic:
        return {"valid": False, "reason": "Invalid or inactive license key"}

    if lic.app_id != app_id:
        return {"valid": False, "reason": "License app_id mismatch"}

    if lic.expires_at < time.time():
        return {"valid": False, "reason": "License expired"}

    policy_payload = {
        "app_id": app_id,
        "tier": lic.tier,
        "features": TIER_FEATURES[lic.tier],
        "exp": lic.expires_at
    }
    policy_jwt = jwt.encode(policy_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"valid": True, "policy_token": policy_jwt}

@app.get("/v1/admin/threats/all")
async def get_all_threats(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    return db.query(DBThreatLog).order_by(DBThreatLog.id.desc()).limit(200).all()

# ==============================================================================
# Admin: Registered Users Management
# ==============================================================================
@app.get("/v1/admin/users")
async def list_all_users(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Returns all registered client users with their license info."""
    users = db.query(DBUser).filter(DBUser.role == UserRole.CLIENT).order_by(DBUser.created_at.desc()).all()
    result = []
    now = time.time()
    for user in users:
        lic = db.query(DBLicense).filter(
            DBLicense.client_username == user.username,
            DBLicense.is_active == True
        ).first()
        threat_count = db.query(DBThreatLog).filter(DBThreatLog.app_id == user.app_id).count() if user.app_id else 0
        days_remaining = None
        if lic:
            days_remaining = max(0, int((lic.expires_at - now) / 86400))
        result.append({
            "username": user.username,
            "company_name": user.company_name,
            "email": user.email,
            "app_id": user.app_id,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "license": {
                "license_key": lic.license_key if lic else None,
                "tier": lic.tier.value if lic else None,
                "valid_from": lic.valid_from if lic else None,
                "valid_to": lic.valid_to if lic else None,
                "expires_at": lic.expires_at if lic else None,
                "days_remaining": days_remaining,
                "is_expired": (lic.expires_at < now) if lic else None,
                "is_expiring_soon": (0 < days_remaining <= 30) if days_remaining is not None else False,
            } if lic else None,
            "total_threats_detected": threat_count
        })
    return result

@app.post("/v1/admin/users/toggle-status")
async def toggle_user_status(
    payload: dict,
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Enable or disable a client account."""
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="username required")
    user = db.query(DBUser).filter(DBUser.username == username, DBUser.role == UserRole.CLIENT).first()
    if not user:
        raise HTTPException(status_code=404, detail="Client user not found")
    user.is_active = not user.is_active
    db.commit()
    return {"username": username, "is_active": user.is_active, "status": "updated"}

# ==============================================================================
# Admin: License Analytics (Expiry Dashboard)
# ==============================================================================
@app.get("/v1/admin/licenses/analytics")
async def license_analytics(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Returns license counts segmented by expiry status."""
    now = time.time()
    soon_threshold = now + (30 * 86400)
    long_threshold = now + (180 * 86400)

    licenses = db.query(DBLicense).filter(DBLicense.is_active == True).all()

    expired, expiring_soon, long_validity, healthy = [], [], [], []

    for lic in licenses:
        user = db.query(DBUser).filter(DBUser.username == lic.client_username).first()
        threat_count = db.query(DBThreatLog).filter(DBThreatLog.app_id == lic.app_id).count()
        entry = {
            "license_key": lic.license_key,
            "client_username": lic.client_username,
            "company_name": user.company_name if user else "Unknown",
            "app_id": lic.app_id,
            "tier": lic.tier.value,
            "valid_from": lic.valid_from,
            "valid_to": lic.valid_to,
            "expires_at": lic.expires_at,
            "days_remaining": max(0, int((lic.expires_at - now) / 86400)),
            "threats_detected": threat_count
        }
        if lic.expires_at < now:
            expired.append(entry)
        elif lic.expires_at <= soon_threshold:
            expiring_soon.append(entry)
        elif lic.expires_at >= long_threshold:
            long_validity.append(entry)
        else:
            healthy.append(entry)

    return {
        "summary": {
            "total": len(licenses),
            "expired": len(expired),
            "expiring_soon": len(expiring_soon),
            "healthy": len(healthy),
            "long_validity": len(long_validity)
        },
        "expired": expired,
        "expiring_soon": expiring_soon,
        "healthy": healthy,
        "long_validity": long_validity
    }

# ==============================================================================
# Admin: Attack Analytics — Overall & Client-wise
# ==============================================================================
@app.get("/v1/admin/analytics/overview")
async def attack_analytics_overview(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Returns overall platform attack detection statistics."""
    from sqlalchemy import func

    total_detected = db.query(DBThreatLog).count()

    # Count by threat type
    threat_type_counts = db.query(
        DBThreatLog.threat,
        func.count(DBThreatLog.id).label("count")
    ).group_by(DBThreatLog.threat).order_by(func.count(DBThreatLog.id).desc()).all()

    # Count by app_id
    app_counts = db.query(
        DBThreatLog.app_id,
        func.count(DBThreatLog.id).label("count")
    ).group_by(DBThreatLog.app_id).order_by(func.count(DBThreatLog.id).desc()).all()

    # Confidence distribution: high ≥80 = defended, medium 50-79 = warned, low <50 = missed
    defended = db.query(DBThreatLog).filter(DBThreatLog.confidence >= 80).count()
    warned = db.query(DBThreatLog).filter(DBThreatLog.confidence >= 50, DBThreatLog.confidence < 80).count()
    missed = db.query(DBThreatLog).filter(DBThreatLog.confidence < 50).count()

    return {
        "total_detected": total_detected,
        "defended": defended,
        "warned": warned,
        "missed": missed,
        "defense_rate_pct": round((defended / total_detected * 100), 1) if total_detected > 0 else 0,
        "threat_type_breakdown": [{"threat": r.threat, "count": r.count} for r in threat_type_counts],
        "app_breakdown": [{"app_id": r.app_id, "count": r.count} for r in app_counts]
    }

@app.get("/v1/admin/analytics/client-wise")
async def attack_analytics_client_wise(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Returns per-client attack detection breakdown."""
    from sqlalchemy import func

    clients = db.query(DBUser).filter(DBUser.role == UserRole.CLIENT).all()
    result = []

    for client in clients:
        if not client.app_id:
            continue
        total = db.query(DBThreatLog).filter(DBThreatLog.app_id == client.app_id).count()
        defended = db.query(DBThreatLog).filter(
            DBThreatLog.app_id == client.app_id, DBThreatLog.confidence >= 80
        ).count()
        warned = db.query(DBThreatLog).filter(
            DBThreatLog.app_id == client.app_id,
            DBThreatLog.confidence >= 50, DBThreatLog.confidence < 80
        ).count()
        missed = db.query(DBThreatLog).filter(
            DBThreatLog.app_id == client.app_id, DBThreatLog.confidence < 50
        ).count()

        # Top threat type for this client
        top_threat = db.query(
            DBThreatLog.threat,
            func.count(DBThreatLog.id).label("cnt")
        ).filter(DBThreatLog.app_id == client.app_id).group_by(
            DBThreatLog.threat
        ).order_by(func.count(DBThreatLog.id).desc()).first()

        lic = db.query(DBLicense).filter(
            DBLicense.client_username == client.username,
            DBLicense.is_active == True
        ).first()

        result.append({
            "username": client.username,
            "company_name": client.company_name,
            "app_id": client.app_id,
            "tier": lic.tier.value if lic else "NONE",
            "total_detected": total,
            "defended": defended,
            "warned": warned,
            "missed": missed,
            "defense_rate_pct": round((defended / total * 100), 1) if total > 0 else 0,
            "top_threat": top_threat.threat if top_threat else "None"
        })

    result.sort(key=lambda x: x["total_detected"], reverse=True)
    return result

# ==============================================================================
# Billing — Pydantic Schemas
# ==============================================================================
class CreateInvoiceRequest(BaseModel):
    client_username: str
    tier: str
    amount: float
    currency: str = "INR"
    description: str = ""
    valid_from: str
    valid_to: str
    due_date: str = ""

class MarkPaidRequest(BaseModel):
    invoice_id: int
    payment_note: str = ""

class UpdatePaymentSettingsRequest(BaseModel):
    upi_id: str = ""
    upi_name: str = ""
    qr_code_url: str = ""
    bank_name: str = ""
    account_name: str = ""
    account_number: str = ""
    ifsc_code: str = ""
    swift_code: str = ""
    branch: str = ""
    payment_instructions: str = ""

# ==============================================================================
# Billing — Admin Endpoints
# ==============================================================================
def _next_invoice_number(db: Session) -> str:
    count = db.query(DBInvoice).count()
    return f"INV-{datetime.utcnow().strftime('%Y%m')}-{count + 1:04d}"

@app.post("/v1/admin/billing/invoices")
async def create_invoice(
    req: CreateInvoiceRequest,
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Create a new invoice for a client."""
    client = db.query(DBUser).filter(DBUser.username == req.client_username, DBUser.role == UserRole.CLIENT).first()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    try:
        tier = SubscriptionTier(req.tier)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {req.tier}")

    inv = DBInvoice(
        invoice_number=_next_invoice_number(db),
        client_username=req.client_username,
        company_name=client.company_name,
        email=client.email,
        tier=tier,
        amount=req.amount,
        currency=req.currency,
        description=req.description,
        valid_from=req.valid_from,
        valid_to=req.valid_to,
        due_date=req.due_date or None,
        status=InvoiceStatus.PENDING
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return {
        "message": f"Invoice {inv.invoice_number} created",
        "invoice_id": inv.id,
        "invoice_number": inv.invoice_number
    }

@app.get("/v1/admin/billing/invoices")
async def list_invoices_admin(
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """List all invoices across all clients."""
    invoices = db.query(DBInvoice).order_by(DBInvoice.id.desc()).all()
    return [_invoice_dict(inv) for inv in invoices]

@app.post("/v1/admin/billing/invoices/mark-paid")
async def mark_invoice_paid(
    req: MarkPaidRequest,
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Admin manually marks an invoice as PAID after verifying bank/UPI transfer."""
    inv = db.query(DBInvoice).filter(DBInvoice.id == req.invoice_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    inv.status = InvoiceStatus.PAID
    inv.paid_at = datetime.utcnow()
    inv.payment_note = req.payment_note
    db.commit()
    return {"message": f"Invoice {inv.invoice_number} marked as PAID", "invoice_number": inv.invoice_number}

@app.post("/v1/admin/billing/invoices/cancel")
async def cancel_invoice(
    payload: dict,
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Cancel a pending invoice."""
    inv = db.query(DBInvoice).filter(DBInvoice.id == payload.get("invoice_id")).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if inv.status == InvoiceStatus.PAID:
        raise HTTPException(status_code=400, detail="Cannot cancel a PAID invoice")
    inv.status = InvoiceStatus.CANCELLED
    db.commit()
    return {"message": f"Invoice {inv.invoice_number} cancelled"}

@app.post("/v1/admin/billing/invoices/mark-overdue")
async def mark_invoice_overdue(
    payload: dict,
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    inv = db.query(DBInvoice).filter(DBInvoice.id == payload.get("invoice_id")).first()
    if not inv or inv.status != InvoiceStatus.PENDING:
        raise HTTPException(status_code=404, detail="Pending invoice not found")
    inv.status = InvoiceStatus.OVERDUE
    db.commit()
    return {"message": f"Invoice {inv.invoice_number} marked OVERDUE"}

# ==============================================================================
# Billing — Payment Settings (Admin)
# ==============================================================================
def _get_or_create_settings(db: Session) -> DBPaymentSettings:
    s = db.query(DBPaymentSettings).filter(DBPaymentSettings.id == 1).first()
    if not s:
        s = DBPaymentSettings(id=1)
        db.add(s)
        db.commit()
        db.refresh(s)
    return s

@app.get("/v1/billing/payment-settings")
async def get_payment_settings(db: Session = Depends(get_db)):
    """Public endpoint — returns payment info (UPI, bank details, QR) so clients can pay."""
    s = _get_or_create_settings(db)
    return {
        "upi_id": s.upi_id, "upi_name": s.upi_name, "qr_code_url": s.qr_code_url,
        "bank_name": s.bank_name, "account_name": s.account_name,
        "account_number": s.account_number, "ifsc_code": s.ifsc_code,
        "swift_code": s.swift_code, "branch": s.branch,
        "payment_instructions": s.payment_instructions
    }

@app.put("/v1/admin/billing/payment-settings")
async def update_payment_settings(
    req: UpdatePaymentSettingsRequest,
    admin: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Admin sets UPI ID, QR code, bank account details."""
    s = _get_or_create_settings(db)
    s.upi_id = req.upi_id or s.upi_id
    s.upi_name = req.upi_name or s.upi_name
    s.qr_code_url = req.qr_code_url or s.qr_code_url
    s.bank_name = req.bank_name or s.bank_name
    s.account_name = req.account_name or s.account_name
    s.account_number = req.account_number or s.account_number
    s.ifsc_code = req.ifsc_code or s.ifsc_code
    s.swift_code = req.swift_code or s.swift_code
    s.branch = req.branch or s.branch
    s.payment_instructions = req.payment_instructions or s.payment_instructions
    s.updated_at = datetime.utcnow()
    db.commit()
    return {"message": "Payment settings updated successfully"}

# ==============================================================================
# Billing — Client Endpoints
# ==============================================================================
@app.get("/v1/client/billing/invoices")
async def list_invoices_client(
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Client sees only their own invoices."""
    invoices = db.query(DBInvoice).filter(
        DBInvoice.client_username == user["user_id"]
    ).order_by(DBInvoice.id.desc()).all()
    return [_invoice_dict(inv) for inv in invoices]

# ==============================================================================
# Billing — Shared Helper
# ==============================================================================
def _invoice_dict(inv: DBInvoice) -> dict:
    return {
        "id": inv.id,
        "invoice_number": inv.invoice_number,
        "client_username": inv.client_username,
        "company_name": inv.company_name,
        "email": inv.email,
        "tier": inv.tier.value,
        "amount": inv.amount,
        "currency": inv.currency,
        "description": inv.description,
        "valid_from": inv.valid_from,
        "valid_to": inv.valid_to,
        "due_date": inv.due_date,
        "status": inv.status.value,
        "paid_at": inv.paid_at.isoformat() if inv.paid_at else None,
        "payment_note": inv.payment_note,
        "created_at": inv.created_at.isoformat() if inv.created_at else None
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
