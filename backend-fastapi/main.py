import hmac
import hashlib
import time
import jwt
import os
import enum
import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Depends, UploadFile, File, Form, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sqlalchemy import create_engine, Column, String, Integer, Float, BigInteger, Text, Boolean, Enum as SQLEnum, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# Secret configurations
SECRET_KEY = b"REPLACE_WITH_PROVISIONED_SECRET"
JWT_SECRET = "super_secret_jwt_key_for_appshield_enterprise_v1"
JWT_ALGORITHM = "HS256"

# Dynamic DB URL: Try Supabase Pooler formats (IPv4 compatible) with password DevSunl%40123
ENC_PWD = "DevSunl%40123"
PROJ_REF = "kuoshydjkhwaemgmelea"

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

# Auto-create tables & seed default accounts
Base.metadata.create_all(bind=engine)

def seed_db():
    db = SessionLocal()
    try:
        # Seed Super Admin
        admin_user = db.query(DBUser).filter(DBUser.username == "admin").first()
        if not admin_user:
            admin_pwd = hashlib.sha256("admin123".encode()).hexdigest()
            db.add(DBUser(
                username="admin",
                password_hash=admin_pwd,
                role=UserRole.SUPER_ADMIN,
                company_name="AppShield Security HQ",
                email="admin@appshield.com",
                app_id="com.appshield.admin"
            ))
        
        # Seed Pre-provisioned Demo B2B Client (Acme Banking Corp)
        client_demo = db.query(DBUser).filter(DBUser.username == "client_demo").first()
        if not client_demo:
            client_pwd = hashlib.sha256("client123".encode()).hexdigest()
            db.add(DBUser(
                username="client_demo",
                password_hash=client_pwd,
                role=UserRole.CLIENT,
                company_name="Acme Banking Corp",
                email="security@acmebank.com",
                app_id="com.acmebank.mobile"
            ))
            
            # Seed active Gold License for demo client valid for 365 days
            today = datetime.utcnow()
            valid_from_str = today.strftime("%Y-%m-%d")
            valid_to_str = (today + timedelta(days=365)).strftime("%Y-%m-%d")
            expires_timestamp = (today + timedelta(days=365)).timestamp()
            
            db.add(DBLicense(
                license_key="SHIELD-ACME-BANKING-GOLD-KEY",
                app_id="com.acmebank.mobile",
                client_username="client_demo",
                tier=SubscriptionTier.GOLD,
                valid_from=valid_from_str,
                valid_to=valid_to_str,
                expires_at=expires_timestamp,
                is_active=True
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

app = FastAPI(
    title="AppShield Enterprise Control Plane (v1.4)",
    description="FastAPI B2B Portal Backend with Dual Role Auth, Sales Pipeline, Custom License Expiry Ranges & Gated SDK Downloads"
)

# Enable CORS for browser fetch requests
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

nonce_cache = set()
security = HTTPBearer()

def verify_hmac(payload: bytes, signature: str) -> bool:
    expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    import base64
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
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    pwd_hash = hashlib.sha256(request.password.encode()).hexdigest()
    user = db.query(DBUser).filter(DBUser.username == request.username).first()
    
    if not user or user.password_hash != pwd_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled by Admin")

    payload = {
        "user_id": user.username,
        "role": user.role.value,
        "company_name": user.company_name,
        "app_id": user.app_id,
        "exp": time.time() + 86400  # 24 hour token
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
    
    pwd_hash = hashlib.sha256(req.password.encode()).hexdigest()
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
    base_dir = "/Users/developdit/Documents/AppSheild/AppShield_Master_Source_v1_1_Hardened_FIXED/saas_release"
    if type == "jar":
        file_path = os.path.join(base_dir, "shield-gradle-plugin-v1.2.0.jar")
        filename = "shield-gradle-plugin-v1.2.0.jar"
    else:
        file_path = os.path.join(base_dir, "shield-sdk-v1.2.0.aar")
        filename = "shield-sdk-v1.2.0.aar"
        
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="SDK binary file not found on server")
        
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
        
    if event.nonce in nonce_cache:
        raise HTTPException(status_code=403, detail="Replay attack detected")
        
    nonce_cache.add(event.nonce)

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
async def validate_license(license_key: str, app_id: str, db: Session = Depends(get_db)):
    lic = db.query(DBLicense).filter(DBLicense.license_key == license_key, DBLicense.is_active == True).first()
    
    if not lic:
        if license_key.startswith("SHIELD-"):
            tier = SubscriptionTier.GOLD
            expires_at = time.time() + (365 * 24 * 3600)
        else:
            return {"valid": False, "reason": "Invalid or inactive license key"}
    else:
        if lic.app_id != app_id or lic.expires_at < time.time():
            return {"valid": False, "reason": "License mismatch or expired"}
        tier = lic.tier
        expires_at = lic.expires_at

    policy_payload = {
        "app_id": app_id,
        "tier": tier,
        "features": TIER_FEATURES[tier],
        "exp": expires_at
    }
    policy_jwt = jwt.encode(policy_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"valid": True, "policy_token": policy_jwt}

@app.get("/v1/admin/threats/all")
async def get_all_threats(admin: dict = Depends(get_admin_user), db: Session = Depends(get_db)):
    return db.query(DBThreatLog).order_by(DBThreatLog.id.desc()).limit(200).all()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
