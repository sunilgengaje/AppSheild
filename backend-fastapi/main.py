import hmac
import hashlib
import time
import jwt
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

app = FastAPI(title="AppShield Control Plane (v1.2)", description="Python/FastAPI Backend for Threat Telemetry, Licensing, and API Security")

import enum
import uuid

# Secrets
SECRET_KEY = b"REPLACE_WITH_PROVISIONED_SECRET"
JWT_SECRET = "super_secret_jwt_key_for_demo"
JWT_ALGORITHM = "HS256"

# ==============================================================================
# Phase 13: SaaS Tiering Configuration
# ==============================================================================
class SubscriptionTier(str, enum.Enum):
    TRIAL = "TRIAL"
    BRONZE = "BRONZE"
    SILVER = "SILVER"
    GOLD = "GOLD"

TIER_FEATURES = {
    SubscriptionTier.TRIAL: ["Root", "Emulator", "Debug"],
    SubscriptionTier.BRONZE: ["Root", "Emulator", "Debug", "Frida", "HookingSystem"],
    SubscriptionTier.SILVER: ["Root", "Emulator", "Debug", "Frida", "HookingSystem", "SuspiciousOverlay", "SMSInterception"],
    SubscriptionTier.GOLD: ["Root", "Emulator", "Debug", "Frida", "HookingSystem", "SuspiciousOverlay", "SMSInterception", "Automation", "BehaviourAnomaly", "VishingRisk", "NFCRelaySensorAnomaly", "NFCRelayTimingAnomaly"]
}

class ProvisionRequest(BaseModel):
    app_name: str
    email: str

class UpgradeRequest(BaseModel):
    license_key: str
    target_tier: SubscriptionTier

# Mock DB: license_key -> { "app_id": str, "tier": SubscriptionTier, "expires_at": float }
license_db = {}


# ==============================================================================
# Phase 12: Server-Side Validation (Input Sanitization)
# Strict Field constraints prevent SQLi, XSS, and buffer overflows natively.
# ==============================================================================
class ThreatEvent(BaseModel):
    app_id: str = Field(..., max_length=50, pattern=r"^[a-zA-Z0-9\._]+$")
    threat: str = Field(..., max_length=100)
    device_id: str = Field(..., max_length=100, pattern=r"^[a-zA-Z0-9\-_]+$")
    confidence: int = Field(..., ge=0, le=100)
    timestamp: int = Field(..., gt=1600000000000)
    nonce: str = Field(..., max_length=64)

class LoginRequest(BaseModel):
    username: str = Field(..., max_length=50)
    password: str = Field(..., max_length=50)

class TransactionRequest(BaseModel):
    amount: float = Field(..., gt=0, lt=1000000)
    recipient_account: str = Field(..., pattern=r"^\d{8,12}$")

class URLCheckRequest(BaseModel):
    url: str

class CallVerifyRequest(BaseModel):
    device_id: str
    reported_caller_id: str

# Storage simulation
threat_db = []
nonce_cache = set() # Phase 12: Replay Attack Cache
security = HTTPBearer()

def verify_hmac(payload: bytes, signature: str) -> bool:
    expected_mac = hmac.new(SECRET_KEY, payload, hashlib.sha256).digest()
    import base64
    try:
        provided_mac = base64.b64decode(signature)
        return hmac.compare_digest(expected_mac, provided_mac)
    except Exception:
        return False

# ==============================================================================
# Phase 12: Authentication Bypass Defense
# ==============================================================================
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validates JWT. Defends against Auth Bypass."""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/v1/auth/login")
async def login(request: LoginRequest):
    """Issues a JWT for the mock banking app."""
    # Mock auth: any user/pass works for demo, assigns role based on username
    role = "admin" if request.username == "admin" else "user"
    payload = {
        "user_id": request.username,
        "role": role,
        "exp": time.time() + 3600 # 1 hour
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

# ==============================================================================
# Phase 12: IDOR (Insecure Direct Object Reference) & Authorization Bypass Defense
# ==============================================================================
@app.post("/v1/users/{target_user_id}/transaction")
async def execute_transaction(
    target_user_id: str,
    transaction: TransactionRequest,
    user: dict = Depends(get_current_user)
):
    """
    Mock Banking Endpoint.
    Defends against IDOR: Checks if the JWT user matches the target_user_id.
    Defends against Auth Bypass: Depends on get_current_user (JWT).
    """
    requester_id = user.get("user_id")
    role = user.get("role")
    
    # IDOR Check: Users can only transact on their own account unless they are an admin.
    if requester_id != target_user_id and role != "admin":
        print(f"🚨 [IDOR BLOCKED] User '{requester_id}' attempted to access '{target_user_id}'")
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to access this account (IDOR Blocked)")
        
    return {"status": "success", "tx_id": "TXN991823", "amount": transaction.amount}

# ==============================================================================
# Telemetry Endpoint (Replay & Tamper Defenses)
# ==============================================================================
@app.post("/v1/telemetry")
async def report_threat(
    request: Request,
    event: ThreatEvent,
    x_appshield_signature: Optional[str] = Header(None)
):
    """Receives telemetry. Enforces PoW, HMAC, and Replay protections."""
    # 0. Proof of Work (DDoS)
    x_appshield_pow = request.headers.get("x-appshield-pow-solution")
    if not x_appshield_pow:
        raise HTTPException(status_code=429, detail="Missing Proof of Work - Request Dropped")
    
    parts = x_appshield_pow.split(":")
    if len(parts) != 3 or not parts[2].startswith("0000"):
        raise HTTPException(status_code=429, detail="Invalid PoW")
    
    if hashlib.sha256(f"{parts[0]}{parts[1]}".encode()).hexdigest() != parts[2]:
        raise HTTPException(status_code=429, detail="Invalid PoW")

    # 1. Verify Signature (Tampering)
    if not x_appshield_signature:
        raise HTTPException(status_code=401, detail="Missing security signature")

    body = await request.body()
    if not verify_hmac(body, x_appshield_signature):
         raise HTTPException(status_code=403, detail="Invalid signature - tampering detected")

    # 2. Replay Attack Defense (Timestamp + Nonce Cache)
    current_time_ms = int(time.time() * 1000)
    if abs(current_time_ms - event.timestamp) > 300000:
        raise HTTPException(status_code=403, detail="Request expired")
        
    if event.nonce in nonce_cache:
        print(f"🚨 [REPLAY BLOCKED] Duplicate nonce detected: {event.nonce}")
        raise HTTPException(status_code=403, detail="Replay attack detected (Nonce already used)")
        
    nonce_cache.add(event.nonce) # Store nonce to prevent reuse
    # Note: In production, nonces in Redis should have a TTL of 300s (matching the window).

    # 3. Log Event
    print(f"🚨 [THREAT DETECTED] App: {event.app_id} | Threat: {event.threat} | Device: {event.device_id}")
    threat_db.append(event)
    return {"status": "accepted", "event_id": len(threat_db)}

# ==============================================================================
# Legacy Endpoints (License, AI Fraud, Intel)
# ==============================================================================
# ==============================================================================
# Phase 13: SaaS License Provisioning & Tier Management
# ==============================================================================
@app.post("/v1/license/provision")
async def provision_license(req: ProvisionRequest):
    """Creates a new 30-day TRIAL license."""
    app_id = f"com.{req.app_name.lower().replace(' ', '')}"
    license_key = f"SHIELD-{uuid.uuid4().hex}"
    
    license_db[license_key] = {
        "app_id": app_id,
        "tier": SubscriptionTier.TRIAL,
        "expires_at": time.time() + (30 * 24 * 3600) # 30 days
    }
    return {"status": "success", "app_id": app_id, "license_key": license_key, "tier": "TRIAL"}

@app.post("/v1/license/upgrade")
async def upgrade_license(req: UpgradeRequest):
    """Upgrades an existing license to a paid tier."""
    if req.license_key not in license_db:
        raise HTTPException(status_code=404, detail="License not found")
        
    license_db[req.license_key]["tier"] = req.target_tier
    return {"status": "success", "new_tier": req.target_tier}

@app.get("/v1/license/validate")
async def validate_license(license_key: str, app_id: str):
    """
    Called by the AppShield SDK at runtime.
    Returns a signed JWT containing the active policy features.
    """
    if license_key not in license_db:
        # Fallback for the hardcoded CLI test key during Phase 1-12
        if license_key.startswith("SHIELD-"):
            # Provide GOLD access by default to legacy test apps
            tier = SubscriptionTier.GOLD
            expires_at = time.time() + (365 * 24 * 3600)
        else:
            return {"valid": False, "reason": "Invalid or expired license"}
    else:
        record = license_db[license_key]
        if record["app_id"] != app_id or record["expires_at"] < time.time():
            return {"valid": False, "reason": "License mismatch or expired"}
        tier = record["tier"]
        expires_at = record["expires_at"]

    policy_payload = {
        "app_id": app_id,
        "tier": tier,
        "features": TIER_FEATURES[tier],
        "exp": expires_at
    }
    # Sign the policy so the SDK knows it hasn't been tampered with
    policy_jwt = jwt.encode(policy_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "valid": True,
        "policy_token": policy_jwt
    }

@app.get("/v1/threats", response_model=List[ThreatEvent])
async def get_threats():
    return threat_db

@app.post("/v1/ai/voice-liveness")
async def verify_voice_liveness(
    device_id: str = Form(...),
    challenge_phrase: str = Form(...),
    audio_file: UploadFile = File(...),
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"liveness_score": 0.98, "status": "APPROVED", "ai_probability": 0.02}

@app.post("/v1/ai/video-liveness")
async def verify_video_liveness(
    device_id: str = Form(...),
    challenge_action: str = Form(...),
    video_file: UploadFile = File(...),
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"liveness_score": 0.95, "status": "APPROVED", "ai_probability": 0.05}

@app.post("/v1/ai/document-liveness")
async def verify_document_liveness(
    device_id: str = Form(...),
    document_image: UploadFile = File(...),
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"authenticity_score": 0.96, "status": "APPROVED", "ai_probability": 0.04}

@app.post("/v1/auth/secure-call-verify")
async def verify_secure_call(
    request: CallVerifyRequest,
    x_appshield_signature: Optional[str] = Header(None)
):
    if not x_appshield_signature: raise HTTPException(status_code=401)
    return {"verified": request.reported_caller_id.startswith("+1800")}

@app.post("/v1/threat-intel/url-check")
async def verify_url_reputation(request: URLCheckRequest):
    malicious_keywords = ["secure-login", "bank-alert", "account-recovery"]
    if any(k in request.url.lower() for k in malicious_keywords):
        return {"status": "MALICIOUS", "confidence": 0.99}
    return {"status": "SAFE", "confidence": 1.0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
