import requests
import time
import hashlib
import hmac
import base64
import json

BASE_URL = "http://127.0.0.1:8000/v1"
SECRET_KEY = b"REPLACE_WITH_PROVISIONED_SECRET"

def generate_pow() -> str:
    # Basic PoW generator for "0000" difficulty
    challenge = str(int(time.time()))
    nonce = 0
    while True:
        h = hashlib.sha256(f"{challenge}{nonce}".encode()).hexdigest()
        if h.startswith("0000"):
            return f"{challenge}:{nonce}:{h}"
        nonce += 1

def run_tests():
    print("=== AppShield Backend Dynamic Tests ===\n")

    # TEST 1: Missing Proof of Work (Volumetric Attack Simulation)
    print("Test 1: Sending request without Proof of Work (Simulating Volumetric Attack)")
    payload = {
        "app_id": "com.appshield.test",
        "threat": "HOOK_DETECTED",
        "device_id": "device123",
        "confidence": 99,
        "timestamp": int(time.time() * 1000),
        "nonce": "abc123nonce"
    }
    try:
        response = requests.post(f"{BASE_URL}/telemetry", json=payload, headers={})
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}\n")
    except Exception as e:
        print(f"Failed to connect: {e}\n")

    # TEST 2: Missing HMAC Signature (API Abuse / Tampering Simulation)
    print("Test 2: Sending request with PoW but missing HMAC signature (Simulating Tampering)")
    pow_header = generate_pow()
    try:
        response = requests.post(
            f"{BASE_URL}/telemetry",
            json=payload,
            headers={"x-appshield-pow-solution": pow_header}
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}\n")
    except Exception as e:
        print(f"Failed to connect: {e}\n")

    # TEST 3: Authorized AppShield Request (Valid PoW and Signature)
    print("Test 3: Sending fully authorized SDK request (Valid PoW & HMAC)")
    # Re-calculate timestamp for replay protection
    payload["timestamp"] = int(time.time() * 1000)
    body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    # Let's just use the exact payload the requests library will serialize to
    # A bit tricky in Python to perfectly match JSON serialization string matching, 
    # so we will use the exact data parameter if needed, but requests json= sorts differently.
    # To be safe, we will post the raw bytes.
    
    mac = hmac.new(SECRET_KEY, body_bytes, hashlib.sha256).digest()
    b64_mac = base64.b64encode(mac).decode('utf-8')
    
    try:
        response = requests.post(
            f"{BASE_URL}/telemetry",
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "x-appshield-pow-solution": generate_pow(),
                "x-appshield-signature": b64_mac
            }
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}\n")
    except Exception as e:
        print(f"Failed to connect: {e}\n")

if __name__ == "__main__":
    time.sleep(1) # Give server a sec to boot
    run_tests()
