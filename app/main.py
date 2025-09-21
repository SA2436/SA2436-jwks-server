from fastapi import FastAPI
from fastapi.responses import JSONResponse
import jwt
from datetime import datetime, timedelta
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = FastAPI()

# Generate RSA key pair
def generate_rsa_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())
    expiry = datetime.utcnow() + timedelta(minutes=10)

    return {
        "kid": kid,
        "expiry": expiry,
        "private_key": private_key,
        "public_key": public_key
    }

# Hold active and expired keys
active_key = generate_rsa_key()
expired_key = generate_rsa_key()
expired_key["expiry"] = datetime.utcnow() - timedelta(minutes=5)

# JWKS endpoint
@app.get("/.well-known/jwks.json")
def jwks():
    keys = []
    now = datetime.utcnow()
    for key in [active_key]:
        if key["expiry"] > now:
            public_numbers = key["public_key"].public_numbers()
            e = public_numbers.e
            n = public_numbers.n
            keys.append({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": key["kid"],
                "n": jwt.utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode("utf-8"),
                "e": jwt.utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode("utf-8")
            })
    return {"keys": keys}

# Auth endpoint
@app.post("/auth")
def auth(expired: bool = False):
    key_to_use = expired_key if expired else active_key
    private_key = key_to_use["private_key"]
    headers = {"kid": key_to_use["kid"]} # This must match JWKS

    payload = {
        "sub": "fake_user",
        "iat": datetime.utcnow(),
        "exp": key_to_use["expiry"]
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return JSONResponse(content={"token": token})
