# app/main.py
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import time
import jwt
from app.keys import KeyStore
from app.jwk import rsa_key_to_jwk

app = FastAPI()
ks = KeyStore()

# Generate keys
now = time.time()
active_key = ks.generate_key(expiry_epoch=now + 600)  # 10 minutes
expired_key = ks.generate_key(expiry_epoch=now - 300)  # expired 5 minutes ago

JWT_ISS = "fake_issuer"

@app.get("/.well-known/jwks.json")
def jwks():
    keys = [rsa_key_to_jwk(k) for k in ks.get_unexpired_public_keys()]
    return {"keys": keys}

@app.post("/auth")
def auth(expired: bool = False):
    key = expired_key if expired else active_key
    headers = {"kid": key.kid}

    payload = {
        "sub": "fake_user",
        "iat": int(time.time()),
        "exp": int(key.expiry)
    }

    token = jwt.encode(payload, key.private_key, algorithm="RS256", headers=headers)
    return JSONResponse(content={"token": token})
