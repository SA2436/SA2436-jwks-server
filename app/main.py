# app/main.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta, timezone
import time
import jwt  # PyJWT
from app.keys import KeyStore
from app.jwk import rsa_public_to_jwk
from typing import Dict


app = FastAPI(title="JWKS Demo")

# create datastore and pre-generate keys: one valid (24h) and one expired (2h ago)
ks = KeyStore()
ks.generate_key(bits=2048, expiry_epoch=time.time() + 24 * 3600)
ks.generate_key(bits=2048, expiry_epoch=time.time() - 2 * 3600)

JWT_ISS = "jwks-python-demo"

@app.get("/jwks")
def jwks():
    """
    Return JWKS containing only **unexpired** public keys.
    """
    now = time.time()
    unexpired = ks.get_unexpired_public_keys(now=now)
    jwks = {"keys": []}
    for e in unexpired:
        pub_nums = e.public_numbers()
        jwks["keys"].append(rsa_public_to_jwk(e.kid, pub_nums))
    return JSONResponse(content=jwks)

@app.post("/auth")
def auth(request: Request):
    """
    Issue a signed JWT. If the query parameter `expired` is present (any value),
    issue token signed with an expired key and set token exp == key.expiry (in the past).
    """
    # method POST enforced by decorator
    params = dict(request.query_params)
    use_expired = "expired" in params

    now = time.time()
    key_entry = None
    if use_expired:
        key_entry = ks.get_newest_expired_key(now=now)
        if key_entry is None:
            raise HTTPException(status_code=500, detail="no expired key available")
    else:
        key_entry = ks.get_newest_unexpired_key(now=now)
        if key_entry is None:
            raise HTTPException(status_code=500, detail="no unexpired key available")

    # Build claims
    iat = int(now)
    if use_expired:
        exp = int(key_entry.expiry)
    else:
        preferred_exp = now + 15 * 60  # 15 minutes
        # ensure token doesn't outlive key
        if preferred_exp > key_entry.expiry:
            exp = int(key_entry.expiry)
        else:
            exp = int(preferred_exp)

    payload = {
        "iss": JWT_ISS,
        "iat": iat,
        "sub": "test-user",
        "exp": exp,
    }

    # prepare headers with kid
    headers = {"kid": key_entry.kid, "alg": "RS256", "typ": "JWT"}

    # private key in PEM format for PyJWT
    private_pem = key_entry.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)
    return {"token": token}
