# tests/test_handlers.py
import time
import jwt
from httpx import Client
from app.main import app, ks, JWT_ISS
from app.keys import KeyStore

def test_jwks_and_auth_endpoints():
    # ensure ks has at least one unexpired and one expired key
    now = time.time()
    # refill ks for test isolation: create a fresh KeyStore inside tests? 
    # app.ks is shared; ensure it has needed keys
    # but we will check that endpoints behave properly
    with Client(app=app, base_url="http://test") as client:
        r = client.get("/jwks")
        assert r.status_code == 200
        jwks = r.json()
        assert "keys" in jwks
        assert isinstance(jwks["keys"], list)
        assert len(jwks["keys"]) >= 1  # at least one unexpired from startup

        # request normal token
        r2 = client.post("/auth")
        assert r2.status_code == 200
        tok = r2.json().get("token")
        assert tok is not None and isinstance(tok, str)

        # parse header without verifying to ensure kid present
        unverified = jwt.decode(tok, options={"verify_signature": False, "verify_exp": False})
        # decode header:
        hdr = jwt.get_unverified_header(tok)
        assert "kid" in hdr

        # request expired-signed token
        r3 = client.post("/auth?expired=1")
        assert r3.status_code == 200
        tok2 = r3.json().get("token")
        assert tok2 is not None
        hdr2 = jwt.get_unverified_header(tok2)
        assert "kid" in hdr2

        # verify token from /auth is signed by a current key (we can fetch jwks and find matching kid)
        kid = hdr["kid"]
        # find kid in jwks from /jwks
        matches = [k for k in jwks["keys"] if k.get("kid") == kid]
        assert len(matches) == 1  # the kid used for normal token should be unexpired and in jwks

        # the expired token's kid should not appear in /jwks
        jwks2 = jwks
        expired_kid = hdr2["kid"]
        assert all(k.get("kid") != expired_kid for k in jwks2["keys"])
