# app/jwk.py
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from typing import Dict
import base64

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def rsa_public_to_jwk(kid: str, pub_numbers: RSAPublicNumbers) -> Dict:
    n = pub_numbers.n
    e = pub_numbers.e
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(n_bytes),
        "e": _b64url(e_bytes),
    }
