# app/jwk.py
import jwt

def rsa_key_to_jwk(key):
    public_numbers = key.public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n

    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": key.kid,
        "n": jwt.utils.base64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).decode("utf-8"),
        "e": jwt.utils.base64url_encode(e.to_bytes((e.bit_length() + 7) // 8, "big")).decode("utf-8")
    }
