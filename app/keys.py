# app/keys.py
from __future__ import annotations
import threading
import time
import hashlib
import binascii
from typing import Optional, List
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

@dataclass
class KeyEntry:
    private_key: rsa.RSAPrivateKey
    kid: str
    expiry: float  # epoch seconds

    def public_numbers(self):
        return self.private_key.public_key().public_numbers()

class KeyStore:
    """
    In-memory key store with basic functions:
    - generate RSA key with expiry
    - get newest unexpired / expired key
    - list unexpired public keys
    - lookup by kid
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._keys: List[KeyEntry] = []

    def generate_key(self, bits: int, expiry_epoch: float) -> KeyEntry:
        if bits < 1024:
            raise ValueError("bits must be >= 1024")
        pk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        # kid generated from SHA1 of modulus+exp, hex truncated
        pub = pk.public_key().public_numbers()
        m_bytes = pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")
        e_bytes = pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")
        h = hashlib.sha1()
        h.update(m_bytes)
        h.update(e_bytes)
        kid = binascii.hexlify(h.digest())[:16].decode()
        entry = KeyEntry(private_key=pk, kid=kid, expiry=expiry_epoch)
        with self._lock:
            self._keys.append(entry)
        return entry

    def get_unexpired_public_keys(self, now: Optional[float] = None):
        if now is None:
            now = time.time()
        with self._lock:
            return [k for k in self._keys if k.expiry > now]

    def get_newest_unexpired_key(self, now: Optional[float] = None) -> Optional[KeyEntry]:
        if now is None:
            now = time.time()
        with self._lock:
            for k in reversed(self._keys):
                if k.expiry > now:
                    return k
        return None

    def get_newest_expired_key(self, now: Optional[float] = None) -> Optional[KeyEntry]:
        if now is None:
            now = time.time()
        with self._lock:
            for k in reversed(self._keys):
                if k.expiry <= now:
                    return k
        return None

    def get_key_by_kid(self, kid: str) -> Optional[KeyEntry]:
        with self._lock:
            for k in self._keys:
                if k.kid == kid:
                    return k
        return None

    def export_public_pem(self, kid: str) -> Optional[bytes]:
        k = self.get_key_by_kid(kid)
        if not k:
            return None
        pub = k.private_key.public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
