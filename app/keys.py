# app/keys.py
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa

class Key:
    def __init__(self, private_key, public_key, expiry):
        self.private_key = private_key
        self.public_key = public_key
        self.expiry = expiry
        self.kid = str(uuid.uuid4())

class KeyStore:
    def __init__(self):
        self.keys = []

    def generate_key(self, key_size=2048, expiry_epoch=None):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        key = Key(private_key, public_key, expiry_epoch)
        self.keys.append(key)
        return key

    def get_unexpired_public_keys(self, now=None):
        if now is None:
            now = time.time()
        return [k for k in self.keys if k.expiry > now]

    def get_newest_unexpired_key(self, now=None):
        keys = self.get_unexpired_public_keys(now)
        if not keys:
            return None
        return max(keys, key=lambda k: k.expiry)

    def get_newest_expired_key(self, now=None):
        if now is None:
            now = time.time()
        expired = [k for k in self.keys if k.expiry <= now]
        if not expired:
            return None
        return max(expired, key=lambda k: k.expiry)

    def get_key_by_kid(self, kid):
        for k in self.keys:
            if k.kid == kid:
                return k
        return None
