# tests/test_keys.py
import time
from app.keys import KeyStore

def test_generate_and_query():
    ks = KeyStore()
    now = time.time()
    e1 = ks.generate_key(2048, expiry_epoch=now + 3600)
    e2 = ks.generate_key(2048, expiry_epoch=now - 3600)  # expired

    unexpired = ks.get_unexpired_public_keys(now=now)
    assert any(k.kid == e1.kid for k in unexpired)
    assert not any(k.kid == e2.kid for k in unexpired)

    assert ks.get_newest_unexpired_key(now=now) is not None
    assert ks.get_newest_expired_key(now=now) is not None

    found = ks.get_key_by_kid(e1.kid)
    assert found is not None
    assert found.kid == e1.kid
