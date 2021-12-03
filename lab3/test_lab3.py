import hashlib

from .sha256 import sha256


def test_sha256():
    text = 'test phrase for sha256'

    assert sha256(text).hex() == hashlib.sha256(text.encode('utf-8')).hexdigest()
