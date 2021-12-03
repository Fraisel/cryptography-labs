import pytest

from .miller_rabin import is_prime
from .rsa import RSA


@pytest.fixture
def rsa():
    return RSA()


def test_prime():
    assert is_prime(1451)
    assert not is_prime(1452)


def test_rsa(rsa):
    plaintext = 12345
    cipher = rsa.encrypt(plaintext)

    assert rsa.decrypt(cipher) == plaintext
    assert rsa.decrypt_crt(cipher) == plaintext
