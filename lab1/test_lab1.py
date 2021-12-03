import pytest
from .aes import AES


@pytest.fixture
def aes():
    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    return AES(key)


def test_aes_encrypt(aes):
    plaintext = 0x3243f6a8885a308d313198a2e0370734
    cipher = aes.encrypt_block(plaintext)

    assert cipher == 0x3925841d02dc09fbdc118597196a0b32


def test_aes_decrypt(aes):
    cipher = 0x3925841d02dc09fbdc118597196a0b32
    decrypted = aes.decrypt_block(cipher)

    assert decrypted == 0x3243f6a8885a308d313198a2e0370734

