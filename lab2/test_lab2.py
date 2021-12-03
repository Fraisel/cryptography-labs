import pytest

from .rc4 import RC4
from .salsa20 import Salsa20


@pytest.fixture()
def rc4():
    key = 'very-simple-key'
    return RC4(key)


@pytest.fixture()
def salsa20():
    key = b'this-is-secret-key-of-length-32!'
    return Salsa20(key)


def test_rc4_encrypt(rc4):
    plaintext = 'Test phrase for RC4'

    assert rc4.encrypt(plaintext) == 'A066EF57459FEB72F233934CFE790C505EA573'


def test_rc4_decrypt(rc4):
    cipher = 'A066EF57459FEB72F233934CFE790C505EA573'

    assert rc4.decrypt(cipher) == 'Test phrase for RC4'


def test_salsa20_encrypt(salsa20):
    plaintext = 'salsa20'.encode('UTF-8')

    assert salsa20.encrypt(plaintext) == [2636323761, 2316560840, 4432725150, 3485213944,
                                          2965961440, 1289521106, 1309247260]


def test_salsa20_decrypt(salsa20):
    cipher = [2636323761, 2316560840, 4432725150, 3485213944, 2965961440, 1289521106, 1309247260]

    assert bytearray(salsa20.encrypt(cipher)).decode("utf-8") == 'salsa20'
