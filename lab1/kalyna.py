import os

import numpy as np

from aes1 import get_key_iv, SALT_SIZE, pad, split_blocks, unpad
from key_expansion import KeyExpand


class KALYNA_TYPE:
    KALYNA_128_128 = {
        "Nk": 2,  # number of columns in key
        "Nb": 2,  # number of columns in state
        "Nr": 10  # number of rounds
    }

    KALYNA_128_256 = {
        "Nk": 4,
        "Nb": 2,
        "Nr": 14
    }

    KALYNA_256_256 = {
        "Nk": 4,
        "Nb": 4,
        "Nr": 14
    }

    KALYNA_256_512 = {
        "Nk": 8,
        "Nb": 4,
        "Nr": 18
    }

    KALYNA_512_512 = {
        "Nk": 8,
        "Nb": 8,
        "Nr": 18
    }


class Kalyna:

    def __init__(self, key, kalyna_type):
        self._key = key

        self._nk = kalyna_type["Nk"]
        self._nb = kalyna_type["Nb"]
        self._nr = kalyna_type["Nr"]

        self._words = KeyExpand(self._nb, self._nk, self._nr).expansion(key)

    def encrypt(self, plaintext):
        state = plaintext.copy()

        KeyExpand.add_round_key_expand(state, self._words[0])
        for word in self._words[1:-1]:
            state = KeyExpand.encipher_round(state, self._nb)
            KeyExpand.xor_round_key_expand(state, word)

        state = KeyExpand.encipher_round(state, self._nb)
        KeyExpand.add_round_key_expand(state, self._words[-1])

        return state

    def decrypt(self, ciphertext):
        state = ciphertext.copy()

        KeyExpand.sub_round_key_expand(state, self._words[-1])
        for word in self._words[1:-1][::-1]:
            state = KeyExpand.decipher_round(state, self._nb)
            KeyExpand.xor_round_key_expand(state, word)

        state = KeyExpand.decipher_round(state, self._nb)
        KeyExpand.sub_round_key_expand(state, self._words[0])

        return state


if __name__ == "__main__":
    master_key = 'secret-key'
    plaintext = b'test phrase'

    plaintext_padded = pad(plaintext)
    salt = os.urandom(SALT_SIZE)
    key = np.frombuffer((get_key_iv(master_key.encode('utf-8'), salt)[0]), dtype=np.uint64)

    res = b''
    k = Kalyna(key, KALYNA_TYPE.KALYNA_128_128)
    for text_block in split_blocks(plaintext_padded):
        encrypted_input = k.encrypt(np.frombuffer(text_block, dtype=np.uint64))
        decrypted_input = k.decrypt(encrypted_input)
        res += bytes(bytearray(decrypted_input))

    assert unpad(res) == plaintext
