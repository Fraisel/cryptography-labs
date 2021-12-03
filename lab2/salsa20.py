class Salsa20:
    def __init__(self, key):
        self._state = None
        self._key = key

    def encrypt(self, text, nonce=bytearray(range(8)), block_counter=[0] * 8):
        assert len(self._key) == 32
        assert len(nonce) == 8
        assert len(block_counter) == 8

        k = [self.__little_endian(self._key[4 * i:4 * i + 4]) for i in range(8)]
        n = [self.__little_endian(nonce[4 * i:4 * i + 4]) for i in range(2)]
        b = [self.__little_endian(block_counter[4 * i:4 * i + 4]) for i in range(2)]
        c = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

        state = [c[0], k[0], k[1], k[2],
                 k[3], c[1], n[0], n[1],
                 b[0], b[1], c[2], k[4],
                 k[5], k[6], k[7], c[3]]
        self._state = state[:]

        for _ in range(10):
            self._state = self.__double_round(self._state)

        self._state = [self._state[i] + state[i] for i in range(16)]

        return [a ^ b for a, b in zip(self._state, list(text))]

    def __QR(self, y):
        z = [0] * 4
        z[1] = y[1] ^ self.__rot_left(((y[0] + y[3]) % 2 ** 32), 7)
        z[2] = y[2] ^ self.__rot_left(((z[1] + y[0]) % 2 ** 32), 9)
        z[3] = y[3] ^ self.__rot_left(((z[2] + z[1]) % 2 ** 32), 13)
        z[0] = y[0] ^ self.__rot_left(((z[3] + z[2]) % 2 ** 32), 18)
        return z

    def __row_round(self, y):
        z = [0] * 16
        z[0], z[1], z[2], z[3] = self.__QR([y[0], y[1], y[2], y[3]])
        z[5], z[6], z[7], z[4] = self.__QR([y[5], y[6], y[7], y[4]])
        z[10], z[11], z[8], z[9] = self.__QR([y[10], y[11], y[8], y[9]])
        z[15], z[12], z[13], z[14] = self.__QR([y[15], y[12], y[13], y[14]])
        return z

    def __column_round(self, y):
        z = [0] * 16
        z[0], z[4], z[8], z[12] = self.__QR([y[0], y[4], y[8], y[12]])
        z[5], z[9], z[13], z[1] = self.__QR([y[5], y[9], y[13], y[1]])
        z[10], z[14], z[2], z[6] = self.__QR([y[10], y[14], y[2], y[6]])
        z[15], z[3], z[7], z[11] = self.__QR([y[15], y[3], y[7], y[11]])
        return z

    def __double_round(self, y):
        return self.__row_round(self.__column_round(y))

    @staticmethod
    def __little_endian(b):
        return b[0] ^ (b[1] << 8) ^ (b[2] << 16) ^ (b[3] << 24)

    @staticmethod
    def __rot_left(x, y):
        return (x << y) % (2 ** 32 - 1)


if __name__ == '__main__':
    key = b'this-is-secret-key-of-length-32!'
    plaintext = 'salsa20'

    print(f'Plaintext: {plaintext}')

    salsa = Salsa20(key)
    cipher = salsa.encrypt(plaintext.encode('UTF-8'))
    print(f'Ciphertext: {cipher}')

    decrypted = bytearray(salsa.encrypt(cipher)).decode("utf-8")
    print(f'Decrypted: {decrypted}')
