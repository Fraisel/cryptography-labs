import codecs


class RC4:
    def __init__(self, key):
        self._key = key

    @staticmethod
    def KSA(key):
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]
        return s

    @staticmethod
    def PRGA(s):
        i, j = 0, 0
        while True:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            t = (s[i] + s[j]) % 256
            k = s[t]
            yield k

    def keystream(self, key):
        s = self.KSA(key)
        return self.PRGA(s)

    def encryption(self, key, plaintext):
        key = [ord(c) for c in key]

        stream = self.keystream(key)

        res = []
        for c in plaintext:
            val = ("%02X" % (c ^ next(stream)))
            res.append(val)
        return ''.join(res)

    def encrypt(self, plaintext):
        return self.encryption(self._key, [ord(c) for c in plaintext])

    def decrypt(self, cipher):
        cipher = codecs.decode(cipher, 'hex_codec')
        res = self.encryption(self._key, cipher)
        return codecs.decode(res, 'hex_codec').decode('utf-8')  # noqa


def main():
    key = 'very-simple-key'
    rc4 = RC4(key)
    plaintext = 'Test phrase for RC4'

    cipher = rc4.encrypt(plaintext)
    print(f'Plaintext: {plaintext}\nCipher: {cipher}')

    decrypted = rc4.decrypt(cipher)
    print(f'Decrypted: {decrypted}')


if __name__ == '__main__':
    main()
