import math
import time
from random import getrandbits

from miller_rabin import is_prime


def encode(s):  # str to int
    n = 0
    for ch in s[::-1]:
        n = n * 128 + ord(ch)
    return n


def decode(n):  # int to str
    s = ""
    copy = n
    while copy != 0:
        copy, val = divmod(copy, 128)
        s += chr(val)
    return s


def generatePrime(k=1024):
    r = 100 * (math.log(k, 2) + 1)
    p = 4
    # keep generating if the primality test fails
    while r > 0:
        p = getrandbits(k)
        p |= (1 << k - 1) | 1
        if is_prime(p):
            return p
        r -= 1
    return p


# extended euclidean algorithm
def xgcd(x, y):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while y > 0:
        q, x, y = int(x // y), y, x % y
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0, y0  # two coefficients


def modinv(F, e):
    """
    return x such that (d * e) % F == 1
    """
    g, d = xgcd(F, e)
    return d % F


def pow_mod(x, y, m):  # pow(x, y) mod m
    # input - tuple (public key)
    binary = bin(y)[2:]
    x0 = x % m
    if binary[-1] == "1":
        c = x
    else:
        c = 1
    for i in range(len(binary) - 1):
        x1 = x0 ** 2 % m
        if binary[-i - 2] == "1":
            c = c * x1 % m
        x0 = x1
    return c


class RSA:
    def __init__(self, key_length=256):
        self.__e = 65537

        self.__p = generatePrime(key_length)
        self.__q = generatePrime(key_length)

        self.__n = self.__p * self.__q
        self.__Fi = (self.__p - 1) * (self.__q - 1)
        self.__d = modinv(self.__Fi, self.__e)

    def encrypt(self, message):
        return pow_mod(message, self.__e, self.__n)

    def decrypt(self, cipher):
        return pow_mod(cipher, self.__d, self.__n)

    def decrypt_crt(self, c):
        """
        Private key for RSA-CRT is (dP, dQ, qInv, p, q).
        """
        p = self.__p
        q = self.__q
        d = self.__d

        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = modinv(q, p)

        x1 = pow_mod(c, dp, p)
        x2 = pow_mod(c, dq, q)
        h = (qinv * (x1 - x2)) % p
        m = x2 + h * q
        return m


if __name__ == '__main__':
    plaintext = 12345
    for length in (256, 512, 1024):
        print(f'Length: {length}')
        print(f'Plaintext: {plaintext}')

        rsa = RSA(length)
        cipher = rsa.encrypt(plaintext)
        print(f'Cipher: {cipher}')

        start = time.time()
        decrypted = rsa.decrypt(cipher)
        finish = time.time()
        print(f'Decrypted: {decrypted} in {finish - start} seconds.')

        start = time.time()
        decrypted_crt = rsa.decrypt_crt(cipher)
        finish = time.time()
        print(f'Decrypted with CRT: {decrypted_crt} in {finish - start} seconds.\n')

