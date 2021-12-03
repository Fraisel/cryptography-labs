import random
import string
import time

from kupyna import Kupyna
from sha256 import sha256


def random_str(size=5, chars=string.printable):
    return ''.join(random.choice(chars) for _ in range(size))


def main():
    kupyna = Kupyna(256)
    for hash_func in [sha256, kupyna.hash]:
        for length in range(1, 6):
            start = time.time()
            hashes = set()
            while True:
                _hash = hash_func(random_str(length))
                if _hash not in hashes:
                    hashes.add(_hash)
                else:
                    break
            finish = time.time()
            print(hash_func, length, len(hashes), round(finish - start, 5))


if __name__ == '__main__':
    main()
