K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def rot_right(num, shift):
    return (num >> shift) | (num << 32 - shift)


def sha256(message):
    message = bytearray(message, 'ascii')

    length = len(message) * 8

    # add one
    message.append(0x80)

    # add zero
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)

    # add 64 bits to end
    message += length.to_bytes(8, 'big')

    blocks = []
    for i in range(0, len(message), 64):
        blocks.append(message[i:i + 64])

    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    for block in blocks:
        w = []
        for i in range(64):
            if i <= 15:
                w.append(bytes(block[i * 4:(i * 4) + 4]))
            else:
                term1 = rot_right(int.from_bytes(w[i - 2], 'big'), 17) \
                        ^ rot_right(int.from_bytes(w[i - 2], 'big'), 19) \
                        ^ (int.from_bytes(w[i - 2], 'big') >> 10)

                term2 = int.from_bytes(w[i - 7], 'big')

                term3 = rot_right(int.from_bytes(w[i - 15], 'big'), 7) \
                        ^ rot_right(int.from_bytes(w[i - 15], 'big'), 18) \
                        ^ (int.from_bytes(w[i - 15], 'big') >> 3)

                term4 = int.from_bytes(w[i - 16], 'big')

                w.append(((term1 + term2 + term3 + term4) % 2 ** 32).to_bytes(4, 'big'))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        for i in range(64):
            t1 = ((h + (rot_right(e, 6) ^ rot_right(e, 11) ^ rot_right(e, 25)) + ((e & f) ^ (~e & g)) + K[
                i] + int.from_bytes(w[i], 'big')) % 2 ** 32)
            t2 = ((rot_right(a, 2) ^ rot_right(a, 13) ^ rot_right(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) % 2 ** 32

            h = g
            g = f
            f = e
            e = (d + t1) % 2 ** 32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2 ** 32

        h0 = (h0 + a) % 2 ** 32
        h1 = (h1 + b) % 2 ** 32
        h2 = (h2 + c) % 2 ** 32
        h3 = (h3 + d) % 2 ** 32
        h4 = (h4 + e) % 2 ** 32
        h5 = (h5 + f) % 2 ** 32
        h6 = (h6 + g) % 2 ** 32
        h7 = (h7 + h) % 2 ** 32

        return (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') +
                h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') +
                h4.to_bytes(4, 'big') + h5.to_bytes(4, 'big') +
                h6.to_bytes(4, 'big') + h7.to_bytes(4, 'big'))


if __name__ == '__main__':
    text = 'test phrase'
    print(sha256(text).hex())
    import hashlib

    m = hashlib.sha256()
    m.update(bytes(text))
    print(m.hexdigest())
