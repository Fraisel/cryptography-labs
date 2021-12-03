from random import randint


def is_prime(n, k=40):
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    d, r = n - 1, 0
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


if __name__ == '__main__':
    print(is_prime(int(input('Enter number to test: '))))
