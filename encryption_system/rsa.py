import secrets


def miller_rabin(n, k=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    
    for _ in range(k):
        a = secrets.randbelow(n-3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
            
    return True


def generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1

        if miller_rabin(candidate):
            return candidate


def generate_keys(bits):
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() == bits:
            break

    phi = (p-1) * (q-1)
    e = 65537 #standard
    d = pow(e, -1, phi)

    return {
        "public_key": (e, n),
        "private_key": (d, n)
    }


def encrypt(m, key):
    e, n = key
    if m >= n:
        raise ValueError("message must be smaller than modulus")
    return pow(m, e, n)


def decrypt(c, key):
    d, n = key
    return pow(c, d, n)