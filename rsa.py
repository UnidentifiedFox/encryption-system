import secrets, math

def miller_rabin(n, k=40):
    #redundant initial checks assuming lsb and msb is 1
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
        prime = secrets.randbits(bits)
        prime |= (1 << (bits - 1))
        prime |= 1

        if miller_rabin(prime):
            return prime

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

def encrypt(m, k):
    return pow(m, k[0], k[1])

def decrypt(c, k):
    return pow(c, k[0], k[1])