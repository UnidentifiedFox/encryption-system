import secrets, math

#TODO implement miller-rabin for a faster algorithm
def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False

    return True

def generate_prime(bits):
    prime = secrets.randbits(bits)
    prime |= (1 << (bits - 1)) #msb to 1
    prime |= 1 #lsb to 1

    #TODO set a limit
    while(not is_prime(prime)):
        prime = secrets.randbits(bits)
        prime |= (1 << (bits - 1))
        prime |= 1
    
    return prime

def generate_rsa_keys(bits):
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