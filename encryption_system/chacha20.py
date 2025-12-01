# RFC8439


def rotl32(v, n):
    return (((v << n) & 0xffffffff) | (v >> (32 - n)))


def bytes_to_words(b):
    return [int.from_bytes(b[i:i+4], "little") for i in range(0, len(b), 4)]


def words_to_bytes(words):
    return b"".join(w.to_bytes(4, "little") for w in words)


def quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    return a, b, c, d


def chacha20_block(key, counter, nonce):
    assert (len(key) == 32 and len(nonce) == 12), "key must be 32 bytes, nonce 12 bytes"

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
    key_words = bytes_to_words(key)
    nonce_words = bytes_to_words(nonce)

    state = constants + key_words + [counter] + nonce_words
    working = state.copy()

    for _ in range(10):
        # column rounds
        working[0], working[4], working[8],  working[12] = quarter_round(working[0], working[4], working[8],  working[12])
        working[1], working[5], working[9],  working[13] = quarter_round(working[1], working[5], working[9],  working[13])
        working[2], working[6], working[10], working[14] = quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = quarter_round(working[3], working[7], working[11], working[15])

        # diagonal rounds
        working[0], working[5], working[10], working[15] = quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8],  working[13] = quarter_round(working[2], working[7], working[8],  working[13])
        working[3], working[4], working[9],  working[14] = quarter_round(working[3], working[4], working[9],  working[14])

    output = [(working[i] + state[i]) & 0xffffffff for i in range(16)]
    return words_to_bytes(output)


def encrypt(key, nonce, plaintext, initial_counter=1):
    counter = initial_counter
    ciphertext = bytearray()
    i = 0

    while i < len(plaintext):
        block = chacha20_block(key, counter, nonce)
        block_len = min(64, len(plaintext) - i)
        for j in range(block_len):
            ciphertext.append(plaintext[i + j] ^ block[j])
        i += block_len
        counter = (counter + 1) & 0xffffffff
    
    return bytes(ciphertext)


def decrypt(key, nonce, ciphertext, initial_counter=1):
    return encrypt(key, nonce, ciphertext, initial_counter)