import pytest

from encryption_system import rsa


def test_miller_rabin_small_primes():
    assert rsa.miller_rabin(2)
    assert rsa.miller_rabin(3)
    assert rsa.miller_rabin(5)
    assert rsa.miller_rabin(17)

    assert not rsa.miller_rabin(1)
    assert not rsa.miller_rabin(4)
    assert not rsa.miller_rabin(15)
    assert not rsa.miller_rabin(21)


def test_generate_prime_bit_length():
    p = rsa.generate_prime(32)
    assert p.bit_length() == 32
    assert rsa.miller_rabin(p)


def test_generate_key_sizes():
    keys = rsa.generate_keys(64)
    (e, n) = keys["public_key"]
    (d, n2) = keys["private_key"]

    assert n == n2
    assert n.bit_length() == 64


def test_encrypt_decrypt():
    keys = rsa.generate_keys(64)
    pub = keys["public_key"]
    priv = keys["private_key"]

    message = 123456789

    ciphertext = rsa.encrypt(message, pub)
    plaintext = rsa.decrypt(ciphertext, priv)

    assert plaintext == message


def test_encrypt_output_range():
    keys = rsa.generate_keys(64)
    pub = keys["public_key"]

    message = 42
    ciphertext = rsa.encrypt(message, pub)

    _, n = pub
    assert 0 <= ciphertext < n


def test_encrypt_value_too_large():
    keys = rsa.generate_keys(64)
    pub = keys["public_key"]
    e, n = pub

    too_large = n + 1

    with pytest.raises(ValueError):
        rsa.encrypt(too_large, pub)