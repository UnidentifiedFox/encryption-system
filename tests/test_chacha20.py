import pytest

from encryption_system import chacha20 as cha

def test_rotl32():
    assert cha.rotl32(0x12345678, 16) == 0x56781234
    assert cha.rotl32(0xffffffff, 5) == 0xffffffff
    assert cha.rotl32(0x00000001, 1) == 0x00000002


def test_bytes_to_words_and_back():
    b = bytes.fromhex("0102030405060708")
    words = cha.bytes_to_words(b)
    assert words == [0x04030201, 0x08070605]
    assert cha.words_to_bytes(words) == b


def test_chacha20_block_rfc8439_vector():
    # RFC 8439 - Section 2.3.2 test vector
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000090000004a00000000")
    counter = 1

    output = cha.chacha20_block(key, counter, nonce)

    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    assert output == expected


def test_chacha20_encrypt_rfc8439():
    # RFC 8439 - Section 2.4.2 test vector
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000000000004a00000000")
    counter = 1
    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e"
    )

    expected = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )

    ciphertext = cha.encrypt(key, nonce, plaintext, counter)

    assert ciphertext == expected


def test_chacha20_decrypt_rfc8439():
    # Same vector but reverse
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000000000004a00000000")
    counter = 1
    ciphertext = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    )

    plaintext = bytes.fromhex(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e"
    )

    decrypted = cha.decrypt(key, nonce, ciphertext, counter)

    assert decrypted == plaintext


def test_encrypt_decrypt():
    key = b"A" * 32
    nonce = b"B" * 12
    plaintext = b"HelloWorld123"

    ct = cha.encrypt(key, nonce, plaintext, 1)
    pt = cha.decrypt(key, nonce, ct, 1)

    assert pt == plaintext


def test_encrypt_partial_block():
    key = b"K" * 32
    nonce = b"N" * 12
    plaintext = b"123"  # < 64 bytes block

    ct = cha.encrypt(key, nonce, plaintext)
    pt = cha.decrypt(key, nonce, ct)

    assert pt == plaintext


def test_block_integrity():
    key = b"A" * 32
    nonce = b"B" * 12

    block1 = cha.chacha20_block(key, 1, nonce)
    block2 = cha.chacha20_block(key, 2, nonce)

    pt = b"\x00" * 128
    ct = cha.encrypt(key, nonce, pt)

    assert ct[:64] == block1
    assert ct[64:] == block2