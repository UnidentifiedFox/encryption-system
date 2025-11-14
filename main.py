import rsa, secrets
import chacha20 as cha

def main():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    m = b"test"

    cipher = cha.encrypt(key, nonce, m)
    print(cipher)

    print(cha.decrypt(key, nonce, cipher))


if __name__ == "__main__":
    main()