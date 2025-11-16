import rsa, secrets
import chacha20 as cha

def main():
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    m = b"testing hybrid encryption"

    print(f"clear chacha key: {key}")

    cipher = cha.encrypt(key, nonce, m)
    print(f"cipher text {cipher}")

    keys = rsa.generate_keys(2048)
    encrypted_key = rsa.encrypt(int.from_bytes(key, "little"), keys["private_key"])
    print(f"encrypted chacha key: {encrypted_key}")

    decrypted_key = rsa.decrypt(encrypted_key, keys["public_key"]).to_bytes(32, "little")
    print(f"decrypted chacha key {decrypted_key}")

    print(f"clear text {cha.decrypt(decrypted_key, nonce, cipher)}")


if __name__ == "__main__":
    main()