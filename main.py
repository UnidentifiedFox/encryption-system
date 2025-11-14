import rsa, chacha20

def main():
    keys = rsa.generate_keys(2048)
    m = 15
    print(f"message: {m}")

    cipher = rsa.encrypt(m, keys["public_key"])
    print(f"encrypted: {cipher}")

    clear = rsa.decrypt(cipher, keys["private_key"])
    print(f"decrypted: {clear}")

if __name__ == "__main__":
    main()