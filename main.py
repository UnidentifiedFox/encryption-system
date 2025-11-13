import rsa, chacha20

def main():
    keys = rsa.generate_rsa_keys(24)
    m = 15

    cipher = rsa.encrypt(m, keys["public_key"])
    print(cipher)

    clear = rsa.decrypt(cipher, keys["private_key"])
    print(clear)
    

if __name__ == "__main__":
    main()