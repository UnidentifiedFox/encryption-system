import secrets, json, base64, socket, argparse, hashlib

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from pikepdf import AttachedFileSpec, Pdf

from . import rsa
from . import chacha20 as cha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("type", choices=["server", "client"], help="Select server or client")
    parser.add_argument("-m", "--message", help="Enter the path of the message file")
    parser.add_argument("-a", "--algorithm", default="chacha20", choices=["chacha20", "rsa"],
                        help="chacha20 by default, enter rsa to also encrypt the message with rsa")
    args = parser.parse_args()       

    if args.type == "server":
        server()
    elif args.type == "client":
        client(args.message, args.algorithm)


def server(host="127.0.0.1", port=5000):
    server_keys = rsa.generate_keys(2048)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    conn, addr = s.accept()

    client_raw = conn.recv(256)
    client_n = int.from_bytes(client_raw, "big")
    client_pubkey = (65537, client_n)

    server_pub_n = server_keys["public_key"][1].to_bytes(256, "big")
    conn.sendall(server_pub_n)

    size = int.from_bytes(conn.recv(4), "big")
    pdf_bytes = b""
    while len(pdf_bytes) < size:
        pdf_bytes += conn.recv(size - len(pdf_bytes))

    pdf_path = "./received_sample.pdf"
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

    extr_payload = extract_json(pdf_path)
    extr_algorithm = extr_payload["algorithm"]
    extr_signature = base64.b64decode(extr_payload["signature"])
    extr_encrypted_key_nonce =  base64.b64decode(extr_payload["encrypted_key_nonce"])
    extr_cipher = base64.b64decode(extr_payload["ciphertext"])

    hash = hashlib.sha256(extr_cipher).digest()
    signature = rsa.decrypt(int.from_bytes(extr_signature, "big"),
                            client_pubkey).to_bytes(32, "big")
    
    if hash != signature:
        print("Signature mismatch")
        return

    if extr_algorithm == "chacha20":
        decrypted_key_nonce = rsa.decrypt(int.from_bytes(extr_encrypted_key_nonce, "big"),
                                          server_keys["private_key"]).to_bytes(44, "big")
    
        decrypted_nonce = decrypted_key_nonce[:12]
        decrypted_key = decrypted_key_nonce[12:]

        print(cha.decrypt(decrypted_key, decrypted_nonce, extr_cipher).decode("utf-8"))
    else:
        decrypted_message = rsa.decrypt(int.from_bytes(extr_cipher, "big"),
                                        server_keys["private_key"]).to_bytes(256, "big").lstrip(b'\x00')
        
        print(decrypted_message.decode("utf-8"))

    conn.close()
    s.close()


def client(message_path, algorithm, host="127.0.0.1", port=5000):
    if message_path:
        try:
            with open(message_path, "rb") as f:
                message = f.read()
        except FileNotFoundError:
            print(f"Error: File not found at {message_path}")
            return
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    else:
        message = input("Message to send:").encode("utf-8") 

    if algorithm == "rsa" and len(message) > 256:
        print("Enter less than 256 bytes for RSA")
        return

    client_keys = rsa.generate_keys(2048)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    client_pub_n = client_keys["public_key"][1].to_bytes(256, "big")
    s.sendall(client_pub_n)

    server_raw = s.recv(256)
    server_n = int.from_bytes(server_raw, "big")
    server_pubkey = (65537, server_n)

    if algorithm == "chacha20":
        chacha_key = secrets.token_bytes(32)
        chacha_nonce = secrets.token_bytes(12)

        cipher = cha.encrypt(chacha_key, chacha_nonce, message)
        chacha_key_nonce =  chacha_nonce + chacha_key

        encrypted_key_nonce = rsa.encrypt(int.from_bytes(chacha_key_nonce, "big"), 
                                          server_pubkey).to_bytes(256, "big")
        
    else:
        padded_message = message.rjust(256, b'\x00')
        cipher = rsa.encrypt(int.from_bytes(padded_message, "big"),
                             server_pubkey).to_bytes(256, "big")
        encrypted_key_nonce = b""


    hash = hashlib.sha256(cipher).digest()
    signature = rsa.encrypt(int.from_bytes(hash, "big"),
                            client_keys["private_key"]).to_bytes(256, "big")

    pdf_path = "./sample.pdf"
    create_pdf(pdf_path)

    payload = {
        "algorithm": algorithm,
        "signature": base64.b64encode(signature).decode("ascii"),
        "ciphertext": base64.b64encode(cipher).decode("ascii"),
        "encrypted_key_nonce": base64.b64encode(encrypted_key_nonce).decode("ascii"),
    }

    embed_json(pdf_path, payload)

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    s.sendall(len(pdf_bytes).to_bytes(4, "big"))
    s.sendall(pdf_bytes)

    s.close()


def create_pdf(pdf_path):
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(100, 700, "Sample PDF")
    c.showPage()
    c.save()


def embed_json(pdf_path, json_data):
    temp_json_path = "temp_payload.json"
    with open(temp_json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=4)

    pdf = Pdf.open(pdf_path, allow_overwriting_input=True)

    filespec = AttachedFileSpec.from_filepath(
        pdf,
        temp_json_path,
        description="payload"
    )

    pdf.attachments["payload.json"] = filespec
    pdf.save(pdf_path)
    pdf.close()


def extract_json(pdf_path):
    pdf = Pdf.open(pdf_path, allow_overwriting_input=True)

    file = pdf.attachments["payload.json"].get_file()
    payload_bytes = file.read_bytes()

    return json.loads(payload_bytes.decode("utf-8"))


if __name__ == "__main__":
    main()