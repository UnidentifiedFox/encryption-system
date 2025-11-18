import rsa, secrets, json, base64
import chacha20 as cha
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from pikepdf import AttachedFileSpec, Pdf

def main():
    chacha_key = secrets.token_bytes(32)
    chacha_nonce = secrets.token_bytes(12)
    m = b"testing hybrid encryption"

    cipher = cha.encrypt(chacha_key, chacha_nonce, m)
    rsa_keys = rsa.generate_keys(2048)
    chacha_key_nonce =  chacha_nonce + chacha_key
    encrypted_key_nonce = rsa.encrypt(int.from_bytes(chacha_key_nonce, "big"), rsa_keys["private_key"]).to_bytes(256, "big")

    pdf_path = "./sample.pdf"
    create_pdf(pdf_path)

    payload = {
        "ciphertext": base64.b64encode(cipher).decode("ascii"),
        "encrypted_key_nonce": base64.b64encode(encrypted_key_nonce).decode("ascii"),
    }

    embed_json(pdf_path, payload)

    extr_payload = extract_json(pdf_path)
    extr_encrypted_key_nonce =  base64.b64decode(extr_payload["encrypted_key_nonce"])
    extr_cipher = base64.b64decode(extr_payload["ciphertext"])

    decrypted_key_nonce = rsa.decrypt(int.from_bytes(extr_encrypted_key_nonce, "big"), rsa_keys["public_key"]).to_bytes(44, "big")
    decrypted_nonce = decrypted_key_nonce[:12]
    decrypted_key = decrypted_key_nonce[12:]

    print(cha.decrypt(decrypted_key, decrypted_nonce, extr_cipher))

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