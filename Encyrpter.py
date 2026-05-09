import os
import struct
import base64

import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


MAGIC_HEADER = b"ENCPACK1\n"
MODE_PASSWORD = b"P"  # PIN/password-based
MODE_KEY = b"K"       # raw key-based

CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256-bit AES key


def derive_key_from_pin(pin: str, salt: bytes) -> bytes:
    """Derive AES key from PIN/password using PBKDF2-HMAC-SHA256."""
    pin_bytes = pin.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(pin_bytes)


def encrypt_file_encpack(input_path: str):
    input_path = input_path.strip().strip('"').strip("'")
    filename = os.path.basename(input_path)

    print("\nChoose encryption mode:")
    print("1) PIN/password")
    print("2) Random key (you must save it)")
    mode_choice = input("Enter 1 or 2: ").strip()

    if mode_choice == "1":
        mode = MODE_PASSWORD
        pin = input("Enter PIN/password (visible): ").strip()
        if not pin:
            print("PIN/password cannot be empty.")
            return
        salt = os.urandom(SALT_SIZE)
        key = derive_key_from_pin(pin, salt)
        salt_to_write = salt
        key_to_show = None
    elif mode_choice == "2":
        mode = MODE_KEY
        key = os.urandom(KEY_SIZE)
        salt_to_write = b""
        key_b64 = base64.b64encode(key).decode("utf-8")
        key_to_show = key_b64
    else:
        print("Invalid choice.")
        return

    output_path = filename + ".encpack"
    aesgcm = AESGCM(key)

    compressor = zstd.ZstdCompressor(level=10)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC_HEADER)
        fout.write(mode + b"\n")

        if mode == MODE_PASSWORD:
            fout.write(salt_to_write)
        else:
            fout.write(b"\x00" * SALT_SIZE)

        filename_bytes = filename.encode("utf-8")
        fout.write(struct.pack(">I", len(filename_bytes)))
        fout.write(filename_bytes)

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break

            comp_chunk = compressor.compress(chunk)
            nonce = os.urandom(NONCE_SIZE)
            ct = aesgcm.encrypt(nonce, comp_chunk, None)

            fout.write(nonce)
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)

    print("\n✔ Encryption complete.")
    print(f"Input : {input_path}")
    print(f"Output: {output_path}")

    if key_to_show is not None:
        print("\nIMPORTANT: Save this key to decrypt later:")
        print(key_to_show)


def decrypt_file_encpack(encpack_path: str):
    encpack_path = encpack_path.strip().strip('"').strip("'")

    with open(encpack_path, "rb") as fin:
        magic = fin.readline()
        if magic != MAGIC_HEADER:
            raise ValueError("Not a valid ENCPACK1 file.")

        mode_line = fin.readline().rstrip(b"\n")
        if mode_line not in (MODE_PASSWORD, MODE_KEY):
            raise ValueError("Unknown mode in header.")

        mode = mode_line

        salt = fin.read(SALT_SIZE)

        filename_len_bytes = fin.read(4)
        if len(filename_len_bytes) != 4:
            raise ValueError("Corrupted header (filename length).")
        (filename_len,) = struct.unpack(">I", filename_len_bytes)

        filename_bytes = fin.read(filename_len)
        if len(filename_bytes) != filename_len:
            raise ValueError("Corrupted header (filename).")
        filename = filename_bytes.decode("utf-8")

        if mode == MODE_PASSWORD:
            pin = input("Enter PIN/password used for encryption: ").strip()
            key = derive_key_from_pin(pin, salt)
        else:
            key_b64 = input("Enter base64 key used for encryption: ").strip()
            key = base64.b64decode(key_b64)

        aesgcm = AESGCM(key)
        decompressor = zstd.ZstdDecompressor()

        with open(filename, "wb") as fout:
            while True:
                nonce = fin.read(NONCE_SIZE)
                if not nonce:
                    break
                if len(nonce) != NONCE_SIZE:
                    raise ValueError("Corrupted file (nonce).")

                ct_len_bytes = fin.read(4)
                if len(ct_len_bytes) != 4:
                    raise ValueError("Corrupted file (ciphertext length).")
                (ct_len,) = struct.unpack(">I", ct_len_bytes)

                ct = fin.read(ct_len)
                if len(ct) != ct_len:
                    raise ValueError("Corrupted file (ciphertext).")

                comp_chunk = aesgcm.decrypt(nonce, ct, None)
                chunk = decompressor.decompress(comp_chunk)
                fout.write(chunk)

    print("\n✔ Decryption complete.")
    print(f"Restored: {filename}")


def main():
    print("1) Encrypt to .encpack")
    print("2) Decrypt from .encpack")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        path = input("Enter file path to encrypt: ")
        encrypt_file_encpack(path)
    elif choice == "2":
        path = input("Enter .encpack file path to decrypt: ")
        decrypt_file_encpack(path)
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
