import os, base64
import pathlib
from pathlib import Path
from sys import excepthook

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    iterations = 200000
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
        )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path: Path, password: str, remove_original: bool = False) -> Path:
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")

    data = file_path.read_bytes()
    salt = os.urandom(16)

    key = _derive_key_from_password(password, salt)
    fernet = Fernet(key)

    token = fernet.encrypt(data)

    output_path = file_path.with_suffix(file_path.suffix + ".enc")
    with open(output_path, "wb") as f:
        f.write(salt + token)

    if remove_original:
        try:
            file_path.unlink()
        except Exception as e:
            print(f"Orijinal dosya silinirken hata: {e}")

    return output_path

def decrypt_file(file_path: Path, password: str, remove_encrypted: bool = False) -> Path:
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError(f"Dosya bulunamadi: {file_path}")

    raw = file_path.read_bytes()


    if len(raw) < 17:
        raise ValueError(f"Geçersiz şifreli dosya formatı:")

    salt = raw[:16]
    token = raw[16:]

    key = _derive_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(token)
    except Exception as e:
        raise ValueError(f"Şifre çözme başarısız. Parola hatalı olabilir") from e


    output_path = file_path.with_suffix("")
    output_path.write_bytes(decrypted)

    if remove_encrypted:
        try:
            file_path.unlink()
        except Exception as e:
            print(f"Orijinal dosya silinirken hata: {e}")

    return output_path









