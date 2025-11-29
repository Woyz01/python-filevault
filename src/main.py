import argparse
import getpass
from pathlib import Path

from crypto_utils import encrypt_file, decrypt_file



def handle_encrypt(args):
    print("encrypting...", args)
    print(args.file.name)
    print(args.remove_original)
    file_path = args.file

    kullanıcı_parola = getpass.getpass("Şifreleme parolası:").strip()
    giris_parola = getpass.getpass("Parolayı tekrar giriniz:").strip()
    if kullanıcı_parola != giris_parola:
        print("Parolalar eşleşmiyor, işlem iptal edildi.")
        return

    try:
        output_path = encrypt_file(file_path, kullanıcı_parola, remove_original=args.remove_original)
        print("Dosya şifrelendi:", output_path)

    except Exception as e:
        print("Hata oluştu",e)



def handle_decrypt(args):
    print("decrypting...", args)
    print(args.file.name)
    print(args.remove_encrypted)

    file_path = args.file

    if not file_path.is_file():
        print(f"Dosya bulunamadı: {file_path}")
        return

    kullanıcı_parola = getpass.getpass("Çözme parolası:").strip()

    try:
        decrypt_file(args.file, kullanıcı_parola, remove_encrypted=args.remove_encrypted)
    except ValueError as e:
        print("Şifre çözme başarısız, parola yanlış olabilir.")
    except FileNotFoundError as e:
        print("Beklenmeyen bir hata oluştu:",e)

    output_path = decrypt_file(file_path, kullanıcı_parola, remove_encrypted=args.remove_encrypted)
    print("Dosya başarıyla çözüldü:", output_path)

def build_parser():
    parser = argparse.ArgumentParser(
        description= "File Vault - Basit dosya şifreleme/deşifre aracı"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    encrypt = subparsers.add_parser("encrypt")
    encrypt.add_argument(
        "-f", "--file",
        type=Path,
        required=True,
        help="Şifrelenecek dosya yolu"
    )
    encrypt.add_argument("--remove-original",
                         action="store_true",
                         help= "Şifreleme sonrası orijinal dosyayı sil"
                         )
    encrypt.set_defaults(func=handle_encrypt)


    decrypt = subparsers.add_parser("decrypt")
    decrypt.add_argument("-f", "--file",
                         type=Path,
                         required=True,
                         help= "Çözülecek dosya yolu"
                         )
    decrypt.add_argument("--remove-encrypted",
                         action="store_true",
                         help="Çözme sonrası şifreli dosyayı sil."
                         )
    decrypt.set_defaults(func=handle_decrypt)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)




if __name__ == "__main__":
    main()



