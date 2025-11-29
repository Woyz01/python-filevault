 FileVault – Python Dosya Şifreleyici

FileVault, dosyaları güçlü kriptografi algoritmaları (PBKDF2HMAC + AES-256 Fernet) ile şifreleyen ve çözen bir komut satırı aracıdır. Tamamen Python ile yazılmıştır ve Windows / Linux / MacOS ile uyumludur.

---

 Özellikler

-  AES-256 tabanlı güvenli şifreleme
-  PBKDF2HMAC ile parola tabanlı anahtar türetme
-  16-byte rastgele salt kullanımı
-  Dosya şifreleme (`encrypt`)
-  Dosya çözme (`decrypt`)
-  `--remove-original` (şifreleme sonrası orijinali sil)
-  `--remove-encrypted` (çözme sonrası .enc dosyasını sil)
-  Güvenli parola girişi (`getpass`)
-  Temiz ve modüler kod yapısı
-  CLI arayüzü (argparse)

---

 Kurulum

Gerekli paketleri yükleyin:

```bash
pip install cryptography


Aracı çalıştırmak için ise;

- python src/main.py

Dosya şifreleme için ise komut;

- python main.py encrypt -f dosya.txt   

//bu komut ile  şifreli dosya çıktısı dosya.txt.enc şeklndedir.Orijinal dosyayı silmek için ise ;

- python main.py encrypt -f dosya.txt --remove-original

Dosya çözme işlemi için ise :

- python main.py decrypt -f dosya.txt.enc

// dosya çıktısı dosya.txt olur ve şifreli dosya silmek istersek eğer;

- python main.py decrypt -f dosya.txt.enc --remove-encrypted


Proje yapısı ise aşağıdaki şekildedir;

FileVault/
 ├── src/
 │    ├── main.py
 │    └── crypto_utils.py
 ├── README.md
 ├── .gitignore




GÜVENLİK NOTLARI


- Parola hiçbir zaman diske yazılmaz.

- Salt ve şifreli veri tek bir .enc dosyasında saklanır.

- Fernet şifreleme, doğrulama ve bütünlük kontrolü sağlar.

- PBKDF2HMAC ile 200.000 iterasyon kullanılır.

- Bu araç eğitim ve kişisel güvenlik amaçlı tasarlanmıştır.



GELİŞTİRİCİ

Cihan ŞAHİN
GitHub: https://github.com/Woyz01
