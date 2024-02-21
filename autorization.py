import main
import pyotp
import qrcode

key = main.generate_random_secret_key()
print(key)
totp = main.pyotp.TOTP(key)
key_uri = pyotp.totp.TOTP(totp).provisioning_uri(name="username", issuer_name="MyWebSite")
qrcode.make(key_uri).save(f"static/{"username"}_qr.png")
while True:
    print(totp.verify(input("Введите код:")))
