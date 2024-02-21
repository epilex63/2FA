import pyotp
import qrcode
import random as r

key = "MyWebKey"
uri = pyotp.totp.TOTP(key).provisioning_uri(name="MyWeb", issuer_name="MyWebSite")

print(uri)

qrcode.make(uri).save("totp.png")