from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

# Tạo khóa DSA
key = DSA.generate(2048)  # Cặp khóa 2048-bit DSA

private_key = key
public_key = key.publickey()

# Lưu private key và public key vào tệp
with open("private_key.pem", "wb") as f:
    f.write(private_key.export_key())
with open("public_key.pem", "wb") as f:
    f.write(public_key.export_key())

# Đọc thông điệp từ file (hoặc có thể thay bằng thông điệp trong biến)
message = b'This is a message to sign.'

# Tạo hash của thông điệp
hash_obj = SHA256.new(message)

# Tạo đối tượng signer (thực hiện ký số)
signer = DSS.new(private_key, 'fips-186-3')

# Ký hash của thông điệp
signature = signer.sign(hash_obj)

# Lưu chữ ký vào file
with open("signature.sig", "wb") as f:
    f.write(signature)

# Đọc chữ ký từ file
with open("signature.sig", "rb") as f:
    signature = f.read()

# Tạo hash của thông điệp
hash_obj = SHA256.new(message)

# Tạo đối tượng verifier (thực hiện xác minh chữ ký)
verifier = DSS.new(public_key, 'fips-186-3')

# Xác minh chữ ký
try:
    verifier.verify(hash_obj, signature)
    print("Chữ ký hợp lệ!")
except ValueError:
    print("Chữ ký không hợp lệ!")
