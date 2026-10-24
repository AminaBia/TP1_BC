from pathlib import Path
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
import ecies

BASE = Path(__file__).resolve().parent
ca = x509.load_pem_x509_certificate((BASE / "ca/ca.crt").read_bytes())

def cert_pem(n): return (BASE / f"nodes/{n}/{n}.crt").read_bytes()
def key(n):
    return serialization.load_pem_private_key(
        (BASE / f"nodes/{n}/{n}.key").read_bytes(), password=None)

# Alice تتحقق من شهادة Bob قبل استخدام مفتاحه العام
bob_cert = x509.load_pem_x509_certificate(cert_pem("bob"))
bob_cert.verify_directly_issued_by(ca)
print("Bob's certificate verified against the CA\n")

msg = b"Block #42 hash: 9f2c... (confidential)"
blob = ecies.encrypt(cert_pem("bob"), msg)
print("plaintext :", msg)
print("ciphertext:", blob.hex()[:80], "...")
print("size      :", len(msg), "->", len(blob), "bytes\n")

print("Bob decrypts   :", ecies.decrypt(key("bob"), blob))

try:
    ecies.decrypt(key("carol"), blob)
except InvalidTag:
    print("Carol decrypts : FAILED (wrong private key)")

tampered = bytearray(blob); tampered[-1] ^= 1
try:
    ecies.decrypt(key("bob"), bytes(tampered))
except InvalidTag:
    print("Tampered data  : FAILED (integrity check)")

print("Same message twice differs:",
      ecies.encrypt(cert_pem("bob"), msg) != ecies.encrypt(cert_pem("bob"), msg))
