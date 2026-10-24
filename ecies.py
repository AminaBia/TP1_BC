import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"tp1-ecies"
POINT_LEN = 65  # نقطة P-256 غير مضغوطة


def _derive(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=INFO).derive(shared)


def encrypt(recipient_cert_pem: bytes, plaintext: bytes) -> bytes:
    recipient_pub = x509.load_pem_x509_certificate(recipient_cert_pem).public_key()
    eph = ec.generate_private_key(ec.SECP256R1())
    key = _derive(eph.exchange(ec.ECDH(), recipient_pub))
    nonce = os.urandom(12)
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    ct = AESGCM(key).encrypt(nonce, plaintext, eph_pub)  # eph_pub مرتبط بالتوثيق (AAD)
    return eph_pub + nonce + ct


def decrypt(private_key, blob: bytes) -> bytes:
    eph_pub, nonce, ct = blob[:POINT_LEN], blob[POINT_LEN:POINT_LEN + 12], blob[POINT_LEN + 12:]
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_pub)
    key = _derive(private_key.exchange(ec.ECDH(), peer))
    return AESGCM(key).decrypt(nonce, ct, eph_pub)
