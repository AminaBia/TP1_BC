import os, time
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ecies

BASE = Path(__file__).resolve().parent

# RSA-OAEP 2048 (كتل من 190 بايت -> 256 بايت)
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pub = rsa_key.public_key()
oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)
CH_IN, CH_OUT = 190, 256

def rsa_enc(d):
    return b"".join(rsa_pub.encrypt(d[i:i+CH_IN], oaep) for i in range(0, len(d), CH_IN))
def rsa_dec(b):
    return b"".join(rsa_key.decrypt(b[i:i+CH_OUT], oaep) for i in range(0, len(b), CH_OUT))

# AES-256-GCM
aes = AESGCM(AESGCM.generate_key(256))
def aes_enc(d):
    n = os.urandom(12)
    return n + aes.encrypt(n, d, None)
def aes_dec(b):
    return aes.decrypt(b[:12], b[12:], None)

# ECIES (الخطوة 4) مع شهادة Bob
bob_cert = (BASE / "nodes/bob/bob.crt").read_bytes()
bob_key = serialization.load_pem_private_key(
    (BASE / "nodes/bob/bob.key").read_bytes(), password=None)
def ecies_enc(d): return ecies.encrypt(bob_cert, d)
def ecies_dec(b): return ecies.decrypt(bob_key, b)

def timed(fn, arg, reps):
    t = time.perf_counter()
    for _ in range(reps):
        out = fn(arg)
    return (time.perf_counter() - t) / reps * 1000, out

SIZES = [("1 KB", 1024, 0), ("1 MB", 1024**2, 1), ("10 MB", 10 * 1024**2, 2)]
FAST_REPS = (200, 10, 3)   # AES وECIES
SLOW_REPS = (20, 1, 1)     # RSA

schemes = [("RSA-OAEP 2048", rsa_enc, rsa_dec, SLOW_REPS),
           ("AES-256-GCM",  aes_enc, aes_dec, FAST_REPS),
           ("ECIES (hybrid)", ecies_enc, ecies_dec, FAST_REPS)]

print("| Size | Scheme | Ciphertext (bytes) | Overhead | Encrypt (ms) | Decrypt (ms) |")
print("|---|---|---|---|---|---|")
for label, size, idx in SIZES:
    data = os.urandom(size)
    for name, enc, dec, reps in schemes:
        te, blob = timed(enc, data, reps[idx])
        td, back = timed(dec, blob, reps[idx])
        assert back == data
        ov = (len(blob) - size) / size * 100
        print(f"| {label} | {name} | {len(blob)} | {ov:.1f}% | {te:.2f} | {td:.2f} |", flush=True)
