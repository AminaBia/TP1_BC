import os, time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)      # 32 بايت، مشترك بين الطرفين
aes = AESGCM(key)

def seal(plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)                      # nonce جديد لكل رسالة
    return nonce + aes.encrypt(nonce, plaintext, aad)

def unseal(blob: bytes, aad: bytes) -> bytes:
    return aes.decrypt(blob[:12], blob[12:], aad)

msg = b"Transaction batch: alice->bob 5 coins; " * 20000
aad = b"alice->bob"                             # بيانات مصادَق عليها لكن غير مشفّرة

t = time.perf_counter()
blob = seal(msg, aad)
dt = time.perf_counter() - t
print(f"plaintext : {len(msg)} bytes")
print(f"ciphertext: {len(blob)} bytes (overhead = {len(blob) - len(msg)} bytes)")
print(f"encrypt   : {dt*1000:.2f} ms\n")

print("Decrypt OK       :", unseal(blob, aad) == msg)

# 1) تعديل بت واحد في المنتصف
bad = bytearray(blob)
bad[len(bad) // 2] ^= 0x01
try:
    unseal(bytes(bad), aad)
    print("Tampered ciphertext: ACCEPTED (bad!)")
except InvalidTag:
    print("Tampered ciphertext: REJECTED (InvalidTag)")

# 2) AAD مختلف (مثلًا رسالة أُعيد توجيهها لمستلم آخر)
try:
    unseal(blob, b"alice->carol")
    print("Wrong AAD          : ACCEPTED (bad!)")
except InvalidTag:
    print("Wrong AAD          : REJECTED (InvalidTag)")

# 3) مفتاح آخر
try:
    AESGCM(AESGCM.generate_key(256)).decrypt(blob[:12], blob[12:], aad)
    print("Wrong key          : ACCEPTED (bad!)")
except InvalidTag:
    print("Wrong key          : REJECTED (InvalidTag)")
