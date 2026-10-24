import asyncio, hashlib, json, os, struct, sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parent
PORTS = {"alice": 9001, "bob": 9002, "carol": 9003, "dave": 9004}
CA_CERT = x509.load_pem_x509_certificate((BASE / "ca/ca.crt").read_bytes())


# ---------- إطار الرسائل: 4 بايت للطول ثم JSON ----------
async def send_frame(writer, obj):
    data = json.dumps(obj).encode()
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def recv_frame(reader):
    (n,) = struct.unpack(">I", await reader.readexactly(4))
    return json.loads(await reader.readexactly(n))


# ---------- الشهادات ----------
def my_private_key(name):
    return serialization.load_pem_private_key(
        (BASE / f"nodes/{name}/{name}.key").read_bytes(), password=None)


def hello_msg(name, nonce):
    pem = (BASE / f"nodes/{name}/{name}.crt").read_text()
    return {"type": "hello", "name": name, "cert": pem, "nonce": nonce.hex()}


def verify_hello(hello):
    cert = x509.load_pem_x509_certificate(hello["cert"].encode())
    cert.verify_directly_issued_by(CA_CERT)
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError("certificate expired or not yet valid")
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != hello["name"]:
        raise ValueError("name does not match certificate")
    return cn, cert, bytes.fromhex(hello["nonce"])


# ---------- مفتاح الجلسة: ECDH + HKDF ----------
def derive_key(me, peer, peer_cert, salt):
    shared = my_private_key(me).exchange(ec.ECDH(), peer_cert.public_key())
    info = ("tp1-session|" + "|".join(sorted([me, peer]))).encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)


def fingerprint(key):
    return hashlib.sha256(key).hexdigest()[:8]   # للعرض التعليمي فقط


# ---------- رسائل مشفّرة AES-256-GCM ----------
async def send_secure(writer, aes, me, text):
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, text.encode(), f"from:{me}".encode())
    await send_frame(writer, {"type": "data", "nonce": nonce.hex(), "ct": ct.hex()})


async def recv_secure(reader, aes, peer):
    f = await recv_frame(reader)
    pt = aes.decrypt(bytes.fromhex(f["nonce"]), bytes.fromhex(f["ct"]),
                     f"from:{peer}".encode())
    return pt.decode()


# ---------- الخادم ----------
async def handle(reader, writer, me):
    try:
        peer, peer_cert, nonce_c = verify_hello(await recv_frame(reader))
        nonce_s = os.urandom(16)
        await send_frame(writer, hello_msg(me, nonce_s))
        key = derive_key(me, peer, peer_cert, nonce_c + nonce_s)
        aes = AESGCM(key)
        print(f"[{me}] session with {peer} established, key fp={fingerprint(key)}")
        while True:
            text = await recv_secure(reader, aes, peer)
            print(f"[{me}] <- {peer}: {text}")
            await send_secure(writer, aes, me, f"ack: {text}")
    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        print(f"[{me}] REJECTED connection: {e!r}")
    finally:
        writer.close()


# ---------- العميل ----------
MESSAGES = [
    "SECRET-BLOCK #1: alice pays bob 5 coins",
    "SECRET-BLOCK #2: bob pays carol 2 coins",
    "SECRET-BLOCK #3: carol pays dave 1 coin",
]


async def connect(me, peer):
    reader, writer = await asyncio.open_connection("127.0.0.1", PORTS[peer])
    nonce_c = os.urandom(16)
    await send_frame(writer, hello_msg(me, nonce_c))
    got, peer_cert, nonce_s = verify_hello(await recv_frame(reader))
    if got != peer:
        raise ValueError(f"expected {peer}, got {got}")
    key = derive_key(me, peer, peer_cert, nonce_c + nonce_s)
    aes = AESGCM(key)
    print(f"[{me}] session with {peer} established, key fp={fingerprint(key)}")
    for m in MESSAGES:
        await send_secure(writer, aes, me, m)
        print(f"[{me}] <- {peer}: {await recv_secure(reader, aes, peer)}")
    writer.close()
    await writer.wait_closed()


async def main():
    me, peers = sys.argv[1], sys.argv[2:]
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, me), "127.0.0.1", PORTS[me])
    print(f"[{me}] listening on port {PORTS[me]}")
    await asyncio.sleep(1)
    for p in peers:
        await connect(me, p)
    async with server:
        await server.serve_forever()


asyncio.run(main())
