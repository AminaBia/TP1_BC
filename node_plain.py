import asyncio, json, struct, sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
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
def hello_msg(name):
    pem = (BASE / f"nodes/{name}/{name}.crt").read_text()
    return {"type": "hello", "name": name, "cert": pem}


def verify_hello(hello):
    """يتحقق من أن الشهادة موقّعة من الـ CA وسارية، ويعيد اسم العقدة."""
    cert = x509.load_pem_x509_certificate(hello["cert"].encode())
    cert.verify_directly_issued_by(CA_CERT)          # الجهة المصدرة + التوقيع
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise ValueError("certificate expired or not yet valid")
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != hello["name"]:
        raise ValueError("name does not match certificate")
    return cn


# ---------- الخادم ----------
async def handle(reader, writer, me):
    try:
        peer = verify_hello(await recv_frame(reader))
        await send_frame(writer, hello_msg(me))
        print(f"[{me}] accepted connection from {peer}")
        while True:
            msg = await recv_frame(reader)
            print(f"[{me}] <- {peer}: {msg['text']}")
    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        print(f"[{me}] REJECTED connection: {e}")
    finally:
        writer.close()


# ---------- العميل ----------
async def connect(me, peer):
    reader, writer = await asyncio.open_connection("127.0.0.1", PORTS[peer])
    await send_frame(writer, hello_msg(me))
    got = verify_hello(await recv_frame(reader))
    if got != peer:
        raise ValueError(f"expected {peer}, got {got}")
    print(f"[{me}] connected to {peer} (certificate verified)")
    await send_frame(writer, {"type": "msg", "text": f"Hello {peer}, this is {me}"})
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
