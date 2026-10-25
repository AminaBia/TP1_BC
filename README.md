# TP1 — Certificates and encrypted messaging between nodes

Team: Amina B.

A small private (consortium) blockchain network with four simulated nodes
(Alice, Bob, Carol, Dave). Each node must hold a certificate issued by the
consortium CA before it can talk to its peers. Messages are protected with
asymmetric (ECIES), symmetric (AES-256-GCM) and hybrid
(ECDH + HKDF + AES-GCM) encryption. Everything runs offline on localhost.

## Requirements

- Linux or WSL (Ubuntu), OpenSSL 3.x
- Python 3.11+
- `tcpdump` (optional, traffic capture) and Wireshark (optional)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./setup_pki.sh          # builds the CA and the 4 node certificates
```

`ca/` and `nodes/` contain private keys, are generated locally and are **not**
committed. Use `FORCE=1 ./setup_pki.sh` to regenerate them (existing nodes
must be restarted afterwards, because they cache the old CA certificate).

## How to run each part

| TP step | Command | What to expect |
|---|---|---|
| 1-2 CA + certificates | `./setup_pki.sh` | five lines ending in `OK` |
| 2 Inspect a certificate | `openssl x509 -in nodes/alice/alice.crt -noout -text` | Issuer = Root CA, Subject = alice, `CA:FALSE`, 1-year validity |
| 2 Negative test | `openssl verify -CAfile nodes/bob/bob.crt nodes/alice/alice.crt` | verification fails |
| 3 Node program (no encryption) | `python node_plain.py bob`, then in another terminal `python node_plain.py alice bob` | certificates verified, message readable |
| 4 Asymmetric (ECIES) | `python demo_ecies.py` | Bob decrypts; Carol and tampered data fail |
| 5 Symmetric (AES-256-GCM) | `python demo_aes.py` | tampering, wrong AAD, wrong key are rejected |
| 6 Hybrid session | `python node_secure.py bob`, then `python node_secure.py alice bob` | both sides print the same `key fp` |
| 7 Traffic capture | see below | payloads unreadable |
| 8 Benchmark | `python bench.py` | table below (RSA 10 MB decryption takes about a minute) |

Ports: alice 9001, bob 9002, carol 9003, dave 9004 (all on 127.0.0.1).
`node_*.py NAME [PEER ...]` starts node NAME and connects to each listed peer;
the peers must already be running.

If you get `address already in use`, an old node is still running:
`pkill -f "node_.*\.py"`.

### Traffic capture (step 7)

```bash
# terminal A
python node_secure.py bob
# terminal B (start before Alice)
sudo tcpdump -i lo -nn -s0 -Z $USER -w captures/capture_secure.pcap port 9002
# terminal C
python node_secure.py alice bob
# afterwards
strings captures/capture_secure.pcap | grep -c "SECRET"     # prints 0
```

Repeat with `node_plain.py` and `captures/capture_plain.pcap`: the message is
then readable (`strings captures/capture_plain.pcap | grep "Hello bob"`).
Certificates and nonces are visible in both captures; this is expected
because they are public.

## Design

- **PKI**: EC P-256 keys, ECDSA-SHA256. Root CA valid 10 years (`CA:TRUE`,
  keyCertSign/cRLSign). Node certificates valid 1 year (`CA:FALSE`,
  digitalSignature/keyAgreement).
- **Handshake**: each side sends its certificate and a random 16-byte nonce.
  The peer checks that the certificate is issued by the CA, is within its
  validity period, and that its CN matches the claimed name.
- **Session key**: `HKDF-SHA256(ECDH(own private key, peer certificate key),
  salt = nonce_client || nonce_server, info = "tp1-session|" + sorted names)`.
  A node that does not own the certificate's private key cannot derive the key.
- **Data**: AES-256-GCM, fresh random 12-byte nonce per message,
  AAD = `from:<sender>`.
- **ECIES** (`ecies.py`): ephemeral ECDH + HKDF + AES-256-GCM.
  Output = ephemeral public key (65 B) + nonce (12 B) + ciphertext + tag (16 B).

## Benchmark results

Measured on the author's machine under WSL; values vary between runs.

| Size | Scheme | Ciphertext (bytes) | Overhead | Encrypt (ms) | Decrypt (ms) |
|---|---|---|---|---|---|
| 1 KB | RSA-OAEP 2048 | 1536 | 50.0% | 0.74 | 7.64 |
| 1 KB | AES-256-GCM | 1052 | 2.7% | 0.01 | 0.01 |
| 1 KB | ECIES (hybrid) | 1117 | 9.1% | 0.73 | 0.55 |
| 1 MB | RSA-OAEP 2048 | 1412864 | 34.7% | 391.09 | 8596.52 |
| 1 MB | AES-256-GCM | 1048604 | 0.0% | 2.06 | 1.21 |
| 1 MB | ECIES (hybrid) | 1048669 | 0.0% | 2.33 | 1.61 |
| 10 MB | RSA-OAEP 2048 | 14128384 | 34.7% | 4213.72 | 84319.00 |
| 10 MB | AES-256-GCM | 10485788 | 0.0% | 36.03 | 12.35 |
| 10 MB | ECIES (hybrid) | 10485853 | 0.0% | 15.68 | 18.26 |

RSA-OAEP can only encrypt 190 bytes per block (2048-bit key, SHA-256), so
messages are split into blocks for this benchmark only.

## Security notes and limitations

- No forward secrecy: the session key comes from the static certificate keys.
  Improvement: ephemeral ECDH signed with the certificate key (as in TLS 1.3).
- No replay or reordering protection inside a session (no sequence numbers);
  peer authentication is implicit, through key derivation.
- Certificates, nonces, ports, timing and message sizes are visible to a
  network observer.
- Private keys are stored unencrypted on disk (demo only).
- The bonus (certificate expiry handling beyond the validity check, and a
  revocation list) is not implemented.
- Everything is simulated on localhost; nothing targets real networks.

## Repository layout

```
setup_pki.sh      build CA + node certificates
requirements.txt  Python dependency (cryptography)
ecies.py          ECIES encrypt/decrypt
node_plain.py     node with certificate check, no encryption
node_secure.py    node with hybrid encryption (ECDH + HKDF + AES-GCM)
demo_ecies.py     step 4 demo
demo_aes.py       step 5 demo
bench.py          step 8 benchmark
captures/         .pcap captures (plain vs secure)
```
