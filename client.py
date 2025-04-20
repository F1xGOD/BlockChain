# client.py
#!/usr/bin/env python3
import asyncio, json, ssl, time
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import websockets

# ───────────────────────────────────────────────────────────────
# CONFIG & YOUR SEED
# ───────────────────────────────────────────────────────────────
NODE_URI    = "wss://xmr.fixcraft.org:8765"
CA_BUNDLE   = None     # or "ca_bundle.pem"
SEED_PHRASE = "vibrant cousin radio license border wonder mirror guitar arrange joy bench rent" #"light deer eye apple media hip giant hurdle people truth pigeon poem"
LANG        = "english"  # your seed is English
# ───────────────────────────────────────────────────────────────

# derive 32‑byte ECDSA key
def derive_sk_vk(seed_phrase):
    seed = Mnemonic(LANG).to_seed(seed_phrase, passphrase="")
    skb  = HKDF(hashes.SHA256(),length=32,salt=None,
                info=b"ecdsa_spend",backend=default_backend()).derive(seed)
    sk = SigningKey.from_string(skb, curve=SECP256k1)
    return sk, sk.get_verifying_key()

# same address_from_pubkey logic!
ADDRESS_ALPHABET    = '0123456789ABab'
ADDRESS_PREFIX_TMPL = "Fx8{}"
ADDRESS_SUFFIX_TMPL = "v{}H"
ADDRESS_LENGTH      = 34
import hmac, hashlib
def address_from_pubkey(pub_bytes: bytes) -> str:
    d1 = (hmac.new(pub_bytes,b"addr_digit1",hashlib.sha256).digest()[0]%9)+1
    d2 = (hmac.new(pub_bytes,b"addr_digit2",hashlib.sha256).digest()[0]%9)+1
    pre = ADDRESS_PREFIX_TMPL.format(d1)
    suf = ADDRESS_SUFFIX_TMPL.format(d2)
    body = HKDF(hashes.SHA256(),length=ADDRESS_LENGTH-len(pre)-len(suf),
                salt=None,info=b"addr_middle",backend=default_backend()).derive(pub_bytes)
    return pre + ''.join(ADDRESS_ALPHABET[b%len(ADDRESS_ALPHABET)] for b in body) + suf

# sign helper
def sign_transaction(tx, sk):
    msg    = json.dumps(tx, sort_keys=True).encode()
    digest = hashlib.sha256(msg).digest()
    sig    = sk.sign_digest(digest)
    return {
        "transaction": tx,
        "signature": sig.hex(),
        "pub_key": sk.get_verifying_key().to_string().hex()
    }

async def main():
    # derive keys & address
    sk, vk = derive_sk_vk(SEED_PHRASE)
    me     = address_from_pubkey(vk.to_string())
    print(f"🔑 Wallet Address: {me}")

    # build SSL context
    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if CA_BUNDLE:
        ssl_ctx.load_verify_locations(cafile=CA_BUNDLE)
    else:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

    async with websockets.connect(NODE_URI, ssl=ssl_ctx) as ws:
        print("🤖 Type `help` for commands.")
        while True:
            cmd = input("> ").strip().split()
            if not cmd:
                continue
            c = cmd[0].lower()

            if c in ("exit","quit"):
                print("👋 Bye!")
                break

            if c in ("help","?"):
                print("📖 Commands:\n  balance\n  send <to> <amount>\n  help\n  exit")
                continue

            if c == "balance":
                await ws.send(json.dumps({"command":"balance","address":me}))
                resp = await ws.recv()
                try:
                    d = json.loads(resp)
                    print(f"💰 Balance: {d['balance']}   🔢 Nonce: {d['nonce']}")
                except:
                    print("⚠️ Unexpected reply:", resp)
                continue

            if c == "send":
                if len(cmd)!=3:
                    print("⚠️ Usage: send <to> <amount>")
                    continue
                to_addr = cmd[1]
                amount  = float(cmd[2])
                # fetch fresh nonce
                await ws.send(json.dumps({"command":"balance","address":me}))
                reply = await ws.recv()
                data  = json.loads(reply)
                nonce = data["nonce"]

                tx = {
                    "from": me,
                    "to":   to_addr,
                    "amount": amount,
                    "nonce":  nonce,
                    "timestamp": int(time.time())
                }
                signed = sign_transaction(tx, sk)
                print(f"✍️  Sending {amount} → {to_addr} (nonce={nonce})")
                await ws.send(json.dumps(signed))
                result = await ws.recv()
                print("📡 Server Reply:", result)
                continue

            print("❓ Unknown command. Type `help`.")

if __name__=="__main__":
    asyncio.run(main())
