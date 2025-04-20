#!/usr/bin/env python3
import os, json, ssl, time, getpass, hashlib, hmac, asyncio
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
import websockets, basefwx
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes; from cryptography.hazmat.backends import default_backend

# ── Config ────────────────────────────────────────────────────────────
NODE        = "wss://xmr.fixcraft.org:8765"
HIST_FILE   = ".wallet_history"
W_FWX       = Path("wallet.fwx")
W_PLAIN     = Path("wallet")               # staging
OWNER_TAG   = "OWNER"
BURN_TAGS   = {"BURN","DESTROY"}

session = PromptSession(history=FileHistory(HIST_FILE))

# ── Key helpers ───────────────────────────────────────────────────────
def hkdf(seed:bytes,info:bytes,n:int=32)->bytes:
    return HKDF(hashes.SHA256(), n, None, info, backend=default_backend()).derive(seed)

def derive_keys(seed_phrase:str):
    seed = Mnemonic("english").to_seed(seed_phrase)
    sk   = SigningKey.from_string(hkdf(seed,b"ecdsa_spend"), curve=SECP256k1)
    vk_b = sk.get_verifying_key().to_string()
    addr = addr_from_pub(vk_b)
    # chain‑style spend keys (64 chars)
    mid_priv = hkdf(seed,b"priv_spend",60).hex()[:60]
    mid_pub  = hkdf(seed,b"pub_spend",60).hex() [:60]
    priv = "AAAA"+mid_priv+"eZ"
    pub  = "AAAA"+mid_pub +"eQ"
    return sk, addr, priv, pub

def addr_from_pub(pub:bytes)->str:
    d1=(hmac.new(pub,b"addr_digit1",hashlib.sha256).digest()[0]%9)+1
    d2=(hmac.new(pub,b"addr_digit2",hashlib.sha256).digest()[0]%9)+1
    pre=f"Fx8{d1}"; suf=f"v{d2}H"; mid_len=34-len(pre)-len(suf)
    body=hkdf(pub,b"addr_middle",mid_len)
    alpha="0123456789ABab"
    mid=''.join(alpha[b%14] for b in body)
    return pre+mid+suf

def sign(tx,sk):
    digest=hashlib.sha256(json.dumps(tx,sort_keys=True).encode()).digest()
    return {"transaction":tx,"signature":sk.sign_digest(digest).hex(),
            "pub_key":sk.get_verifying_key().to_string().hex()}

# ── Wallet load/create (sync) ─────────────────────────────────────────
def load_wallet():
    if W_FWX.exists():
        pw=getpass.getpass("Wallet Password: ")
        try: basefwx.fwxAES(str(W_FWX),pw)
        except SystemExit: print("❌ Wrong password."); exit(1)
        data=json.loads(W_PLAIN.read_text())
        W_PLAIN.unlink(missing_ok=True)
        return data
    print("🆕 Create Wallet")
    pw    = getpass.getpass("New Password: ")
    seed  = Mnemonic("english").generate(128)
    sk,addr,priv,pub = derive_keys(seed)
    wallet={"seed":seed,"address":addr,"priv_spend":priv,"pub_spend":pub}
    W_PLAIN.write_text(json.dumps(wallet))
    basefwx.fwxAES(str(W_PLAIN),pw)
    W_PLAIN.unlink(missing_ok=True)
    print("\n🎉 Wallet Created!")
    print(f"🧬 Seed Phrase:       {seed}")
    print(f"🔑 Wallet Address:    {addr}")
    print(f"🔒 Private Spend Key: {priv}")
    print(f"🔓 Public Spend Key:  {pub}\n")
    return wallet

wallet=load_wallet()
SK        = derive_keys(wallet["seed"])[0]
MY_ADDR   = wallet["address"]

# ── Async main loop ───────────────────────────────────────────────────
async def main():
    # fetch genesis
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    async with websockets.connect(NODE,ssl=ctx) as ws:
        await ws.send(json.dumps({"command":"genesis"}))
        GENESIS=await ws.recv()
    print(f"💼 Address: {MY_ADDR}   |   Genesis: {GENESIS}")
    print("💡 Type `help` for commands.\n")

    async with websockets.connect(NODE,ssl=ctx) as ws:
        while True:
            try: line=await session.prompt_async("> ")
            except (EOFError,KeyboardInterrupt): print("\n👋"); break
            parts=line.strip().split()
            if not parts: continue
            cmd=parts[0].lower()

            if cmd in ("exit","quit"): break

            if cmd in ("help","?"):
                print("Commands:\n"
                      "  balance\n  send <to> <amount>\n"
                      "  sweep <to|OWNER|BURN>\n  security\n  exit")
                continue

            if cmd=="security":
                print(f"\n🧬 Seed Phrase:       {wallet['seed']}\n"
                      f"🔑 Wallet Address:    {wallet['address']}\n"
                      f"🔒 Private Spend Key: {wallet['priv_spend']}\n"
                      f"🔓 Public Spend Key:  {wallet['pub_spend']}\n")
                continue

            if cmd=="balance":
                await ws.send(json.dumps({"command":"balance","address":MY_ADDR}))
                bal=json.loads(await ws.recv())
                print(f"💰 Balance: {bal['balance']}   🔢 Nonce: {bal['nonce']}")
                continue

            # send / sweep
            if cmd=="send" and len(parts)==3:
                dest, amt = parts[1], float(parts[2])
            elif cmd=="sweep" and len(parts)==2:
                dest=parts[1]
                await ws.send(json.dumps({"command":"balance","address":MY_ADDR}))
                amt=float(json.loads(await ws.recv())["balance"])
                print(f"🔄 Sweep {amt} → {dest}")
            else:
                print("❓ Bad syntax."); continue

            if dest.upper()==OWNER_TAG: dest=GENESIS
            if dest.upper() in BURN_TAGS: dest=""

            await ws.send(json.dumps({"command":"balance","address":MY_ADDR}))
            nonce = json.loads(await ws.recv())["nonce"]

            tx={"from":MY_ADDR,"to":dest,"amount":amt,"nonce":nonce,
                "timestamp":int(time.time())}
            await ws.send(json.dumps(sign(tx,SK)))
            print("📡",await ws.recv())

if __name__=="__main__":
    asyncio.run(main())
