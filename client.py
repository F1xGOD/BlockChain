#!/usr/bin/env python3
import os, json, ssl, time, getpass, hashlib, hmac, asyncio
from pathlib import Path
from langdetect import detect
import websockets, basefwx
from websockets.exceptions import ConnectionClosedOK
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes; from cryptography.hazmat.backends import default_backend

# ── config ────────────────────────────────────────────────────────────
NODE          = "wss://xmr.fixcraft.org:8765"
HIST_FILE     = ".wallet_history"
FWX_WALLET    = Path("wallet.fwx")
PLAINTEXT     = Path("wallet.json")

OWNER_TAG     = "OWNER"
BURN_TAGS     = {"BURN","DESTROY"}
LANGUAGES     = {"english","russian","japanese"}
preferred_lang= "english"

session = PromptSession(history=FileHistory(HIST_FILE))

def detect_language(mnemonic: str) -> str:
    """
    Return 'english' | 'japanese' | 'russian' if the words fit one of the
    BIP‑39 dictionaries. Fall back to langdetect for best‑effort guess.
    """
    w = mnemonic.strip().split()
    for lang in LANGUAGES:
        if all(word in Mnemonic(lang).wordlist for word in w):
            return lang
    # best effort
    try:
        code = detect(mnemonic)         # e.g. 'en', 'ru', 'ja'
        return {"en":"english","ru":"russian","ja":"japanese"}.get(code,"english")
    except:
        return "english"

def translate_seed(mnemonic_phrase: str, target_language: str) -> str:
    """
    Convert mnemonic_phrase → equivalent phrase in target_language.
    Raises ValueError on unsupported target or bad checksum.
    """
    target_language = target_language.lower()
    if target_language not in LANGUAGES:
        raise ValueError(f"Target language must be one of {', '.join(LANGUAGES)}")

    src_lang = detect_language(mnemonic_phrase)
    mn_src   = Mnemonic(src_lang)
    if not mn_src.check(mnemonic_phrase):
        raise ValueError("❌ Invalid or non‑checksummed seed phrase")

    entropy = mn_src.to_entropy(mnemonic_phrase)
    return Mnemonic(target_language).to_mnemonic(entropy)

# ── helpers ───────────────────────────────────────────────────────────
def hkdf(seed, info, n=32):
    return HKDF(hashes.SHA256(),n,None,info,backend=default_backend()).derive(seed)

def address_from_pub(pub):
    d1=(hmac.new(pub,b"addr_digit1",hashlib.sha256).digest()[0]%9)+1
    d2=(hmac.new(pub,b"addr_digit2",hashlib.sha256).digest()[0]%9)+1
    pre,suf=f"Fx8{d1}",f"v{d2}H"; midlen=34-len(pre)-len(suf)
    mid=hkdf(pub,b"addr_middle",midlen)
    alpha="0123456789ABab"
    return pre+''.join(alpha[b%len(alpha)]for b in mid)+suf

def derive_all(seed_phrase):
    seed=Mnemonic("english").to_seed(seed_phrase)
    sk  =SigningKey.from_string(hkdf(seed,b"ecdsa_spend"),curve=SECP256k1)
    pub =sk.get_verifying_key().to_string()
    addr=address_from_pub(pub)
    priv_mid=hkdf(seed,b"priv_spend",60).hex()[:60]
    pub_mid =hkdf(seed,b"pub_spend" ,60).hex()[:60]
    return sk, addr, f"AAAA{priv_mid}eZ", f"AAAA{pub_mid}eQ"

def sign(tx,sk):
    dg=hashlib.sha256(json.dumps(tx,sort_keys=True).encode()).digest()
    return {"transaction":tx,
            "signature":sk.sign_digest(dg).hex(),
            "pub_key":sk.get_verifying_key().to_string().hex()}

# ── wallet load / create ──────────────────────────────────────────────
def load_wallet():
    if FWX_WALLET.exists():
        pw=getpass.getpass("Wallet Password: ")
        if basefwx.fwxAES(str(FWX_WALLET),pw) == 'FAIL!':
            print("❌ Wrong password."); exit(1)
        data=json.loads(PLAINTEXT.read_text())
        basefwx.fwxAES(str(PLAINTEXT), pw)
        return data,pw
    else:
        print("🆕 Create Wallet")
        pw=getpass.getpass("New Password: ")
        seed=Mnemonic(preferred_lang).generate(128)
        sk,addr,priv,pub=derive_all(seed)
        wallet={"seed":seed,"address":addr,"priv_spend":priv,"pub_spend":pub}
        PLAINTEXT.write_text(json.dumps(wallet)); basefwx.fwxAES(str(PLAINTEXT),pw)

        print("\n🎉 Wallet Created!")
        print(f"🧬 Seed Phrase:       {seed}")
        print(f"🔑 Wallet Address:    {addr}")
        print(f"🔒 Private Spend Key: {priv}")
        print(f"🔓 Public Spend Key:  {pub}\n")
    return wallet,pw

wallet,pw        = load_wallet()
SK, MY_ADDR   = derive_all(wallet["seed"])[0], wallet["address"]

# ── interactive client logic ──────────────────────────────────────────
async def interactive(ws, genesis):
    global preferred_lang
    while True:
        try: line=await session.prompt_async("> ")
        except (EOFError,KeyboardInterrupt): raise
        parts=line.split(); cmd=parts[0].lower() if parts else ""

        # ─ basic
        if cmd in {"exit","quit"}: raise EOFError
        if cmd in {"help","?"}:
            print("balance | send <to> <amt> | sweep <to|OWNER|BURN>"
                  " | security | language <lang> | exit"); continue
        if cmd=="language" and len(parts)==2:
            lg=parts[1].lower()
            if lg in LANGUAGES:
                preferred_lang=lg
                new=translate_seed(wallet["seed"], lg)
                basefwx.fwxAES(str(FWX_WALLET), pw)
                sk, addr, priv, pub = derive_all(wallet["seed"])
                wallet2 = {"seed": new, "address": addr, "priv_spend": priv, "pub_spend": pub}
                PLAINTEXT.write_text(json.dumps(wallet2))
                basefwx.fwxAES(str(PLAINTEXT), pw)
                print(f"🌐 Preferred seed language set to {lg.capitalize()}. (RESTART TO APPLY)")
            else: print("❓ Supported:",", ".join(LANGUAGES)); continue
        if cmd=="security":
            emoji_map = {
                "Seed Phrase": "🧬",
                "Wallet Address": "📬",
                "Private Spend Key": "🔐",
                "Public Spend Key": "🔓"
            }

            for k, v in (
                    ("Seed Phrase", wallet['seed']),
                    ("Wallet Address", wallet['address']),
                    ("Private Spend Key", wallet['priv_spend']),
                    ("Public Spend Key", wallet['pub_spend'])
            ):
                print(f"{emoji_map[k]} {k}: {v}")
            continue

        # ─ balance
        if cmd=="balance":
            await ws.send(json.dumps({"command":"balance","address":MY_ADDR}))
            bal=json.loads(await ws.recv())
            print(f"💰 Balance: {bal['balance']}   🔢 Nonce: {bal['nonce']}")
            continue

        # ─ send / sweep
        if cmd=="send" and len(parts)==3:
            dest,amt=parts[1],float(parts[2])
        elif cmd=="sweep" and len(parts)==2:
            dest=parts[1]
            await ws.send(json.dumps({"command":"balance","address":MY_ADDR}))
            amt=float(json.loads(await ws.recv())["balance"])
            print(f"🔄 Sweep {amt} → {dest}")
        else:
            if cmd!="language" and len(parts)==2:
                print("❓ Unknown or bad syntax.")
            continue

        dest=genesis if dest.upper()==OWNER_TAG else dest
        if dest.upper() in BURN_TAGS: dest=""

        await ws.send(json.dumps({"command":"balance","address":MY_ADDR}))
        nonce=json.loads(await ws.recv())["nonce"]
        tx={"from":MY_ADDR,"to":dest,"amount":amt,"nonce":nonce,
            "timestamp":int(time.time())}

        try:
            await ws.send(json.dumps(sign(tx,SK)))
            print("📡",await ws.recv())
        except ConnectionClosedOK:
            raise ConnectionClosedOK(1000,"server closed")

# ── main ──────────────────────────────────────────────────────────────
async def main():
    ctx=ssl.create_default_context(); ctx.check_hostname=True; ctx.verify_mode=ssl.CERT_REQUIRED
    # fetch genesis first
    try:
        async with websockets.connect(NODE,ssl=ctx) as ws:
            await ws.send(json.dumps({"command":"genesis"}))
            GENESIS=await ws.recv()
    except OSError:
        print("❌ Server unreachable."); return
    if MY_ADDR == GENESIS:
        print(f"👑 Welcome, Itsuki! 💼 Address: {MY_ADDR}   |   🔥 You ARE the GOD.")
    else:
        print(f"💼 Address: {MY_ADDR}   |   Welcome!")
        print("💡 Type `help` for commands.\n")

    while True:
        try:
            async with websockets.connect(NODE,ssl=ctx) as ws:
                await interactive(ws, GENESIS)
        except (OSError,ConnectionClosedOK):
            print("⚠️ Lost connection — retrying in 3 s …")
            await asyncio.sleep(3)
        except (EOFError,KeyboardInterrupt):
            print("👋 Bye"); return

if __name__=="__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n👋 Cancelled")
