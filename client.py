#!/usr/bin/env python3
import ssl, json, time, asyncio, getpass, hashlib, hmac, argparse
from pathlib import Path
import aiohttp, basefwx
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes; from cryptography.hazmat.backends import default_backend
from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.history import FileHistory
from langdetect import detect

# ── CONFIG ────────────────────────────────────────────────────────────
RPC_URL        = "https://xmr.fixcraft.org:8545/rpc"
HIST_FILE      = ".wallet_history"
FWX_WALLET     = Path("wallet.fwx")
WALLET_PLAIN   = Path("wallet.json")
ADDR_LEN       = 34
OWNER_TAG      = "OWNER"
BURN_TAGS      = {"BURN","DESTROY"}
LANGUAGES      = {"english","russian","japanese"}

sslctx = ssl.create_default_context(); sslctx.check_hostname=False; sslctx.verify_mode=ssl.CERT_NONE
session_cli = PromptSession(history=FileHistory(HIST_FILE))

# ── ADDRESS / KEY HELPERS ─────────────────────────────────────────────
def hkdf(seed,info,n=32):
    return HKDF(hashes.SHA256(),n,None,info,backend=default_backend()).derive(seed)

def addr_from_pub(pub):
    d1=(hmac.new(pub,b"addr_digit1",hashlib.sha256).digest()[0]%9)+1
    d2=(hmac.new(pub,b"addr_digit2",hashlib.sha256).digest()[0]%9)+1
    pre,suf=f"Fx8{d1}",f"v{d2}H"
    body_len = ADDR_LEN - len(pre) - len(suf)      # <- dynamic again
    body     = hkdf(pub,b"addr_mid",body_len)
    alpha    = "0123456789ABab"
    return pre + ''.join(alpha[b%len(alpha)] for b in body) + suf

def derive_keys(seed_phrase):
    seed = Mnemonic("english").to_seed(seed_phrase)
    sk   = SigningKey.from_string(hkdf(seed,b"ecdsa_spend"),curve=SECP256k1)
    pub  = sk.get_verifying_key().to_string()
    addr = addr_from_pub(pub)
    priv_mid = hkdf(seed,b"priv_spend",60).hex()[:60]
    pub_mid  = hkdf(seed,b"pub_spend" ,60).hex()[:60]
    return sk, addr, f"AAAA{priv_mid}eZ", f"AAAA{pub_mid}eQ"

def sign_tx(tx, sk):
    dig = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).digest()
    return {"transaction":tx,
            "signature":sk.sign_digest(dig).hex(),
            "pub_key":sk.get_verifying_key().to_string().hex()}

# ── LANGUAGE DETECT / TRANSLATE ───────────────────────────────────────
def detect_language(m):                        # same logic as before
    words=m.split()
    for l in LANGUAGES:
        if all(w in Mnemonic(l).wordlist for w in words): return l
    return {"en":"english","ru":"russian","ja":"japanese"}.get(detect(m),"english")

def translate_seed(phrase,target):
    if target not in LANGUAGES: raise ValueError("lang?")
    src = detect_language(phrase)
    ms  = Mnemonic(src)
    if not ms.check(phrase): raise ValueError("bad checksum")
    return Mnemonic(target).to_mnemonic(ms.to_entropy(phrase))

# ── JSON‑RPC wrapper ──────────────────────────────────────────────────
async def rpc(method, params=None):
    async with aiohttp.ClientSession() as s:
        j = {"jsonrpc":"2.0","method":method,"params":params or [],"id":1}
        async with s.post(RPC_URL, json=j, ssl=sslctx) as r:
            out = await r.json()
            if "error" in out: raise RuntimeError(out["error"])
            return out["result"]

# ── WALLET load / restore / create ────────────────────────────────────
def load_or_create_wallet(restore_seed: str|None):
    if restore_seed:
        seed  = restore_seed.strip()
        sk, addr, priv, pub = derive_keys(seed)
        wallet = {"seed":seed,"address":addr,"priv_spend":priv,"pub_spend":pub}
        print_formatted_text(f"🔑 Restored Address: {addr}")
        return wallet, None   # no .fwx yet

    if FWX_WALLET.exists():
        pw=getpass.getpass("Wallet Password: ")
        if basefwx.fwxAES(str(FWX_WALLET),pw)=="FAIL!":
            print("Retrying...")
            if basefwx.fwxAES(str(FWX_WALLET)) == "FAIL!":
                print("❌")
                exit(1)
            print("✅ Recovered! 🎉")
        data=json.loads(WALLET_PLAIN.read_text()); basefwx.fwxAES(str(WALLET_PLAIN),pw)
        return data,pw

    print("🆕 Create Wallet")
    pw = getpass.getpass("New Password: ")
    seed = Mnemonic("english").generate(128)
    sk, addr, priv, pub = derive_keys(seed)
    wallet={"seed":seed,"address":addr,"priv_spend":priv,"pub_spend":pub}
    WALLET_PLAIN.write_text(json.dumps(wallet)); basefwx.fwxAES(str(WALLET_PLAIN),pw)
    print_formatted_text(f"🎉 Wallet Created!\n🧬 {seed}\n📬 {addr}")
    return wallet,pw

# ── argparse entry ────────────────────────────────────────────────────
argp = argparse.ArgumentParser()
argp.add_argument("--restore", help="restore from given seed phrase", nargs='+')
args = argp.parse_args()
restore_phrase = " ".join(args.restore) if args.restore else None

wallet, wallet_pw = load_or_create_wallet(restore_phrase)
SK, MY_ADDR       = derive_keys(wallet["seed"])[0], wallet["address"]

# ── CLI loop ──────────────────────────────────────────────────────────
async def cli_loop():
    if await rpc("get_genesis")==MY_ADDR:
        print_formatted_text(f"👑 Welcome, Itsuki! 💼 Address: {MY_ADDR}  |  RPC: {RPC_URL}")
    else:
        print_formatted_text(f"💼 Address: {MY_ADDR}  |  RPC: {RPC_URL}\nType `help`.")

    while True:
        try: line = await session_cli.prompt_async("> ")
        except (EOFError,KeyboardInterrupt): print("\n👋 Bye"); break
        cmd=line.split()
        if not cmd: continue
        c=cmd[0].lower()

        if c in {"exit","quit"}: break
        if c in {"help","?"}:
            print("balance | send <to> <amt> | sweep <to|OWNER|BURN>"
                  " | security | language <lang> | exit"); continue

        # language translate
        if c=="language" and len(cmd)==2:
            tgt=cmd[1].lower()
            if tgt not in LANGUAGES: print("❓ languages:",", ".join(LANGUAGES)); continue
            ff=translate_seed(wallet["seed"],tgt)
            basefwx.fwxAES(str(FWX_WALLET),wallet_pw)
            wallet["seed"]=ff
            open(WALLET_PLAIN, "w").write(json.dumps(wallet))
            basefwx.fwxAES(str(WALLET_PLAIN), wallet_pw)
            print("✅ Applied"); continue


        # security
        if c=="security":
            if c == "security":
                # Brutal truth dump:
                print(f"🧬 Seed Phrase:       {wallet['seed']}")
                print(f"📬 Wallet Address:     {wallet['address']}")
                print(f"🔐 Private Spend Key:  {wallet['priv_spend']}")
                print(f"🔓 Public Spend Key:   {wallet['pub_spend']}")
                continue

        # balance
        if c=="balance":
            res = await rpc("get_balance",[MY_ADDR])
            print(f"💰 Balance: {res['balance']} CPX  🔢 Nonce: {res['nonce']}"); continue

        # send / sweep
        if c=="send" and len(cmd)==3:
            dest, amt = cmd[1], float(cmd[2])
            if dest.upper() == OWNER_TAG:
                print(f"🎉 Donating {amt} CPX")
            elif dest.upper() in BURN_TAGS:
                print(f"♻️ Deleting {amt} CPX")
            else:
                print(f"📤 Sending {amt} CPX → {dest}")
        elif c=="sweep" and len(cmd)==2:
            dest = cmd[1]
            bal = await rpc("get_balance",[MY_ADDR]); amt = bal["balance"]
            if dest.upper() == OWNER_TAG: print(f"🎉 Donating {amt} CPX")
            elif dest.upper() in BURN_TAGS: print(f"♻️ Deleting {amt} CPX")
            else: print(f"🔄 Sweeping {amt} CPX → {dest}")
        else:
            print("❓ Unknown CMD"); continue

        if dest.upper()==OWNER_TAG: dest = await rpc("get_genesis")
        if dest.upper() in BURN_TAGS: dest=""

        nonce = (await rpc("get_balance",[MY_ADDR]))["nonce"]
        tx={"from":MY_ADDR,"to":dest,"amount":amt,"nonce":nonce,"timestamp":int(time.time())}
        print("📡", await rpc("submit_tx",[sign_tx(tx,SK)]))

asyncio.run(cli_loop())
