# client.py  —  wallet CLI
#!/usr/bin/env python3
import ssl, json, time, asyncio, getpass, hashlib, hmac, argparse, sys, os
from pathlib import Path
import aiohttp, basefwx
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.history import FileHistory
from langdetect import detect

# UTF‑8 for Windows
if os.name == "nt":
    os.system("chcp 65001 > nul")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ── CONFIG ────────────────────────────────────────────────────────────
RPC_URL      = "https://xmr.fixcraft.org:8545/rpc"
HIST_FILE    = ".wallet_history"
FWX_WALLET   = Path("wallet.fwx")
WALLET_PLAIN = Path("wallet.json")
ADDR_LEN     = 34
OWNER_TAG    = "OWNER"
BURN_TAGS    = {"BURN","DESTROY"}
LANGUAGES    = {"english","russian","japanese"}

# ── FEE CONFIG ───────────────────────────────────────────────────────
BASE_FEE_RATE = 0.003
FEE_OPTIONS   = [
    ("1","Slow",    0.2),
    ("2","Normal",  1),
    ("3","Fast",    5),
    ("4","Faster",  100),
    ("5","Fastest", 200),
]

sslctx = ssl.create_default_context()
sslctx.check_hostname = False
sslctx.verify_mode   = ssl.CERT_NONE

session_cli = PromptSession(history=FileHistory(HIST_FILE))
OFFLINE_MODE = False

# ── HELPERS ──────────────────────────────────────────────────────────
def hkdf(seed, info, n=32):
    return HKDF(hashes.SHA256(), n, None, info, backend=default_backend()).derive(seed)

def derive_keys(seed_phrase):
    seed = Mnemonic("english").to_seed(seed_phrase)
    sk   = SigningKey.from_string(hkdf(seed,b"ecdsa_spend"),curve=SECP256k1)
    pub  = sk.get_verifying_key().to_string()
    d1   = (hmac.new(pub,b"addr_digit1",hashlib.sha256).digest()[0] % 9) + 1
    d2   = (hmac.new(pub,b"addr_digit2",hashlib.sha256).digest()[0] % 9) + 1
    pre, suf = f"Fx8{d1}", f"v{d2}H"
    body = hkdf(pub, b"addr_mid", ADDR_LEN - len(pre) - len(suf))
    alpha = "0123456789ABab"
    addr  = pre + ''.join(alpha[b % len(alpha)] for b in body) + suf
    priv_mid = hkdf(seed,b"priv_spend",60).hex()[:60]
    pub_mid  = hkdf(seed,b"pub_spend",60).hex()[:60]
    return sk, addr, f"AAAA{priv_mid}eZ", f"AAAA{pub_mid}eQ"

def sign_tx(tx, sk):
    dig = hashlib.sha256(json.dumps(tx,sort_keys=True).encode()).digest()
    return {
        "transaction":tx,
        "signature":   sk.sign_digest(dig).hex(),
        "pub_key":     sk.get_verifying_key().to_string().hex()
    }

def sign_tx_with_fee(tx, sk, fee):
    w = sign_tx(tx, sk)
    w["fee"] = fee
    return w

async def rpc(method, params=None):
    if OFFLINE_MODE:
        raise RuntimeError("Offline mode")
    async with aiohttp.ClientSession() as s:
        j = {"jsonrpc":"2.0","method":method,"params":params or [],"id":1}
        async with s.post(RPC_URL, json=j, ssl=sslctx) as r:
            out = await r.json()
            if "error" in out:
                raise RuntimeError(out["error"])
            return out["result"]

def detect_language(m):
    words = m.split()
    for l in LANGUAGES:
        if all(w in Mnemonic(l).wordlist for w in words):
            return l
    return {"en":"english","ru":"russian","ja":"japanese"}.get(detect(m),"english")

def translate_seed(phrase, target):
    phrase = phrase.lower().strip()
    if target not in LANGUAGES:
        raise ValueError(f"Unknown language: {target}")
    src = detect_language(phrase)
    ms  = Mnemonic(src)
    if not ms.check(phrase):
        raise ValueError("Bad checksum")
    return Mnemonic(target).to_mnemonic(ms.to_entropy(phrase))

def load_or_create_wallet(restore_seed):
    if restore_seed:
        seed = " ".join(restore_seed).strip()
        sk, addr, priv, pub = derive_keys(seed)
        print_formatted_text(f"🔑 Restored Address: {addr}")
        return {"seed":seed,"address":addr,"priv_spend":priv,"pub_spend":pub}, None

    if FWX_WALLET.exists():
        pw = getpass.getpass("Wallet Password: ")
        if basefwx.fwxAES(str(FWX_WALLET),pw) == "FAIL!":
            print("Retrying...")
            if basefwx.fwxAES(str(FWX_WALLET)) == "FAIL!":
                print("❌ Bad password"); sys.exit(1)
            print("✅ Recovered!")
        data = json.loads(WALLET_PLAIN.read_text())
        basefwx.fwxAES(str(WALLET_PLAIN),pw)
        return data, pw

    print("🆕 Create Wallet")
    pw   = getpass.getpass("New Password: ")
    seed = Mnemonic("english").generate(128)
    sk, addr, priv, pub = derive_keys(seed)
    wallet = {"seed":seed,"address":addr,"priv_spend":priv,"pub_spend":pub}
    WALLET_PLAIN.write_text(json.dumps(wallet))
    basefwx.fwxAES(str(WALLET_PLAIN),pw)
    print_formatted_text(f"🎉 Wallet Created!\n🧬 {seed}\n📬 {addr}")
    return wallet, pw

async def confirm_prompt():
    ans = await session_cli.prompt_async("✒️ Confirm? Y/n: ")
    return ans.strip().lower() in ("y","yes")

# INITIAL CONNECTION TEST & CTRL+C
try:
    genesis = asyncio.run(rpc("get_genesis"))
except KeyboardInterrupt:
    print("\n❌ Cancelled by user."); sys.exit(1)
except:
    choice = input("⚠️ Can't connect to server. [O]ffline mode or [E]xit? (O/E): ").strip().lower()
    if choice.startswith("e"):
        print("👋 Exiting."); sys.exit(1)
    else:
        OFFLINE_MODE = True
        print("🔌 Running in OFFLINE mode.")

# ENTRY POINT
parser = argparse.ArgumentParser()
parser.add_argument("--restore", nargs='+', help="restore from seed phrase")
args = parser.parse_args()
wallet, wallet_pw = load_or_create_wallet(args.restore)
SK, MY_ADDR = derive_keys(wallet["seed"])[0], wallet["address"]

async def cli_loop():
    if not OFFLINE_MODE:
        try:
            g = await rpc("get_genesis")
            if g == MY_ADDR:
                print_formatted_text(f"👑 Welcome, Itsuki!  💼 Address: {MY_ADDR}  |  RPC: {RPC_URL}")
            else:
                print_formatted_text(f"💼 Address: {MY_ADDR}  |  RPC: {RPC_URL}\nType `help`.")
        except:
            print_formatted_text(f"💼 Address: {MY_ADDR}  |  OFFLINE MODE")
    else:
        print_formatted_text(f"💼 Address: {MY_ADDR}  |  OFFLINE MODE")

    while True:
        try:
            line = await session_cli.prompt_async("> ")
        except (EOFError,KeyboardInterrupt):
            print("\n👋 Bye")
            break

        cmd = line.split()
        if not cmd: continue
        c = cmd[0].lower()

        if c in {"exit","quit"}:
            break
        if c in {"help","?"}:
            print("balance | send <to> <amt> | sweep <to> | transactions [detailed|compact|group] | security | language <lang> | exit")
            continue

        if c == "balance":
            if OFFLINE_MODE:
                print("⚠️ Offline mode: cannot fetch balance.")
            else:
                res = await rpc("get_balance",[MY_ADDR])
                locked = res["total"] - res["unlocked"]
                print(f"💰 Balance: {res['total']:.2f} CPX (🔒 Locked: {locked:.2f}) 🔢 Nonce: {res['nonce']}")
            continue

        if c in {"send","sweep"}:
            if OFFLINE_MODE:
                print("⚠️ Offline mode: cannot send transactions.")
                continue
            if c=="send" and len(cmd)==3:
                dest, amt = cmd[1], float(cmd[2])
            elif c=="sweep" and len(cmd)==2:
                dest = cmd[1]
                bal = await rpc("get_balance",[MY_ADDR])
                amt = bal["unlocked"]
            else:
                print("❓ Usage: send <to> <amt>   or   sweep <to>")
                continue

            # Fee picker
            menu = ["\n💸 Pick The Fee:"]
            for key,label,mult in FEE_OPTIONS:
                menu.append(f"  [{key}] {label} (×{mult})")
            menu.append("Select speed (1–5): ")
            choice = await session_cli.prompt_async("\n".join(menu))
            opt = next((o for o in FEE_OPTIONS if o[0]==choice.strip()), None)
            if not opt:
                print("❌ Invalid selection")
                continue
            _, speed_label, mult = opt

            fee = 0 if MY_ADDR==genesis else round(amt*BASE_FEE_RATE*mult,8)
            note = "(Cool You're The King 👑)" if fee==0 else f"({speed_label})"
            total = amt + fee

            if dest.upper() in BURN_TAGS:
                emoji, action = "♻️", f"Burning {amt} CPX → VOID"
                dest = ""
            elif c=="sweep":
                emoji, action = "🔄", f"Sweeping {amt} CPX → {dest}"
            else:
                emoji, action = "📤", f"Sending {amt} CPX → {dest}"

            print(f"{emoji} {action}")
            print(f"⚡ Network Fee: {fee} CPX   {note}")
            print(f"🏁 Total: {total} CPX")

            if not await confirm_prompt():
                print("❌ Cancelled")
                continue

            if dest.upper()==OWNER_TAG:
                dest = await rpc("get_genesis")

            nonce = (await rpc("get_balance",[MY_ADDR]))["nonce"]
            tx = {"from":MY_ADDR,"to":dest,"amount":amt,"nonce":nonce,"timestamp":int(time.time())}
            wrapper = sign_tx_with_fee(tx, SK, fee)
            resp = await rpc("submit_tx",[wrapper])
            print(f"📡 {resp}")
            continue

        # ── TRANSACTIONS HISTORY (detailed / compact / group) ──────────────────
        if c == "transactions":
            # pick mode
            mode = "detailed"
            if len(cmd) > 1 and cmd[1].lower() in ("detailed", "compact", "group"):
                mode = cmd[1].lower()

            if OFFLINE_MODE:
                print("⚠️ Offline mode: cannot fetch transactions.")
                continue

            hist = await rpc("get_tx_history", [MY_ADDR])

            # build unified timeline
            entries = []
            for r in hist["rewards"]:
                entries.append(("reward",   r["height"], r["amount"], r["ts"], r))
            for t in hist["confirmed"]:
                kind = "sent" if t["from"] == MY_ADDR else "received"
                entries.append((kind, t["height"], t["amount"], t["ts"], t))
            for p in hist["pending"]:
                kind = "pending_send" if p["from"] == MY_ADDR else "pending_recv"
                entries.append((kind, None, p["amount"], p["ts"], p))

            # sort chronologically
            entries.sort(key=lambda e: e[3])

            if mode == "group":
                # aggregate totals and last timestamps
                agg = {
                    "reward":      {"sum":0, "last_ts":0},
                    "pending":     {"sum":0, "last_ts":0},
                    "received":    {"sum":0, "last_ts":0},
                    "sent":        {"sum":0, "last_ts":0},
                }
                for kind, height, amt, ts, data in entries:
                    if kind == "reward":
                        a = agg["reward"]
                    elif kind in ("pending_send", "pending_recv"):
                        a = agg["pending"]
                    else:
                        a = agg[kind]
                    a["sum"] += amt
                    a["last_ts"] = max(a["last_ts"], ts)

                print("📜 Transaction History (grouped):")
                for label, emoji in [("reward","⛏️ Mined"), ("pending","⏳ Pending"),
                                     ("received","📥 Received"), ("sent","📤 Sent")]:
                    total = agg[label]["sum"]
                    if total > 0:
                        human = time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.localtime(agg[label]["last_ts"]))
                        print(f"{emoji}:  {total} CPX  {human}")
                continue

            # detailed or compact
            print("📜 Transaction History:")
            for kind, height, amt, ts, data in entries:
                human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

                if kind == "reward":
                    if mode == "detailed":
                        print(f"⛏️ Mined {height}:  <coinbase> → {data['to']} | {amt} CPX | fee 0 | ts {ts}")
                    else:
                        print(f"⛏️ Mined {height}:  {amt} CPX  {human}")

                elif kind == "sent":
                    if mode == "detailed":
                        print(f"📤 Sent     : {amt} CPX → {data['to']} | fee {data['fee']} | block {height} | ts {ts}")
                    else:
                        print(f"📤 Sent     : {amt} CPX  {human}")

                elif kind == "received":
                    if mode == "detailed":
                        print(f"📥 Received : {amt} CPX ← {data['from']} | block {height} | ts {ts}")
                    else:
                        print(f"📥 Received : {amt} CPX  {human}")

                elif kind == "pending_send":
                    if mode == "detailed":
                        print(f"⏳ Pending  : {amt} CPX → {data['to']} | fee {data['fee']} | ts {ts}")
                    else:
                        print(f"⏳ Pending  : {amt} CPX  {human}")

                elif kind == "pending_recv":
                    if mode == "detailed":
                        print(f"⏳ Pending  : {amt} CPX ← {data['from']} | fee {data['fee']} | ts {ts}")
                    else:
                        print(f"⏳ Pending  : {amt} CPX  {human}")

            continue


        if c == "security":
            print_formatted_text(f"🧬 Seed Phrase:       {wallet['seed']}")
            print_formatted_text(f"📬 Wallet Address:     {wallet['address']}")
            print_formatted_text(f"🔐 Private Spend Key:  {wallet['priv_spend']}")
            print_formatted_text(f"🔓 Public Spend Key:   {wallet['pub_spend']}")
            continue

        if c=="language" and len(cmd)==2:
            tgt = cmd[1].lower()
            if tgt not in LANGUAGES:
                print("❓ Supported languages:", ", ".join(LANGUAGES))
                continue
            try:
                new_seed = translate_seed(wallet["seed"], tgt)
            except ValueError as e:
                print(f"❌ Translation failed: {e}")
                continue
            basefwx.fwxAES(str(FWX_WALLET), wallet_pw)
            wallet["seed"] = new_seed
            WALLET_PLAIN.write_text(json.dumps(wallet))
            basefwx.fwxAES(str(WALLET_PLAIN), wallet_pw)
            print("✅ Seed language updated to", tgt)
            continue

        print("❓ Unknown command")

asyncio.run(cli_loop())
