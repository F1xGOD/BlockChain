#!/usr/bin/env python3
import ssl, json, time, asyncio, getpass, hashlib, hmac, argparse, sys, os
from pathlib import Path
import aiohttp
import basefwx
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.history import FileHistory
from langdetect import detect

# ── CONFIG ────────────────────────────────────────────────────────────
RPC_URL    = "https://xmr.fixcraft.org:8545"
HIST_FILE  = ".wallet_history"
FWX_WALLET = Path("wallet.fwx")
WALLET_PLAIN= Path("wallet.json")
ADDR_LEN   = 34
LANGUAGES  = {"english","russian","japanese"}
OWNER_TAG  = "OWNER"
BURN_TAGS  = {"BURN","DESTROY"}

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

# ── WALLET & KEYS ───────────────────────────────────────────────────
# secp256k1 curve order (n)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ALPHABET = "0123456789ABab"
PRE, SUF = "Fx8{}", "v{}H"

CACHE_FILE = Path("tx_cache.json")

def load_cache():
    """
    Load (or initialize) on-disk cache of all rewards, confirmed & pending txs,
    plus last block index we synced up to.
    """
    if CACHE_FILE.exists():
        c = json.loads(CACHE_FILE.read_text())
    else:
        c = {"last_block": -1, "rewards": [], "confirmed": [], "pending": []}
        save_cache(c)
    # ensure keys
    if "last_block" not in c:    c["last_block"] = -1
    if "rewards"    not in c:    c["rewards"]    = []
    if "confirmed"  not in c:    c["confirmed"]  = []
    if "pending"    not in c:    c["pending"]    = []
    return c

def save_cache(c):
    """Write cache back to disk."""
    CACHE_FILE.write_text(json.dumps(c, indent=2))

def save_cache(cache):
    with CACHE_FILE.open("w") as f:
        json.dump(cache, f)
def hkdf(seed, info, n=32):
    return HKDF(hashes.SHA256(), n, None, info, backend=default_backend()).derive(seed)
def derive_keys(seed_phrase):
    # 1) master seed → HKDF
    seed = Mnemonic("english").to_seed(seed_phrase)

    # 2) spend keypair (ECDSA)
    sk = SigningKey.from_string(hkdf(seed, b"ecdsa_spend"), curve=SECP256k1)
    pub = sk.get_verifying_key().to_string()

    # 3) address
    d1 = (hmac.new(pub, b"addr_digit1", hashlib.sha256).digest()[0] % 9) + 1
    d2 = (hmac.new(pub, b"addr_digit2", hashlib.sha256).digest()[0] % 9) + 1
    pre, suf = PRE.format(d1), SUF.format(d2)
    body = hkdf(pub, b"addr_mid", ADDR_LEN - len(pre) - len(suf))
    addr = pre + ''.join(ALPHABET[b % len(ALPHABET)] for b in body) + suf

    # 4) wrapped spend keys
    priv_s = "AAAA" + hkdf(seed, b"priv_spend", 60).hex()[:60] + "eZ"
    pub_s  = "AAAA" + hkdf(seed, b"pub_spend", 60).hex()[:60] + "eQ"

    # 5) raw 32-byte view private
    raw_priv_v = hkdf(seed, b"priv_view", 32)
    # reduce mod curve order so it's valid
    curve_order = SECP256k1.order
    priv_v_int = int.from_bytes(raw_priv_v, "big") % curve_order
    priv_view_key = ec.derive_private_key(priv_v_int, ec.SECP256K1(), default_backend())

    # 6) compressed public point (33 bytes) → hex
    raw_pub_v = priv_view_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint
    )

    # 7) wrap view keys
    priv_v = "ABBA" + raw_priv_v.hex() + "eZ"
    pub_v  = "ABBA" + raw_pub_v.hex()    + "eQ"

    return sk, addr, priv_s, pub_s, priv_v, pub_v





def load_or_create_wallet(restore_seed):
    if restore_seed:
        seed = " ".join(restore_seed).strip()
        sk, addr, ps, pu, pv_s, pv_p = derive_keys(seed)
        print_formatted_text(f"🔑 Restored Address: {addr}")
        return {
            "seed":       seed,
            "address":    addr,
            "priv_spend": ps,  "pub_spend": pu,
            "priv_view":  pv_s, "pub_view":  pv_p
        }, None

    if FWX_WALLET.exists():
        pw = getpass.getpass("Wallet Password: ")
        if basefwx.fwxAES(str(FWX_WALLET), pw) == "FAIL!":
            print("❌ Bad password"); sys.exit(1)
        data = json.loads(WALLET_PLAIN.read_text())
        basefwx.fwxAES(str(WALLET_PLAIN), pw)
        return data, pw

    # new wallet
    print("🆕 Create Wallet")
    pw   = getpass.getpass("New Password: ")
    seed = Mnemonic("english").generate(128)
    sk, addr, ps, pu, pv_s, pv_p = derive_keys(seed)
    wallet = {
        "seed":       seed,
        "address":    addr,
        "priv_spend": ps,  "pub_spend": pu,
        "priv_view":  pv_s, "pub_view":  pv_p
    }
    WALLET_PLAIN.write_text(json.dumps(wallet))
    basefwx.fwxAES(str(WALLET_PLAIN), pw)
    print_formatted_text(f"🎉 Wallet Created!\n🧬 {seed}\n📬 {addr}")
    return wallet, pw


async def confirm_prompt():
    ans = await session_cli.prompt_async("\n✒️ Confirm? Y/n: ")
    return ans.strip().lower() in ("y","yes")



# ── ECIES decrypt helper ─────────────────────────────────────────────
def ecies_decrypt(priv_hex: str, msg: dict):
    # strip the "ABBA" prefix (4 chars) and "eZ" suffix (2 chars)
    core = priv_hex[4:-2]
    # now core is pure hex
    priv_int = int(core, 16)
    priv = ec.derive_private_key(priv_int, ec.SECP256K1(), default_backend())

    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), bytes.fromhex(msg["epub"])
    )
    shared = priv.exchange(ec.ECDH(), peer_pub)
    key = HKDF(hashes.SHA256(), 32, None, b"ecies", default_backend()).derive(shared)
    aes = AESGCM(key)
    pt  = aes.decrypt(bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["ct"]), None)
    return pt


# ── RPC wrapper ──────────────────────────────────────────────────────
async def rpc(method, params=None):
    if OFFLINE_MODE:
        raise RuntimeError("Offline mode")
    async with aiohttp.ClientSession() as s:
        j={"jsonrpc":"2.0","method":method,"params":params or [],"id":1}
        async with s.post(f"{RPC_URL}/rpc", json=j, ssl=sslctx) as r:
            out=await r.json()
            if "error" in out: raise RuntimeError(out["error"])
            return out["result"]

# ── ENTRY POINT ─────────────────────────────────────────────────────
parser=argparse.ArgumentParser()
parser.add_argument("--restore", nargs="+", help="restore from seed")
args=parser.parse_args()
wallet, wallet_pw = load_or_create_wallet(args.restore)
SK, MY_ADDR, PRIV_SPEND, PUB_SPEND, PRIV_VIEW, PUB_VIEW = derive_keys(wallet["seed"])

# fetch remote genesis & miner
try:
    genesis = asyncio.run(rpc("get_genesis"))
    miner   = asyncio.run(rpc("get_miner"))
except:
    OFFLINE_MODE=True; print("🔌 Running in OFFLINE mode.")
POLL_INTERVAL = 30  # seconds between background syncs

async def background_sync():
    while True:
        if not OFFLINE_MODE:
            try:
                # fetch tip
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(f"{RPC_URL}/height", ssl=sslctx) as resp:
                        tip = (await resp.json())["height"]
                # load cache
                cache = load_cache()
                last = cache.get("last_height", -1)
                # pull new blocks
                async with aiohttp.ClientSession() as sess:
                    for h in range(last + 1, tip + 1):
                        async with sess.get(f"{RPC_URL}/block/{h}", ssl=sslctx) as r2:
                            blk = await r2.json()
                        # same coinbase & tx‐parsing logic you already wrote…
                        # append to cache["rewards"] and cache["confirmed"]
                        # …
                cache["last_height"] = tip
                # fetch & update cache["pending"]
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(f"{RPC_URL}/mempool", ssl=sslctx) as rm:
                        pool = await rm.json()
                new_pending = []
                for w in pool:
                    tx = w.get("transaction", w)
                    frm, to_ = tx.get("from",""), tx.get("to","")
                    if frm == MY_ADDR or to_ == MY_ADDR:
                        new_pending.append({
                            "from": frm, "to": to_,
                            "amount": tx.get("amount",0),
                            "fee": w.get("fee",0),
                            "ts": tx.get("timestamp",0)
                        })
                cache["pending"] = new_pending
                save_cache(cache)
            except Exception:
                pass
        await asyncio.sleep(POLL_INTERVAL)
async def fetch_chain():
    async with aiohttp.ClientSession() as s:
        # 1) tip
        async with s.get(f"{RPC_URL}/height", ssl=sslctx) as r:
            tip = (await r.json())["height"]
        blocks=[]
        for h in range(tip+1):
            async with s.get(f"{RPC_URL}/block/{h}", ssl=sslctx) as r2:
                blocks.append(await r2.json())
        return blocks

async def calculate_state():
    blocks = await fetch_chain()
    STATE_, NONCES_ = {}, {}

    for blk in blocks:
        for w in blk.get("txs", []):
            # 1) unwrap either a signed‐wrapper or a raw/coinbase tx
            if isinstance(w, dict) and "transaction" in w:
                # normal tx
                tx_enc = w["transaction"]
                fee    = w.get("fee", 0)
                # decrypt the encrypted fields
                tx = {}
                for fld in ("from", "to", "amount", "timestamp"):
                    pt = ecies_decrypt(PRIV_VIEW, tx_enc[fld]).decode()
                    if fld == "amount":
                        tx[fld] = float(pt)
                    elif fld == "timestamp":
                        tx[fld] = int(pt)
                    else:
                        tx[fld] = pt
                # nonce is unencrypted
                tx["nonce"] = tx_enc.get("nonce", 0)
            else:
                # coinbase or any raw tx
                tx  = w
                fee = 0

            # 2) apply to your in-memory state
            frm, to, amt = tx.get("from", ""), tx.get("to", ""), tx.get("amount", 0)
            if frm:
                STATE_[frm]  = STATE_.get(frm, 0) - amt - fee
                NONCES_[frm] = NONCES_.get(frm, 0) + 1
            if to:
                STATE_[to]   = STATE_.get(to, 0) + amt

    return STATE_, NONCES_

async def cli_loop():
    asyncio.create_task(background_sync())
    print_formatted_text(f"💼 Address: {MY_ADDR}  |  ⛓️🌐 Loaded")
    while True:
        line = await session_cli.prompt_async("> ")
        cmd  = line.split()
        if not cmd: continue
        c=cmd[0].lower()
        if c in ("exit","quit"): break
        if c in ("help","?"):
            print("balance | send <to> <amt> | sweep <to> | transactions | exit")
            continue

        if c == "balance":
            # 1) load or init cache
            cache = load_cache()
            last = cache.get("last_height", -1)

            # 2) if online, sync new blocks + mempool
            if not OFFLINE_MODE:
                # 2a) fetch chain tip
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(f"{RPC_URL}/height", ssl=sslctx) as resp:
                        resp.raise_for_status()
                        height = (await resp.json())["height"]

                # 2b) pull only the new blocks
                async with aiohttp.ClientSession() as sess:
                    for h in range(last + 1, height + 1):
                        async with sess.get(f"{RPC_URL}/block/{h}", ssl=sslctx) as r2:
                            r2.raise_for_status()
                            blk = await r2.json()

                        # ── coinbase reward ────────────────────────────
                        if blk.get("txs"):
                            cb = blk["txs"][0]
                            if "transaction" in cb:
                                enc = cb["transaction"]
                                to_ = ecies_decrypt(PRIV_VIEW, enc["to"]).decode()
                                amt = float(ecies_decrypt(PRIV_VIEW, enc["amount"]).decode())
                            else:
                                to_, amt = cb["to"], cb["amount"]
                            if to_ == MY_ADDR:
                                cache.setdefault("rewards", []).append({
                                    "height": h, "to": to_, "amount": amt, "ts": blk["ts"]
                                })

                        # ── user txs ───────────────────────────────────
                        for w in blk.get("txs", [])[1:]:
                            if "transaction" in w:
                                enc = w["transaction"]
                                frm = ecies_decrypt(PRIV_VIEW, enc["from"]).decode()
                                to_ = ecies_decrypt(PRIV_VIEW, enc["to"]).decode()
                                amt = float(ecies_decrypt(PRIV_VIEW, enc["amount"]).decode())
                                fee = w.get("fee", 0)
                            else:
                                frm = w.get("from", "");
                                to_ = w.get("to", "")
                                amt = w.get("amount", 0);
                                fee = w.get("fee", 0)
                            if frm == MY_ADDR or to_ == MY_ADDR:
                                cache.setdefault("confirmed", []).append({
                                    "from": frm, "to": to_, "amount": amt,
                                    "fee": fee, "height": h, "ts": blk["ts"]
                                })

                cache["last_height"] = height

                # 2c) fetch mempool
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(f"{RPC_URL}/mempool", ssl=sslctx) as rm:
                        pool = await rm.json()

                new_pending = []
                for w in pool:
                    tx = w.get("transaction", w)
                    frm, to_ = tx.get("from", ""), tx.get("to", "")
                    amt = tx.get("amount", 0);
                    fee = w.get("fee", 0)
                    ts_ = tx.get("timestamp", 0)
                    if frm == MY_ADDR or to_ == MY_ADDR:
                        new_pending.append({
                            "from": frm, "to": to_, "amount": amt,
                            "fee": fee, "ts": ts_
                        })
                cache["pending"] = new_pending

                save_cache(cache)

            # 3) compute balance, locked, nonce from cache
            bal_map = {}
            for r in cache.get("rewards", []):
                bal_map[r["to"]] = bal_map.get(r["to"], 0) + r["amount"]
            for t in cache.get("confirmed", []):
                bal_map[t["from"]] = bal_map.get(t["from"], 0) - (t["amount"] + t["fee"])
                bal_map[t["to"]] = bal_map.get(t["to"], 0) + t["amount"]

            total = bal_map.get(MY_ADDR, 0)

            locked = 0
            for p in cache.get("pending", []):
                if p["from"] == MY_ADDR:
                    locked += p["amount"] + p["fee"]

            nonce = (
                    sum(1 for t in cache.get("confirmed", []) if t["from"] == MY_ADDR) +
                    sum(1 for p in cache.get("pending", []) if p["from"] == MY_ADDR)
            )

            # 4) display
            print(f"💰 Balance: {total:.2f} CPX (🔒 Locked: {locked:.2f}) 🔢 Nonce: {nonce}")
            continue

        if c == "security":
            print_formatted_text(f"🧬 Seed Phrase:       {wallet['seed']}")
            print_formatted_text(f"📬 Wallet Address:     {wallet['address']}")
            print_formatted_text(f"🔐 Private Spend Key:  {wallet['priv_spend']}")
            print_formatted_text(f"🔓 Public Spend Key:   {wallet['pub_spend']}")
            print_formatted_text(f"👁️ Private View Key:   {wallet['priv_view']}")
            print_formatted_text(f"🔎 Public View Key:    {wallet['pub_view']}")
            continue

        if c in ("send", "sweep"):
            # figure out dest + amount
            if c == "send" and len(cmd) == 3:
                dest, amt = cmd[1], float(cmd[2])
            elif c == "sweep" and len(cmd) == 2:
                dest = cmd[1]
                STATE_, _ = await calculate_state()
                bal = STATE_.get(MY_ADDR, 0)
                # fee is computed on full balance, then sweep the rest
                fee = 0 if MY_ADDR == miner else round(bal * BASE_FEE_RATE, 8)
                amt = bal - fee
            else:
                print("❓ Usage: send <to> <amt>  or  sweep <to>"); continue

            # fee picker (only for send – sweep already baked in)
            if c == "send":
                opts = "\n".join(f"  [{k}] {l} (×{m})" for k,l,m in FEE_OPTIONS)
                choice = await session_cli.prompt_async(f"\n{opts}\n💸 Pick The Fee: ")
                opt = next((o for o in FEE_OPTIONS if o[0] == choice.strip()), None)
                if not opt:
                    print("❌ Invalid"); continue
                _, label, mult = opt
                fee = 0 if MY_ADDR == miner else round(amt * BASE_FEE_RATE * mult, 8)

            total = amt + fee
            note = "(Cool You're The King 👑)" if fee == 0 else f"({label})"
            # emoji + action
            if dest.upper() in BURN_TAGS:
                emoji, action = "♻️", f"Burning {amt} CPX → VOID"
                dest = ""
            elif c == "sweep":
                emoji, action = "🔄", f"Sweeping {amt} CPX → {dest}"
            else:
                emoji, action = "📤", f"Sending {amt} CPX → {dest}"

            print(f"{emoji} {action}")
            print(f"⚡ Network Fee: {fee} CPX   {note}")
            print(f"🏁 Total: {total} CPX")
            if not await confirm_prompt():
                print("❌ Cancelled"); continue

            # build plain tx
            nonce = (await calculate_state())[1].get(MY_ADDR, 0)
            tx = {
                "from":      MY_ADDR,
                "to":        dest,
                "amount":    amt,
                "nonce":     nonce,
                "timestamp": int(time.time())
            }
            # sign
            dig = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).digest()
            sig = SK.sign_digest(dig).hex()
            # strip ABBA/eQ wrapper for raw hex
            raw_view = PUB_VIEW
            if raw_view.startswith("ABBA") and raw_view.endswith("eQ"):
                raw_view = raw_view[4:-2]

            payload = {
                "transaction": tx,
                "signature":   SK.sign_digest(dig).hex(),
                "pub_key":     SK.get_verifying_key().to_string().hex(),
                "view_priv":   PRIV_VIEW,     # <-- pass your private-view here
                "fee":         fee
            }
            res = await rpc("submit_tx", [payload])
            print(f"📡 {res}")
            continue

        if c == "transactions":
            # ── 1) pick display mode ─────────────────────────────────────────
            mode = "detailed"
            if len(cmd) > 1 and cmd[1].lower() in ("detailed", "compact", "group"):
                mode = cmd[1].lower()

            # ── 2) load on-disk cache ─────────────────────────────────────────
            cache = load_cache()
            last = cache.get("last_height", -1)

            # ── 3) if online, fetch new blocks + mempool ──────────────────────
            if not OFFLINE_MODE:
                # 3a) fetch current tip
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(f"{RPC_URL}/height", ssl=sslctx) as resp:
                        resp.raise_for_status()
                        height = (await resp.json())["height"]

                # 3b) pull only blocks (last+1 .. height)
                async with aiohttp.ClientSession() as sess:
                    for h in range(last + 1, height + 1):
                        async with sess.get(f"{RPC_URL}/block/{h}", ssl=sslctx) as resp2:
                            resp2.raise_for_status()
                            blk = await resp2.json()

                        # ── coinbase reward ────────────────────────────────────
                        if blk.get("txs"):
                            cb = blk["txs"][0]
                            if "transaction" in cb:
                                enc = cb["transaction"]
                                to_ = ecies_decrypt(PRIV_VIEW, enc["to"]).decode()
                                amt = float(ecies_decrypt(PRIV_VIEW, enc["amount"]).decode())
                                ts_ = int(ecies_decrypt(PRIV_VIEW, enc["timestamp"]).decode())
                            else:
                                to_, amt, ts_ = cb["to"], cb["amount"], blk["ts"]
                            if to_ == MY_ADDR:
                                cache["rewards"].append({
                                    "height": h, "to": to_, "amount": amt, "ts": ts_
                                })

                        # ── user-txs ────────────────────────────────────────────
                        for w in blk.get("txs", [])[1:]:
                            if "transaction" in w:
                                enc = w["transaction"]
                                frm = ecies_decrypt(PRIV_VIEW, enc["from"]).decode()
                                to_ = ecies_decrypt(PRIV_VIEW, enc["to"]).decode()
                                amt = float(ecies_decrypt(PRIV_VIEW, enc["amount"]).decode())
                                ts_ = int(ecies_decrypt(PRIV_VIEW, enc["timestamp"]).decode())
                                fee = w.get("fee", 0)
                            else:
                                frm = w.get("from", "")
                                to_ = w.get("to", "")
                                amt = w.get("amount", 0)
                                ts_ = blk["ts"]
                                fee = w.get("fee", 0)

                            if frm == MY_ADDR or to_ == MY_ADDR:
                                cache["confirmed"].append({
                                    "from": frm, "to": to_, "amount": amt,
                                    "fee": fee, "height": h, "ts": ts_
                                })

                # 3c) update last_height
                cache["last_height"] = height

                # 3d) fetch fresh mempool
                async with aiohttp.ClientSession() as sess:
                    async with sess.get(f"{RPC_URL}/mempool", ssl=sslctx) as resp3:
                        pool = await resp3.json()

                new_pending = []
                for w in pool:
                    tx = w.get("transaction", w)
                    frm, to_ = tx.get("from", ""), tx.get("to", "")
                    amt = tx.get("amount", 0)
                    ts_ = tx.get("timestamp", 0)
                    fee = w.get("fee", 0)
                    if frm == MY_ADDR or to_ == MY_ADDR:
                        new_pending.append({
                            "from": frm, "to": to_, "amount": amt,
                            "fee": fee, "ts": ts_
                        })

                cache["pending"] = new_pending
                save_cache(cache)

            # ── 4) now assemble for display ────────────────────────────────────
            rewards = cache["rewards"]
            confirmed = cache["confirmed"]
            pending = cache["pending"]

            # ── 5) grouped summary ────────────────────────────────────────────
            if mode == "group":
                agg = {
                    "mined": {"sum": 0, "last_ts": 0},
                    "received": {"sum": 0, "last_ts": 0},
                    "sent": {"sum": 0, "last_ts": 0},
                    "pending": {"sum": 0, "last_ts": 0},
                }
                for r in rewards:
                    agg["mined"]["sum"] += r["amount"]
                    agg["mined"]["last_ts"] = max(agg["mined"]["last_ts"], r["ts"])
                for t in confirmed:
                    kind = "sent" if t["from"] == MY_ADDR else "received"
                    agg[kind]["sum"] += t["amount"]
                    agg[kind]["last_ts"] = max(agg[kind]["last_ts"], t["ts"])
                for p in pending:
                    agg["pending"]["sum"] += p["amount"]
                    agg["pending"]["last_ts"] = max(agg["pending"]["last_ts"], p["ts"])

                print("📜 Transaction History (grouped):")

                def _p(lbl, emoji):
                    s = agg[lbl]["sum"]
                    if s:
                        hm = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(agg[lbl]["last_ts"]))
                        print(f"{emoji}:  {s} CPX  {hm}")

                _p("mined", "⛏️  Mined")
                _p("pending", "⏳  Pending")
                _p("received", "📥  Received")
                _p("sent", "📤  Sent")
                continue

            # ── 6) detailed / compact list ─────────────────────────────────────
            print("📜 Transaction History:")
            # mined
            for r in rewards:
                hm = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
                if mode == "detailed":
                    print(f"⛏️  Mined {r['height']}: <coinbase> → {r['to']} | {r['amount']} CPX | ts {r['ts']}")
                else:
                    print(f"⛏️  Mined {r['height']}: {r['amount']} CPX  {hm}")

            # confirmed
            for t in confirmed:
                hm = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t["ts"]))
                if t["from"] == MY_ADDR:
                    arrow, label = "→", "Sent"
                else:
                    arrow, label = "←", "Received"
                if mode == "detailed":
                    print(f"📤  {label:<8}: {t['amount']} CPX {arrow} {t['to' if label == 'Sent' else 'from']} "
                          f"| fee {t['fee']} | block {t['height']} | ts {t['ts']}")
                else:
                    print(f"📤  {label:<8}: {t['amount']} CPX  {hm}")

            # pending
            for p in pending:
                hm = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p["ts"]))
                if mode == "detailed":
                    print(f"⏳  Pending  : {p['amount']} CPX → {p['to']} | fee {p['fee']} | ts {p['ts']}")
                else:
                    print(f"⏳  Pending  : {p['amount']} CPX  {hm}")
            continue

        print("❓ Unknown command")

try:
    asyncio.run(cli_loop())
except (EOFError, KeyboardInterrupt):
    print("\n👋 Bye")

