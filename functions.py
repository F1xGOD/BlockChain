# functions.py
# ────────────────────────────────────────────────────────────────────────
import hmac, hashlib, secrets
from mnemonic import Mnemonic
from langdetect import detect
import pycountry
from ecdsa import SigningKey, SECP256k1
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from config import *
import json

def sign_transaction(tx: dict, sk: SigningKey) -> dict:
    """
    Canonical JSON → SHA256 digest → ECDSA‑secp256k1 signature.
    Returns a dict with the tx, hex sig, and hex pub_key.
    """
    # 1) Canonicalize & hash
    message = json.dumps(tx, sort_keys=True).encode()
    digest  = hashlib.sha256(message).digest()
    # 2) Sign
    sig = sk.sign_digest(digest)
    # 3) Package
    return {
        "transaction": tx,
        "signature": sig.hex(),
        "pub_key": sk.get_verifying_key().to_string().hex()
    }

def detect_full_language_name(text: str) -> str:
    # Prefer Mnemonic's built‑in detector, fallback to langdetect
    langs = Mnemonic.detect_language(text)
    if langs:
        return langs[0]
    code = detect(text)
    lang = pycountry.languages.get(alpha_2=code)
    return lang.name.lower() if lang else 'english'

def generate_seed(language: str='english', strength: int=SEED_STRENGTH) -> str:
    mn = Mnemonic(language)
    return mn.generate(strength=strength)

def derive_ecdsa_keypair(seed_bytes: bytes):
    # 32‑byte ECDSA key from your BIP39 seed
    sk_bytes = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"ecdsa_spend", backend=default_backend()
    ).derive(seed_bytes)
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    return sk, sk.get_verifying_key()

def address_from_pubkey(pub_bytes: bytes) -> str:
    # two “random” digits
    d1 = (hmac.new(pub_bytes, b"addr_digit1", hashlib.sha256).digest()[0] % 9) + 1
    d2 = (hmac.new(pub_bytes, b"addr_digit2", hashlib.sha256).digest()[0] % 9) + 1
    pre = ADDRESS_PREFIX_TMPL.format(d1)
    suf = ADDRESS_SUFFIX_TMPL.format(d2)
    mid_len = ADDRESS_LENGTH - len(pre) - len(suf)
    body = HKDF(
        algorithm=hashes.SHA256(), length=mid_len, salt=None,
        info=b"addr_middle", backend=default_backend()
    ).derive(pub_bytes)
    return pre + ''.join(ADDRESS_ALPHABET[b % len(ADDRESS_ALPHABET)] for b in body) + suf

def restore_from_seed(mnemonic_phrase: str, language: str=None):
    # 1) Normalize & detect lang
    words = mnemonic_phrase.strip().split()
    if words[-1].lower() in SUPPORTED_LANGS:
        words = words[:-1]
    phrase = " ".join(words)
    language = (language or detect_full_language_name(phrase)).lower()

    mn = Mnemonic(language)
    if not mn.check(phrase):
        raise ValueError("❌ Invalid mnemonic for "+language)
    seed_bytes = mn.to_seed(phrase, passphrase="")

    # 2) Derive chain‑style spend keys (AAAA…eZ / AAAA…eQ)
    priv_mid = KEY_LENGTH - len(PRIV_PREFIX) - len(PRIV_SUFFIX)
    priv_b   = HKDF(hashes.SHA256(), length=priv_mid, salt=None,
                    info=b"priv_spend", backend=default_backend()).derive(seed_bytes)
    priv_key = PRIV_PREFIX + ''.join(KEY_ALPHABET[b % len(KEY_ALPHABET)] for b in priv_b) + PRIV_SUFFIX

    pub_mid = KEY_LENGTH - len(PUB_PREFIX) - len(PUB_SUFFIX)
    pub_b   = HKDF(hashes.SHA256(), length=pub_mid, salt=None,
                    info=b"pub_spend", backend=default_backend()).derive(seed_bytes)
    pub_key = PUB_PREFIX + ''.join(KEY_ALPHABET[b % len(KEY_ALPHABET)] for b in pub_b) + PUB_SUFFIX

    # 3) Derive ECDSA keypair → and address from pubkey
    sk, vk = derive_ecdsa_keypair(seed_bytes)
    address = address_from_pubkey(vk.to_string())

    return address, priv_key, pub_key
