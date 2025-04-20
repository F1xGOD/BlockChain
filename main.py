# main.py
# ────────────────────────────────────────────────────────────────────────
from functions import generate_seed, restore_from_seed, detect_full_language_name
from config import *

if __name__ == "__main__":
    lang = input("Lang: ").strip().lower()
    seed = generate_seed(lang)
    addr, prv, pub = restore_from_seed(seed, lang)
    print("🧬 Seed Phrase:       ", seed)
    print("🔑 Wallet Address:    ", addr)
    print("🔒 Private Spend Key: ", prv)
    print("🔓 Public Spend Key:  ", pub)

    # Test restore
    entered = input("Enter seed again: ").strip()
    lang2 = detect_full_language_name(entered)
    r_addr, r_prv, r_pub = restore_from_seed(entered, lang2)
    print("🔄 Restored Address:    ", r_addr)
    print("🔄 Restored Private Key:", r_prv)
    print("🔄 Restored Public Key: ", r_pub)
