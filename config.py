# ——————————————————————————————
# CONFIG
# ——————————————————————————————
# Address charset and patterns
import string

# ——————————————————————————————
# CONFIG
# ——————————————————————————————
ADDRESS_ALPHABET    = '0123456789ABab'
ADDRESS_PREFIX_TMPL = "Fx8{}"
ADDRESS_SUFFIX_TMPL = "v{}H"
ADDRESS_LENGTH      = 34
NODE_URI = "wss://xmr.fixcraft.org:8765"
KEY_ALPHABET        = string.ascii_letters + string.digits
KEY_LENGTH          = 64
PRIV_PREFIX, PRIV_SUFFIX = "AAAA", "eZ"
PUB_PREFIX, PUB_SUFFIX   = "AAAA", "eQ"

SUPPORTED_LANGS     = ('english','japanese','russian')
SEED_STRENGTH       = 128  # 12‑word seed