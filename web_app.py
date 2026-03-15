import hashlib
import io
import base64
import math
import os
import re

from flask import Flask, render_template, jsonify, request
from bip_utils import (
    Bip32Secp256k1,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
)
import qrcode

BIP39_WORD_COUNT = 2048
BIP39_ENGLISH_SHA256 = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae"
VALID_MNEMONIC_LENGTHS = [12, 15, 18, 21, 24]

app = Flask(__name__)

_wordlist = None
_word_index = None


def validate_wordlist(words):
    if len(words) != BIP39_WORD_COUNT:
        return False, f"La liste contient {len(words)} mots au lieu de {BIP39_WORD_COUNT}."
    if len(set(words)) != len(words):
        return False, "La liste contient des doublons."
    invalid = [w for w in words if not re.fullmatch(r"[a-z]+", w)]
    if invalid:
        return False, f"Format invalide détecté (exemple : '{invalid[0]}')."
    digest = hashlib.sha256("\n".join(words).encode("utf-8")).hexdigest()
    if digest != BIP39_ENGLISH_SHA256:
        return False, "Le contenu ou l'ordre des mots ne correspond pas à la liste BIP39 officielle."
    return True, "OK"


def load_wordlist():
    global _wordlist, _word_index
    path = os.path.join(os.path.dirname(__file__), "bip39_words.txt")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Fichier 'bip39_words.txt' introuvable.")
    with open(path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    is_valid, reason = validate_wordlist(words)
    if not is_valid:
        raise ValueError(f"Wordlist invalide : {reason}")
    _wordlist = words
    _word_index = {w: i for i, w in enumerate(words)}


def get_wordlist():
    if _wordlist is None:
        load_wordlist()
    return _wordlist, _word_index


def parse_and_validate_mnemonic(raw_phrase):
    if not isinstance(raw_phrase, str):
        return None, "Entrée invalide."

    phrase = raw_phrase.strip().lower().split()
    length = len(phrase)

    if length == 0:
        return None, "Aucune phrase saisie."
    if length not in VALID_MNEMONIC_LENGTHS:
        valid_str = ", ".join(str(n) for n in VALID_MNEMONIC_LENGTHS)
        return None, f"{length} mot(s) détecté(s). Longueurs BIP39 valides : {valid_str}."

    _, word_index = get_wordlist()
    invalid_words = [w for w in phrase if w not in word_index]
    if invalid_words:
        return None, f"Le mot « {invalid_words[0]} » n'est pas dans la liste BIP39."

    checksum_size = length // 3
    entropy_size = length * 11 - checksum_size
    bits = "".join(bin(word_index[w])[2:].zfill(11) for w in phrase)
    entropy_bits = bits[:entropy_size]
    provided_cksum = bits[entropy_size:]
    ent_bytes = int(entropy_bits, 2).to_bytes(entropy_size // 8, "big")
    calc_cksum = bin(int.from_bytes(hashlib.sha256(ent_bytes).digest(), "big"))[2:].zfill(256)[:checksum_size]

    if provided_cksum != calc_cksum:
        return None, "Phrase invalide — le checksum ne correspond pas."

    return " ".join(phrase), None


def parse_non_negative_int(value, field_name):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, f"{field_name} doit être un entier >= 0."
    if parsed < 0:
        return None, f"{field_name} doit être un entier >= 0."
    return parsed, None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.get_json(silent=True) or {}
    word_count = data.get("word_count", 12)
    if word_count not in [12, 24]:
        return jsonify({"error": "word_count doit être 12 ou 24."}), 400

    wordlist, _ = get_wordlist()
    entropy_bits = word_count * 11 - word_count // 3   # 128 or 256
    checksum_bits = word_count // 3                     # 4 or 8

    entropy_bytes = os.urandom(entropy_bits // 8)
    ent_str = bin(int.from_bytes(entropy_bytes, "big"))[2:].zfill(entropy_bits)
    hash_str = bin(int.from_bytes(hashlib.sha256(entropy_bytes).digest(), "big"))[2:].zfill(256)
    final = ent_str + hash_str[:checksum_bits]
    mnemonic = [wordlist[int(final[i:i + 11], 2)] for i in range(0, len(final), 11)]
    return jsonify({"mnemonic": mnemonic, "word_count": word_count})


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    mnemonic, err = parse_and_validate_mnemonic(data.get("phrase", ""))
    if err:
        return jsonify({"valid": False, "message": err})
    return jsonify({"valid": True, "message": f"Phrase de {len(mnemonic.split())} mots valide — checksum correct."})


@app.route("/api/bitcoin/derive", methods=["POST"])
def api_bitcoin_derive():
    data = request.get_json(silent=True) or {}
    mnemonic, err = parse_and_validate_mnemonic(data.get("phrase", ""))
    if err:
        return jsonify({"error": err}), 400

    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str):
        return jsonify({"error": "La passphrase doit être une chaîne."}), 400

    try:
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
        seed_hex = seed_bytes.hex()
        master_xprv = Bip32Secp256k1.FromSeed(seed_bytes).PrivateKey().ToExtended()

        ctx44 = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        acc44 = ctx44.Purpose().Coin().Account(0)
        ext44 = acc44.Change(Bip44Changes.CHAIN_EXT)
        addr44_ctx = ext44.AddressIndex(0)

        ctx49 = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
        acc49 = ctx49.Purpose().Coin().Account(0)
        ext49 = acc49.Change(Bip44Changes.CHAIN_EXT)
        addr49_ctx = ext49.AddressIndex(0)

        ctx84 = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        acc84 = ctx84.Purpose().Coin().Account(0)
        ext84 = acc84.Change(Bip44Changes.CHAIN_EXT)
        addr84_ctx = ext84.AddressIndex(0)
    except Exception as e:
        return jsonify({"error": f"Échec de dérivation Bitcoin : {str(e)}"}), 500

    return jsonify({
        "mnemonic": mnemonic,
        "seed_hex": seed_hex,
        "bip32_root_key": master_xprv,
        "bip44": {
            "path": "m/44'/0'/0'/0/0",
            "account_xprv": acc44.PrivateKey().ToExtended(),
            "account_xpub": acc44.PublicKey().ToExtended(),
            "address": addr44_ctx.PublicKey().ToAddress(),
            "wif": addr44_ctx.PrivateKey().ToWif(),
        },
        "bip49": {
            "path": "m/49'/0'/0'/0/0",
            "account_xprv": acc49.PrivateKey().ToExtended(),
            "account_xpub": acc49.PublicKey().ToExtended(),
            "address": addr49_ctx.PublicKey().ToAddress(),
            "wif": addr49_ctx.PrivateKey().ToWif(),
        },
        "bip84": {
            "path": "m/84'/0'/0'/0/0",
            "account_xprv": acc84.PrivateKey().ToExtended(),
            "account_xpub": acc84.PublicKey().ToExtended(),
            "address": addr84_ctx.PublicKey().ToAddress(),
            "wif": addr84_ctx.PrivateKey().ToWif(),
        },
    })


@app.route("/api/bitcoin/derive-path", methods=["POST"])
def api_bitcoin_derive_path():
    data = request.get_json(silent=True) or {}
    mnemonic, err = parse_and_validate_mnemonic(data.get("phrase", ""))
    if err:
        return jsonify({"error": err}), 400

    passphrase = data.get("passphrase", "")
    if not isinstance(passphrase, str):
        return jsonify({"error": "La passphrase doit être une chaîne."}), 400

    scheme = str(data.get("scheme", "bip84")).lower()
    if scheme not in ["bip32", "bip44", "bip49", "bip84"]:
        return jsonify({"error": "scheme invalide (bip32, bip44, bip49, bip84)."}), 400

    account, err = parse_non_negative_int(data.get("account", 0), "account")
    if err:
        return jsonify({"error": err}), 400
    chain, err = parse_non_negative_int(data.get("chain", 0), "chain")
    if err:
        return jsonify({"error": err}), 400
    index, err = parse_non_negative_int(data.get("index", 0), "index")
    if err:
        return jsonify({"error": err}), 400

    if chain not in [0, 1]:
        return jsonify({"error": "chain doit être 0 (external) ou 1 (internal)."}), 400

    try:
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

        if scheme == "bip32":
            master = Bip32Secp256k1.FromSeed(seed_bytes)
            account_node = master.DerivePath(f"{account}'")
            child_node = account_node.DerivePath(f"{chain}/{index}")
            return jsonify({
                "scheme": "bip32",
                "account": account,
                "chain": chain,
                "index": index,
                "derivation_path": f"m/{account}'/{chain}",
                "full_path": f"m/{account}'/{chain}/{index}",
                "account_xprv": account_node.PrivateKey().ToExtended(),
                "account_xpub": account_node.PublicKey().ToExtended(),
                "child_private_key_hex": child_node.PrivateKey().Raw().ToHex(),
                "child_public_key_hex": child_node.PublicKey().RawCompressed().ToHex(),
            })

        if scheme == "bip44":
            ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
            acc = ctx.Purpose().Coin().Account(account)
            child_ctx = acc.Change(Bip44Changes.CHAIN_EXT if chain == 0 else Bip44Changes.CHAIN_INT).AddressIndex(index)
            return jsonify({
                "scheme": "bip44",
                "account": account,
                "chain": chain,
                "index": index,
                "derivation_path": f"m/44'/0'/{account}'/{chain}",
                "full_path": f"m/44'/0'/{account}'/{chain}/{index}",
                "account_xprv": acc.PrivateKey().ToExtended(),
                "account_xpub": acc.PublicKey().ToExtended(),
                "address": child_ctx.PublicKey().ToAddress(),
                "wif": child_ctx.PrivateKey().ToWif(),
            })

        if scheme == "bip49":
            ctx = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
            acc = ctx.Purpose().Coin().Account(account)
            child_ctx = acc.Change(Bip44Changes.CHAIN_EXT if chain == 0 else Bip44Changes.CHAIN_INT).AddressIndex(index)
            return jsonify({
                "scheme": "bip49",
                "account": account,
                "chain": chain,
                "index": index,
                "derivation_path": f"m/49'/0'/{account}'/{chain}",
                "full_path": f"m/49'/0'/{account}'/{chain}/{index}",
                "account_xprv": acc.PrivateKey().ToExtended(),
                "account_xpub": acc.PublicKey().ToExtended(),
                "address": child_ctx.PublicKey().ToAddress(),
                "wif": child_ctx.PrivateKey().ToWif(),
            })

        ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        acc = ctx.Purpose().Coin().Account(account)
        child_ctx = acc.Change(Bip44Changes.CHAIN_EXT if chain == 0 else Bip44Changes.CHAIN_INT).AddressIndex(index)
        return jsonify({
            "scheme": "bip84",
            "account": account,
            "chain": chain,
            "index": index,
            "derivation_path": f"m/84'/0'/{account}'/{chain}",
            "full_path": f"m/84'/0'/{account}'/{chain}/{index}",
            "account_xprv": acc.PrivateKey().ToExtended(),
            "account_xpub": acc.PublicKey().ToExtended(),
            "address": child_ctx.PublicKey().ToAddress(),
            "wif": child_ctx.PrivateKey().ToWif(),
        })
    except Exception as e:
        return jsonify({"error": f"Échec de dérivation avancée : {str(e)}"}), 500


@app.route("/api/entropy", methods=["GET"])
def api_entropy():
    sample_size = 1024 * 1024
    raw = os.urandom(sample_size)
    counts = [0] * 256
    for b in raw:
        counts[b] += 1

    used = sum(1 for c in counts if c > 0)
    expected = sample_size / 256
    shannon = 0.0
    chi2 = 0.0
    for c in counts:
        if c > 0:
            p = c / sample_size
            shannon -= p * math.log2(p)
        chi2 += ((c - expected) ** 2) / expected

    good = used == 256 and shannon >= 7.98
    return jsonify({
        "used_values": used,
        "entropy": round(shannon, 4),
        "chi2": round(chi2, 2),
        "status": "good" if good else "warning",
    })


@app.route("/api/qrcode", methods=["POST"])
def api_qrcode():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "Le champ text est requis."}), 400

    if len(text) > 4096:
        return jsonify({"error": "Texte trop long pour QR (max 4096 caractères)."}), 400

    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        png_b64 = base64.b64encode(buffer.getvalue()).decode("ascii")
        return jsonify({"png_base64": png_b64})
    except Exception as e:
        return jsonify({"error": f"Échec génération QR: {str(e)}"}), 500


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        load_wordlist()
        print("✅ Wordlist BIP39 chargée et validée.")
    except Exception as e:
        print(f"❌ Erreur au chargement de la wordlist : {e}")
        raise SystemExit(1)
    print("🌐 Serveur démarré → http://127.0.0.1:5000")
    app.run(debug=False, host="127.0.0.1", port=5000)
