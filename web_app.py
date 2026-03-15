import hashlib
import math
import os
import re

from flask import Flask, render_template, jsonify, request

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
    raw = data.get("phrase", "")
    if not isinstance(raw, str):
        return jsonify({"valid": False, "message": "Entrée invalide."}), 400

    phrase = raw.strip().lower().split()
    length = len(phrase)

    if length == 0:
        return jsonify({"valid": False, "message": "Aucune phrase saisie."})
    if length not in VALID_MNEMONIC_LENGTHS:
        valid_str = ", ".join(str(n) for n in VALID_MNEMONIC_LENGTHS)
        return jsonify({
            "valid": False,
            "message": f"{length} mot(s) détecté(s). Longueurs BIP39 valides : {valid_str}."
        })

    wordlist, word_index = get_wordlist()
    invalid_words = [w for w in phrase if w not in word_index]
    if invalid_words:
        return jsonify({
            "valid": False,
            "message": f"Le mot « {invalid_words[0]} » n'est pas dans la liste BIP39."
        })

    checksum_size = length // 3
    entropy_size = length * 11 - checksum_size
    bits = "".join(bin(word_index[w])[2:].zfill(11) for w in phrase)
    entropy_bits = bits[:entropy_size]
    provided_cksum = bits[entropy_size:]
    ent_bytes = int(entropy_bits, 2).to_bytes(entropy_size // 8, "big")
    calc_cksum = bin(int.from_bytes(hashlib.sha256(ent_bytes).digest(), "big"))[2:].zfill(256)[:checksum_size]

    if provided_cksum == calc_cksum:
        return jsonify({"valid": True, "message": f"Phrase de {length} mots valide — checksum correct."})
    return jsonify({"valid": False, "message": "Phrase invalide — le checksum ne correspond pas."})


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
