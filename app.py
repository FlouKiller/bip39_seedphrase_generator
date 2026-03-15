import hashlib
import math
import os
import re

BIP39_WORD_COUNT = 2048
BIP39_ENGLISH_SHA256 = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae"
VALID_MNEMONIC_LENGTHS = [12, 15, 18, 21, 24]


def validate_wordlist(words):
    if len(words) != BIP39_WORD_COUNT:
        return False, f"La liste contient {len(words)} mots au lieu de {BIP39_WORD_COUNT}."

    if len(set(words)) != len(words):
        return False, "La liste contient des doublons."

    # BIP39 english.txt contains lowercase ASCII words only.
    invalid_words = [w for w in words if not re.fullmatch(r"[a-z]+", w)]
    if invalid_words:
        return False, f"Format invalide detecte (exemple: '{invalid_words[0]}')."

    normalized = "\n".join(words).encode("utf-8")
    digest = hashlib.sha256(normalized).hexdigest()
    if digest != BIP39_ENGLISH_SHA256:
        return False, "Le contenu ou l'ordre des mots ne correspond pas a la liste BIP39 officielle."

    return True, "OK"

def load_wordlist(filename):
    if not os.path.exists(filename):
        print(f"❌ Erreur : Le fichier '{filename}' est introuvable.")
        return None
    with open(filename, 'r', encoding='utf-8') as f:
        words = [line.strip() for line in f if line.strip()]

    is_valid, reason = validate_wordlist(words)
    if not is_valid:
        print(f"❌ Erreur wordlist : {reason}")
        return None
    else:
        print("✅ Wordlist valide et chargée.")

    return words

def generate_seed(wordlist):
    while True:
        print("\n--- GÉNÉRATION ---")
        print("1. Générer une phrase de 12 mots")
        print("2. Générer une phrase de 24 mots")
        print("3. Retour au menu principal")
        choix = input("\nChoix : ")

        # Configuration selon le standard BIP39
        if choix == '1':
            entropy_bits_size = 128
            checksum_bits_size = 4
            word_count = 12
            break
        elif choix == '2':
            entropy_bits_size = 256
            checksum_bits_size = 8
            word_count = 24
            break
        elif choix == '3':
            return
        else:
            print("Invalide.")

    # 1. Génération de l'entropie (16 octets pour 128 bits, 32 pour 256 bits)
    entropy_bytes = os.urandom(entropy_bits_size // 8)
    entropy_bits = bin(int.from_bytes(entropy_bytes, 'big'))[2:].zfill(entropy_bits_size)
    
    # 2. Calcul du Checksum (SHA-256)
    hash_bytes = hashlib.sha256(entropy_bytes).digest()
    hash_str = bin(int.from_bytes(hash_bytes, 'big'))[2:].zfill(256)
    checksum = hash_str[:checksum_bits_size]
    
    # 3. Assemblage (Entropie + Checksum)
    final_bits = entropy_bits + checksum
    
    # 4. Conversion en mots (paquets de 11 bits)
    mnemonic = [wordlist[int(final_bits[i:i+11], 2)] for i in range(0, len(final_bits), 11)]
    
    print(f"\n✅ Votre phrase de {word_count} mots :")
    print(" ".join(mnemonic))

def verify_seed(wordlist):
    phrase = input("\nEntrez votre phrase (mots séparés par des espaces) :\n> ").strip().lower().split()
    length = len(phrase)

    if length == 0:
        print("❌ Erreur : Aucune phrase saisie.")
        return

    if length not in VALID_MNEMONIC_LENGTHS:
        valid_lengths = ", ".join(str(n) for n in VALID_MNEMONIC_LENGTHS)
        print(f"❌ Erreur : {length} mots détectés. Longueurs BIP39 valides : {valid_lengths}.")
        return

    # Configuration dynamique selon la longueur de la phrase
    checksum_size = length // 3  # Ratio standard BIP39
    entropy_size = length * 11 - checksum_size

    try:
        bits = "".join([bin(wordlist.index(w))[2:].zfill(11) for w in phrase])
        entropy_bits = bits[:entropy_size]
        provided_cksum = bits[entropy_size:]
        
        # Recalcul
        ent_bytes = int(entropy_bits, 2).to_bytes(entropy_size // 8, 'big')
        calc_cksum = bin(int.from_bytes(hashlib.sha256(ent_bytes).digest(), 'big'))[2:].zfill(256)[:checksum_size]
        
        if provided_cksum == calc_cksum:
            print(f"✅ Phrase de {length} mots VALIDE.")
        else:
            print("❌ Phrase INVALIDE (le checksum ne correspond pas).")
    except ValueError:
        print("❌ Erreur : Un mot n'est pas dans la liste BIP39.")


def check_system_entropy(sample_size=1024 * 1024):
    print("\n--- DIAGNOSTIC ENTROPIE SYSTÈME ---")
    print(f"Analyse d'un échantillon de {sample_size} octets depuis os.urandom...\n")

    data = os.urandom(sample_size)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    used_values = sum(1 for c in counts if c > 0)
    expected = sample_size / 256
    entropy = 0.0
    chi2 = 0.0

    for c in counts:
        if c > 0:
            p = c / sample_size
            entropy -= p * math.log2(p)
        chi2 += ((c - expected) ** 2) / expected

    print(f"Valeurs d'octet observées : {used_values}/256")
    print(f"Entropie estimée : {entropy:.4f} bits/octet (max théorique: 8.0000)")
    print(f"Score chi-square : {chi2:.2f} (plus bas = distribution plus uniforme)")

    # Seuils simples pour un indicateur utilisateur (ce n'est pas un test crypto formel).
    if used_values == 256 and entropy >= 7.98:
        print("✅ Source aléatoire système: indicateurs bons.")
    else:
        print("⚠️ Résultat atypique. Relancez le test; si ça persiste, vérifiez l'environnement système.")

    print("\nNote: ce diagnostic est informatif et ne remplace pas un audit RNG complet.")

def main():
    wordlist = load_wordlist('bip39_words.txt')
    if not wordlist: return

    while True:
        print("\n--- MENU SEED PHRASE ---")
        print("1. Générer une nouvelle phrase")
        print("2. Vérifier une phrase")
        print("3. Diagnostiquer l'entropie du PC")
        print("4. Quitter")
        c = input("\nChoix : ")
        if c == '1': generate_seed(wordlist)
        elif c == '2': verify_seed(wordlist)
        elif c == '3': check_system_entropy()
        elif c == '4': break
        else: print("Invalide.")

if __name__ == "__main__":
    main()