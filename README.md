# BIP39 Seed Phrase Generator (Python)

Petit outil CLI pour:
- generer une phrase mnemotechnique BIP39 (12 ou 24 mots),
- verifier une phrase BIP39 (checksum + mots valides),
- diagnostiquer rapidement la source aleatoire du systeme.

## Fonctionnalites

- Chargement et validation stricte de la wordlist BIP39:
  - 2048 mots obligatoires,
  - aucun doublon,
  - format attendu (mots en minuscules a-z),
  - empreinte SHA-256 comparee a la liste officielle BIP39 anglaise.
- Generation BIP39:
  - 12 mots (128 bits d'entropie + checksum 4 bits),
  - 24 mots (256 bits d'entropie + checksum 8 bits).
- Verification BIP39:
  - accepte uniquement 12, 15, 18, 21, 24 mots,
  - verifie presence des mots dans la liste,
  - verifie le checksum BIP39.
- Diagnostic entropie (informatif):
  - couverture des octets observes,
  - entropie estimee (Shannon),
  - score chi-square.

## Prerequis

- Python 3.8+
- Fichiers dans le meme dossier:
  - app.py
  - bip39_words.txt

## Installation / Lancement

1. Ouvrir un terminal dans le dossier du projet.
2. Lancer:

```bash
python app.py
```

Sous Windows, selon votre installation:

```powershell
py app.py
```

## Utilisation

Au lancement, un menu principal apparait:

1. Generer une nouvelle phrase
2. Verifier une phrase
3. Diagnostiquer l'entropie du PC
4. Quitter

### 1) Generation

- Choisir 12 ou 24 mots.
- Le script utilise `os.urandom` pour generer l'entropie.
- La phrase mnemotechnique est affichee dans le terminal.

### 2) Verification

- Coller votre phrase separee par des espaces.
- Le script verifie:
  - le nombre de mots,
  - la presence de chaque mot dans la wordlist,
  - le checksum BIP39.

### 3) Diagnostic entropie

- Lance un test simple sur un echantillon de 1 Mo.
- Donne des indicateurs utiles, mais ce n'est pas un audit cryptographique complet.

## Structure du projet

- app.py: logique principale (menus, generation, verification, diagnostic)
- bip39_words.txt: wordlist BIP39 anglaise officielle (2048 mots)

## Securite et bonnes pratiques

- Ne partagez jamais votre seed phrase.
- Evitez de generer une seed sur une machine non fiable.
- Idealement, utilisez une machine hors ligne (air-gapped) pour la generation.
- Sauvegardez la seed hors ligne (papier/metal), pas dans le cloud.

## Limitations

- Outil CLI educatif/pratique, pas un wallet complet.
- Le test d'entropie est informatif seulement.
- Ce projet n'implemente pas de passphrase BIP39 (25e mot) pour le moment.

## Idee d'ameliorations

- Ajouter support de la passphrase BIP39.
- Export optionnel vers QR (hors seed en clair).
- Ajouter tests unitaires automatiques.
