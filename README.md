# BIP39 Seed Phrase Generator

Outil local en Python avec deux modes:

- une version CLI simple pour generer/verifier une phrase BIP39,
- une version web Flask avec interface moderne et outils Bitcoin derives.

## Fonctionnalites

### CLI

- generation de seed phrase BIP39 en 12 ou 24 mots,
- verification de phrase BIP39 (mots + checksum),
- diagnostic simple de l'entropie systeme.

### Web Flask

- generation BIP39 avec interface graphique,
- verification de phrase BIP39,
- diagnostic d'entropie,
- derivation Bitcoin a partir d'une phrase + passphrase optionnelle,
- affichage de:
  - seed hex,
  - BIP32 root key,
  - comptes BIP44 / BIP49 / BIP84,
  - adresses, XPUB, XPRV, WIF,
- derivation avancee avec:
  - choix du schema `BIP32`, `BIP44`, `BIP49`, `BIP84`,
  - compte (`account`),
  - chaine (`chain`: externe/interne),
  - index,
- section repliable d'adresses de depot,
- QR code local pour adresses, cles et champs derives,
- copie rapide des valeurs sensibles.

## Validation de la wordlist

La wordlist anglaise BIP39 est verifiee strictement:

- 2048 mots exacts,
- aucun doublon,
- format attendu en minuscules ASCII,
- hash SHA-256 compare a la liste officielle BIP39 anglaise.

## Prerequis

- Python 3.8+
- fichiers du projet dans le meme dossier:
  - `app.py`
  - `web_app.py`
  - `bip39_words.txt`
  - `templates/index.html`
  - `requirements.txt`

## Installation

Dans le dossier du projet:

```bash
pip install -r requirements.txt
```

Sous Windows, vous pouvez aussi utiliser:

```powershell
py -m pip install -r requirements.txt
```

## Lancement

### Mode CLI

```bash
python app.py
```

### Mode Web Flask

```bash
python web_app.py
```

Puis ouvrir:

```text
http://127.0.0.1:5000
```

## Utilisation de la version web

### 1. Generer

- choisir 12 ou 24 mots,
- generer une phrase BIP39,
- copier la phrase si besoin.

### 2. Verifier

- coller une phrase,
- verifier le nombre de mots,
- verifier les mots de la wordlist,
- verifier le checksum.

### 3. Bitcoin

- saisir une phrase BIP39,
- ajouter une passphrase optionnelle,
- deriver:
  - la seed hex,
  - la BIP32 root key,
  - les donnees BIP44 / BIP49 / BIP84.

Le mode avance permet aussi de:

- changer le schema de derivation,
- modifier `account`, `chain` et `index`,
- afficher les account keys,
- lister les adresses de depot derivees,
- afficher des QR codes pour les champs importants.

### 4. Entropie

- lance un test simple sur 1 Mo de donnees `os.urandom`,
- affiche entropie estimee, chi-square et couverture des octets.

## Endpoints Flask utiles

- `POST /api/generate`
- `POST /api/verify`
- `GET /api/entropy`
- `POST /api/bitcoin/derive`
- `POST /api/bitcoin/derive-path`
- `POST /api/bitcoin/addresses`
- `POST /api/qrcode`

Exemple `curl` pour tester la generation:

```bash
curl -s -X POST http://127.0.0.1:5000/api/generate -H "Content-Type: application/json" -d "{\"word_count\": 12}"
```

## Structure du projet

- `app.py` : version CLI
- `web_app.py` : backend Flask + APIs
- `templates/index.html` : interface web
- `bip39_words.txt` : wordlist BIP39 anglaise
- `requirements.txt` : dependances Python

## Dependances

- `flask`
- `bip-utils`
- `qrcode[pil]`

## Securite

- utilisez cet outil uniquement en local,
- ne partagez jamais votre seed phrase,
- ne stockez pas seed / xprv / WIF dans le cloud,
- evitez les captures d'ecran si vous manipulez des cles privees,
- idealement, travaillez hors ligne sur une machine de confiance.

## Limitations

- ce projet est un outil educatif/local, pas un wallet complet,
- aucune diffusion sur le reseau Bitcoin n'est faite,
- aucun solde on-chain n'est charge,
- le test d'entropie est informatif seulement.

## Pistes d'amelioration

- ajout du testnet,
- pagination des adresses derivees,
- affichage optionnel des balances via une API externe,
- export QR plus avance pour les donnees publiques,
- tests automatises.
