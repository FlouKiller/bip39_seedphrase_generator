# BIP39 Seed Phrase Generator

Outil local avec deux modes:

- une version CLI simple pour generer/verifier une phrase BIP39,
- une version web a logique 100% client-side (HTML/CSS/JavaScript) avec outils Bitcoin derives.

## Fonctionnalites

### CLI

- generation de seed phrase BIP39 en 12 ou 24 mots,
- verification de phrase BIP39 (mots + checksum),
- diagnostic simple de l'entropie systeme.

### Web (client-side)

- generation BIP39 avec interface graphique,
- verification de phrase BIP39,
- diagnostic d'entropie,
- derivation Bitcoin locale a partir d'une phrase + passphrase optionnelle,
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
- QR code genere localement dans le navigateur,
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

### Mode Web

```bash
python web_app.py
```

Puis ouvrir:

```text
http://127.0.0.1:5000
```

Note: le backend Flask sert uniquement la page HTML. Les operations de generation,
verification, derivation Bitcoin, QR et test d'entropie sont executees dans le navigateur,
sans envoi des secrets a une API serveur du projet.

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

- lance un test simple sur 1 Mo de donnees aleatoires via `window.crypto.getRandomValues`,
- affiche entropie estimee, chi-square et couverture des octets.

## Structure du projet

- `app.py` : version CLI
- `web_app.py` : serveur Flask minimal pour servir l'interface
- `templates/index.html` : interface web
- `bip39_words.txt` : wordlist BIP39 anglaise
- `requirements.txt` : dependances Python

## Dependances

- `flask`

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
