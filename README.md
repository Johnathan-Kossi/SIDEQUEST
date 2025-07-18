# CTF Challenges - Sidequest

## Présentation

Ce dépôt contient une collection de write-ups pour différents challenges de Capture The Flag (CTF) réalisés dans le cadre d'une sidequest.
## Challenges documentés

### Bank-Simulator
- **Événement**: Non spécifié
- **Catégorie**: Exploitation binaire
- **Difficulté**: Facile
- **Description**: Challenge impliquant l'analyse d'un binaire ELF simple avec extraction de chaînes de caractères pour obtenir le flag.
- **Techniques utilisées**: Analyse statique, extraction de chaînes, identification de messages de succès/échec.
- **Fichier**: [bank-simulator-writeup.md](./bank-simulator-writeup.md)

### TEXSAW Sleep Survey
- **Événement**: TEXSAW CTF
- **Catégorie**: Rétro-ingénierie / Exploitation binaire
- **Difficulté**: Moyenne
- **Description**: Analyse d'un binaire utilisant un gestionnaire de signal (SIGALRM) et décodage d'un flag via une boîte de substitution (sbox).
- **Techniques utilisées**: Analyse de fonction, inversion de sbox, décodage de flag, exploitation de signaux.
- **Fichier**: [texsaw-sleep-survey-writeup.md](./texsaw-sleep-survey-writeup.md)

### Beginner Pwn 2
- **Événement**: SwampCTF 2025
- **Catégorie**: Exploitation binaire (Pwn)
- **Difficulté**: Facile
- **Description**: Challenge de type ret2win exploitant un débordement de tampon pour rediriger l'exécution vers une fonction cachée.
- **Techniques utilisées**: Analyse de binaire, exploitation de débordement de tampon, redirection de flux d'exécution.
- **Fichier**: [beginner-pwn2-writeup.md](./beginner-pwn2-writeup.md)


## Outils utilisés

- **Analyse statique**: objdump, file, strings
- **Débogage**: GDB, peda/gef
- **Exploitation**: Python, pwntools

