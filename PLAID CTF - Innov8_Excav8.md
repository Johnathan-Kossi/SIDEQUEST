# Write-up PLAID CTF 2025

# 🔨 Plaid CTF - Innov8_Excav8 🔨

![V8 Engine](https://i.imgur.com/dSYqK7L.png)

## 🎮 Description du challenge

Ce challenge du Plaid CTF exploite les différences entre le moteur JavaScript V8 de Chrome (d8) et Node.js pour encoder un message secret. Le challenge nous donne un script Python qui génère une séquence de nombres aléatoires selon que chaque bit du flag soit 0 ou 1.

## 🛠️ Fichiers du challenge

- **chall.py**: Script principal qui lit un fichier secret et génère des séquences de nombres
- **gen.js**: Script JavaScript qui génère 24 nombres aléatoires
- **d8**: Binaire du moteur V8 de Chrome (39MB)
- **secret.txt**: Le message secret à découvrir (303KB)

## 📝 Analyse du code

```python
# Pour chaque bit du message secret
for bit in secretbits:
    if bit == '0':
        # Utiliser le moteur d8 pour générer des nombres aléatoires
        output += [float(i) for i in subprocess.check_output('./d8 gen.js', shell=True).decode().split()]
    else:
        # Utiliser Node.js pour générer des nombres aléatoires
        output += [float(i) for i in subprocess.check_output('node gen.js', shell=True).decode().split()]
```

Le script JavaScript est simple:
```javascript
for (let i = 0; i < 24; i++) {
    console.log(Math.random());
}
```

## 🧠 L'astuce

La clé du challenge est que **d8 (V8) et Node.js génèrent des nombres aléatoires différemment**! Même si le code est identique, leurs générateurs de nombres pseudo-aléatoires ont des implémentations différentes.

Cela signifie que pour chaque bit du message secret:
- Si c'est un 0, nous obtenons 24 nombres du générateur de d8
- Si c'est un 1, nous obtenons 24 nombres du générateur de Node.js

## 💡 Solution

1. **Entraîner un classificateur**
   - Générer des échantillons de nombres avec d8 et Node.js
   - Entraîner un modèle pour distinguer les deux distributions

2. **Classifier les séquences**
   - Pour chaque groupe de 24 nombres dans la sortie
   - Déterminer s'il provient de d8 (bit 0) ou de Node.js (bit 1)

3. **Reconstruire le message**
   - Convertir la séquence de bits en caractères
   - Obtenir le flag

## 🎯 Ce que j'ai appris

- Les générateurs de nombres pseudo-aléatoires ne sont pas vraiment aléatoires
- Différentes implémentations produisent des distributions différentes
- Les subtiles différences entre les environnements JavaScript peuvent être exploitées
- L'apprentissage automatique peut être utilisé pour classifier des données apparemment aléatoires

Ce challenge combine cryptographie, statistiques et reverse engineering de façon ingénieuse!

