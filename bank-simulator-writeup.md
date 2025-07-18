# Write-up : Challenge Bank-Simulator - BREIZHCTF

## Contexte

Ce challenge a été réalisé dans le cadre du BREIZH CTF.

## Analyse initiale du binaire

L'examen préliminaire du fichier fourni a été effectué à l'aide de la commande `file` :

```bash
$ file bank-simulator
bank-simulator: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e54bba1560a88b8c9e17322fd9e0acf87636e741, for GNU/Linux 3.2.0, stripped
```

Le fichier est un exécutable ELF 64 bits pour architecture x86-64, lié dynamiquement et strippé (les symboles de débogage ont été retirés).

## Exécution du programme

Lors de l'exécution du binaire, une interface simulant une procédure bancaire s'affiche :

```
./bank-simulator
[BANK-SIMULATOR]
Bienvenue dans le simulateur bancaire ultime !

Voici les etapes :
1. Rendez-vous en physique (9h45-10h12 le mardi).
2. Completez le dossier (bonne chance pour
   comprendre les formulaires).
3. Retournez voir votre conseiller
   (si vous le retrouvez).
4. Ce n'etait pas le bon dossier,
   mais on vous l'avait dit, non ? Recommencez
5. Payez les frais de dossier (x2).
6. Une lettre devrait arriver d'ici 1-2 ans
   (ou pas).
7. Ouvrez-la, un code vous est peut-etre donne
   (si la poste ne l'a pas egare).
8. Saisissez le code ci-dessous pour acceder a
   l'ultime verite.

SAISIR LE CODE >
```

Le programme attend une entrée utilisateur sous forme de code. Plutôt que d'attendre une hypothétique lettre comme suggéré dans le scénario, il est préférable de chercher directement dans le binaire.

## Extraction des chaînes de caractères

La commande `strings` permet d'extraire les chaînes de caractères lisibles contenues dans le binaire :

```bash
strings bank-simulator
```

Parmi les résultats, plusieurs chaînes pertinentes sont identifiées :

```
Bravo, vH
ous avezH
 triomphH
e de la H
bureaucrH
atie !  H
Mauvais H
code ! UH
n formulH
aire supH
plementaH
ire vousH
BZHCTF{CH
oB0l_4_3H
v3r}
```

## Analyse des résultats

L'examen des chaînes extraites permet d'identifier plusieurs éléments importants :

1. Un message de succès : "Bravo, vous avez triomphé de la bureaucratie !"

2. Un message d'échec : "Mauvais code ! Un formulaire supplémentaire vous sera envoyé."

3. Le flag recherché : `BZHCTF{CoB0l_4_3v3r}`, fragmenté par des caractères 'H' et des sauts de ligne.

La présence de ces caractères 'H' intercalés pourrait être une référence à la façon dont COBOL gère les chaînes de caractères, ce qui est cohérent avec le thème du challenge.

## Conclusion

En analysant directement les chaînes de caractères présentes dans le binaire, il a été possible d'extraire le flag `BZHCTF{CoB0l_4_3v3r}` sans avoir à exécuter le programme avec les entrées correctes.

Cette méthode directe d'extraction a permis de contourner l'aspect simulé des procédures bancaires présentées par le programme.
