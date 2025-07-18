# Write-up : Challenge TEXSAW Sleep Survey

## Analyse du binaire

Après examen du code désassemblé, la fonction principale `main` présente les caractéristiques suivantes :

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  signal(0xe,sigalrm_handler);
  printf(
        "Welcome to the TEXSAW sleep survey! To submit your quick and easy one-minute survey, simply answer the following question [y/n]\nDo you feel existential dread when setting your alarm before bed?\n> "
        );
  fgets(local_58,0x40,stdin);
  if (local_58[0] == 'y') {
    puts("Exactly. I\'m glad you share my sentiments.");
  }
  else {
    if (local_58[0] != 'n') {
      printf(
            "I\'m sorry, I couldn\'t parse that response. You should try not wasting my valuable, precious time moving forward.\nGood day."
            );
      goto LAB_001013a0;
    }
    puts("What are you? What are you made of?");
  }
  puts("Your response has been submitted successfully. Thank you for your time.");
LAB_001013a0:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Point important : on note la présence d'un appel à `signal(0xe,sigalrm_handler)` au début de la fonction. Cette instruction configure un gestionnaire pour le signal SIGALRM (signal 14 ou 0xe en hexadécimal).

Le programme simule un sondage sur le sommeil et accepte les réponses 'y' ou 'n' à une question. La réponse est traitée normalement sans aucune fonctionnalité cachée apparente.

## Analyse du gestionnaire de signal

En examinant le gestionnaire de signal SIGALRM configuré dans la fonction principale :

```c
void sigalrm_handler(void)
{
  decode_flag();
  return;
}
```

Ce gestionnaire appelle simplement la fonction `decode_flag()`. Cette fonction est définie comme suit :

```c
void decode_flag(void)
{
  long in_FS_OFFSET;
  int local_120;
  uint local_11c;
  byte abStack_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  for (local_120 = 0; local_120 < 0x100; local_120 = local_120 + 1) {
    abStack_118[(int)(uint)(byte)sbox[local_120]] = (byte)local_120;
  }
  printf("Decoded flag: ");
  for (local_11c = 0; local_11c < 0x22; local_11c = local_11c + 1) {
    putchar((uint)abStack_118[(int)(uint)(byte)encoded_flag[(int)local_11c]]);
  }
  putchar(10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Cette fonction réalise les opérations suivantes :
1. Elle crée un tableau d'inversion pour un tableau global nommé `sbox`
2. Elle utilise ce tableau d'inversion pour décoder les valeurs contenues dans un autre tableau global `encoded_flag`
3. Elle affiche le résultat décodé, qui est probablement le flag

## Problématique et résolution

Le problème principal est que le programme ne déclenche jamais le signal SIGALRM pendant son exécution normale, donc la fonction `decode_flag()` n'est jamais appelée. Pour obtenir le flag, deux options sont possibles :

1. Modifier le binaire pour appeler directement la fonction `decode_flag()`
2. Reproduire la logique de décodage dans un script externe

Pour une approche non-intrusive, j'ai choisi de reproduire le fonctionnement dans un script Python. J'ai d'abord extrait les valeurs des tableaux `sbox` et `encoded_flag` depuis le binaire.

## Implémentation de la solution

```python
#!/usr/bin/env python3

sbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC3, 0x1C, 0x1D, 0x9E, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16, 0x3E, 0x7A, 0x4B, 0x8B, 0x8A, 0x79, 0x52, 0x7F, 0x5B, 0x8D, 0x8C, 0x7D, 0x5A, 0x4E, 0x4C, 0x7E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
encoded_flag = [0x8A, 0x9E, 0x5B, 0x8B, 0x86, 0x7F, 0x7D, 0x41, 0x16, 0x7F, 0x57, 0x8B, 0x99, 0x68, 0xBB, 0x86, 0xB0, 0x99, 0x1C, 0x99, 0x16, 0x79, 0x8B, 0x57, 0x54, 0x79, 0x1C, 0x41, 0x57, 0x8B, 0x7F, 0x86, 0x68, 0x4E]

stack = [0] * 264

# Création du tableau d'inversion pour sbox
for i in range(256):
    stack[sbox[i]] = i

# Décodage du flag
flag = ''
for i in range(34):  # 0x22 = 34 en décimal
    flag += chr(stack[encoded_flag[i]])
print(flag)
```

L'exécution de ce script permet d'obtenir le flag : `texsaw{how_signalicious_much_swag}`

## Solution alternative

Une autre méthode possible aurait été d'envoyer manuellement le signal SIGALRM au programme en cours d'exécution. En connaissant le PID du processus, on peut utiliser la commande `kill -SIGALRM <PID>` depuis un autre terminal, ce qui déclencherait l'exécution du gestionnaire et l'affichage du flag.

## Conclusion

Ce challenge met en évidence l'utilisation des gestionnaires de signaux comme mécanisme pour masquer des fonctionnalités. Le programme ne contient aucun appel au gestionnaire de signal dans son flux d'exécution normal, mais celui-ci peut être activé par un événement externe.

Le flag obtenu, `texsaw{how_signalicious_much_swag}`, fait référence à l'utilisation des signaux dans ce challenge.
