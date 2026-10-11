# HttpsProxy — capture / replay HTTPS

Proxy HTTPS en C# (.NET 8) à deux modes, pensé pour **reproduire une réponse HTTPS à l'identique**.

- **capture** : reverse-proxy TLS vers une destination `IP[:port]`. Il relaie chaque
  requête vers le vrai serveur, renvoie la vraie réponse au client, **et enregistre
  la réponse brute (octet pour octet)** indexée par le **path** de la requête
  (la query string / les paramètres GET/POST sont ignorés). Une nouvelle capture
  sur le même path écrase la précédente.
- **replay** : ne contacte plus personne. Pour chaque requête, il prend le **path**
  (query ignorée) et renvoie **la dernière réponse capturée pour ce path**, telle quelle.

La fidélité « octet pour octet » vient du fait que le proxy travaille sur les **octets
bruts** (TcpListener + SslStream), sans jamais reconstruire les en-têtes : ordre, casse,
`Server:`, `Date:`, corps (y compris `chunked`/gzip) sont restitués à l'identique.

## Prérequis

- .NET SDK 8+ (présent sur la machine).

## Compilation

```powershell
cd C:\TP\HttpsProxy
dotnet build -c Release
```

## Utilisation

```
setup <domaine[,domaine...]> [--ca .\proxy-ca.pfx] [--cert .\proxy-cert.pfx] [--machine] [--renew] [--renew-ca]
capture <ip[:port]>          [--bind 0.0.0.0] [--listen 443] [--store .\captures] [--sni host]
                             [--cert .\proxy-cert.pfx] [--ca .\proxy-ca.pfx] [--domain host]
                             [--trust] [--machine] [--renew] [--renew-ca]
                             [--set-hosts <domaine>:<ip>] [--force-disable-hosts]
                             [--close-after-replay <sec>] [--close-after-timeout <sec>]
replay                       [--bind 0.0.0.0] [--listen 443] [--store .\captures]
                             [--forward-leftover <ip[:port]>] [--save-misses] [--sni host]
                             [--cert .\proxy-cert.pfx] [--ca .\proxy-ca.pfx] [--domain host]
                             [--trust] [--machine] [--renew] [--renew-ca]
                             [--set-hosts <domaine>:<ip>] [--force-disable-hosts]
                             [--close-after-replay <sec>] [--close-after-timeout <sec>]
```

- `--bind` : adresse (interface) d'écoute. Défaut `0.0.0.0` = toutes les interfaces.
  Exemple pour n'écouter que sur une IP de loopback précise : `--bind 127.0.0.2`.
  (Sous Windows, tout `127.x.x.x` est utilisable en loopback sans configuration.)
- `--forward-leftover <ip[:port]>` : **(replay)** pour tout path **absent** de la capture,
  relaie la requête en live vers cette destination et renvoie sa vraie réponse
  (au lieu du `404`). Les paths capturés, eux, continuent d'être servis depuis le store.
- `--save-misses` : **(replay)** enregistre aussi dans le store les réponses obtenues
  via `--forward-leftover` (le replay devient alors un cache qui se remplit tout seul).
  Sans cette option, les paths relayés ne sont pas mémorisés.

### Redirection hosts + fermeture automatique

- `--set-hosts <domaine>:<ip>` : active (décommente, ou ajoute) la ligne
  `<ip> <domaine>` dans `C:\Windows\System32\drivers\etc\hosts`, puis la **restaure**
  (re-commente, ou supprime si elle a été ajoutée) à l'arrêt du proxy. Exemple :
  `--set-hosts exemple.com:127.0.0.2`. **Nécessite un terminal administrateur.**
  Fonctionne en `capture` comme en `replay`.
- `--force-disable-hosts` : à l'arrêt, désactive la ligne hosts **même si elle était
  déjà active avant** le lancement (sinon, une ligne préexistante est laissée telle quelle).
- `--close-after-replay <sec>` : ferme le proxy `<sec>` secondes après la **première**
  réponse servie en mode replay (utile pour : servir une fois, puis s'arrêter).
- `--close-after-timeout <sec>` : ferme le proxy après `<sec>` secondes, quel que soit
  le trafic.

Exemple de session « une requête, on intercepte, on ferme et on nettoie le hosts » :

```powershell
# en admin
dotnet run -c Release -- replay --forward-leftover 11.22.33.44 --save-misses \
      --domain exemple.com --bind 127.0.0.2 --listen 443 \
      --set-hosts exemple.com:127.0.0.2 --close-after-replay 5
```

## Certificat de confiance (CA locale)

Pour que le client accepte le proxy **sans** option `-k`, on peut générer une
**autorité de certification locale** et l'installer dans le magasin « Racines de
confiance » de Windows :

```powershell
dotnet run -c Release -- setup api.example.com
```

Cela :

1. crée une **CA racine** auto-signée `proxy-ca.pfx` (réutilisée ensuite) ;
2. crée un **certificat serveur** `proxy-cert.pfx` signé par cette CA, couvrant le
   domaine fourni (`SAN`), plus `localhost` et `127.0.0.1` ;
3. installe la CA dans le magasin **Racines de confiance** (`CurrentUser`) si elle
   n'y est pas déjà — Windows affiche alors une **boîte de confirmation** à accepter.

Options associées :

- `--domain <hôte[,hôte...]>` : domaine(s) à couvrir. Plusieurs hôtes possibles,
  séparés par des virgules (`setup api.example.com,www.example.com`).
- `--ca <chemin>` : emplacement de la CA (défaut `.\proxy-ca.pfx`).
- `--machine` : installer la CA dans `LocalMachine` au lieu de `CurrentUser`
  (nécessite d'exécuter le terminal **en tant qu'administrateur**).
- `--trust` : en mode `capture`/`replay`, installe aussi la CA dans le magasin de
  confiance au démarrage si elle est absente (équivalent au `setup` mais sans
  s'arrêter).
- `--renew` : régénère le certificat serveur même s'il existe déjà (utile pour
  changer de domaine, ou pour remplacer un ancien `proxy-cert.pfx` auto-signé
  par la version signée par la CA).
- `--renew-ca` : régénère la **CA** (nouvelle clé) **et** le certificat serveur,
  puis **remplace** l'ancienne CA dans le magasin Racines de confiance (supprime
  l'ancienne du même nom, installe la nouvelle). À utiliser pour faire tourner la
  CA ou après avoir perdu la clé privée de la CA.

En mode `capture`/`replay`, `--domain` permet d'utiliser ce certificat :

```powershell
dotnet run -c Release -- capture 11.22.33.44 --domain api.example.com --listen 8443
dotnet run -c Release -- replay                --domain api.example.com --listen 8443
```

> **Migration** : un `proxy-cert.pfx` généré par une ancienne version du proxy est
> auto-signé (non rattaché à la CA). Pour bénéficier de la chaîne de confiance,
> régénérez-le une fois : `dotnet run -c Release -- setup api.example.com --renew`.

### 1) Enregistrer la réponse du vrai serveur (ex. 11.22.33.44)

```powershell
dotnet run -c Release -- capture 11.22.33.44 --listen 8443
```

Puis fais passer **ton client** par le proxy (`https://<ip-du-proxy>:8443/...`) au lieu
du vrai serveur. Le proxy relaie, tu obtiens la vraie réponse, et elle est enregistrée
dans `.\captures\`.

### 2) Rejouer hors-ligne

```powershell
dotnet run -c Release -- replay --listen 8443
```

Maintenant, toute requête sur un path déjà capturé reçoit **exactement** la réponse
enregistrée, sans contacter le vrai serveur.

## Point important : le certificat (c'est du HTTPS)

Le proxy **termine le TLS** côté client : il présente le certificat serveur
(`proxy-cert.pfx`), signé par la CA locale `proxy-ca.pfx` (généré une seule fois
puis réutilisé). Le client doit l'accepter :

- en ignorant la vérification (ex. `curl -k`, ou l'option équivalente du client), **ou**
- en installant la **CA** `proxy-ca.pfx` dans le magasin de confiance du client
  (c'est ce que fait le mode `setup`, cf. section précédente).

C'est seulement possible si **tu contrôles le client**. On ne peut pas intercepter
silencieusement un client qu'on ne maîtrise pas (c'est voulu).

## Faire passer le client par le proxy

Selon ce qu'est ton client :

- **curl / script** : change l'URL cible pour `https://<proxy>:8443/...` (le plus simple).
- **client qui vise une IP/host fixe** : redirige via le fichier `hosts`
  (`C:\Windows\System32\drivers\etc\hosts`) ou le DNS pour faire pointer le nom vers
  le proxy, et fais écouter le proxy sur `--listen 443`.

## Où sont les captures

Dans le dossier `--store` (défaut `.\captures`). Par path :

- `<path>_<hash>.response.bin` — la réponse brute rejouée (octet pour octet) ;
- `<path>_<hash>.request.bin` — la requête correspondante (pour info) ;
- `<path>_<hash>.meta.txt` — résumé lisible (date, path, lignes requête/réponse, taille).

## Notes / limites

- La clé de correspondance est le **path seul** (query ignorée). Un `GET /x` et un
  `POST /x` partagent donc la même entrée ; pour les distinguer, passer à
  `méthode+path` dans `HttpMessage.NormalizePath` / `Store`.
- En capture, une **connexion amont neuve par requête** (simple, sans état).
- Le certificat amont (vrai serveur) est accepté sans vérification (destination par IP).
- Le certificat serveur (et la CA) sont **réutilisés tels quels** s'ils existent déjà ;
  pour changer de domaine ou régénérer, utiliser `--renew`.
