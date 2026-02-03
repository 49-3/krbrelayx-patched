# Active Directory Attacks - Lab Resources

Ce dépôt contient des outils et guides pratiques pour les attaques Active Directory dans le cadre de l'OSEP.

## 📚 Sommaire

### Guides d'attaque

- [**krbrelayx - Unconstrained Delegation Attack from Kali**](krbrelayx%20-%20Unconstrained%20Delegation%20Attack%20from%20Kali.md)
  - Exploitation de l'unconstrained delegation depuis Kali Linux
  - Utilisation de krbrelayx et PrinterBug
  - Capture de TGT du contrôleur de domaine
  - DCSync et compromission totale du domaine
  - Setup venv et procédure one-shot complète

- [**23.1.2. I am a Domain Controller**](23.1.2.%20I%20am%20a%20Domain%20Controller.md)
  - Cours théorique sur l'unconstrained delegation
  - Lab Windows avec Rubeus + SpoolSample
  - Lab Linux avec krbrelayx

### Outils

#### krbrelayx/
Suite d'outils Python pour les attaques Kerberos relay et unconstrained delegation.

**Outils principaux** :
- `krbrelayx.py` - Serveur relay pour capturer les TGT (version patchée)
- `printerbug.py` - Exploit PrintSpooler pour forcer l'authentification (version patchée)
- `dnstool.py` - Gestion des enregistrements DNS Active Directory
- `addspn.py` - Ajout/modification de Service Principal Names

**Documentation** : [krbrelayx GitHub](https://github.com/dirkjanm/krbrelayx)

## 🚀 Quick Start

### Installation

```bash
# Cloner le dépôt
git clone <url-du-repo>
cd "23. Attacking Active Directory"

# Setup de l'environnement krbrelayx
cd krbrelayx
python3 -m venv venv
source venv/bin/activate
pip install impacket dnspython ldap3 pyasn1 pycryptodome
```

### Attaque Unconstrained Delegation

Pour une exploitation complète depuis un environnement neuf :

```bash
# 1. Suivre le guide complet
cat "krbrelayx - Unconstrained Delegation Attack from Kali.md"

# 2. Ou utiliser le script one-shot (adapter les variables)
# Voir section "Procédure One-Shot" dans le guide
```

## 🎯 Scénarios d'attaque

### Scenario 1 : Compromise depuis Windows
**Prérequis** : Accès à un serveur avec unconstrained delegation (FILES01)

1. Utiliser Rubeus en mode monitor
2. Déclencher SpoolSample vers FILES01
3. Capturer le TGT de DC01$
4. Effectuer un DCSync avec Mimikatz
5. Créer un Golden Ticket

**Guide** : [23.1.2. I am a Domain Controller.md](23.1.2.%20I%20am%20a%20Domain%20Controller.md#labs) - Lab 1

### Scenario 2 : Compromise depuis Kali Linux
**Prérequis** : Serveur compromis avec unconstrained delegation + compte domaine

1. Configurer DNS et enregistrements
2. Ajouter les SPN nécessaires
3. Lancer krbrelayx avec l'AES key de FILES01$
4. Déclencher PrinterBug
5. Capturer le TGT et DCSync

**Guide** : [krbrelayx - Unconstrained Delegation Attack from Kali.md](krbrelayx%20-%20Unconstrained%20Delegation%20Attack%20from%20Kali.md)

## 🔧 Configuration requise

### Environnement Kali Linux

```bash
# Packages requis
sudo apt update
sudo apt install python3 python3-venv python3-pip

# Outils Impacket
pip install impacket

# Evil-WinRM (optionnel)
sudo gem install evil-winrm
```

### Configuration DNS

```bash
# Éditer /etc/resolv.conf
sudo nano /etc/resolv.conf
```

Ajouter :
```
search corp.com
nameserver <DC_IP>
```

## 📝 Notes importantes

### Hash et clés utilisées

| Type | Compte | Usage |
|------|--------|-------|
| NTLM Hash | Administrator (local FILES01) | Pass-the-Hash initial pour secretsdump |
| AES-256 Key | FILES01$ (machine) | krbrelayx authentication en tant que FILES01$ |
| NTLM Hash | Administrator (domain) | Shell final sur DC après DCSync |

### Bypass NTLMSSP

**Erreur commune** : `Unsupported MechType 'NTLMSSP'`

**Solution** : Ajouter le SPN `cifs/attacker.corp.com` sur le compte FILES01$ pour forcer l'utilisation de Kerberos au lieu de NTLM.

```bash
python3 addspn.py -u "CORP\\Administrator" \
  -p "aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>" \
  -t FILES01$ -s cifs/attacker.corp.com \
  -dc-ip <DC_IP> dc01.corp.com
```

## 🎓 Références

- [MS-RPRN Protocol Documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/)
- [Unconstrained Delegation Abuse - HarmJ0y](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [krbrelayx by Dirk-jan](https://github.com/dirkjanm/krbrelayx)
- [Impacket Tools](https://github.com/fortra/impacket)
- [SpoolSample by Lee Christensen](https://github.com/leechristensen/SpoolSample)

## 🏆 Labs validés

- ✅ Lab 1 - Unconstrained Delegation depuis Windows (FILES01)
- ✅ Lab 2 - Unconstrained Delegation depuis Kali Linux
  - Flag : `OS{ac1b63242f30440efafcfcad001cf8db}`

## ⚠️ Disclaimer

Ces outils et techniques sont fournis à des fins éducatives dans le cadre de l'OSEP. Utilisez-les uniquement dans des environnements de laboratoire autorisés.

---

**Dernière mise à jour** : 3 février 2026
**Version** : 1.0
