# Browsers
from DonPAPI.lazagne.softwares.browsers.chromium_based import chromium_browsers
from DonPAPI.lazagne.softwares.browsers.ie import IE
from DonPAPI.lazagne.softwares.browsers.mozilla import firefox_browsers
from DonPAPI.lazagne.softwares.browsers.ucbrowser import UCBrowser
# Chats
from DonPAPI.lazagne.softwares.chats.pidgin import Pidgin
from DonPAPI.lazagne.softwares.chats.psi import PSI
from DonPAPI.lazagne.softwares.chats.skype import Skype
# Databases
from DonPAPI.lazagne.softwares.databases.dbvis import Dbvisualizer
from DonPAPI.lazagne.softwares.databases.postgresql import PostgreSQL
from DonPAPI.lazagne.softwares.databases.robomongo import Robomongo
from DonPAPI.lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from DonPAPI.lazagne.softwares.databases.squirrel import Squirrel
# Games
from DonPAPI.lazagne.softwares.games.galconfusion import GalconFusion
from DonPAPI.lazagne.softwares.games.kalypsomedia import KalypsoMedia
from DonPAPI.lazagne.softwares.games.roguestale import RoguesTale
from DonPAPI.lazagne.softwares.games.turba import Turba
# Git
from DonPAPI.lazagne.softwares.git.gitforwindows import GitForWindows
# Mails
from DonPAPI.lazagne.softwares.mails.outlook import Outlook
from DonPAPI.lazagne.softwares.mails.thunderbird import Thunderbird
# Maven
from DonPAPI.lazagne.softwares.maven.mavenrepositories import MavenRepositories
# Memory
from DonPAPI.lazagne.softwares.memory.keepass import Keepass
from DonPAPI.lazagne.softwares.memory.memorydump import MemoryDump
# Multimedia
from DonPAPI.lazagne.softwares.multimedia.eyecon import EyeCON
# Php
from DonPAPI.lazagne.softwares.php.composer import Composer
# Svn
from DonPAPI.lazagne.softwares.svn.tortoise import Tortoise
# Sysadmin
from DonPAPI.lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from DonPAPI.lazagne.softwares.sysadmin.coreftp import CoreFTP
from DonPAPI.lazagne.softwares.sysadmin.cyberduck import Cyberduck
from DonPAPI.lazagne.softwares.sysadmin.filezilla import Filezilla
from DonPAPI.lazagne.softwares.sysadmin.filezillaserver import FilezillaServer
from DonPAPI.lazagne.softwares.sysadmin.ftpnavigator import FtpNavigator
from DonPAPI.lazagne.softwares.sysadmin.opensshforwindows import OpenSSHForWindows
from DonPAPI.lazagne.softwares.sysadmin.openvpn import OpenVPN
from DonPAPI.lazagne.softwares.sysadmin.iiscentralcertp import IISCentralCertP
from DonPAPI.lazagne.softwares.sysadmin.keepassconfig import KeePassConfig
from DonPAPI.lazagne.softwares.sysadmin.iisapppool import IISAppPool
from DonPAPI.lazagne.softwares.sysadmin.puttycm import Puttycm
from DonPAPI.lazagne.softwares.sysadmin.rdpmanager import RDPManager
from DonPAPI.lazagne.softwares.sysadmin.unattended import Unattended
from DonPAPI.lazagne.softwares.sysadmin.vnc import Vnc
from DonPAPI.lazagne.softwares.sysadmin.winscp import WinSCP
from DonPAPI.lazagne.softwares.sysadmin.wsl import Wsl
# Wifi
from DonPAPI.lazagne.softwares.wifi.wifi import Wifi
# Windows
from DonPAPI.lazagne.softwares.windows.autologon import Autologon
from DonPAPI.lazagne.softwares.windows.cachedump import Cachedump
from DonPAPI.lazagne.softwares.windows.credman import Credman
from DonPAPI.lazagne.softwares.windows.credfiles import CredFiles
from DonPAPI.lazagne.softwares.windows.hashdump import Hashdump
from DonPAPI.lazagne.softwares.windows.ppypykatz import Pypykatz
from DonPAPI.lazagne.softwares.windows.lsa_secrets import LSASecrets
from DonPAPI.lazagne.softwares.windows.vault import Vault
from DonPAPI.lazagne.softwares.windows.vaultfiles import VaultFiles
from DonPAPI.lazagne.softwares.windows.windows import WindowsPassword


def get_categories():
    category = {
        'browsers': {'help': 'Web browsers supported'},
        'chats': {'help': 'Chat clients supported'},
        'databases': {'help': 'SQL/NoSQL clients supported'},
        'games': {'help': 'Games etc.'},
        'git': {'help': 'GIT clients supported'},
        'mails': {'help': 'Email clients supported'},
        'maven': {'help': 'Maven java build tool'},
        'memory': {'help': 'Retrieve passwords from memory'},
        'multimedia': {'help': 'Multimedia applications, etc'},
        'php': {'help': 'PHP build tool'},
        'svn': {'help': 'SVN clients supported'},
        'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
        'windows': {'help': 'Windows credentials (credential manager, etc.)'},
        'wifi': {'help': 'Wifi'},
    }
    return category


def get_modules():
    module_names = [

        # Browser
        IE(),
        UCBrowser(),

        # Chats
        Pidgin(),
        Skype(),
        PSI(),

        # Databases
        Dbvisualizer(),
        Squirrel(),
        SQLDeveloper(),
        Robomongo(),
        PostgreSQL(),

        # games
        KalypsoMedia(),
        GalconFusion(),
        RoguesTale(),
        Turba(),

        # Git
        GitForWindows(),

        # Mails
        Outlook(),
        Thunderbird(),

        # Maven
        MavenRepositories(),

        # Memory
        MemoryDump(),  # retrieve browsers and keepass passwords
        Keepass(),  # should be launched after memory dump

        # Multimedia
        EyeCON(),

        # Php
        Composer(),

        # SVN
        Tortoise(),

        # Sysadmin
        ApacheDirectoryStudio(),
        CoreFTP(),
        Cyberduck(),
        Filezilla(),
        FilezillaServer(),
        FtpNavigator(),
        KeePassConfig(),
        Puttycm(),
        OpenSSHForWindows(),
        OpenVPN(),
        IISCentralCertP(),
        IISAppPool(),
        RDPManager(),
        Unattended(),
        WinSCP(),
        Vnc(),
        Wsl(),

        # Wifi
        Wifi(),

        # Windows
        Autologon(),
        Pypykatz(),
        Cachedump(),
        Credman(),
        Hashdump(),
        LSASecrets(),
        CredFiles(),
        Vault(),
        VaultFiles(),
        WindowsPassword(),
    ]
    return module_names + chromium_browsers + firefox_browsers
