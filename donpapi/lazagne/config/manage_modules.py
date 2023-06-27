# Browsers
from donpapi.lazagne.softwares.browsers.chromium_based import chromium_browsers
from donpapi.lazagne.softwares.browsers.ie import IE
from donpapi.lazagne.softwares.browsers.mozilla import firefox_browsers
from donpapi.lazagne.softwares.browsers.ucbrowser import UCBrowser
# Chats
from donpapi.lazagne.softwares.chats.pidgin import Pidgin
from donpapi.lazagne.softwares.chats.psi import PSI
from donpapi.lazagne.softwares.chats.skype import Skype
# Databases
from donpapi.lazagne.softwares.databases.dbvis import Dbvisualizer
from donpapi.lazagne.softwares.databases.postgresql import PostgreSQL
from donpapi.lazagne.softwares.databases.robomongo import Robomongo
from donpapi.lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from donpapi.lazagne.softwares.databases.squirrel import Squirrel
# Games
from donpapi.lazagne.softwares.games.galconfusion import GalconFusion
from donpapi.lazagne.softwares.games.kalypsomedia import KalypsoMedia
from donpapi.lazagne.softwares.games.roguestale import RoguesTale
from donpapi.lazagne.softwares.games.turba import Turba
# Git
from donpapi.lazagne.softwares.git.gitforwindows import GitForWindows
# Mails
from donpapi.lazagne.softwares.mails.outlook import Outlook
from donpapi.lazagne.softwares.mails.thunderbird import Thunderbird
# Maven
from donpapi.lazagne.softwares.maven.mavenrepositories import MavenRepositories
# Memory
from donpapi.lazagne.softwares.memory.keepass import Keepass
from donpapi.lazagne.softwares.memory.memorydump import MemoryDump
# Multimedia
from donpapi.lazagne.softwares.multimedia.eyecon import EyeCON
# Php
from donpapi.lazagne.softwares.php.composer import Composer
# Svn
from donpapi.lazagne.softwares.svn.tortoise import Tortoise
# Sysadmin
from donpapi.lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from donpapi.lazagne.softwares.sysadmin.coreftp import CoreFTP
from donpapi.lazagne.softwares.sysadmin.cyberduck import Cyberduck
from donpapi.lazagne.softwares.sysadmin.filezilla import Filezilla
from donpapi.lazagne.softwares.sysadmin.filezillaserver import FilezillaServer
from donpapi.lazagne.softwares.sysadmin.ftpnavigator import FtpNavigator
from donpapi.lazagne.softwares.sysadmin.opensshforwindows import OpenSSHForWindows
from donpapi.lazagne.softwares.sysadmin.openvpn import OpenVPN
from donpapi.lazagne.softwares.sysadmin.iiscentralcertp import IISCentralCertP
from donpapi.lazagne.softwares.sysadmin.keepassconfig import KeePassConfig
from donpapi.lazagne.softwares.sysadmin.iisapppool import IISAppPool
from donpapi.lazagne.softwares.sysadmin.puttycm import Puttycm
from donpapi.lazagne.softwares.sysadmin.rdpmanager import RDPManager
from donpapi.lazagne.softwares.sysadmin.unattended import Unattended
from donpapi.lazagne.softwares.sysadmin.vnc import Vnc
from donpapi.lazagne.softwares.sysadmin.winscp import WinSCP
from donpapi.lazagne.softwares.sysadmin.wsl import Wsl
# Wifi
from donpapi.lazagne.softwares.wifi.wifi import Wifi
# Windows
from donpapi.lazagne.softwares.windows.autologon import Autologon
from donpapi.lazagne.softwares.windows.cachedump import Cachedump
from donpapi.lazagne.softwares.windows.credman import Credman
from donpapi.lazagne.softwares.windows.credfiles import CredFiles
from donpapi.lazagne.softwares.windows.hashdump import Hashdump
from donpapi.lazagne.softwares.windows.ppypykatz import Pypykatz
from donpapi.lazagne.softwares.windows.lsa_secrets import LSASecrets
from donpapi.lazagne.softwares.windows.vault import Vault
from donpapi.lazagne.softwares.windows.vaultfiles import VaultFiles
from donpapi.lazagne.softwares.windows.windows import WindowsPassword


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
