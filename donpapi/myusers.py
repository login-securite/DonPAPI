
#!/usr/bin/env python
# coding:utf-8
'''
PA Vandewoestyne
'''
from __future__ import division
from __future__ import print_function
import errno, binascii, shutil
import sys, json, operator
from datetime import datetime
from binascii import hexlify, unhexlify
import logging
import sys
from donpapi.lib.toolbox import bcolors

class MyUser:
	def __init__(self, username,logger,options):
		self.username = username
		self.options=options
		self.logging = logger
		self.sid = ''#un user peut avoir plusieurs SID ?
		self.type = 'LOCAL'#LOCAL,DOMAIN,MACHINE,MACHINE-USER
		self.type_validated = False
		self.appdata = ''
		self.password = ''
		self.domain = ''
		self.lmhash = ''
		self.nthash = ''
		self.aesKey = ''
		self.TGT = ''
		#self.masterkeys = {}  # GUID_File: masterkey
		self.masterkeys_file = {}
		self.files = {}
		self.secrets = {}
		self.dpapi_machinekey: []
		self.dpapi_userkey: []
		self.share = None
		self.pwd = None
		self.is_adconnect = False

	def resume_user_info(self):
		try:
			encrypted=0
			decrypted=0
			decryption_failed=0

			for masterkey in self.masterkeys_file:
				if self.masterkeys_file[masterkey]['status']=='decrypted':
					decrypted+=1
				elif self.masterkeys_file[masterkey]['status']=='encrypted':
					encrypted+=1
				elif self.masterkeys_file[masterkey]['status'] == 'decryption_failed':
					decryption_failed+=1
			file_stats={}
			for file in self.files:
				if self.files[file]['type'] not in file_stats:
					file_stats[self.files[file]['type']]={}
				if self.files[file]['status'] not in file_stats[self.files[file]['type']]:
					file_stats[self.files[file]['type']][self.files[file]['status']]=[file]
				else:
					file_stats[self.files[file]['type']][self.files[file]['status']].append(file)



			self.logging.info(f"[{self.options.target_ip}] {bcolors.OKGREEN}{self.username}{bcolors.ENDC} - ({self.sid}) - [{self.type} account]")
			self.logging.info(f"[{self.options.target_ip}] [{len(self.masterkeys_file)} Masterkeys ({bcolors.OKGREEN}{decrypted} decrypted{bcolors.ENDC}/{bcolors.WARNING}{decryption_failed} failed{bcolors.ENDC}/{bcolors.OKBLUE}{encrypted} not used{bcolors.ENDC})]")
			self.logging.info(f"[{self.options.target_ip}] [{len(self.files)} secrets files : ]")
			for secret_type in file_stats:
				for status in file_stats[secret_type]:
					self.logging.info(f"[{self.options.target_ip}] - {bcolors.OKGREEN}{len(file_stats[secret_type][status])}{bcolors.ENDC} {status} {secret_type}")
					if status == 'decrypted':
						for secret_file in file_stats[secret_type][status]:
							try:
								if secret_type == 'vault' :
									for vcrd_file in self.files[secret_file]['vcrd']:
										if self.files[secret_file]['vcrd'][vcrd_file]['status']=='decrypted':
											self.logging.info(f"[{self.options.target_ip}] Vault {secret_file} - {vcrd_file} : {self.files[secret_file]['vcrd'][vcrd_file]['secret']}")
											#self.logging.info(f"[{self.options.target_ip}] Vault {secret_file} : {self.secrets[vcrd_file]}")
								elif secret_type in ["ChromeLoginData","MozillaLoginData"]:
									for uri in self.files[secret_file]['secret']:
										self.logging.info(f"[{self.options.target_ip}] Chrome {uri} - {self.files[secret_file]['secret'][uri]['username']} : {self.files[secret_file]['secret'][uri]['password']}")
								elif secret_type == "ChromeCookies" :
									for uri in self.files[secret_file]['secret']:
										for cookie_name in self.files[secret_file]['secret'][uri]:
											self.logging.debug(f"[{self.options.target_ip}] Chrome {uri} - {cookie_name} : {self.files[secret_file]['secret'][uri][cookie_name]}")
								elif secret_type == "wifi":
									if secret_file in self.files:
										self.logging.info(f"[{self.options.target_ip}] Wifi : {self.files[secret_file]['wifi_name']} : {self.files[secret_file]['secret']}")

								else:
									if secret_file in self.files: #For Credential & Wifi
										self.logging.info(f"[{self.options.target_ip}] {secret_file} : {self.files[secret_file]['secret']}")
							except Exception as ex:
								self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception 00 in ResumeUserInfo for user {self.username} secret file {secret_file} type {secret_type} {bcolors.ENDC}")
								self.logging.debug(ex)
					else:
						for secret_file in file_stats[secret_type][status]:
							self.logging.debug(f"[{self.options.target_ip}] {secret_file} : {self.files[secret_file]['path']}")

			self.logging.debug(f"[{self.options.target_ip}] -=-=-=-= Masterkeys details =-=-=-=-")
			for masterkey in self.masterkeys_file:
				self.logging.debug(f"		[*]GUID : {masterkey}")
				self.logging.debug(f"		[*]Status : {self.masterkeys_file[masterkey]['status']}")
				self.logging.debug(f"		[*]path : {self.masterkeys_file[masterkey]['path']}")
				if self.masterkeys_file[masterkey]['status']=='decrypted':
					self.logging.debug(f"		[*]key : {self.masterkeys_file[masterkey]['key']}")
				self.logging.debug(f"		[*] -=-   -=-   -=-   -=-   -=-   -=- [*]")
			self.resume_secrets()
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ResumeUserInfo for user {self.username} {bcolors.ENDC}")
			self.logging.debug(ex)

	def resume_secrets(self):
		self.logging.info(f"[{self.options.target_ip}] [*]User : {self.username} - {len(self.secrets)} secrets :")
		for secret in self.secrets:
			self.logging.info(f"[{self.options.target_ip}]	[*]secret : {secret}")
			self.logging.info(f"[{self.options.target_ip}]	{self.secrets[secret]}")

	def get_secrets(self):
		return self.secrets

	def check_usertype(self):
		#Todo
		if self.sid =='':
			return 'DOMAIN'
		else :
			return 'LOCAL'