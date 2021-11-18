import binascii
import json
import os
import shutil
from datetime import date

from pkg_resources import resource_filename

from DonPAPI.lib.toolbox import bcolors


class reporting:
	def __init__(self, conn,logger,options,targets):
		self.conn = conn
		self.logging=logger
		self.options=options
		self.targets = targets
		self.report_file = os.path.join(self.options.output_directory,'%s_result.html' % date.today().strftime("%d-%m-%Y"))

	def add_to_resultpage(self, datas):
		try:
			datas = datas.encode('ascii', 'ignore')
			f = open(self.report_file, 'ab')
			f.write(datas)
			f.close()
			return True
		except Exception as ex:
			self.logging.debug(f" Exception {bcolors.WARNING}  in add to resultat {bcolors.ENDC}")
			self.logging.debug(ex)
			return False

	def generate_report(self,type='', user='', target=''):
		_config_file = 'seatbelt_config.json'
		_config_location = resource_filename(__name__, 'config/' + _config_file)
		_res_location = resource_filename(__name__, 'res/')
		_current_date = date.today().strftime("%d-%m-%Y")
		with open(_config_location) as config:
			config_parser = json.load(config)
			# Gérer les chemins Win vs Linux pour le .replace('\\', '/')
			mycss = os.path.join(_res_location, config_parser['css']).replace('\\', '/')
			mychartjs = os.path.join(_res_location, config_parser['mychartjs']).replace('\\', '/')
			logo_file_path = os.path.join(_res_location, config_parser['logo_file']).replace('\\', '/')
			logo_filename = os.path.basename(logo_file_path)
		# self.logging.debug(f"[+] {logo_file_path}")

		self.logging.info("[+] Generating report")
		if self.conn == None :
			self.logging.debug(f"[+] db ERROR - {self.options.output_directory}")
			return -1

		try:
			if os.path.exists(os.path.join(self.options.output_directory,'%s_result.html' % date.today().strftime("%d-%m-%Y"))):
				if os.path.exists(os.path.join(self.options.output_directory,'%s_result_old.html' % date.today().strftime("%d-%m-%Y"))):
					os.remove(os.path.join(self.options.output_directory,'%s_result_old.html' % date.today().strftime("%d-%m-%Y")))
					os.rename(os.path.join(self.options.output_directory,'%s_result.html' % date.today().strftime("%d-%m-%Y")), os.path.join(self.options.output_directory,'%s_result_old.html' % date.today().strftime("%d-%m-%Y")))
				os.remove(os.path.join(os.path.join(self.options.output_directory,'%s_result.html' % date.today().strftime("%d-%m-%Y"))))
			self.report_file = os.path.join(self.options.output_directory,'%s_result.html' % date.today().strftime("%d-%m-%Y"))
			if not os.path.exists(os.path.join(self.options.output_directory,'res')):
				os.mkdir(os.path.join(self.options.output_directory,'res'))
		except Exception as ex:
			self.logging.debug(f" Exception {bcolors.WARNING}  in Creating Report File {bcolors.ENDC}")
			self.logging.debug(ex)
			return False
		# Copy static file is resource directory
		try:
			for my_file in [mycss, logo_file_path]:
				my_filename = os.path.basename(my_file)
				if not os.path.exists(os.path.join(self.options.output_directory, 'res', my_filename)):
					try:
						shutil.copy2(my_file, os.path.join(self.options.output_directory, 'res', my_filename))
					except Exception as e:
						print(str(e))
				else:
					self.logging.debug(
						f"{os.path.exists(my_file)} - {os.path.exists(os.path.join(os.path.join(self.options.output_directory, 'res'), my_filename))}")

		except Exception as ex:
			self.logging.debug(f" Exception {bcolors.WARNING}  in RES copy {bcolors.ENDC}")
			self.logging.debug(ex)
			return False

		data = """	<!DOCTYPE html>
		<link rel="stylesheet" type="text/css" href="%s">
			<html>
			<head>
			  <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
			  <title>MySeatBelt - Result for %s</title>	
			</head>
			<body>\n""" % ('res/style.css', "[client_name]")
		self.add_to_resultpage(data)

		# Tableau en top de page pour les liens ?
		data = """<table class="statistics"><TR><Th><a class="firstletter">M</a><a>enu</A></Th></TR>\n"""
		data = """<div class="navbar">\n"""
		for menu in ['wifi', 'taskscheduler', 'credential-blob', 'browser-internet_explorer', 'SAM', 'LSA', 'DCC2',
		             'Files', 'Connected-users', 'Local_account_reuse', 'Scope_Audited']:
			# data += f"""<TR><TD class="menu_top"><BR><a href="#{menu}"> {menu} </A><BR></TD></TR>\n"""
			data += f"""<a href="#{menu}"> {menu.upper()}</A>\n"""
		data += """</DIV><BR>\n"""
		self.add_to_resultpage(data)

		# Logo @ Titre
		data = """<DIV class="main">\n"""
		data += """<table class="main"><TR><TD>\n"""

		data += """<table><TR><TD class="menu_top"><a class="firstletter">P</a><a>assword Audit - %s</a></TD></TR>\n""" % '[client_name]'.upper()
		data += """<TR><TD class="menu_top"><BR> %s <BR></TD></TR></TABLE><BR>\n""" % date.today().strftime("%d/%m/%Y")

		data += """<table><TR><TD><img class="logo_left" src='%s'></TD>""" % os.path.join('res', logo_filename)
		'''if os.path.isfile(os.path.join(logdir, 'logo.png')):
			data += """<TD><img class="logo" src='%s'></TD>""" % (os.path.join(logdir, 'logo.png'))'''
		data += """<BR></div></TD></TR></TABLE><BR>\n"""
		self.add_to_resultpage(data)


		#JS Stuff
		data = """
		<script>
		function toggle_by_class(cls, on) {
	    	var lst = document.getElementsByClassName(cls);
    		for(var i = 0; i < lst.length; ++i) {
        		lst[i].style.display = on ? '' : 'none';
    		}
		}
		
		function toggle_it(thisname) {
		 tr=document.getElementsByTagName('tr')
		 for (i=0;i<tr.length;i++){
		  if (tr[i].getAttribute(thisname)){
		   if ( tr[i].style.display=='none' ){
			 tr[i].style.display = '';
		   }
		   else {
			tr[i].style.display = 'none';
		   }
		  }
		 }
		}
  		</script>
		"""
		self.add_to_resultpage(data)

		results = self.get_credz()

		data = """<table class="statistics"><TR><Th><a class="firstletter">U</a><a>sername</A></Th>
		<Th><a class="firstletter">P</a><a>assword</A></Th>
		<Th><a class="firstletter">T</a><a>arget</A></Th>
		<Th><a class="firstletter">T</a><a>ype</A></Th>
		<Th><a class="firstletter">P</a><a>illaged_from_computerid</A></Th>
		<Th><a class="firstletter">P</a><a>illaged_from_userid</A></Th></TR>\n"""

		#<a href="#" id="toggle" onClick="toggle_it('tr1');toggle_it('tr2')">
		current_type=''
		for index,cred in enumerate(results):
			cred_id, file_path, username, password, target, type, pillaged_from_computerid, pillaged_from_userid = cred
			if type != current_type:
				current_type=type
				data += f"""<TR id={current_type}><TD colspan="6" class="toggle_menu" onClick="toggle_it('{current_type}')"><A>{current_type}</A></TD></TR>"""


			#Skip infos of
			# WindowsLive:target=virtualapp/didlogical
			untreated_targets =["WindowsLive:target=virtualapp/didlogical","Adobe App Info","Adobe App Prefetched Info","Adobe User Info","Adobe User OS Info","MicrosoftOffice16_Data:ADAL","LegacyGeneric:target=msteams_adalsso/adal_contex"]
			untreated_users = ["NL$KM_history"]

			blacklist_bypass=False
			for untreated in untreated_targets:
				if untreated in target:
					blacklist_bypass=True
			for untreated in untreated_users:
				if untreated in username:
					blacklist_bypass=True
			if blacklist_bypass:
				continue

			#Get computer infos
			res=self.get_computer_infos(pillaged_from_computerid)
			for index_, res2 in enumerate(res):
				ip, hostname=res2
			computer_info=f"{ip} | {hostname}"
			#pillaged_from_userid
			if pillaged_from_userid != None:
				res=self.get_user_infos(pillaged_from_userid)
				for index_, pillaged_username in enumerate(res):
					pillaged_from_userid=pillaged_username[0]
			else:
				pillaged_from_userid=str(pillaged_from_userid)

			if index % 2 == 0:
				data += f"""<TR class=tableau_resultat_row0 {current_type}=1>"""
			else:
				data += f"""<TR class=tableau_resultat_row1 {current_type}=1>"""

			if 'admin' in username.lower() : #Pour mettre des results en valeur
				special_style = '''class="cracked"'''
			else:
				special_style = ""



			###Print block
			#Recup des username dans le target #/# a update dans myseatbelt.py pour faire une fonction dump_CREDENTIAL_XXXXX clean
			if "LegacyGeneric:target=MicrosoftOffice1" in target:
				username = f'''{target.split(':')[-1]}'''
			#Les pass LSA sont souvent en Hexa
			#if "LSA" in type:
			try:
				hex_passw=''
				hex_passw=binascii.unhexlify(password).replace(b'>',b'')
			except Exception as ex:
				#print(ex)
				pass


			for info in [username]:
				data += f"""<TD {special_style} ><A title="{info}"> {str(info)[:48]} </A></TD>"""
			for info in [password]:
				data += f"""<TD {special_style} ><A title="{hex_passw}"> {str(info)[:48]} </A></TD>"""

				#check if info contains a URL
			if 'http:' in target or 'https:' in target:
				info2 = target[target.index('http'):]
				special_ref = f'''href="{info2}" target="_blank" title="{target}"'''
			elif 'ftp:' in target:
				info2 = target[target.index('ftp'):]
				special_ref = f'''href="{info2}" target="_blank" title="{target}"'''
			elif "Domain:target=" in target:
				info2=f'''rdp://full%20address=s:{target[target.index('Domain:target=')+len('Domain:target='):]}:3389&username=s:{username}&audiomode=i:2&disable%20themes=i:1'''
				special_ref = f'''href="{info2}" title="{target}"'''
			elif "LegacyGeneric:target=MicrosoftOffice1" in target:
				target=f'''{target[target.index('LegacyGeneric:target=')+len('LegacyGeneric:target='):]}'''
				special_ref = f'''href="https://login.microsoftonline.com/" target="_blank" title="OfficeLogin"'''
			else:
				special_ref = f'''title="{target}"'''
			data += f"""<TD {special_style} ><A {special_ref}> {str(target)[:48]} </A></TD>"""

			for info in [type, computer_info, pillaged_from_userid]:
					data += f"""<TD {special_style} ><A title="{info}"> {str(info)[:48]} </A></TD>"""
			data+="""</TR>\n"""

		data += """</TABLE><BR>"""
		self.add_to_resultpage(data)
		###
		##### List gathered files
		results = self.get_file()

		data = """<table class="statistics" id="Files"><TR><Th><a class="firstletter">F</a><a>ilename</A></Th>
								<Th><a class="firstletter">T</a><a>ype</A></Th>
								<Th><a class="firstletter">U</a><a>ser</A></Th>
								<Th><a class="firstletter">I</a><a>p</A></Th></TR>\n"""
		for index, myfile in enumerate(results):
			try:
				file_path, filename, extension, pillaged_from_computerid,pillaged_from_userid = myfile
				res = self.get_computer_infos(pillaged_from_computerid)
				for index, res2 in enumerate(res):
					ip, hostname = res2
				computer_info = f"{ip} | {hostname}"
				res = self.get_user_infos(pillaged_from_userid)
				for index, res2 in enumerate(res):
					username = res2[0]
				special_ref = f'''href="file://{file_path}" target="_blank" title="{filename}"'''
				data += f"""<TR><TD><A {special_ref}> {filename} </A></TD><TD> {extension} </TD><TD> {username} </TD><TD> {computer_info} </TD></TR>\n"""
			except Exception as ex:
				self.logging.debug(f" Exception {bcolors.WARNING}  in getting File for {file_path} {bcolors.ENDC}")
				self.logging.debug(ex)
				return False
		data += """</TABLE><BR>"""
		self.add_to_resultpage(data)

		##### Identify user / IP relations
		# Confirm audited scope :
		results = self.get_connected_user()

		data = """<table class="statistics" id="Connected-users"><TR><Th><a class="firstletter">U</a><a>sername</A></Th>
						<Th><a class="firstletter">I</a><a>P</A></Th></TR>\n"""

		for index, cred in enumerate(results):
			try:
				ip, username = cred
				data += """<TR><TD> %s </TD><TD> %s </TD></TR>\n""" % (username,ip)
			except Exception as ex:
				self.logging.debug(f" Exception {bcolors.WARNING}  in Identify user / IP relations for {cred} {bcolors.ENDC}")
				self.logging.debug(ex)
				return False
		data += """</TABLE><BR>"""
		self.add_to_resultpage(data)


		##### Identify Local hash reuse
		results = self.get_credz_sam()
		data = """<table class="statistics" id="Local_account_reuse"><TR><Th><a class="firstletter">L</a><a>ocal account reuse : </Th></TR>\n"""
		for index, cred in enumerate(results):
			username, password, type, pillaged_from_computerid = cred
			res = self.get_computer_infos(pillaged_from_computerid)
			for index, res2 in enumerate(res):
				ip, hostname = res2
			computer_info = f"{ip} | {hostname}"
			data += """<TR><TD> %s </TD><TD> %s </TD><TD> %s </TD><TD> %s </TD></TR>\n""" % (username, password, type, computer_info)
		data += """</TABLE><BR>"""
		self.add_to_resultpage(data)


		# Confirm audited scope :
		results = self.get_computers()
		data = """<table class="statistics" id="Scope_Audited"><TR><Th><a class="firstletter">S</a><a>cope Audited : </Th></TR>\n"""
		data += """<TR><Th><a class="firstletter">I</a><a>p</A></Th>
				<Th><a class="firstletter">H</a><a>ostname</A></Th>
				<Th><a class="firstletter">D</a><a>omain</A></Th>
				<Th><a class="firstletter">O</a><a>S</A></Th>
				<Th><a class="firstletter">S</a><a>mb signing enabled</A></Th>
				<Th><a class="firstletter">S</a><a>mb v1</A></Th>
				<Th><a class="firstletter">I</a><a>s Admin</A></Th>
				<Th><a class="firstletter">C</a><a>onnectivity</A></Th>
				</TR>\n"""

		for index, cred in enumerate(results):
			ip, hostname, domain, my_os, smb_signing_enabled,smbv1_enabled,is_admin,connectivity = cred
			data+="<TR>"
			for info in [ip, hostname, domain, my_os]:
				data += f"""<TD> {info} </TD>"""
			if smb_signing_enabled:
				data+="<TD> Ok </TD>"
			else:
				data += """<TD><a class="firstletter"> NOT required </A></TD>"""
			if smbv1_enabled:
				data+="<TD> Yes </TD>"
			else:
				data += "<TD> No </TD>"
			if is_admin:
				data+="""<TD> Admin </A></TD>"""
			else:
				data += """<TD><a class="firstletter"> No </A></TD>"""
			for info in [connectivity]:
				data += f"""<TD> {info} </TD>"""
			data+="</TR>\n"
		data += """</TABLE><BR>\n"""
		self.add_to_resultpage(data)

		#Etat des masterkeyz
		if self.options.debug :
			results=self.get_masterkeys()
			data = """<table class="statistics" id="Scope_Audited"><TR><Th><a class="firstletter">M</a><a>asterkeys : </Th></TR>\n"""
			data += """<TR><Th><a class="firstletter">G</a><a>uid</A></Th>
							<Th><a class="firstletter">S</a><a>tatus</A></Th>
							<Th><a class="firstletter">D</a><a>ecrypted_with</A></Th>
							<Th><a class="firstletter">D</a><a>ecrypted_value</A></Th>
							<Th><a class="firstletter">C</a><a>omputer</A></Th>
							<Th><a class="firstletter">U</a><a>ser</A></Th>
							</TR>\n"""

			for index, cred in enumerate(results):
				id, file_path, guid, status, pillaged_from_computerid, pillaged_from_userid, decrypted_with, decrypted_value = cred
				data+="<TR>"
				for info in [guid, status, decrypted_with]:
					data += f"""<TD> {info} </TD>"""
				for info in [decrypted_value]:
					data += f"""<TD><A title="{info}"> {str(info)[:12]}</A></TD>"""

				res = self.get_computer_infos(pillaged_from_computerid)
				for index, res2 in enumerate(res):
					ip, hostname = res2
				computer_info = f"{ip} | {hostname}"
				data += f"""<TD> {computer_info} </TD>"""
				res = self.get_user_infos(pillaged_from_userid)
				for index, res2 in enumerate(res):
					username = res2[0]
				data += f"""<TD> {username} </TD>"""
			data += "</TR>\n"
			data += """</TABLE><BR>\n"""
			self.add_to_resultpage(data)
		# finalise result page
		data = "</body></html>"
		self.add_to_resultpage(data)


	def get_dpapi_hashes(self):
		user_hashes=[]
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT sid,hash FROM dpapi_hash")
		results = cur.fetchall()
		for line in results:
			sid=line[0]
			hash=line[1]
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(f"SELECT user_id FROM user_sid WHERE LOWER(sid)=LOWER('{sid}')")
			res1 = cur.fetchall()
			if len(res1) > 0:
				result = res1[0]
				user_id = result[0]
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT username FROM users WHERE id={user_id}")
				res2 = cur.fetchall()
				if len(res2) > 0:
					result = res2[0]
					username = result[0]
					user_hashes.append((username,hash))
		return user_hashes

	def export_MKF_hashes(self):
		user_hashes=self.get_dpapi_hashes()
		self.logging.debug(f"Exporting {len(user_hashes)} MKF Dpapi hash to {self.options.output_directory}")

		for algo_type in [1,2]:
			for context in [1,2,3]:
				filename = os.path.join(self.options.output_directory, 'MKFv%i_type_%i' % (algo_type,context))
				if os.path.exists(filename):
					os.remove(filename)
		for entry in user_hashes:
			try:
				username=entry[0]
				hash=entry[1]
				#on retire les hash "MACHINE$"
				if username != "MACHINE$":
					#Pour le moment on copie juste les hash. voir pour faire evoluer CrackHash et prendrre username:hash
					algo_type=int(hash.split('*')[0][-1])
					context=int(hash.split('*')[1])
					filename = os.path.join(self.options.output_directory, 'MKFv%i_type_%i' % (algo_type, context))
					filename2 = os.path.join(self.options.output_directory, 'MKFv%i_type_%i_WITH_USERNAME' % (algo_type, context))
					f=open(filename,'ab')
					f.write(f"{hash}\n".encode('utf-8'))
					f.close()
					f = open(filename2, 'ab')
					f.write(f"{username}:{hash}\n".encode('utf-8'))
					f.close()
			except Exception as ex:
				self.logging.error(f"Exception in export dpapi hash to {filename}")
				self.logging.debug(ex)

	def get_dcc2_hashes(self):
		with self.conn:
				cur = self.conn.cursor()
				cur.execute("SELECT DISTINCT username,password FROM credz WHERE LOWER(type)=LOWER('DCC2') ORDER BY username ASC ")
		results = cur.fetchall()
		return results
	def export_dcc2_hashes(self):
		user_hashes=self.get_dcc2_hashes()
		filename = os.path.join(self.options.output_directory, 'hash_DCC2')
		self.logging.debug(f"Exporting {len(user_hashes)} DCC2 hash to {self.options.output_directory}")
		if os.path.exists(filename):
			os.remove(filename)
		for entry in user_hashes:
			try:
				username=entry[0]
				hash=entry[1]
				f=open(filename,'ab')
				f.write(f"{username}:{hash}\n".encode('utf-8'))
				f.close()
			except Exception as ex:
				self.logging.error(f"Exception in export DCC2 hash to {filename}")
				self.logging.debug(ex)
		self.logging.debug(f"Export Done!")

	def get_credz(self, filterTerm=None, credz_type=None):
		"""
		Return credentials from the database.
		"""
		if credz_type:
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(f"SELECT * FROM credz WHERE LOWER(type)=LOWER('{credz_type}')")

		# if we're filtering by username
		elif filterTerm and filterTerm != '':
			with self.conn:
				cur = self.conn.cursor()
				cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

		# otherwise return all credentials
		else:
			with self.conn:
				cur = self.conn.cursor()
				cur.execute("SELECT * FROM credz ORDER BY type DESC, target ASC ")

		results = cur.fetchall()
		return results

	def get_credz_sam(self):

		all=[]
		with self.conn:
			cur = self.conn.cursor()
			cur.execute("SELECT count(DISTINCT pillaged_from_computerid),password FROM credz WHERE LOWER(type)=LOWER('SAM') AND LOWER(password) != LOWER('31d6cfe0d16ae931b73c59d7e0c089c0') GROUP BY password ORDER BY username ASC")
		results = cur.fetchall()


		for index, res in enumerate(results):
			nb,passw=res
			if nb>1:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute("SELECT DISTINCT username, password, type, pillaged_from_computerid FROM credz WHERE LOWER(type)=LOWER('SAM') AND LOWER(password)=LOWER('%s') ORDER BY password ASC, username ASC "%(passw))
				all+=cur.fetchall()
		return all

	def get_computers(self):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute("SELECT ip,hostname,domain,os,smb_signing_enabled,smbv1_enabled,is_admin,connectivity from computers ORDER BY ip")
		results = cur.fetchall()
		return results

	def get_masterkeys(self):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute("SELECT id,file_path,guid,status,pillaged_from_computerid,pillaged_from_userid,decrypted_with,decrypted_value from masterkey ORDER BY pillaged_from_computerid ASC, pillaged_from_userid ASC")
		results = cur.fetchall()
		return results

	def get_computer_infos(self,computer_id):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT ip,hostname FROM computers WHERE id={computer_id} LIMIT 1")
			results = cur.fetchall()
		return results

	def get_user_infos(self,user_id):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT username FROM users WHERE id={user_id} LIMIT 1")
			results = cur.fetchall()
		return results

	def get_user_id(self,username):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT id FROM users WHERE username={username} LIMIT 1")
			results = cur.fetchall()
		return results

	def get_connected_user(self):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT ip,username FROM connected_user ORDER BY username ASC, ip ASC")
			results = cur.fetchall()
		return results

	def get_os_from_ip(self,ip):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT os FROM computers WHERE ip={ip} LIMIT 1")
			results = cur.fetchall()
		return results

	def get_file(self):
		with self.conn:
			cur = self.conn.cursor()
			cur.execute(f"SELECT file_path,filename,extension,pillaged_from_computerid,pillaged_from_userid  FROM files ORDER BY pillaged_from_computerid ASC, extension ASC ")
			results = cur.fetchall()
		return results

class database:

	def __init__(self, conn,logger):
		self.conn = conn
		self.logging=logger

	def get_credz(self, filterTerm=None, credz_type=None):
		"""
		Return credentials from the database.
		"""

		if credz_type:
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(f"SELECT * FROM credz WHERE type='{credz_type}'")

		# if we're filtering by username
		elif filterTerm and filterTerm != '':
			with self.conn:
				cur = self.conn.cursor()
				cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

		# otherwise return all credentials
		else:
			with self.conn:
				cur = self.conn.cursor()
				cur.execute("SELECT * FROM credz")

		results = cur.fetchall()
		return results

	@staticmethod
	def db_schema(db_conn):
		db_conn.execute('''CREATE TABLE "computers" (
			"id" integer PRIMARY KEY,
			"ip" text,
			"hostname" text,
			"domain" text,
			"os" text,
			"dc" boolean,
			"smb_signing_enabled" boolean,
			"smbv1_enabled" boolean,
			'default_user_id' integer,
			"is_admin" boolean,
			"connectivity" text 
			)''')
		db_conn.execute('''CREATE TABLE "compliance" (
					"id" integer PRIMARY KEY,
					"laps_enabled" boolean DEFAULT 0,
					"smb_signing_enabled" boolean DEFAULT 0,
					"smbv1_enabled" boolean DEFAULT 0,
					"llmnr_disabled" boolean DEFAULT 0,
					"pillaged_from_computerid" integer,
					FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
					)''')
		# type = hash, plaintext
		db_conn.execute('''CREATE TABLE "users" (
			"id" integer PRIMARY KEY,
			"domain" text,
			"username" text,
			"password" text,
			"credtype" text,
			"pillaged_from_computerid" integer,
			FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
			)''')

		db_conn.execute('''CREATE TABLE "groups" (
			"id" integer PRIMARY KEY,
			"domain" text,
			"name" text
			)''')

		db_conn.execute('''CREATE TABLE "credz" (
					"id" integer PRIMARY KEY,
					"file_path" text,
					"username" text,
					"password" text,
					"target" text,
					"type" text,
					"pillaged_from_computerid" integer,
					"pillaged_from_userid" integer,
					FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id),
					FOREIGN KEY(pillaged_from_userid) REFERENCES users(id)
					)''')
		db_conn.execute('''CREATE TABLE "dpapi_hash" (
							"id" integer PRIMARY KEY,
							"file_path" text,
							"sid" text,
							"guid" text,
							"hash" text,
							"context" text,
							"pillaged_from_computerid" integer,
							FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id)
							)''')
		db_conn.execute('''CREATE TABLE "user_sid" (
									"id" integer PRIMARY KEY,
									"sid" text,
									"user_id" integer,
									FOREIGN KEY(user_id) REFERENCES users(id)
									)''')
		db_conn.execute('''CREATE TABLE "connected_user" (
											"id" integer PRIMARY KEY,
											"username" text,
											"ip" text
											)''')
		db_conn.execute('''CREATE TABLE "files" (
							"id" integer PRIMARY KEY,
							"file_path" text,
							"filename" text,
							"extension" text,
							"pillaged_from_computerid" integer,
							"pillaged_from_userid" integer,
							FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id),
							FOREIGN KEY(pillaged_from_userid) REFERENCES users(id)
							)''')
		db_conn.execute('''CREATE TABLE "masterkey" (
							"id" integer PRIMARY KEY,
							"file_path" text,
							"guid" text,
							"status" integer DEFAULT 0,
							"pillaged_from_computerid" integer,
							"pillaged_from_userid" integer,
							"decrypted_with" text,
							"decrypted_value" text,
							FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id),
							FOREIGN KEY(pillaged_from_userid) REFERENCES users(id)
							)''')

		# This table keeps track of which credential has admin access over which machine and vice-versa
		"""
		db_conn.execute('''CREATE TABLE "admin_relations" (
			"id" integer PRIMARY KEY,
			"userid" integer,
			"computerid" integer,
			FOREIGN KEY(userid) REFERENCES users(id),
			FOREIGN KEY(computerid) REFERENCES computers(id)
			)''')

		db_conn.execute('''CREATE TABLE "loggedin_relations" (
			"id" integer PRIMARY KEY,
			"userid" integer,
			"computerid" integer,
			FOREIGN KEY(userid) REFERENCES users(id),
			FOREIGN KEY(computerid) REFERENCES computers(id)
			)''')

		db_conn.execute('''CREATE TABLE "group_relations" (
			"id" integer PRIMARY KEY,
			"userid" integer,
			"groupid" integer,
			FOREIGN KEY(userid) REFERENCES users(id),
			FOREIGN KEY(groupid) REFERENCES groups(id)
			)''')

		#db_conn.execute('''CREATE TABLE "ntds_dumps" (
		#    "id" integer PRIMARY KEY,
		#    "computerid", integer,
		#    "domain" text,
		#    "username" text,
		#    "hash" text,
		#    FOREIGN KEY(computerid) REFERENCES computers(id)
		#    )''')

		#db_conn.execute('''CREATE TABLE "shares" (
		#    "id" integer PRIMARY KEY,
		#    "hostid" integer,
		#    "name" text,
		#    "remark" text,
		#    "read" boolean,
		#    "write" boolean
		#    )''')

	#def add_share(self, hostid, name, remark, read, write):
	#    cur = self.conn.cursor()

	#    cur.execute("INSERT INTO shares (hostid, name, remark, read, write) VALUES (?,?,?,?,?)", [hostid, name, remark, read, write])

	#    cur.close()
	"""
	def add_computer(self, ip, hostname='', domain='', os='', default_user_id=0, dc=0, smb_signing_enabled=False, smbv1_enabled=False,is_admin=False,connectivity='Ok'):
		"""
		Check if this host has already been added to the database, if not add it in.
		"""
		self.logging.debug(f"[{ip}] {bcolors.OKBLUE}Adding Computer {hostname}{bcolors.ENDC}")
		try:
			#domain = domain.split('.')[0].upper()
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(f'SELECT * FROM computers WHERE ip LIKE "{ip}"')
				results = cur.fetchall()

			if not len(results):
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"INSERT INTO computers (ip, hostname, domain, os, dc, default_user_id,smb_signing_enabled,is_admin,smbv1_enabled,connectivity) VALUES ('{ip}', '{hostname}', '{domain}', '{os}', {dc},{default_user_id},{smb_signing_enabled},{is_admin},{smbv1_enabled},'{connectivity}')")

			return cur.lastrowid
		except Exception as ex:
			self.logging.error(f"Exception in Add Computeur")
			self.logging.debug(ex)
	def update_computer(self, ip, hostname=None, domain=None, os=None, default_user_id=None, dc=None, smb_signing_enabled=None, smbv1_enabled=None,is_admin=None,connectivity=None):
		"""
		Check if this host has already been added to the database, if not add it in.
		"""
		self.logging.debug(f"Updating Computer {ip}")
		try:
			#domain = domain.split('.')[0].upper()
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(f'SELECT * FROM computers WHERE ip LIKE "{ip}"')
				results = cur.fetchall()

			if len(results):
				for host in results:
					id_=host[0]
					hostname_ = host[2]
					domain_ = host[3]
					os_ = host[4]
					dc_ = host[5]
					is_admin_ = host[8]
					connectivity_ = host[9]
					for val in [(hostname,'hostname'),(domain,'domain'),(os,'os'),(hostname,'hostname'),(default_user_id,'default_user_id'),(dc,'dc'),(smb_signing_enabled,'smb_signing_enabled'),(smbv1_enabled,'smbv1_enabled'),(is_admin,'is_admin'),(connectivity,'connectivity')]:
						value=val[0]
						var=val[1]
						if value != None:
							with self.conn:
								cur = self.conn.cursor()
								cur.execute(f"UPDATE computers SET {var}='{value}' WHERE id={id_}")
		except Exception as ex:
			self.logging.error(f"Exception in Add Computeur")
			self.logging.debug(ex)

	def add_file(self, file_path, filename,extension,pillaged_from_computerid=None,pillaged_from_computer_ip=None,pillaged_from_userid=None,pillaged_from_username=None):
		"""
		Check if this host has already been added to the database, if not add it in.
		"""
		self.logging.debug(f"Adding file {filename} - path : {file_path} - {extension} - from user  {pillaged_from_username}")
		try:
			#domain = domain.split('.')[0].upper()
			if pillaged_from_userid == None and pillaged_from_username != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT id FROM users WHERE username='{pillaged_from_username}'")
					results = cur.fetchall()
					if len(results) > 0:
						result = results[0]
						pillaged_from_userid = result[0]
						#print(f"{pillaged_from_userid} is {pillaged_from_username}")
			if pillaged_from_computer_ip != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
					results = cur.fetchall()
					if len(results)>0:
						result=results[0]
						pillaged_from_computerid=result[0]
			if pillaged_from_computerid != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f'SELECT * FROM files WHERE filename LIKE "{filename}" AND pillaged_from_computerid={pillaged_from_computerid}')
					results = cur.fetchall()

					if not len(results):
						#self.logging.debug(f"inserting file {filename} - {file_path} -{extension}")
						cur.execute(f"INSERT INTO files (file_path,filename,extension,pillaged_from_computerid,pillaged_from_userid) VALUES ('{file_path}', '{filename}', '{extension}', '{pillaged_from_computerid}', {pillaged_from_userid})")
		except Exception as ex:
			self.logging.error(f"Exception in Add Files")
			self.logging.debug(ex)

	def add_masterkey(self, file_path, guid,status,decrypted_with='',decrypted_value='',pillaged_from_computerid=None,pillaged_from_computer_ip=None,pillaged_from_userid=None,pillaged_from_username=None):
		"""
		Check if this host has already been added to the database, if not add it in.
		"""
		self.logging.debug(f"[{pillaged_from_computer_ip}] Adding Masterkey {guid} - path : {file_path} - from user  {pillaged_from_username} - {status} ")
		try:
			#domain = domain.split('.')[0].upper()
			if pillaged_from_userid == None and pillaged_from_username != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT id FROM users WHERE username='{pillaged_from_username}'")
					results = cur.fetchall()
					if len(results) > 0:
						result = results[0]
						pillaged_from_userid = result[0]
						self.logging.debug(f"[{pillaged_from_computer_ip}] {pillaged_from_userid} is {pillaged_from_username}")
			if pillaged_from_computer_ip != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
					results = cur.fetchall()
					if len(results)>0:
						result=results[0]
						pillaged_from_computerid=result[0]
						self.logging.debug(
							f"[{pillaged_from_computer_ip}] {pillaged_from_computer_ip} is {pillaged_from_computerid}")
			if pillaged_from_computerid != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f'SELECT * FROM masterkey WHERE guid LIKE "{guid}" AND pillaged_from_computerid={pillaged_from_computerid}')
					results = cur.fetchall()

					if not len(results):
						with self.conn:
							cur = self.conn.cursor()
							self.logging.debug(
								f"[{pillaged_from_computer_ip}] inserting Masterkey {guid} - {file_path} -{status} {pillaged_from_computerid}', {pillaged_from_userid},{decrypted_with},{decrypted_value}")
							cur.execute(f"INSERT INTO masterkey (file_path,guid,status,pillaged_from_computerid,pillaged_from_userid,decrypted_with,decrypted_value) VALUES ('{file_path}', '{guid}', '{status}', '{pillaged_from_computerid}', {pillaged_from_userid},'{decrypted_with}','{decrypted_value}')")
					else:
						for masterkey in results:
							if (status != masterkey[3]) or (decrypted_with != masterkey[6]) or (decrypted_value!= masterkey[7]):
								with self.conn:
									cur = self.conn.cursor()
									cur.execute(f"UPDATE masterkey SET status='{status}', decrypted_with='{decrypted_with}', decrypted_value='{decrypted_value}' WHERE id={masterkey[0]}")
		except Exception as ex:
			self.logging.error(f"Exception in Add Masterkey")
			self.logging.debug(ex)

	def update_masterkey(self, file_path, guid,status,decrypted_with=None,decrypted_value=None,pillaged_from_computerid=None,pillaged_from_computer_ip=None,pillaged_from_userid=None,pillaged_from_username=None):
		"""
		Check if this host has already been added to the database, if not add it in.
		"""
		self.logging.debug(f"Updating Masterkey {guid} {status} {decrypted_value} {decrypted_with}")
		try:
			if pillaged_from_computer_ip != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
					results = cur.fetchall()
					if len(results)>0:
						result=results[0]
						pillaged_from_computerid=result[0]
						self.logging.debug(
							f"[{pillaged_from_computer_ip}] {pillaged_from_computer_ip} is {pillaged_from_computerid}")
			if pillaged_from_computerid != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f'SELECT * FROM masterkey WHERE guid LIKE "{guid}" AND pillaged_from_computerid={pillaged_from_computerid}')
					results = cur.fetchall()

					if len(results):
						self.logging.debug("Found initial Masterkey")
						for masterkey in results:
							with self.conn:
								cur = self.conn.cursor()
								cur.execute(f"UPDATE masterkey SET status='{status}', decrypted_with='{decrypted_with}', decrypted_value='{decrypted_value}' WHERE id={masterkey[0]}")
		except Exception as ex:
			self.logging.debug(f"Exception in update Masterkey")
			self.logging.debug(ex)


	def add_connected_user(self, ip, username):
		"""
		Check if this host has already been added to the database, if not add it in.
		"""
		self.logging.debug(f"Adding connected user {username} from {ip}")
		ip=ip.replace('\\','')
		try:
			#domain = domain.split('.')[0].upper()
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(f'SELECT * FROM connected_user WHERE username LIKE "{username}" AND ip LIKE "{ip}"')
				results = cur.fetchall()

			if not len(results):
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"INSERT INTO connected_user (username, ip) VALUES ('{username}','{ip}')")
			return cur.lastrowid
		except Exception as ex:
			self.logging.error(f"Exception in Add Connected users")
			self.logging.debug(ex)

	def add_user(self, domain='', username='', password='', credtype='', pillaged_from_computerid=None,pillaged_from_computer_ip=None):
		try:
			#domain = domain.split('.')[0].upper()
			user_rowid = None
			if pillaged_from_computer_ip != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
					results = cur.fetchall()
					if len(results)>0:
						result=results[0]
						pillaged_from_computerid=result[0]
			if pillaged_from_computerid != None:
				query = f"SELECT * FROM users WHERE LOWER(domain)=LOWER('{domain}') AND LOWER(username)=LOWER('{username}') AND pillaged_from_computerid={pillaged_from_computerid}"
				self.logging.debug(query)
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(query)
					results = cur.fetchall()

				if not len(results):
					query=f"INSERT INTO users (domain, username, password, credtype, pillaged_from_computerid) VALUES ('{domain}','{username}','{password}','{credtype}',{pillaged_from_computerid})"
					self.logging.debug(query)
					with self.conn:
						cur = self.conn.cursor()
						cur.execute(query)
					user_rowid = cur.lastrowid
					self.logging.debug('add_user(domain={}, username={}) => {}'.format(domain, username, user_rowid))
				else:
					self.logging.debug('add_user(domain={}, username={}) ALREADY EXIST'.format(domain, username))
			else:
				self.logging.error(f"user {username} associated computer not found ")
		except Exception as ex:
			self.logging.error(f"Exception in add_user ")
			self.logging.debug(ex)
		return user_rowid



	def add_sid(self,username=None,user_id=None,sid=None):
		try:
			if user_id == None and username != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT id FROM users WHERE LOWER(username)=LOWER('{username}')")
				results = cur.fetchall()
				if len(results) > 0:
					result = results[0]
					user_id = result[0]
			if user_id != None and sid != None:
				#Deja en base ?
				query = f"SELECT * FROM user_sid WHERE LOWER(sid)=LOWER('{sid}') AND user_id={user_id}"
				self.logging.debug(query)
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(query)
				results = cur.fetchall()
				if not len(results):
					query = f"INSERT INTO user_sid (user_id, sid) VALUES ('{user_id}','{sid}')"
					self.logging.debug(query)
					with self.conn:
						cur = self.conn.cursor()
						cur.execute(query)
					user_rowid = cur.lastrowid
					self.logging.debug(f'added SID {sid} for user id {user_id}')
		except Exception as ex:
			self.logging.error(f"Exception in add_sid ")
			self.logging.debug(ex)
		self.logging.debug(f"Added {username} sid {sid} to database")
		return 1

	def add_dpapi_hash(self, file_path=None, sid=None, guid=None, hash=None,context=None, pillaged_from_computerid=None,pillaged_from_computer_ip=None):
		try:
			#domain = domain.split('.')[0].upper()
			user_rowid = None
			if pillaged_from_computer_ip != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
				results = cur.fetchall()
				if len(results)>0:
					result=results[0]
					pillaged_from_computerid=result[0]
			if pillaged_from_computerid != None and sid != None and guid != None and hash != None and context !=None:
				query = f"SELECT * FROM dpapi_hash WHERE LOWER(sid)=LOWER('{sid}') AND LOWER(guid)=LOWER('{guid}') AND LOWER(hash)=LOWER('{hash}') AND pillaged_from_computerid={pillaged_from_computerid} AND LOWER(context)=LOWER('{context}')"
				self.logging.debug(query)
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(query)
				results = cur.fetchall()

				if not len(results):
					query=f"INSERT INTO dpapi_hash (file_path, sid, guid, hash, context, pillaged_from_computerid) VALUES ('{file_path}','{sid}','{guid}','{hash}','{context}',{pillaged_from_computerid})"
					self.logging.debug(query)
					with self.conn:
						cur = self.conn.cursor()
						cur.execute(query)
					user_rowid = cur.lastrowid
					self.logging.debug(f'added DPAPI hash {hash}')
				else:
					self.logging.debug(f'DPAPI hash {hash} ALREADY EXIST')
			else:
				self.logging.error(f"missing infos to register DPAPI hash {hash} - {file_path},{sid},{guid},{hash},{context},{pillaged_from_computerid}")
		except Exception as ex:
			self.logging.error(f"Exception in add_hash ")
			self.logging.debug(ex)
		return user_rowid

	def clear_input(self,data):
		if data is None:
			data = ''
		result = data.replace('\x00','')
		return result

	def add_credz(self, credz_type, credz_username, credz_password, credz_target, credz_path , pillaged_from_computerid=None,pillaged_from_userid=None,pillaged_from_computer_ip=None,pillaged_from_username=None):
		"""
		Check if this credential has already been added to the database, if not add it in.
		"""
		user_rowid=None
		try:
			credz_username=self.clear_input(credz_username)
			credz_password = self.clear_input(credz_password)
			credz_target = self.clear_input(credz_target)
			credz_path = self.clear_input(credz_path)
			self.logging.debug(f"{credz_username} - {binascii.hexlify(credz_username.encode('utf-8'))}")
			self.logging.debug(f"{credz_password} - {binascii.hexlify(credz_password.encode('utf-8'))}")
			self.logging.debug(f"{credz_target} - {binascii.hexlify(credz_target.encode('utf-8'))}")
			self.logging.debug(f"{credz_path} - {binascii.hexlify(credz_path.encode('utf-8'))}")
			self.logging.debug(f"pillaged_from_computer_ip {pillaged_from_computer_ip} - {binascii.hexlify(pillaged_from_computer_ip.encode('utf-8'))}")
			self.logging.debug(f"pillaged_from_username {pillaged_from_username}")


			if pillaged_from_computer_ip != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
				results = cur.fetchall()
				if len(results)>0:
					result=results[0]
					pillaged_from_computerid=result[0]
					self.logging.debug(f"[+] Resolved {pillaged_from_computer_ip} to id : {pillaged_from_computerid}")
		except Exception as ex:
			self.logging.error(f"Exception in add_credz 1")
			self.logging.debug(ex)

		try:
			if pillaged_from_username != None:
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(f"SELECT * FROM users WHERE LOWER(username)=LOWER('{pillaged_from_username}') AND pillaged_from_computerid={pillaged_from_computerid}")
				results = cur.fetchall()
				if len(results) > 0:
					result = results[0]
					pillaged_from_userid = result[0]
					self.logging.debug(f"[+] Resolved {pillaged_from_username} on machine {pillaged_from_computerid} to id : {pillaged_from_userid}")
		except Exception as ex:
			self.logging.error(f"Exception in add_credz 2")
			self.logging.debug(ex)
			pass
		if pillaged_from_computerid == None or pillaged_from_userid == None :
			self.logging.debug(f"[-] Missing computerId or UserId to register Credz {credz_username} {credz_password} - {credz_target}")
			#return None
		try:
			if pillaged_from_userid == None :
				query = "SELECT * FROM credz WHERE LOWER(username)=LOWER(:credz_username) AND LOWER(password)=LOWER(:credz_password) AND LOWER(type)=LOWER(:credz_type) AND LOWER(target)=LOWER(:credz_target) AND pillaged_from_computerid=:pillaged_from_computerid"
				parameters = {
					"credz_username": credz_username,
					"credz_password": credz_password,
					"credz_type": credz_type, "credz_target": credz_target,
					"pillaged_from_computerid": int(pillaged_from_computerid),
				}
			else:
				query = "SELECT * FROM credz WHERE LOWER(username)=LOWER(:credz_username) AND LOWER(password)=LOWER(:credz_password) AND LOWER(type)=LOWER(:credz_type) AND LOWER(target)=LOWER(:credz_target) AND pillaged_from_computerid=:pillaged_from_computerid AND pillaged_from_userid=:pillaged_from_userid"
				parameters = {
					"credz_username": credz_username,
					"credz_password": credz_password,
					"credz_type": credz_type, "credz_target": credz_target,
					"pillaged_from_computerid": int(pillaged_from_computerid),
					"pillaged_from_userid": int(pillaged_from_userid)
				}
			self.logging.debug(query)
			with self.conn:
				cur = self.conn.cursor()
				cur.execute(query, parameters)
			results = cur.fetchall()
		except Exception as ex:
			self.logging.error(f"Exception in add_credz 3")
			self.logging.debug(ex)
		try:
			if not len(results):
				if pillaged_from_userid == None:
					query = "INSERT INTO credz (username, password, target, type, pillaged_from_computerid, file_path) VALUES (:credz_username, :credz_password, :credz_target, :credz_type, :pillaged_from_computerid, :credz_path)"
					parameters = {
						"credz_username": credz_username,
						"credz_password": credz_password,
						"credz_target": credz_target,
						"credz_type": credz_type,
						"pillaged_from_computerid": int(pillaged_from_computerid),
						"credz_path": credz_path,
					}
				else:
					query = "INSERT INTO credz (username, password, target, type, pillaged_from_computerid,pillaged_from_userid, file_path) VALUES (:credz_username, :credz_password, :credz_target, :credz_type, :pillaged_from_computerid, :pillaged_from_userid, :credz_path)"
					parameters = {
						"credz_username": credz_username,
						"credz_password": credz_password,
						"credz_type": credz_type,
						"credz_target": credz_target,
						"pillaged_from_computerid": int(pillaged_from_computerid),
						"pillaged_from_userid": int(pillaged_from_userid),
						"credz_path": credz_path,
					}
				self.logging.debug(query)
				with self.conn:
					cur = self.conn.cursor()
					cur.execute(query, parameters)
				user_rowid = cur.lastrowid
				self.logging.debug(
					f'added_credential(credtype={credz_type}, target={credz_target}, username={credz_username}, password={credz_password}) => {user_rowid}')
			else:
				self.logging.debug(
					f'added_credential(credtype={credz_type}, target={credz_target}, username={credz_username}, password={credz_password}) => ALREADY IN DB')

		except Exception as ex:
			self.logging.error(f"Exception in add_credz 4")
			self.logging.debug(ex)

		return None

	def get_credz_old(self, filterTerm=None, credz_type=None):
		"""
		Return credentials from the database.
		"""

		cur = self.conn.cursor()

		if credz_type:
			cur.execute(f"SELECT * FROM credz WHERE credtype='{credz_type}'")

		# if we're filtering by username
		elif filterTerm and filterTerm != '':
			cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

		# otherwise return all credentials
		else:
			cur.execute("SELECT * FROM credz")

		results = cur.fetchall()
		cur.close()
		return results

	def add_group(self, domain, name):

		domain = domain.split('.')[0].upper()
		cur = self.conn.cursor()

		cur.execute("SELECT * FROM groups WHERE LOWER(domain)=LOWER(?) AND LOWER(name)=LOWER(?)", [domain, name])
		results = cur.fetchall()

		if not len(results):
			cur.execute("INSERT INTO groups (domain, name) VALUES (?,?)", [domain, name])

		cur.close()

		self.logging.debug('add_group(domain={}, name={}) => {}'.format(domain, name, cur.lastrowid))

		return cur.lastrowid

	def add_admin_user(self, credtype, domain, username, password, host, userid=None):

		domain = domain.split('.')[0].upper()
		cur = self.conn.cursor()

		if userid:
			cur.execute("SELECT * FROM users WHERE id=?", [userid])
			users = cur.fetchall()
		else:
			cur.execute("SELECT * FROM users WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?", [credtype, domain, username, password])
			users = cur.fetchall()

		cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [host])
		hosts = cur.fetchall()

		if len(users) and len(hosts):
			for user, host in zip(users, hosts):
				userid = user[0]
				hostid = host[0]

				#Check to see if we already added this link
				cur.execute("SELECT * FROM admin_relations WHERE userid=? AND computerid=?", [userid, hostid])
				links = cur.fetchall()

				if not len(links):
					cur.execute("INSERT INTO admin_relations (userid, computerid) VALUES (?,?)", [userid, hostid])

		cur.close()

	def get_admin_relations(self, userID=None, hostID=None):

		cur = self.conn.cursor()

		if userID:
			cur.execute("SELECT * FROM admin_relations WHERE userid=?", [userID])

		elif hostID:
			cur.execute("SELECT * FROM admin_relations WHERE computerid=?", [hostID])

		results = cur.fetchall()
		cur.close()

		return results

	def get_group_relations(self, userID=None, groupID=None):

		cur = self.conn.cursor()

		if userID and groupID:
			cur.execute("SELECT * FROM group_relations WHERE userid=? and groupid=?", [userID, groupID])

		elif userID:
			cur.execute("SELECT * FROM group_relations WHERE userid=?", [userID])

		elif groupID:
			cur.execute("SELECT * FROM group_relations WHERE groupid=?", [groupID])

		results = cur.fetchall()
		cur.close()

		return results

	def remove_admin_relation(self, userIDs=None, hostIDs=None):

		cur = self.conn.cursor()

		if userIDs:
			for userID in userIDs:
				cur.execute("DELETE FROM admin_relations WHERE userid=?", [userID])

		elif hostIDs:
			for hostID in hostIDs:
				cur.execute("DELETE FROM admin_relations WHERE hostid=?", [hostID])

		cur.close()

	def remove_group_relations(self, userID=None, groupID=None):

		cur = self.conn.cursor()

		if userID:
			cur.execute("DELETE FROM group_relations WHERE userid=?", [userID])

		elif groupID:
			cur.execute("DELETE FROM group_relations WHERE groupid=?", [groupID])

		results = cur.fetchall()
		cur.close()

		return results

	def is_credential_valid(self, credentialID):
		"""
		Check if this credential ID is valid.
		"""
		cur = self.conn.cursor()
		cur.execute('SELECT * FROM users WHERE id=? AND password IS NOT NULL LIMIT 1', [credentialID])
		results = cur.fetchall()
		cur.close()
		return len(results) > 0

	def is_credential_local(self, credentialID):
		cur = self.conn.cursor()
		cur.execute('SELECT domain FROM users WHERE id=?', [credentialID])
		user_domain = cur.fetchall()

		if user_domain:
			cur.execute('SELECT * FROM computers WHERE LOWER(hostname)=LOWER(?)', [user_domain])
			results = cur.fetchall()
			cur.close()
			return len(results) > 0

	def get_credentials(self, filterTerm=None, credtype=None):
		"""
		Return credentials from the database.
		"""

		cur = self.conn.cursor()

		# if we're returning a single credential by ID
		if self.is_credential_valid(filterTerm):
			cur.execute("SELECT * FROM users WHERE id=?", [filterTerm])

		elif credtype:
			cur.execute("SELECT * FROM users WHERE credtype=?", [credtype])

		# if we're filtering by username
		elif filterTerm and filterTerm != '':
			cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

		# otherwise return all credentials
		else:
			cur.execute("SELECT * FROM users")

		results = cur.fetchall()
		cur.close()
		return results

	def is_user_valid(self, userID):
		"""
		Check if this User ID is valid.
		"""
		cur = self.conn.cursor()
		cur.execute('SELECT * FROM users WHERE id=? LIMIT 1', [userID])
		results = cur.fetchall()
		cur.close()
		return len(results) > 0

	def get_users(self, filterTerm=None):

		cur = self.conn.cursor()

		if self.is_user_valid(filterTerm):
			cur.execute("SELECT * FROM users WHERE id=? LIMIT 1", [filterTerm])

		# if we're filtering by username
		elif filterTerm and filterTerm != '':
			cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

		else:
			cur.execute("SELECT * FROM users")

		results = cur.fetchall()
		cur.close()
		return results

	def is_computer_valid(self, hostID):
		"""
		Check if this host ID is valid.
		"""
		cur = self.conn.cursor()
		cur.execute('SELECT * FROM computers WHERE id=? LIMIT 1', [hostID])
		results = cur.fetchall()
		cur.close()
		return len(results) > 0

	def get_computers(self, filterTerm=None, domain=None):
		"""
		Return hosts from the database.
		"""

		cur = self.conn.cursor()

		# if we're returning a single host by ID
		if self.is_computer_valid(filterTerm):
			cur.execute("SELECT * FROM computers WHERE id=? LIMIT 1", [filterTerm])

		# if we're filtering by domain controllers
		elif filterTerm == 'dc':
			if domain:
				cur.execute("SELECT * FROM computers WHERE dc=1 AND LOWER(domain)=LOWER(?)", [domain])
			else:
				cur.execute("SELECT * FROM computers WHERE dc=1")

		# if we're filtering by ip/hostname
		elif filterTerm and filterTerm != "":
			cur.execute("SELECT * FROM computers WHERE ip LIKE ? OR LOWER(hostname) LIKE LOWER(?)", ['%{}%'.format(filterTerm), '%{}%'.format(filterTerm)])

		# otherwise return all computers
		else:
			cur.execute("SELECT * FROM computers")

		results = cur.fetchall()
		cur.close()
		return results

	def get_domain_controllers(self, domain=None):
		return self.get_computers(filterTerm='dc', domain=domain)

	def is_group_valid(self, groupID):
		"""
		Check if this group ID is valid.
		"""
		cur = self.conn.cursor()
		cur.execute('SELECT * FROM groups WHERE id=? LIMIT 1', [groupID])
		results = cur.fetchall()
		cur.close()

		self.logging.debug('is_group_valid(groupID={}) => {}'.format(groupID, True if len(results) else False))
		return len(results) > 0

	def get_groups(self, filterTerm=None, groupName=None, groupDomain=None):
		"""
		Return groups from the database
		"""
		if groupDomain:
			groupDomain = groupDomain.split('.')[0].upper()

		cur = self.conn.cursor()

		if self.is_group_valid(filterTerm):
			cur.execute("SELECT * FROM groups WHERE id=? LIMIT 1", [filterTerm])

		elif groupName and groupDomain:
			cur.execute("SELECT * FROM groups WHERE LOWER(name)=LOWER(?) AND LOWER(domain)=LOWER(?)", [groupName, groupDomain])

		elif filterTerm and filterTerm !="":
			cur.execute("SELECT * FROM groups WHERE LOWER(name) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

		else:
			cur.execute("SELECT * FROM groups")

		results = cur.fetchall()
		cur.close()
		self.logging.debug('get_groups(filterTerm={}, groupName={}, groupDomain={}) => {}'.format(filterTerm, groupName, groupDomain, results))
		return results

