#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import binascii
from donpapi.lib.toolbox import bcolors


class Database:
    """SQLite 3 Database wrapper."""
    def __init__(self, conn, logger):
        self.conn = conn
        self.logging = logger

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

        db_conn.execute('''CREATE TABLE "certificates" (
					"id" integer PRIMARY KEY,
					"pfx_file_path" text,
					"guid" text,
					"issuer" text,
					"subject" text,
					"client_auth" bool,
					"pillaged_from_computerid" integer,
					"pillaged_from_userid" integer,
					FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id),
					FOREIGN KEY(pillaged_from_userid) REFERENCES users(id)
					)''')
        db_conn.execute('''CREATE TABLE "cookies" (
					"id" integer PRIMARY KEY,
					"file_path" text,
					"name" text,
					"value" text,
					"expires_utc" int,
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
        db_conn.execute('''CREATE TABLE "browser_version" (
									"id" integer PRIMARY KEY,
									"browser_type" text,
									"version" text,
									"pillaged_from_computerid" integer,
									"pillaged_from_userid" integer,
									FOREIGN KEY(pillaged_from_computerid) REFERENCES computers(id),
									FOREIGN KEY(pillaged_from_userid) REFERENCES users(id)
									)''')

    def add_browser_version(self, browser_type, version, pillaged_from_computerid=None, pillaged_from_computer_ip=None,
                            pillaged_from_userid=None, pillaged_from_username=None):
        """
		Check if this host has already been added to the database, if not add it in.
		"""
        self.logging.debug(
            f"Adding Browser version {browser_type} : {version} - from user  {pillaged_from_username}")
        try:
            if pillaged_from_userid == None and pillaged_from_username != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT id FROM users WHERE username='{pillaged_from_username}'")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_userid = result[0]
            # print(f"{pillaged_from_userid} is {pillaged_from_username}")
            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_computerid = result[0]
            if pillaged_from_computerid != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f'SELECT * FROM browser_version WHERE browser_type LIKE "{browser_type}" AND pillaged_from_computerid={pillaged_from_computerid} AND pillaged_from_userid={pillaged_from_userid}')
                    results = cur.fetchall()

                    if not len(results):
                        # self.logging.debug(f"inserting file {filename} - {file_path} -{extension}")
                        cur.execute(
                            f"INSERT INTO browser_version (browser_type,version,pillaged_from_computerid,pillaged_from_userid) VALUES ('{browser_type}', '{version}', '{pillaged_from_computerid}', {pillaged_from_userid})")
        except Exception as ex:
            self.logging.error(f"Exception in Add browser_version")
            self.logging.debug(ex)


    def add_computer(self, ip, hostname='', domain='', os='', default_user_id=0, dc=0, smb_signing_enabled=False,
                    smbv1_enabled=False, is_admin=False, connectivity='Ok'):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        self.logging.debug(f"[{ip}] {bcolors.OKBLUE}Adding Computer {hostname}{bcolors.ENDC}")
        try:
            # domain = domain.split('.')[0].upper()
            with self.conn:
                cur = self.conn.cursor()
                cur.execute(f'SELECT * FROM computers WHERE ip LIKE "{ip}"')
                results = cur.fetchall()

            if not len(results):
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f"INSERT INTO computers (ip, hostname, domain, os, dc, default_user_id,smb_signing_enabled,is_admin,smbv1_enabled,connectivity) VALUES ('{ip}', '{hostname}', '{domain}', '{os}', {dc},{default_user_id},{smb_signing_enabled},{is_admin},{smbv1_enabled},'{connectivity}')")

            return cur.lastrowid
        except Exception as ex:
            self.logging.error(f"Exception in Add Computeur")
            self.logging.debug(ex)


    def update_computer(self, ip, hostname=None, domain=None, os=None, default_user_id=None, dc=None,
                        smb_signing_enabled=None, smbv1_enabled=None, is_admin=None, connectivity=None):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        self.logging.debug(f"Updating Computer {ip}")
        try:
            # domain = domain.split('.')[0].upper()
            with self.conn:
                cur = self.conn.cursor()
                cur.execute(f'SELECT * FROM computers WHERE ip LIKE "{ip}"')
                results = cur.fetchall()

            if len(results):
                for host in results:
                    id_ = host[0]
                    hostname_ = host[2]
                    domain_ = host[3]
                    os_ = host[4]
                    dc_ = host[5]
                    is_admin_ = host[8]
                    connectivity_ = host[9]
                    for val in [(hostname, 'hostname'), (domain, 'domain'), (os, 'os'), (hostname, 'hostname'),
                                (default_user_id, 'default_user_id'), (dc, 'dc'),
                                (smb_signing_enabled, 'smb_signing_enabled'), (smbv1_enabled, 'smbv1_enabled'),
                                (is_admin, 'is_admin'), (connectivity, 'connectivity')]:
                        value = val[0]
                        var = val[1]
                        if value != None:
                            with self.conn:
                                cur = self.conn.cursor()
                                cur.execute(f"UPDATE computers SET {var}='{value}' WHERE id={id_}")
        except Exception as ex:
            self.logging.error(f"Exception in Add Computeur")
            self.logging.debug(ex)


    def add_file(self, file_path, filename, extension, pillaged_from_computerid=None, pillaged_from_computer_ip=None,
                pillaged_from_userid=None, pillaged_from_username=None):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        self.logging.debug(
            f"Adding file {filename} - path : {file_path} - {extension} - from user  {pillaged_from_username}")
        try:
            # domain = domain.split('.')[0].upper()
            if pillaged_from_userid == None and pillaged_from_username != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT id FROM users WHERE username='{pillaged_from_username}'")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_userid = result[0]
                # print(f"{pillaged_from_userid} is {pillaged_from_username}")
            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_computerid = result[0]
            if pillaged_from_computerid != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f'SELECT * FROM files WHERE filename LIKE "{filename}" AND pillaged_from_computerid={pillaged_from_computerid}')
                    results = cur.fetchall()

                    if not len(results):
                        # self.logging.debug(f"inserting file {filename} - {file_path} -{extension}")
                        cur.execute(
                            f"INSERT INTO files (file_path,filename,extension,pillaged_from_computerid,pillaged_from_userid) VALUES ('{file_path}', '{filename}', '{extension}', '{pillaged_from_computerid}', {pillaged_from_userid})")
        except Exception as ex:
            self.logging.error(f"Exception in Add Files")
            self.logging.debug(ex)


    def add_masterkey(self, file_path, guid, status, decrypted_with='', decrypted_value='', pillaged_from_computerid=None,
                    pillaged_from_computer_ip=None, pillaged_from_userid=None, pillaged_from_username=None):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        self.logging.debug(
            f"[{pillaged_from_computer_ip}] Adding Masterkey {guid} - path : {file_path} - from user  {pillaged_from_username} - {status} ")
        try:
            # domain = domain.split('.')[0].upper()
            if pillaged_from_userid == None and pillaged_from_username != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT id FROM users WHERE username='{pillaged_from_username}'")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_userid = result[0]
                        self.logging.debug(
                            f"[{pillaged_from_computer_ip}] {pillaged_from_userid} is {pillaged_from_username}")
            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_computerid = result[0]
                        self.logging.debug(
                            f"[{pillaged_from_computer_ip}] {pillaged_from_computer_ip} is {pillaged_from_computerid}")
            if pillaged_from_computerid != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f'SELECT * FROM masterkey WHERE guid LIKE "{guid}" AND pillaged_from_computerid={pillaged_from_computerid}')
                    results = cur.fetchall()

                    if not len(results):
                        with self.conn:
                            cur = self.conn.cursor()
                            self.logging.debug(
                                f"[{pillaged_from_computer_ip}] inserting Masterkey {guid} - {file_path} -{status} {pillaged_from_computerid}', {pillaged_from_userid},{decrypted_with},{decrypted_value}")
                            cur.execute(
                                f"INSERT INTO masterkey (file_path,guid,status,pillaged_from_computerid,pillaged_from_userid,decrypted_with,decrypted_value) VALUES ('{file_path}', '{guid}', '{status}', '{pillaged_from_computerid}', {pillaged_from_userid},'{decrypted_with}','{decrypted_value}')")
                    else:
                        for masterkey in results:
                            if (status != masterkey[3]) or (decrypted_with != masterkey[6]) or (
                                    decrypted_value != masterkey[7]):
                                with self.conn:
                                    cur = self.conn.cursor()
                                    cur.execute(
                                        f"UPDATE masterkey SET status='{status}', decrypted_with='{decrypted_with}', decrypted_value='{decrypted_value}' WHERE id={masterkey[0]}")
        except Exception as ex:
            self.logging.error(f"Exception in Add Masterkey")
            self.logging.debug(ex)


    def update_masterkey(self, file_path, guid, status, decrypted_with=None, decrypted_value=None,
                        pillaged_from_computerid=None, pillaged_from_computer_ip=None, pillaged_from_userid=None,
                        pillaged_from_username=None):
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
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_computerid = result[0]
                        self.logging.debug(
                            f"[{pillaged_from_computer_ip}] {pillaged_from_computer_ip} is {pillaged_from_computerid}")
            if pillaged_from_computerid != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f'SELECT * FROM masterkey WHERE guid LIKE "{guid}" AND pillaged_from_computerid={pillaged_from_computerid}')
                    results = cur.fetchall()

                    if len(results):
                        self.logging.debug("Found initial Masterkey")
                        for masterkey in results:
                            with self.conn:
                                cur = self.conn.cursor()
                                cur.execute(
                                    f"UPDATE masterkey SET status='{status}', decrypted_with='{decrypted_with}', decrypted_value='{decrypted_value}' WHERE id={masterkey[0]}")
        except Exception as ex:
            self.logging.debug(f"Exception in update Masterkey")
            self.logging.debug(ex)


    def add_connected_user(self, ip, username):
        """
        Check connected users to the machine
        """
        self.logging.info(f"Adding connected user {username} from {ip}")
        ip = ip.replace('\\', '')
        try:
            # domain = domain.split('.')[0].upper()
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


    def add_user(self, domain='', username='', password='', credtype='', pillaged_from_computerid=None,
                pillaged_from_computer_ip=None):
        try:
            # domain = domain.split('.')[0].upper()
            user_rowid = None
            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                    results = cur.fetchall()
                    if len(results) > 0:
                        result = results[0]
                        pillaged_from_computerid = result[0]
            if pillaged_from_computerid != None:
                query = f"SELECT * FROM users WHERE LOWER(domain)=LOWER('{domain}') AND LOWER(username)=LOWER('{username}') AND pillaged_from_computerid={pillaged_from_computerid}"
                self.logging.debug(query)
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(query)
                    results = cur.fetchall()

                if not len(results):
                    query = f"INSERT INTO users (domain, username, password, credtype, pillaged_from_computerid) VALUES ('{domain}','{username}','{password}','{credtype}',{pillaged_from_computerid})"
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


    def add_sid(self, username=None, user_id=None, sid=None):
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
                # Deja en base ?
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


    def add_dpapi_hash(self, file_path=None, sid=None, guid=None, hash=None, context=None, pillaged_from_computerid=None,
                    pillaged_from_computer_ip=None):
        try:
            # domain = domain.split('.')[0].upper()
            user_rowid = None
            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_computerid = result[0]
            if pillaged_from_computerid != None and sid != None and guid != None and hash != None and context != None:
                query = f"SELECT * FROM dpapi_hash WHERE LOWER(sid)=LOWER('{sid}') AND LOWER(guid)=LOWER('{guid}') AND LOWER(hash)=LOWER('{hash}') AND pillaged_from_computerid={pillaged_from_computerid} AND LOWER(context)=LOWER('{context}')"
                self.logging.debug(query)
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(query)
                results = cur.fetchall()

                if not len(results):
                    query = f"INSERT INTO dpapi_hash (file_path, sid, guid, hash, context, pillaged_from_computerid) VALUES ('{file_path}','{sid}','{guid}','{hash}','{context}',{pillaged_from_computerid})"
                    self.logging.debug(query)
                    with self.conn:
                        cur = self.conn.cursor()
                        cur.execute(query)
                    user_rowid = cur.lastrowid
                    self.logging.debug(f'added DPAPI hash {hash}')
                else:
                    self.logging.debug(f'DPAPI hash {hash} ALREADY EXIST')
            else:
                self.logging.error(
                    f"missing infos to register DPAPI hash {hash} - {file_path},{sid},{guid},{hash},{context},{pillaged_from_computerid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_hash ")
            self.logging.debug(ex)
        return user_rowid


    def clear_input(self, data):
        if isinstance(data, int):
            return data
        if data is None:
            data = ''
        result = data.replace('\x00', '')
        return result


    def add_certificate(self, guid, pfx_file_path, issuer, subject, client_auth, pillaged_from_computerid=None,
                        pillaged_from_userid=None, pillaged_from_computer_ip=None, pillaged_from_username=None):
        """
        Check if this cert has already been added to db, if not then add it
        """
        user_rowid = None
        try:
            guid = self.clear_input(guid)
            pfx_file_path = self.clear_input(pfx_file_path)
            issuer = self.clear_input(issuer)
            subject = self.clear_input(subject)
            self.logging.debug(f"{guid} - {binascii.hexlify(guid.encode('utf-8'))}")
            self.logging.debug(f"{issuer} - {binascii.hexlify(issuer.encode('utf-8'))}")
            self.logging.debug(f"{subject} - {binascii.hexlify(subject.encode('utf-8'))}")
            self.logging.debug(f"{client_auth}")
            self.logging.debug(f"{pfx_file_path} - {binascii.hexlify(pfx_file_path.encode('utf-8'))}")
            self.logging.debug(
                f"pillaged_from_computer_ip {pillaged_from_computer_ip} - {binascii.hexlify(pillaged_from_computer_ip.encode('utf-8'))}")
            self.logging.debug(f"pillaged_from_username {pillaged_from_username}")

            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_computerid = result[0]
                    self.logging.debug(f"[+] Resolved {pillaged_from_computer_ip} to id : {pillaged_from_computerid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_certificate 1")
            self.logging.debug(ex)

        try:
            if pillaged_from_username != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f"SELECT * FROM users WHERE LOWER(username)=LOWER('{pillaged_from_username}') AND pillaged_from_computerid={pillaged_from_computerid}")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_userid = result[0]
                    self.logging.debug(
                        f"[+] Resolved {pillaged_from_username} on machine {pillaged_from_computerid} to id : {pillaged_from_userid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_certificate 2")
            self.logging.debug(ex)
            pass
        if pillaged_from_computerid == None or pillaged_from_userid == None:
            self.logging.debug(
                f"[-] Missing computerId or UserId to register Certificate {pillaged_from_username} {pfx_file_path}")
        # return None

        try:
            if pillaged_from_userid == None:
                query = "SELECT * FROM certificates WHERE LOWER(guid)=LOWER(:guid) AND LOWER(subject)=LOWER(:subject) AND LOWER(issuer)=LOWER(:issuer) AND pillaged_from_computerid=:pillaged_from_computerid"
                parameters = {
                    "guid": guid,
                    "subject": subject,
                    "issuer": issuer,
                    "pillaged_from_computerid": int(pillaged_from_computerid),
                }
            else:
                query = "SELECT * FROM certificates WHERE LOWER(guid)=LOWER(:guid) AND LOWER(subject)=LOWER(:subject) AND LOWER(issuer)=LOWER(:issuer) AND pillaged_from_computerid=:pillaged_from_computerid AND pillaged_from_userid=:pillaged_from_userid"
                parameters = {
                    "guid": guid,
                    "subject": subject,
                    "issuer": issuer,
                    "pillaged_from_computerid": int(pillaged_from_computerid),
                    "pillaged_from_computerid": int(pillaged_from_computerid),
                    "pillaged_from_userid": int(pillaged_from_userid)
                }
            self.logging.debug(query)
            with self.conn:
                cur = self.conn.cursor()
                cur.execute(query, parameters)
            results = cur.fetchall()
        except Exception as ex:
            self.logging.error(f"Exception in add_certificate 3")
            self.logging.debug(ex)

        try:
            if not result or not len(results):
                if pillaged_from_userid == None:
                    query = "INSERT INTO certificates (pfx_file_path, guid, issuer, subject, client_auth, pillaged_from_computerid) VALUES (:pfx_file_path, :guid, :issuer, :subject, :client_auth, :pillaged_from_computerid)"
                    parameters = {
                        "pfx_file_path": pfx_file_path,
                        "guid": guid,
                        "issuer": issuer,
                        "subject": subject,
                        "client_auth": client_auth,
                        "pillaged_from_computerid": int(pillaged_from_computerid),
                    }
                else:
                    query = "INSERT INTO certificates (pfx_file_path, guid, issuer, subject, client_auth, pillaged_from_computerid, pillaged_from_userid) VALUES (:pfx_file_path, :guid, :issuer, :subject, :client_auth, :pillaged_from_computerid, :pillaged_from_userid)"
                    parameters = {
                        "pfx_file_path": pfx_file_path,
                        "guid": guid,
                        "issuer": issuer,
                        "subject": subject,
                        "client_auth": client_auth,
                        "pillaged_from_computerid": int(pillaged_from_computerid),
                        "pillaged_from_userid": int(pillaged_from_userid),
                    }
                self.logging.debug(query)
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(query, parameters)
                user_rowid = cur.lastrowid
                self.logging.debug(
                    f'added_certificate(guid={guid}, issuer={issuer}, subject={subject}, client_auth={client_auth}) => {user_rowid}')
            else:
                self.logging.debug(
                    f'added_certificate(guid={guid}, issuer={issuer}, subject={subject}, client_auth={client_auth}) => ALREADY IN DB')

        except Exception as ex:
            self.logging.error(f"Exception in add_certificates 4")
            self.logging.debug(ex)


    def add_credz(self, credz_type, credz_username, credz_password, credz_target, credz_path, pillaged_from_computerid=None,
                pillaged_from_userid=None, pillaged_from_computer_ip=None, pillaged_from_username=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        user_rowid = None
        try:
            credz_username = self.clear_input(credz_username)
            credz_password = self.clear_input(credz_password)
            credz_target = self.clear_input(credz_target)
            credz_path = self.clear_input(credz_path)
            self.logging.debug(f"{credz_username} - {binascii.hexlify(credz_username.encode('utf-8'))}")
            self.logging.debug(f"{credz_password} - {binascii.hexlify(credz_password.encode('utf-8'))}")
            self.logging.debug(f"{credz_target} - {binascii.hexlify(credz_target.encode('utf-8'))}")
            self.logging.debug(f"{credz_path} - {binascii.hexlify(credz_path.encode('utf-8'))}")
            self.logging.debug(
                f"pillaged_from_computer_ip {pillaged_from_computer_ip} - {binascii.hexlify(pillaged_from_computer_ip.encode('utf-8'))}")
            self.logging.debug(f"pillaged_from_username {pillaged_from_username}")

            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_computerid = result[0]
                    self.logging.debug(f"[+] Resolved {pillaged_from_computer_ip} to id : {pillaged_from_computerid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_credz 1")
            self.logging.debug(ex)

        try:
            if pillaged_from_username != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f"SELECT * FROM users WHERE LOWER(username)=LOWER('{pillaged_from_username}') AND pillaged_from_computerid={pillaged_from_computerid}")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_userid = result[0]
                    self.logging.debug(
                        f"[+] Resolved {pillaged_from_username} on machine {pillaged_from_computerid} to id : {pillaged_from_userid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_credz 2")
            self.logging.debug(ex)
            pass
        if pillaged_from_computerid == None or pillaged_from_userid == None:
            self.logging.debug(
                f"[-] Missing computerId or UserId to register Credz {credz_username} {credz_password} - {credz_target}")
        # return None
        try:
            if pillaged_from_userid == None:
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


    def add_cookies(self, credz_type, credz_name, credz_value, credz_expires_utc, credz_target, credz_path,
                    pillaged_from_computerid=None, pillaged_from_userid=None, pillaged_from_computer_ip=None,
                    pillaged_from_username=None):
        """
        Check if this credential has already been added to the database, if not add it in.
        """
        user_rowid = None
        try:
            credz_name = self.clear_input(credz_name)
            self.logging.debug(f"{credz_name} - {binascii.hexlify(credz_name.encode('utf-8'))}")
            credz_value = self.clear_input(credz_value)
            self.logging.debug(f"{credz_value} - {binascii.hexlify(credz_value.encode('utf-8'))}")
            credz_expires_utc = self.clear_input(credz_expires_utc)
            self.logging.debug(f"{credz_expires_utc}")
            credz_target = self.clear_input(credz_target)
            self.logging.debug(f"{credz_target} - {binascii.hexlify(credz_target.encode('utf-8'))}")
            credz_path = self.clear_input(credz_path)
            self.logging.debug(f"{credz_path} - {binascii.hexlify(credz_path.encode('utf-8'))}")
            self.logging.debug(
                f"pillaged_from_computer_ip {pillaged_from_computer_ip} - {binascii.hexlify(pillaged_from_computer_ip.encode('utf-8'))}")
            self.logging.debug(f"pillaged_from_username {pillaged_from_username}")

            if pillaged_from_computer_ip != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT * FROM computers WHERE LOWER(ip)=LOWER('{pillaged_from_computer_ip}')")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_computerid = result[0]
                    self.logging.debug(f"[+] Resolved {pillaged_from_computer_ip} to id : {pillaged_from_computerid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_cookie 1")
            self.logging.debug(ex)

        try:
            if pillaged_from_username != None:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(
                        f"SELECT * FROM users WHERE LOWER(username)=LOWER('{pillaged_from_username}') AND pillaged_from_computerid={pillaged_from_computerid}")
                results = cur.fetchall()
                if len(results) > 0:
                    result = results[0]
                    pillaged_from_userid = result[0]
                    self.logging.debug(
                        f"[+] Resolved {pillaged_from_username} on machine {pillaged_from_computerid} to id : {pillaged_from_userid}")
        except Exception as ex:
            self.logging.error(f"Exception in add_cookies 2")
            self.logging.debug(ex)
            pass
        if pillaged_from_computerid == None or pillaged_from_userid == None:
            self.logging.debug(
                f"[-] Missing computerId or UserId to register Cookie {credz_name} {credz_value} - {credz_target}")
        # return None
        try:
            if pillaged_from_userid == None:
                query = "SELECT * FROM cookies WHERE LOWER(name)=LOWER(:credz_name) AND LOWER(value)=LOWER(:credz_value) AND expires_utc=:credz_expires_utc AND LOWER(type)=LOWER(:credz_type) AND LOWER(target)=LOWER(:credz_target) AND pillaged_from_computerid=:pillaged_from_computerid"
                parameters = {
                    "credz_name": credz_name,
                    "credz_value": credz_value,
                    "credz_expires_utc": credz_expires_utc,
                    "credz_type": credz_type, "credz_target": credz_target,
                    "pillaged_from_computerid": int(pillaged_from_computerid),
                }
            else:
                query = "SELECT * FROM cookies WHERE LOWER(name)=LOWER(:credz_name) AND LOWER(value)=LOWER(:credz_value) AND expires_utc=:credz_expires_utc AND LOWER(type)=LOWER(:credz_type) AND LOWER(target)=LOWER(:credz_target) AND pillaged_from_computerid=:pillaged_from_computerid AND pillaged_from_userid=:pillaged_from_userid"
                parameters = {
                    "credz_name": credz_name,
                    "credz_value": credz_value,
                    "credz_expires_utc": credz_expires_utc,
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
            self.logging.error(f"Exception in add_cookie 3")
            self.logging.debug(ex)
        try:
            if not len(results):
                if pillaged_from_userid == None:
                    query = "INSERT INTO cookies (name, value, expires_utc, target, type, pillaged_from_computerid, file_path) VALUES (:credz_name, :credz_value, :credz_expires_utc, :credz_target, :credz_type, :pillaged_from_computerid, :credz_path)"
                    parameters = {
                        "credz_name": credz_name,
                        "credz_value": credz_value,
                        "credz_expires_utc": credz_expires_utc,
                        "credz_target": credz_target,
                        "credz_type": credz_type,
                        "pillaged_from_computerid": int(pillaged_from_computerid),
                        "credz_path": credz_path,
                    }
                else:
                    query = "INSERT INTO cookies (name, value, expires_utc, target, type, pillaged_from_computerid,pillaged_from_userid, file_path) VALUES (:credz_name, :credz_value, :credz_expires_utc, :credz_target, :credz_type, :pillaged_from_computerid, :pillaged_from_userid, :credz_path)"
                    parameters = {
                        "credz_name": credz_name,
                        "credz_value": credz_value,
                        "credz_expires_utc": credz_expires_utc,
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
                    f'added_cookies(credtype={credz_type}, target={credz_target}, name={credz_name}, value={credz_value}) => {user_rowid}')
            else:
                self.logging.debug(
                    f'added_credential(credtype={credz_type}, target={credz_target}, name={credz_name}, value={credz_value}) => ALREADY IN DB')

        except Exception as ex:
            self.logging.error(f"Exception in add_cookie 4")
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
            cur.execute(
                "SELECT * FROM users WHERE credtype=? AND LOWER(domain)=LOWER(?) AND LOWER(username)=LOWER(?) AND password=?",
                [credtype, domain, username, password])
            users = cur.fetchall()

        cur.execute('SELECT * FROM computers WHERE ip LIKE ?', [host])
        hosts = cur.fetchall()

        if len(users) and len(hosts):
            for user, host in zip(users, hosts):
                userid = user[0]
                hostid = host[0]

                # Check to see if we already added this link
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
            cur.execute("SELECT * FROM computers WHERE ip LIKE ? OR LOWER(hostname) LIKE LOWER(?)",
                        ['%{}%'.format(filterTerm), '%{}%'.format(filterTerm)])

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
            cur.execute("SELECT * FROM groups WHERE LOWER(name)=LOWER(?) AND LOWER(domain)=LOWER(?)",
                        [groupName, groupDomain])

        elif filterTerm and filterTerm != "":
            cur.execute("SELECT * FROM groups WHERE LOWER(name) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])

        else:
            cur.execute("SELECT * FROM groups")

        results = cur.fetchall()
        cur.close()
        self.logging.debug(
            'get_groups(filterTerm={}, groupName={}, groupDomain={}) => {}'.format(filterTerm, groupName, groupDomain,
                                                                                results))
        return results

