import base64
import os
import sys
from typing import Optional
import warnings
from sqlite3 import connect
from donpapi.lib.logger import donpapi_logger
from donpapi.lib.paths import DPP_DB_FILE_PATH

from sqlalchemy import MetaData, create_engine, func, Table, select
from sqlalchemy.dialects.sqlite import Insert  # used for upsert
from sqlalchemy.exc import (
    NoInspectionAvailable,
    NoSuchTableError,
)
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import sessionmaker, scoped_session

warnings.filterwarnings("ignore", category=SAWarning)

def create_db_engine(db_path):
    return create_engine(f"sqlite:///{db_path}", isolation_level="AUTOCOMMIT", future=True)

class Database:
    def __init__(self, db_engine) -> None:
        self.ComputersTable = None
        self.SamHashesTable = None
        self.SecretsTable = None
        self.CertificatesTable = None
        self.CookiesTable = None
        self.FilesTable = None
        self.DpapiBackupkeysTable = None

        self.db_engine = db_engine
        self.db_path = self.db_engine.url.database
        self.metadata = MetaData()
        self.reflect_tables()
        session_factory = sessionmaker(bind=self.db_engine, expire_on_commit=True)

        Session = scoped_session(session_factory)
        self.conn = Session()
        pass

    @staticmethod
    def db_schema(db_conn):
        db_conn.execute(
            """CREATE TABLE "computers" (
            "id" integer PRIMARY KEY,
            "ip" text,
            "hostname" text,
            "domain" text,
            "dc" boolean
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "sam_hashes" (
            "id" integer PRIMARY KEY,
            "rid" integer,
            "username" text,
            "lmhash" text,
            "nthash" text,
            "computerid" integer,
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "secrets" (
            "id" integer PRIMARY KEY,
            "windows_user" text,
            "username" text,
            "password" text,
            "target" text,
            "name" text,
            "collector" text,
            "computerid" integer,
            "program" text,
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "certificates" (
            "id" integer PRIMARY KEY,
            "pfx_file_path" text,
            "guid" text,
            "username" text,
            "client_auth" bool,
            "computerid" integer,
            "windows_user" text,
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "cookies" (
            "id" integer PRIMARY KEY,
            "browser" text,
            "windows_user" text,
            "url" text,
            "cookie_name" text,
            "cookie_value" text,
            "creation_utc" text,
            "expires_utc" text,
            "last_access_utc" text,
            "computerid" integer,
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "files" (
            "id" integer PRIMARY KEY,
            "checksum" text,
            "file_path" text,
            "filename" text,
            "extension" text,
            "computerid" integer,
            "userid" integer,
            "windows_user" text,
            FOREIGN KEY(computerid) REFERENCES computers(id)
            )"""
        )
        db_conn.execute(
            """CREATE TABLE "dpapi_backupkeys" (
            "id" integer PRIMARY KEY,
            "domain" text,
            "pvk" text,
            UNIQUE(domain)
            )"""
        )

    def reflect_tables(self):
        with self.db_engine.connect():
            try:
                self.ComputersTable = Table("computers", self.metadata, autoload_with=self.db_engine)
                self.SamHashesTable = Table("sam_hashes", self.metadata, autoload_with=self.db_engine)
                self.SecretsTable = Table("secrets", self.metadata, autoload_with=self.db_engine)
                self.CertificatesTable = Table("certificates", self.metadata, autoload_with=self.db_engine)
                self.CookiesTable = Table("cookies", self.metadata, autoload_with=self.db_engine)
                self.FilesTable = Table("files", self.metadata, autoload_with=self.db_engine)
                self.DpapiBackupkeysTable = Table("dpapi_backupkeys", self.metadata, autoload_with=self.db_engine)
                
            except (NoInspectionAvailable, NoSuchTableError):
                donpapi_logger.debug("schema mismatch")
                sys.exit()

    def add_computer(
            self,
            ip,
            hostname,
            domain, 
            dc=None,
        ):
        """
        Check if this host has already been added to the database, if not add it in.
        """
        hosts = []
        q = select(self.ComputersTable).filter(self.ComputersTable.c.ip == ip)
        results = self.conn.execute(q).all()
        if not results:
            new_host = {
                "ip": ip,
                "hostname": hostname,
                "domain": domain,
                "dc": dc,
            }
            hosts = [new_host]
        # update existing hosts data
        else:
            for host in results:
                host_data = host._asdict()
                # only update column if it is being passed in
                if ip is not None:
                    host_data["ip"] = ip
                if hostname is not None:
                    host_data["hostname"] = hostname
                if domain is not None:
                    host_data["domain"] = domain
                if dc is not None:
                    host_data["dc"] = dc
                # only add host to be updated if it has changed
                if host_data not in hosts:
                    hosts.append(host_data)
            donpapi_logger.debug(f"Update Hosts: {hosts}")

        q = Insert(self.ComputersTable)
        update_columns = {col.name: col for col in q.excluded if col.name not in "id"}
        q = q.on_conflict_do_update(index_elements=self.ComputersTable.primary_key, set_=update_columns)
        donpapi_logger.debug(f"Adding/Updating computers: {len(hosts)}")

        self.conn.execute(q, hosts)  # .scalar()
    
    def get_computer(self, filter_term=None):
        """Return computers from the database."""
        q = select(self.ComputersTable)
        results = None
        # if we're returning a single computer by ID
        if self.is_computer_valid(filter_term):
            q = q.filter(self.ComputersTable.c.id == filter_term)
            results = self.conn.execute(q).first()
            # all() returns a list, so we keep the return format the same so consumers don't have to guess
            return results
        elif filter_term and filter_term != "":
            filter = func.lower(f"%{filter_term}%")
            q = q.filter(self.ComputersTable.c.ip.like(filter) | func.lower(self.ComputersTable.c.hostname).like(filter))
            results = self.conn.execute(q).first()
        donpapi_logger.debug(f"get_computer(filter_term={filter_term}) - results: {results}")
        return results
    
    def is_computer_valid(self, computer_id):
        """Check if this computer ID is valid."""
        q = select(self.ComputersTable).filter(self.ComputersTable.c.id == computer_id)
        results = self.conn.execute(q).all()
        return len(results) > 0
    
    def get_samhashes(self, computer=None):
        q = select(self.SamHashesTable)
        results = None
        # if we're returning a single computer by ID
        if computer is not None:
            computer_id= self.get_computer(computer).id
            q = q.filter(self.SamHashesTable.c.computerid == computer_id)
            results = self.conn.execute(q).all()
        else:
            results = self.conn.execute(q).all()
        donpapi_logger.debug(f"get_samhashes(computer={computer}) - results: {results}")
        return results

    def add_samhash(self, samstring, computer):
        computer_id= self.get_computer(computer).id

        username, rid, lmhash, nthash, _, _, _ = samstring.split(":")

        q = select(self.SamHashesTable).filter(
            self.SamHashesTable.c.rid == int(rid),
            func.lower(self.SamHashesTable.c.username) == func.lower(username),
            func.lower(self.SamHashesTable.c.lmhash) == func.lower(lmhash),
            func.lower(self.SamHashesTable.c.nthash) == func.lower(nthash),
            self.SamHashesTable.c.computerid == computer_id,
        )

        results = self.conn.execute(q).all()
        donpapi_logger.debug(results)
        if not results:

            sam_entry = {
                "rid": rid,
                "username": username,
                "lmhash": lmhash,
                "nthash": nthash,
                "computerid": computer_id,
            }

            try:
                q = Insert(self.SamHashesTable)
                self.conn.execute(q, [sam_entry])
                donpapi_logger.debug(f"add_samhash(samstring={samstring}, computer={computer})")
            except Exception as e:
                donpapi_logger.debug(f"Issue while inserting SAM hash into db: {e}")

    def add_domain_backupkey(self, domain: str, pvk: bytes):
        """
        Add domain backupkey
        :domain is the domain fqdn
        :pvk is the domain backupkey
        """
        q = select(self.DpapiBackupkeysTable).filter(func.lower(self.DpapiBackupkeysTable.c.domain) == func.lower(domain))
        results = self.conn.execute(q).all()
        if not len(results):
            pvk_encoded = base64.b64encode(pvk)
            backup_key = {"domain": domain, "pvk": pvk_encoded}
            try:
                q = Insert(self.DpapiBackupkeysTable)
                self.conn.execute(q, [backup_key])
                donpapi_logger.debug(f"add_domain_backupkey(domain={domain}, pvk={pvk_encoded})")
            except Exception as e:
                donpapi_logger.debug(f"Issue while inserting DPAPI Backup Key: {e}")

    def get_domain_backupkey(self, domain: Optional[str] = None):
        """
        Get domain backupkey
        :domain is the domain fqdn
        """
        q = select(self.DpapiBackupkeysTable)
        if domain is not None:
            q = q.filter(func.lower(self.DpapiBackupkeysTable.c.domain) == func.lower(domain))
        results = self.conn.execute(q).all()

        donpapi_logger.debug(f"get_domain_backupkey(domain={domain}) => {results}")

        if len(results) > 0:
            results = [(id_key, domain, base64.b64decode(pvk)) for id_key, domain, pvk in results]
        return results

    def is_secret_valid(self, secret_id):
        """
        Check if this secret ID is valid.
        :secret_id is a primary id
        """
        q = select(self.SecretsTable).filter(func.lower(self.SecretsTable.c.id) == secret_id)
        results = self.conn.execute(q).first()
        valid = results is not None
        donpapi_logger.debug(f"is_secret_valid(secret_ID={secret_id}) => {valid}")
        return valid

    def add_secret(
        self,
        computer,
        collector: str,
        windows_user: str,
        password: str,
        username: str = "",
        target: str = "",
        program: str = "N/A",
    ):
        """Add secret to database"""
        computer_id= self.get_computer(computer).id

        if program == "N/A":
            program = collector

        q = select(self.SecretsTable).filter(
            func.lower(self.SecretsTable.c.collector) == func.lower(collector),
            func.lower(self.SecretsTable.c.username) == func.lower(username),
            self.SecretsTable.c.password == password,
            func.lower(self.SecretsTable.c.target) == func.lower(target),
            func.lower(self.SecretsTable.c.windows_user) == func.lower(windows_user),
            func.lower(self.SecretsTable.c.program) == func.lower(program),
            self.SecretsTable.c.computerid == computer_id,
        )
        results = self.conn.execute(q).all()

        if not results:
            secret_entry = {
                "computerid": computer_id,
                "collector": collector,
                "windows_user": windows_user,
                "username": username,
                "password": password,
                "target": target,
                "program": program,
            }

            try:
                q = Insert(self.SecretsTable) 
                self.conn.execute(q, [secret_entry])
                donpapi_logger.debug(f"add_secret(computer={computer}, collector={collector}, windows_user={windows_user}, username={username}, password={password}, target={target}, program={program})")
            except Exception as e:
                donpapi_logger.debug(f"Issue while inserting secret: {e}")

    def add_cookie(
            self,
            computer:str,
            browser:str,
            windows_user:str,
            url:str,
            cookie_name:str,
            cookie_value:str,
            creation_utc:str,
            expires_utc:str,
            last_access_utc:str,
    ):
        computer_id= self.get_computer(computer).id
        last_access_utc = str(last_access_utc)
        q = select(self.CookiesTable).filter(
            func.lower(self.CookiesTable.c.browser) == func.lower(browser),
            func.lower(self.CookiesTable.c.windows_user) == func.lower(windows_user),
            func.lower(self.CookiesTable.c.url) == func.lower(url),
            func.lower(self.CookiesTable.c.cookie_name) == func.lower(cookie_name),
            self.CookiesTable.c.cookie_value == cookie_value,
            func.lower(self.CookiesTable.c.creation_utc) == func.lower(creation_utc),
            func.lower(self.CookiesTable.c.expires_utc) == func.lower(expires_utc),
            self.CookiesTable.c.computerid == computer_id,
        )

        results = self.conn.execute(q).all()

        if not results:
            cookie_entry = {
                "computerid": computer_id,
                "browser":browser,
                "windows_user":windows_user,
                "url":url,
                "cookie_name":cookie_name,
                "cookie_value":cookie_value,
                "creation_utc":creation_utc,
                "expires_utc":expires_utc,
                "last_access_utc":last_access_utc,
            }

            try:
                q = Insert(self.CookiesTable) 
                self.conn.execute(q, [cookie_entry])
                donpapi_logger.debug(f"add_cookie(computer={computer}, browser={browser}, windows_user={windows_user}, url={url}, cookie_name={cookie_name}, cookie_value={cookie_value}, creation_utc={creation_utc}, expires_utc={expires_utc}, last_access_utc={last_access_utc})")
            except Exception as e:
                donpapi_logger.debug(f"Issue while inserting cookie: {e}")
        else:
            for cookie in results:
                cookie_data = cookie._asdict()
                if cookie_data["last_access_utc"] != last_access_utc:
                    cookie_data["last_access_utc"] = last_access_utc

                    try:
                        q = Insert(self.CookiesTable) 
                        update_columns = {col.name: col for col in q.excluded if col.name == "last_access_utc"}
                        q = q.on_conflict_do_update(index_elements=self.CookiesTable.primary_key, set_=update_columns)
                        self.conn.execute(q, [cookie_data])
                        donpapi_logger.debug(f"update_cookie(id={cookie_data['id']}, computer={computer}, browser={browser}, windows_user={windows_user}, url={url}, cookie_name={cookie_name}, cookie_value={cookie_value}, creation_utc={creation_utc}, expires_utc={expires_utc}, last_access_utc={last_access_utc})")
                    except Exception as e:
                        donpapi_logger.debug(f"Issue while updating cookie {cookie_data['id']}: {e}")

    def add_certificate(self, filepath, certificate, computer):
        computer_id= self.get_computer(computer).id

        q = select(self.CertificatesTable).filter(
                self.CertificatesTable.c.pfx_file_path == filepath,
                func.lower(self.CertificatesTable.c.guid) == func.lower(certificate.filename),
                func.lower(self.CertificatesTable.c.username) == func.lower(certificate.username),
                self.CertificatesTable.c.client_auth == certificate.clientauth,
                self.CertificatesTable.c.computerid == computer_id,
                func.lower(self.CertificatesTable.c.windows_user) == func.lower(certificate.winuser),
            )

        results = self.conn.execute(q).all()

        if not results:
            certificate_entry = {
                "pfx_file_path": filepath,
                "guid": certificate.filename,
                "username": certificate.username,
                "client_auth": certificate.clientauth,
                "computerid": computer_id,
                "windows_user": certificate.winuser,
            }

            try:
                q = Insert(self.CertificatesTable) 
                self.conn.execute(q, [certificate_entry])
                donpapi_logger.debug(f"add_certificate(filepath={filepath}, certificate={certificate}, computer={computer})")
            except Exception as e:
                donpapi_logger.debug(f"Issue while inserting certificate: {e}")

    # Get

    def get_sam_reuse(self):
        # get the dups
        q = select(self.SamHashesTable.c.nthash).group_by(self.SamHashesTable.c.nthash).having(func.count(self.SamHashesTable.c.id) > 1)
        results = self.conn.execute(q).all()
        nthashes_dup = [row for row, in results]

        q = select(self.SamHashesTable, self.ComputersTable).join(self.SamHashesTable).filter(
                self.SamHashesTable.c.nthash.in_(nthashes_dup), # we want the duplicates
                func.lower(self.SamHashesTable.c.nthash) != "31d6cfe0d16ae931b73c59d7e0c089c0", # but not on 31d6 hash
                self.ComputersTable.c.dc.is_(False), # and not on DC
            ).order_by(self.SamHashesTable.c.nthash)
        
        results2 = self.conn.execute(q).all()
        json_result = [row._asdict() for row in results2]
        donpapi_logger.debug(f"get_sam_reuse() - results: {json_result}")
        return json_result
    
    def get_scheduled_tasks(self):
        q = select(self.SecretsTable, self.ComputersTable).join(self.SecretsTable)
        q = q.filter(func.lower(self.SecretsTable.c.target).like("%TaskScheduler%"))
        results = self.conn.execute(q).all()
        json_result = [row._asdict() for row in results]
        donpapi_logger.debug(f"get_scheduled_tasks() - results: {json_result}")
        return json_result
    
    def get_lsa_secrets(self):
        q = select(self.SecretsTable, self.ComputersTable).join(self.SecretsTable)
        q = q.filter(self.SecretsTable.c.collector == "LSA")
        results = self.conn.execute(q).all()
        json_result = [row._asdict() for row in results]
        donpapi_logger.debug(f"get_lsa_secrets() - results: {json_result}")
        return json_result

    def get_cookie(self, id):
        q = select(self.CookiesTable)
        q = q.filter(self.CookiesTable.c.id == id)
        results = self.conn.execute(q).first()
        json_result = results._asdict() if results is not None else None
        donpapi_logger.debug(f"get_cookie(id={id}) - results: {json_result}")
        return json_result
       
    def get_cookies(self, page = 0, page_size = 500, computer_hostname = None, cookie_name = None, cookie_value = None, windows_user = None, url = None):
        if page <0:
            page = 0

        q = select(self.CookiesTable, self.ComputersTable).join(self.CookiesTable)
        if computer_hostname and computer_hostname != "":
            computer_hostname_like_term = func.lower(f"%{computer_hostname}%")
            q = q.filter(func.lower(self.ComputersTable.c.hostname).like(computer_hostname_like_term))
        if cookie_name and cookie_name != "":
            cookie_name_like_term = func.lower(f"%{cookie_name}%")
            q = q.filter(func.lower(self.CookiesTable.c.cookie_name).like(cookie_name_like_term))
        if cookie_value and cookie_value != "":
            cookie_value_like_term = func.lower(f"%{cookie_value}%")
            q = q.filter(func.lower(self.CookiesTable.c.cookie_value).like(cookie_value_like_term))
        if windows_user and windows_user != "":
            windows_user_like_term = func.lower(f"%{windows_user}%")
            q = q.filter(func.lower(self.CookiesTable.c.windows_user).like(windows_user_like_term))
        if url and url != "":
            url_like_term = func.lower(f"%{url}%")
            q = q.filter(func.lower(self.CookiesTable.c.url).like(url_like_term))
        results = self.conn.execute(q).all()

        cookies = [row._asdict() for row in results]

        cookies_return = {
            'count': len(cookies),
            'cookies': cookies[page*page_size:page*page_size+page_size],
        }
        return cookies_return
    
    def get_distinct_value_for_column(self, column):
        q = select(func.distinct(column))
        results = self.conn.execute(q).all()

        return [row[0] for row in results]


    def get_secret(self, id):
        q = select(self.SecretsTable)
        q = q.filter(self.SecretsTable.c.id == id)
        results = self.conn.execute(q).first()
        return results._asdict() if results is not None else None
    
    def get_secrets(self, page = 0, page_size = 500, computer_hostname = None, collector = None, program = None, windows_user = None, target = None, username = None, password = None):
        if page < 0:
            page = 0

        q = select(self.SecretsTable, self.ComputersTable).join(self.SecretsTable)
        if computer_hostname and computer_hostname != "":
            computer_hostname_like_term = func.lower(f"%{computer_hostname}%")
            q = q.filter(func.lower(self.ComputersTable.c.hostname).like(computer_hostname_like_term))
        if collector and collector != "":
            collector_like_term = func.lower(f"%{collector}%")
            q = q.filter(func.lower(self.SecretsTable.c.collector).like(collector_like_term))
        if program and program != "":
            q = q.filter(func.lower(self.SecretsTable.c.program) == func.lower(program))
        if windows_user and windows_user != "":
            windows_user_like_term = func.lower(f"%{windows_user}%")
            q = q.filter(func.lower(self.SecretsTable.c.windows_user).like(windows_user_like_term))
        if target and target != "":
            target_like_term = func.lower(f"%{target}%")
            q = q.filter(func.lower(self.SecretsTable.c.target).like(target_like_term))
        if username and username != "":
            username_like_term = func.lower(f"%{username}%")
            q = q.filter(func.lower(self.SecretsTable.c.username).like(username_like_term))
        if password and password != "":
            password_like_term = func.lower(f"%{password}%")
            q = q.filter(func.lower(self.SecretsTable.c.password).like(password_like_term))
        q = q.order_by(self.SecretsTable.c.collector)
        results = self.conn.execute(q).all()

        secrets = [row._asdict() for row in results]

        secrets_return = {
            'count': len(secrets),
            'secrets': secrets[page*page_size:page*page_size+page_size],
            'programs_list': self.get_distinct_value_for_column(self.SecretsTable.c.program),
        }
        
        return secrets_return
    
    def get_certificate(self, id):
        q = select(self.CertificatesTable)
        q = q.filter(self.CertificatesTable.c.id == id)
        results = self.conn.execute(q).first()
        return results._asdict() if results is not None else None

    def get_certificates(self, page = 0, page_size = 500, computer_hostname = None, windows_user = None, username = None, client_auth:bool = None):
        q = select(self.CertificatesTable, self.ComputersTable).join(self.CertificatesTable)
        if computer_hostname and computer_hostname != "":
            computer_hostname_like_term = func.lower(f"%{computer_hostname}%")
            q = q.filter(func.lower(self.ComputersTable.c.hostname).like(computer_hostname_like_term))
        if windows_user and windows_user != "":
            windows_user_like_term = func.lower(f"%{windows_user}%")
            q = q.filter(func.lower(self.CertificatesTable.c.windows_user).like(windows_user_like_term))
        if username and username != "":
            username_like_term = func.lower(f"%{username}%")
            q = q.filter(func.lower(self.CertificatesTable.c.username).like(username_like_term))
        if client_auth in [True, False] and client_auth is not None:
            q = q.filter(self.CertificatesTable.c.client_auth == client_auth)

        results = self.conn.execute(q).all()

        certificates = [row._asdict() for row in results]

        certificates_return = {
            'count': len(certificates),
            'certificates': certificates[page*page_size:page*page_size+page_size],
        }
        return certificates_return

def init_db(logger=donpapi_logger, custom_db_dir=DPP_DB_FILE_PATH):
    if not os.path.exists(custom_db_dir):
        logger.debug("Initializing DonPAPI database")
        conn = connect(custom_db_dir)
        c = conn.cursor()
        # try to prevent some weird sqlite I/O errors
        c.execute("PRAGMA journal_mode = OFF")  # could try setting to PERSIST if DB corruption starts occurring
        c.execute("PRAGMA foreign_keys = 1")
        # set a small timeout (5s) so if another thread is writing to the database, the entire program doesn't crash
        c.execute("PRAGMA busy_timeout = 5000")
        Database.db_schema(c)
        # commit the changes and close everything off
        conn.commit()
        conn.close()