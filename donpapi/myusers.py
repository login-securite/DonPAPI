#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
MyUser module contain MyUser class.
@Author: Pierre-Alexandre Vandewoestyne (@T00uF)
"""

from donpapi.lib.toolbox import bcolors


class MyUser:
    """MyUser class."""
    def __init__(self, username, logger, options):
        self.username = username
        self.options = options
        self.logging = logger
        self.sid = ''  # A user may have many SID ?
        self.type = 'LOCAL'  # LOCAL, DOMAIN, MACHINE, MACHINE-USER
        self.type_validated = False
        self.appdata = ''
        self.password = ''
        self.domain = ''
        self.lmhash = ''
        self.nthash = ''
        self.aesKey = ''
        self.TGT = ''
        # self.masterkeys = {}  # GUID_File: masterkey
        self.masterkeys_file = {}
        self.files = {}
        self.secrets = {}
        self.dpapi_machinekey: []
        self.dpapi_userkey: []
        self.share = None
        self.pwd = None
        self.is_adconnect = False

    def resume_user_info(self):
        """Resume user informations."""
        try:
            encrypted = 0
            decrypted = 0
            decryption_failed = 0

            for masterkey in self.masterkeys_file.items():
                if masterkey['status'] == 'decrypted':
                    decrypted += 1
                elif masterkey['status'] == 'encrypted':
                    encrypted += 1
                elif masterkey['status'] == 'decryption_failed':
                    decryption_failed += 1
            file_stats = {}
            for key, user_file in self.files.items():
                if user_file['type'] not in file_stats:
                    file_stats[user_file['type']] = {}
                if user_file['status'] not in file_stats[user_file['type']]:
                    file_stats[user_file['type']][user_file['status']] = [key]
                else:
                    file_stats[user_file['type']][user_file['status']].append(key)

            msg_log = f"[{self.options.target_ip}] {bcolors.OKGREEN}{self.username}{bcolors.ENDC}" \
                      f" - ({self.sid}) - [{self.type} account]"
            self.logging.info(msg_log)

            msg_log = f"[{self.options.target_ip}] [{len(self.masterkeys_file)} Masterkeys " \
                      f"({bcolors.OKGREEN}{decrypted} decrypted{bcolors.ENDC}/{bcolors.WARNING}" \
                      f"{decryption_failed} failed{bcolors.ENDC}/{bcolors.OKBLUE}{encrypted} " \
                      f"not used{bcolors.ENDC})]"
            self.logging.info(msg_log)
            self.logging.info(f"[{self.options.target_ip}] [{len(self.files)} secrets files : ]")

            for secret_type, file_status in file_stats.items():
                for status in file_status:

                    msg_log = f"[{self.options.target_ip}] - " \
                              f"{bcolors.OKGREEN}{len(file_status[status])}{bcolors.ENDC} " \
                              f"{status} {secret_type}"
                    self.logging.info(msg_log)

                    if status == 'decrypted':
                        for secret_file in file_status[status]:
                            try:
                                s_file = self.files[secret_file]
                                if secret_type == 'vault':
                                    for vcrd_file in s_file['vcrd']:
                                        if s_file['vcrd'][vcrd_file]['status'] == 'decrypted':
                                            msg_log = f"[{self.options.target_ip}] Vault " \
                                                      f"{secret_file} - {vcrd_file} : " \
                                                      f"{s_file['vcrd'][vcrd_file]['secret']}"
                                            self.logging.info(msg_log)
                                elif secret_type in ["ChromeLoginData", "MozillaLoginData"]:
                                    for uri in s_file['secret']:
                                        msg_log = f"[{self.options.target_ip}] Chrome {uri} - " \
                                                  f"{s_file['secret'][uri]['username']} : " \
                                                  f"{s_file['secret'][uri]['password']}"
                                        self.logging.info(msg_log)
                                elif secret_type == "ChromeCookies":
                                    for uri in s_file['secret']:
                                        for cookie_name in s_file['secret'][uri]:
                                            msg_log = f"[{self.options.target_ip}] Chrome {uri}" \
                                                      f" - {cookie_name} : " \
                                                      f"{s_file['secret'][uri][cookie_name]}"
                                            self.logging.debug(msg_log)
                                elif secret_type == "wifi":
                                    if secret_file in self.files:
                                        msg_log = f"[{self.options.target_ip}] Wifi : " \
                                                  f"{s_file['wifi_name']} : {s_file['secret']}"
                                        self.logging.info(msg_log)
                                else:
                                    if secret_file in self.files:  # For Credential & Wifi
                                        msg_log = f"[{self.options.target_ip}] {secret_file} : " \
                                                  f"{s_file['secret']}"
                                        self.logging.info(msg_log)
                            except OSError as ex:
                                msg_log = f"[{self.options.target_ip}] {bcolors.WARNING}Exception" \
                                          f" in ResumeUserInfo for user {self.username} secret" \
                                          f" file {secret_file} type {secret_type} {bcolors.ENDC}"
                                self.logging.debug(msg_log)
                                self.logging.debug(ex)
                    else:
                        for secret_file in file_status[status]:
                            msg_log = f"[{self.options.target_ip}] {secret_file} : " \
                                      f"{self.files[secret_file]['path']}"
                            self.logging.debug(msg_log)

            self.logging.debug(f"[{self.options.target_ip}] -=-=-=-= Masterkeys details =-=-=-=-")

            for masterkey, masterkey_content in self.masterkeys_file.items():
                self.logging.debug(f"\t\t[*]GUID : {masterkey}")
                self.logging.debug(f"\t\t[*]Status : {masterkey_content['status']}")
                self.logging.debug(f"\t\t[*]path : {masterkey_content['path']}")
                if masterkey_content['status'] == 'decrypted':
                    self.logging.debug(f"\t\t[*]key : {masterkey_content['key']}")
                self.logging.debug("\t\t[*] -=-   -=-   -=-   -=-   -=-   -=- [*]")
            self.resume_secrets()

        except OSError as ex:
            msg_log = f"[{self.options.target_ip}] {bcolors.WARNING}Exception in " \
                      f"ResumeUserInfo for user {self.username} {bcolors.ENDC}"
            self.logging.debug(msg_log)
            self.logging.debug(ex)

    def resume_secrets(self):
        """Resume secrets."""
        msg_log = f"[{self.options.target_ip}] [*]User : " \
                  f"{self.username} - {len(self.secrets)} secrets :"
        self.logging.info(msg_log)
        for secret, secret_content in self.secrets:
            self.logging.info(f"[{self.options.target_ip}]\t[*]secret : {secret}")
            self.logging.info(f"[{self.options.target_ip}]\t{secret_content}")

    def get_secrets(self):
        """Get secrets."""
        return self.secrets

    def check_usertype(self):
        """Check user type."""
        # TODO
        if self.sid == '':
            return 'DOMAIN'
        else:
            return 'LOCAL'
