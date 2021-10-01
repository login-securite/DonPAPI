# Code based on vncpasswd.py by trinitronx
# https://github.com/trinitronx/vncpasswd.py
import binascii
import codecs
import traceback

import d3des as d


#from DonPAPI.lazagne.config.winstructure import *



class Vnc():
    def __init__(self):
        self.vnckey = [23, 82, 107, 6, 35, 78, 88, 7]
        

    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def do_crypt(self, password, decrypt):
        try:
            print(f"[] decoding VNC 1  {password}")
            passpadd = (password + b'\x00' * 8)[:8]
            strkey = ''.join([chr(x) for x in self.vnckey]).encode()
            print(f"[] decoding VNC {passpadd} : {strkey}")
            key = d.deskey(strkey, decrypt)
            crypted = d.desfunc(passpadd, key)
            print(f"[] decoding VNC 2 {crypted}")
            return crypted
        except Exception as ex:
            print(
                f"[] exception in do_crypt")
            print(ex)
    def unhex(self, s):
        try:
            s = codecs.decode(s, 'hex')
        except TypeError as e:
            if e.message == 'Odd-length string':
                print('%s . Chopping last char off... "%s"' % (e.message, s[:-1]))
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
            print(f"Exception reverse_vncpassword {hash} ")
            print(ex)
        return pwd




if __name__ == "__main__":
    hash="3571774C74336546BB000000000000000000"
    #hash=binascii.unhexlify(hash)
    a=Vnc()
    a.reverse_vncpassword(hash=hash)
    