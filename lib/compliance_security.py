import ntpath
import LnkParse3
from lib.toolbox import bcolors
from lib.fileops import MyFileOps

class new_module():
    def __init__(self,smb,myregops,myfileops,logger,options,db,users):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.users = users
        self.smb = smb


    def run(self):
        self.check_laps()
        #self.process_files()
        #self.decrypt_all()

    def get_files(self):
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering New Module Secrets {bcolors.ENDC}")
        blacklist = ['.', '..']

        user_directories = [("Users\\{username}\\Recent", ('*.xls','*.pdf','*.doc*','*.txt','*.lnk')),
                            ("Users\\{username}\\Desktop", ('*.xls','*.pdf','*.doc*','*.lnk'))]
        machine_directories = [("Windows\\System32\\config\\", '*'),]

        for user in self.users:
            self.logging.debug(
                f"[{self.options.target_ip}] Looking for {user.username} ")
            if user.username == 'MACHINE$':
                directories_to_use = machine_directories
            else:
                directories_to_use = user_directories

            for info in directories_to_use:
                my_dir, my_mask = info
                tmp_pwd = my_dir.format(username=user.username)
                self.logging.debug(f"[{self.options.target_ip}] Looking for {user.username} files in {tmp_pwd} with mask {my_mask}")
                for mask in my_mask:
                    my_directory = self.myfileops.do_ls(tmp_pwd, mask, display=False)
                    for infos in my_directory:
                        longname, is_directory = infos
                        self.logging.debug("ls returned file %s" % longname)
                        if longname not in blacklist and not is_directory:
                            try:
                                # Downloading file
                                localfile = self.myfileops.get_file(ntpath.join(tmp_pwd, longname), allow_access_error=True)
                                self.process_file(localfile,user)
                            except Exception as ex:
                                self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in DownloadFile {localfile}{bcolors.ENDC}")
                                self.logging.debug(ex)
    def process_file(self,localfile,username):
        try:
            self.db.add_credz(credz_type='XXXXX',credz_username=username.decode('utf-8'),redz_password='',credz_target='',credz_path=localfile,pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=username)
            return 1
        except Exception as ex:
            self.logging.debug(
                f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ProcessFile {localfile}{bcolors.ENDC}")
            self.logging.debug(ex)

    def check_laps(self):
        try:
            reg_key = self.myregops.get_reg_value('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}','DllName')
            mytype = reg_key[0]
            myvalue = reg_key[1]
            if 'AdmPwd.dll' in myvalue:
                self.logging.debug(f"[{self.options.target_ip}] LAPS Found")
                return True
        except Exception:
            self.logging.debug(f'No LAPS Found')
            return False

    def check_llmnr(self):
        try:
            reg_key = self.myregops.get_reg_value('HKLM:\Software\policies\Microsoft\Windows NT\DNSClient','EnableMulticast')
            mytype = reg_key[0]
            myvalue = reg_key[1]
            if '0' in myvalue:
                self.logging.debug(f"[{self.options.target_ip}] LLMNR is Disabled")
                return True
        except Exception:
            self.logging.debug(f'No LAPS Found')
            return False

    """
    ("WDigest disabled","HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest","UseLogonCredential","0","Prevent clear text password to be stored in lsass"),
    ("WDigest cleaning","HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","TokenLeakDetectDelaySecs","30","Clear LoggedOf users creadential from lass after x Sec"),
    ("CredSSP Allow",HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults","","any applications are explicitly listed in the “Allow” keys (Fig. 35) - as this would permit the tspkgs / CredSSP providers to store cleartext passwords in memory"),
    ()
    """