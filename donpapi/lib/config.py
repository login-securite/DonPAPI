import configparser
from dataclasses import dataclass

from donpapi.lib.first_run import first_run
from donpapi.lib.paths import DPP_CONFIG_FILE_PATH

DEFAULT_CUSTOM_SHARE = "C$"
DEFAULT_REMOTE_FILEPATH = "\\Users\\Default\\AppData\\Local\\Temp"
DEFAULT_FILENAME_REGEX = r"\d{4}-\d{4}-\d{4}-[0-9]{4}"
DEFAULT_FILE_EXTENSION = ".log"

@dataclass
class DonPAPIConfig:
    custom_share: str = DEFAULT_CUSTOM_SHARE
    custom_remote_filepath: str = DEFAULT_REMOTE_FILEPATH
    custom_filename_regex: str = DEFAULT_FILENAME_REGEX
    custom_file_extension: str = DEFAULT_FILE_EXTENSION

def parse_config_file():
    donpapi_config = configparser.ConfigParser()
    donpapi_config.read(DPP_CONFIG_FILE_PATH)

    if "secretsdump" not in donpapi_config.sections():
        first_run()
        donpapi_config.read(DPP_CONFIG_FILE_PATH)

    return DonPAPIConfig(
        custom_share = donpapi_config.get("secretsdump", "share", fallback=DEFAULT_CUSTOM_SHARE),
        custom_remote_filepath = donpapi_config.get("secretsdump", "remote_filepath", fallback=DEFAULT_REMOTE_FILEPATH),
        custom_filename_regex = donpapi_config.get("secretsdump", "filename_regex", fallback=DEFAULT_FILENAME_REGEX),
        custom_file_extension = donpapi_config.get("secretsdump", "file_extension", fallback=DEFAULT_FILE_EXTENSION),
    )