import os
import shutil
from donpapi.lib.database import init_db
from donpapi.lib.logger import donpapi_logger
from donpapi.lib.paths import DPP_CONFIG_FILE, DPP_CONFIG_FILE_PATH, DPP_DB_FILE, DPP_LOOT_DIR_NAME, DPP_PATH, DPP_RECOVER_DIR_NAME, DPP_REPORT_DIR_NAME, DPP_RESOURCES_PATH


def first_run():
    #Create directory if needed
    if not os.path.exists(DPP_PATH):
        donpapi_logger.display("First time use detected. Creating home directory")
    init_output_dir(DPP_PATH)

    if not os.path.exists(DPP_CONFIG_FILE_PATH):
        shutil.copy(os.path.join(DPP_RESOURCES_PATH, DPP_CONFIG_FILE), DPP_CONFIG_FILE_PATH)

def init_output_dir(directory = DPP_PATH):
    if not os.path.exists(directory):
        if directory != DPP_PATH:
            donpapi_logger.display(f"Creating custom directory at {directory}")
        os.mkdir(directory)
        for dirname in [DPP_REPORT_DIR_NAME, DPP_LOOT_DIR_NAME, DPP_RECOVER_DIR_NAME]:
            os.mkdir(os.path.join(directory, dirname))
    
    init_db(custom_db_dir = os.path.join(directory,DPP_DB_FILE))