import os
import re
from ipaddress import ip_address, ip_network, summarize_address_range, ip_interface
import time
from typing import Dict
import json

from donpapi.lib.paths import DPP_RECOVER_DIR_NAME
from dploot.triage.masterkeys import parse_masterkey_file
from donpapi.lib.logger import donpapi_logger

def create_recover_file(dirpath, targets, options):
    timestamp = int(time.time())
    filepath = os.path.join(dirpath, DPP_RECOVER_DIR_NAME, f"recover_{timestamp}")
    with open(filepath, "w") as f:
        write_recover_file(f, [f"{json.dumps(vars(options))}\n", ",".join(targets)])

    return filepath

def update_recover_file(recover_file_handle, targets):
    recover_file_handle.seek(0)
    recover_file_lines = recover_file_handle.readlines()
    recover_file_lines[1] = ",".join(targets)
    write_recover_file(recover_file_handle, recover_file_lines)

def write_recover_file(recover_file_handle, lines):
    recover_file_handle.seek(0)
    recover_file_handle.truncate()
    recover_file_handle.writelines(lines)

def load_recover_file(recover_file_path):
    options = None
    targets_todo = None
    with open(recover_file_path, "r") as f:
        lines = f.readlines()
        options = json.loads(lines[0])
        targets_todo = lines[1].split(",")
    return options, targets_todo

def parse_targets(target):
    try:
        if "-" in target:
            start_ip, end_ip = target.split("-")
            try:
                end_ip = ip_address(end_ip)
            except ValueError:
                first_three_octets = start_ip.split(".")[:-1]
                first_three_octets.append(end_ip)
                end_ip = ip_address(".".join(first_three_octets))

            for ip_range in summarize_address_range(ip_address(start_ip), end_ip):
                for ip in ip_range:
                    yield str(ip)
        else:
            if ip_interface(target).ip.version == 6 and ip_address(target).is_link_local:
                yield str(target)
            else:
                for ip in ip_network(target, strict=False):
                    yield str(ip)
    except ValueError:
        yield str(target)

def parse_file_as_dict(filename: str) -> Dict[str,str]:
    arr = dict()
    with open(filename, 'r') as lines:
        for line in lines:
            line_modified = line.rstrip('\n')
            line_modified = line_modified.split(':',1)
            arr[line_modified[0]]=line_modified[1]
    return arr

def parse_credentials_files(pvkfile, passwords_file, nthashes_file, masterkeys_file, username, password, nthash):
    pvkbytes = None
    passwords = {}
    nthashes = {}
    masterkeys = []

    if pvkfile is not None:
        try:
            pvkbytes = open(pvkfile, 'rb').read()
        except Exception as e:
            donpapi_logger.error(f"Error while reading file {passwords_file}: {e}")

    if passwords_file is not None:
        try:
            passwords = parse_file_as_dict(passwords_file)
        except Exception as e:
            donpapi_logger.error(f"Error while reading file {passwords_file}: {e}")

    if nthashes_file is not None:
        try:
            nthashes = parse_file_as_dict(nthashes_file)
        except Exception as e:
            donpapi_logger.error(f"Error while reading file {nthashes_file}: {e}")

    if masterkeys_file is not None:
        try:
            masterkeys = parse_masterkey_file(masterkeys_file)
        except Exception as e:
            donpapi_logger.error(f"Error while reading file {masterkeys_file}: {e}")

    if username is not None:
        if password is not None and password != '':
            if passwords is None:
                passwords = dict()
            passwords[username] = password

        if nthash is not None and nthash != '':
            if nthashes is None:
                nthashes = dict()
            nthashes[username] = nthash.lower()

    if nthashes is not None:
        nthashes = {k.lower():v.lower() for k, v in nthashes.items()}
    
    if passwords is not None:
        passwords = {k.lower():v for k, v in passwords.items()}

    return pvkbytes, passwords, nthashes, masterkeys

def is_guid(value: str):
    GUID = re.compile(r'^(\{{0,1}([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$')
    if GUID.match(value):
        return True
    else:
        return False
    
def dump_file_to_loot_directories(local_filepath: str, file_content: bytes=b"") -> None:
    os.makedirs(os.path.dirname(local_filepath), exist_ok = True)
    with open(local_filepath, "wb") as f:
        f.write(file_content)