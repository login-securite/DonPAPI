#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
Reporting Module.
Generate HTML content from a given database and formating choices.
"""

import base64
import binascii
import json
import os
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from donpapi.lib.toolbox import bcolors


class Reporting:
    """Reporting class, generate multiple reports."""
    def __init__(self, conn, logger, options, targets):
        self.conn = conn
        self.logging = logger
        self.options = options
        self.targets = targets
        self.time = int(time.time())
        self.report_prefix = f"DonPAPI_{self.time}_"
        self.report_name = f"{self.report_prefix}result.html"
        self.report_file = Path(self.options.output_directory, self.report_name)
        self.html_path = Path(self.options.output_directory, 'html')

    def add_to_resultpage(self, datas):
        """Write datas string to self.result_file (append mode). """
        try:
            with open(self.report_file, 'a', encoding="utf-8") as report:
                report.write(datas)
            return True
        except OSError as ex:
            error = f" Exception {bcolors.WARNING} in add_to_resultpage() {bcolors.ENDC}"
            self.logging.debug(error)
            self.logging.debug(ex)
            return False

    def generate_report(self, report_name="", report_content=None, credz_content=None):
        """Generate html reports with specified options."""

        # Update report name if needed
        if report_name is not None:
            self.report_name = f"{self.report_prefix}{report_name}.html"
            self.report_file = Path(self.options.output_directory, self.report_name)

        # Set default options content if not specified
        if report_content is None:
            report_content = ['credz', 'certificates', 'cookies', 'files',
                              'connected_user', 'hash_reuse', 'audited_scope',
                              'masterkeys']

        if credz_content is None:
            credz_content = ['wifi', 'taskscheduler', 'credential-blob',
                             'browser', 'sysadmin', 'SAM', 'LSA', 'DCC2']

        # Read CSS and Logo contents from configuration
        try:
            my_path = Path(__file__).parent
            dp_config = Path(my_path, "config", "donpapi_config.json")
            with open(dp_config, encoding="utf-8", mode="r") as config:
                config_parser = json.load(config)
            css_path = Path(my_path, "res", config_parser['css'])
            logo_path = Path(my_path, "res", config_parser['logo_login'])
            with open(css_path, encoding="utf-8", mode="r") as css_file:
                mycss = css_file.read()
            with open(logo_path, mode="rb") as logo_file:
                logo_login = base64.b64encode(logo_file.read()).decode('utf-8')
        except OSError as ex:
            error = f" Exception {bcolors.WARNING}  in generate_report() {bcolors.ENDC}"
            self.logging.debug(error)
            self.logging.debug(ex)

        self.logging.info(f"[+] Generating report : {self.report_file}")

        # Verify SQL database
        if self.conn is None:
            error = f"[+] db ERROR - self.conn is None : {self.options.output_directory}"
            self.logging.debug(error)
            return False

        try:
            if not os.path.exists(self.html_path):
                os.mkdir(self.html_path)
        except OSError as ex:
            error = f" Exception {bcolors.WARNING}  in generate_report() {bcolors.ENDC}"
            self.logging.debug(error)
            self.logging.debug(ex)
            return False

        data = f"""<!DOCTYPE html>
            <html>
            <head>
              <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
              <title>DonPapi - Results</title>
              <style>
                {mycss}
              </style>
            </head>
            <body onload="toggleAll()">
            \n"""

        self.add_to_resultpage(data)

        # Top table for links ?
        data = """<table class="statistics"><tr><th>"""
        data += """<a class="firstletter">M</a><a>enu</a></th></tr>\n"""
        data = """<div class="navbar">\n"""
        for menu in ['wifi', 'taskscheduler', 'credential-blob', 'certificates',
                     'browser-internet_explorer', 'cookies', 'SAM', 'LSA', 'DCC2',
                     'Files', 'Connected-users', 'Local_account_reuse', 'Scope_Audited']:
            data += f"""<a href="#{menu}"> {menu.upper()}</a>\n"""
        data += """</DIV><br>\n"""
        self.add_to_resultpage(data)

        # Logo @ Titre
        today = date.today().strftime("%d/%m/%Y")

        data = """<DIV class="main">\n"""
        data += """<table class="main"><tr><td>\n"""
        data += """<table><tr><TD class="menu_top"><a class="firstletter">"""
        data += """D</a><a>onPapi Audit</a></td></tr>\n"""
        data += f"""<tr><TD class="menu_top"><br> {today} <br></td></tr></table><br>\n"""
        data += """<table><tr><td><img class="logo_left" src="data:image/png;"""
        data += f"""base64,{logo_login}"></td>"""
        data += """<br></div></td></tr></table><br>\n"""
        self.add_to_resultpage(data)

        # JS Stuff
        data = """
        <script>
        function toggle_by_class(cls, on) {
            var lst = document.getElementsByClassName(cls);
            for(var i = 0; i < lst.length; ++i) {
                lst[i].style.display = on ? '' : 'none';
            }
        }

        function toggle_it(thisname) {
         tr=document.getElementsByTagName('tr')
         for (i=0;i<tr.length;i++){
          if (tr[i].getAttribute(thisname)){
           if ( tr[i].style.display=='none' ){
             tr[i].style.display = '';
           }
           else {
            tr[i].style.display = 'none';
           }
          }
         }
        }

        function toggleAll() {
        toggle_it("cookies");
        toggle_it("wifi");
        toggle_it("taskscheduler");
        toggle_it("credential-blob");
        toggle_it("browser-internet_explorer");
        toggle_it("browser-firefox");
        toggle_it("browser-chrome");
        toggle_it("SAM");
        toggle_it("LSA");
        toggle_it("DCC2");
        toggle_it("VNC");
        toggle_it("MRemoteNG");
        }

        function CopyToClipboard(data_to_copy) {
        const dummy = document.createElement('textarea');
        dummy.style.position = 'absolute';
        dummy.style.left = '-9999px';
        dummy.style.top = '-9999px';
        document.body.appendChild(dummy);
        dummy.value = data_to_copy;
        dummy.select();
        document.execCommand('copy');
        document.body.removeChild(dummy);
        // Copy the text inside the text field
        //navigator.clipboard.writeText(data_to_copy);
        //alert("Copied the text: " + data_to_copy);
        }
        </script>

        """

        self.add_to_resultpage(data)

        if 'credz' in report_content:
            results = self.get_credz()
            # populate credentials report filtering :
            if 'browser' in credz_content:
                credz_content.append('browser-internet_explorer')
                credz_content.append('browser-firefox')
                credz_content.append('browser-chrome')
            if 'sysadmin' in credz_content:
                credz_content.append('VNC')
                credz_content.append('MRemoteNG')
                credz_content.append('Putty')
                credz_content.append('Winscp')

            data = """<table class="statistics"><tr>
            <th><a class="firstletter">U</a><a>sername</a></th>
            <th><a class="firstletter">P</a><a>assword</a></th>
            <th><a class="firstletter">T</a><a>arget</a></th>
            <th><a class="firstletter">T</a><a>ype</a></th>
            <th><a class="firstletter">P</a><a>illaged_from_computerid</a></th>
            <th><a class="firstletter">P</a><a>illaged_from_userid</a></th></tr>\n"""

            current_type = ''
            for index, credentials in enumerate(results):
                _, file_path, username, password, target, \
                   creds_type, pillaged_from_computerid, pillaged_from_userid = credentials

                # filtering data to be included in the report
                if creds_type not in credz_content:
                    continue

                # Skip infos of WindowsLive:target=virtualapp/didlogical
                untreated_targets = ["WindowsLive:target=virtualapp/didlogical", "Adobe App Info",
                                     "Adobe App Prefetched Info", "Adobe User Info",
                                     "Adobe User OS Info", "MicrosoftOffice16_Data:ADAL",
                                     "LegacyGeneric:target=msteams_adalsso/adal_contex"]
                untreated_users = ["NL$KM_history"]

                if creds_type != current_type:
                    current_type = creds_type
                    query = f"""AND username NOT IN ("{'","'.join(untreated_users)}") """
                    query += f"""AND target NOT IN ("{'","'.join(untreated_targets)}")"""
                    current_type_count = self.get_credz_count(current_type, query)[0][0]
                    data += f"""<TR id={current_type}><TD colspan="6" class="toggle_menu" """
                    data += f"""onClick="toggle_it('{current_type}')"><a>{current_type} """
                    data += f"""({current_type_count})</a></td></tr>"""

                # blacklist_bypass
                if (len(set(untreated_targets) & set(target)) or
                   len(set(untreated_users) & set(username))):
                    continue

                # Get computer infos
                computer_ip, hostname = list(self.get_computer_infos(pillaged_from_computerid))[0]
                computer_info = f"{computer_ip} | {hostname}"

                # pillaged_from_userid
                if pillaged_from_userid is not None:
                    pillaged_from_userid = list(self.get_user_infos(pillaged_from_userid))[0][0]
                else:
                    pillaged_from_userid = str(pillaged_from_userid)  # TODO : ??

                if index % 2 == 0:
                    data += f"""<TR class=tableau_resultat_row0 {current_type}=1>"""
                else:
                    data += f"""<TR class=tableau_resultat_row1 {current_type}=1>"""

                if 'admin' in username.lower():  # Pour mettre des results en valeur
                    special_style = '''class="cracked"'''
                else:
                    special_style = ""

                # Print block
                # recover username from target
                # TODO: update myseatbelt.py to make a clean function dump_CREDENTIAL_XXXXX

                if "LegacyGeneric:target=MicrosoftOffice1" in target:
                    username = target.split(':')[-1]

                # LSA passwords are often in Hexadecimals
                # if "LSA" in type:
                try:
                    hex_passw = ''
                    hex_passw = binascii.unhexlify(password).replace(b'>', b'')
                except ValueError:
                    hex_passw = password
                except binascii.Error:
                    hex_passw = password

                data += f'<TD {special_style} ><A title="{username}"> {username[:48]} </a></td>'
                data += f'<TD {special_style} ><A title="{hex_passw}"> {password[:48]} </a></td>'

                # check if info contains a URL
                if 'http:' in target or 'https:' in target:
                    info2 = target[target.index('http'):]
                    special_ref = f'''href="{info2}" target="_blank" title="{target}"'''
                elif 'ftp:' in target:
                    info2 = target[target.index('ftp'):]
                    special_ref = f'''href="{info2}" target="_blank" title="{target}"'''
                elif "Domain:target=" in target:
                    target_addr = target[target.index('Domain:target=') + len('Domain:target='):]
                    info2 = f"rdp://full%20address=s:{target_addr}:3389&username=s:{username}"
                    info2 += "&audiomode=i:2&disable%20themes=i:1"
                    special_ref = f'''href="{info2}" title="{target}"'''
                elif "LegacyGeneric:target=MicrosoftOffice1" in target:
                    target = target[target.index('LegacyGeneric:target=') +
                                    len('LegacyGeneric:target='):]
                    special_ref = 'href="https://login.microsoftonline.com/" target="_blank" ' \
                                  'title="OfficeLogin"'
                else:
                    special_ref = f'''title="{target}"'''
                data += f'<TD {special_style} ><A {special_ref}> {str(target)[:48]} </a></td>'

                for info in [creds_type, computer_info, pillaged_from_userid]:
                    data += f'<TD {special_style} ><A title="{info}"> {str(info)[:48]} </a></td>'
                data += """</tr>\n"""

            data += """</table><br>"""
            self.add_to_resultpage(data)
        #

        if 'certificates' in report_content:
            results = self.get_certificates()

            data = """
                    <table class="statistics"><tr>
                    <Th style="text-align: center"><a class="firstletter">I</a><a>ssuer</a></th>
                    <Th style="text-align: center"><a class="firstletter">S</a><a>ubject</a></th>
                    <Th style="text-align: center"><a class="firstletter">P</a><a>illaged from</a></th>
                    <Th style="text-align: center"><a class="firstletter">P</a><a>illaged with</a></th>
                    <Th style="text-align: center"><a class="firstletter">C</a><a>lient auth</a></th></tr>\n
                    """

            current_type = 'certificates'
            data += """<TR id=certificates><TD colspan="6" class="toggle_menu" """
            data += """onClick="toggle_it('certificates')"><a>Certificates """
            data += f"""({len(results)})</a></td></tr>"""
            for index, cred in enumerate(results):
                _, pfx_filepath, guid, issuer, subject, \
                   client_auth, pillaged_from_computerid, pillaged_from_userid = cred[7]

                computer_ip, hostname = list(self.get_computer_infos(pillaged_from_computerid))[0]
                computer_info = f"{computer_ip} | {hostname}"
                if pillaged_from_userid is not None:
                    res = self.get_user_infos(pillaged_from_userid)
                    for _, pillaged_username in enumerate(res):
                        pillaged_from_userid = pillaged_username[0]
                else:
                    pillaged_from_userid = str(pillaged_from_userid)

                if index % 2 == 0:
                    data += f"""<TR class=tableau_resultat_row0 {current_type}=1>"""
                else:
                    data += f"""<TR class=tableau_resultat_row1 {current_type}=1>"""

                special_style = ""

                # Print block
                for info in [issuer, subject, computer_info, pillaged_from_userid]:
                    data += f"""<td><A title="{info}"> {str(info)[:48]} </a></td>"""
                for info in [client_auth]:
                    if client_auth:
                        cmd = f"certipy auth -pfx {os.path.join(os.getcwd(), pfx_filepath)}"
                        data += f"""<td><button onclick="CopyToClipboard('{cmd}')">"""
                        data += "Yes</button></td>"
                    else:
                        data += """<td><A title="No">No</a></td>"""
                data += """</tr>\n"""
            data += """</table><br>"""
            self.add_to_resultpage(data)

        # List cookies
        if 'cookies' in report_content:
            results = self.get_cookies()

            data = """<table class="statistics"><tr>
                    <th><a class="firstletter">N</a><a>ame</a></th>
                    <th><a class="firstletter">V</a><a>alue</a></th>
                    <th><a class="firstletter">U</a><a>ntil</a></th>
                    <th><a class="firstletter">T</a><a>arget</a></th>
                    <th><a class="firstletter">T</a><a>ype</a></th>
                    <th><a class="firstletter">P</a><a>illaged_from_computerid</a></th>
                    <th><a class="firstletter">P</a><a>illaged_from_userid</a></th>
                    <th><a class="firstletter">B</a><a>ypass MFA</a></th></tr>\n"""

            # <a href="#" id="toggle" onClick="toggle_it('tr1');toggle_it('tr2')">
            current_type = 'cookies'
            data += """<TR id=cookies><TD colspan="8" class="toggle_menu" """
            data += f"""onClick="toggle_it('cookies')"><a>Cookies ({len(results)})</a></td></tr>"""
            previous_target = ''
            previous_userid = ''
            previous_computerid = ''
            temp_cookie = ''
            temp = []
            groupindex = 0
            for index_, cred_ in enumerate(results):
                name_, value_, expires_utc, target, _type, \
                    pillaged_from_computerid, pillaged_from_userid = cred_

                if target == previous_target and \
                   pillaged_from_userid == previous_userid and \
                   pillaged_from_computerid == previous_computerid:
                    temp.append((index_, cred_))
                    if value_ != '':
                        temp_cookie = f"{temp_cookie}\\ndocument.cookie=\\'{name_}={value_}\\'"
                    rendering = False
                else:
                    rendering = True
                    previous_target = target
                    previous_computerid = pillaged_from_computerid
                    previous_userid = pillaged_from_userid
                if rendering is True or index_ == (len(results) - 1):
                    groupindex += 1
                    for index, cred in temp:
                        name, value, expires_utc, target, type_cred, \
                              pillaged_from_computerid, pillaged_from_userid = cred
                        # Skip infos of
                        log_debug = f" analysing cookie  {bcolors.WARNING}  {name} {value} "
                        log_debug += f"{type_cred} {target} UTC:{expires_utc} {bcolors.ENDC}"
                        self.logging.debug(log_debug)
                        try:
                            if value == '':
                                continue
                            utc_time = (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc))
                            if (type_cred == "browser-chrome" and (expires_utc != 0) and
                                utc_time < datetime.today()) or \
                               (type_cred != "browser-chrome" and
                               self.datetime_to_time(expires_utc) < datetime.today().strftime('%b %d %Y %H:%M:%S')):
                                log_debug = f" Skipping old cookie  {bcolors.WARNING}  {name} "
                                log_debug += f"{value} {type_cred} {target} {expires_utc} "
                                log_debug += f"{bcolors.ENDC}"
                                self.logging.debug(log_debug)
                                continue
                        #
                        except OSError as ex:
                            error = f" Exception {bcolors.WARNING} Exception in Cookie "
                            error += f" {name} {value} {type_cred} {target}"
                            error += f" {expires_utc} {bcolors.ENDC}"
                            self.logging.debug(error)
                            self.logging.debug(ex)
                            continue
                        # Add browser version
                        # self.logging.debug(f'get browser type browser_type={type_cred},
                        # pillaged_from_computerid={pillaged_from_computerid},
                        # pillaged_from_userid={pillaged_from_userid}')
                        res = self.get_browser_version(
                                browser_type=type_cred,
                                pillaged_from_computerid=pillaged_from_computerid,
                                pillaged_from_userid=pillaged_from_userid
                        )
                        if len(res) > 0:
                            type_cred += f" - {res[0]}"
                        # self.logging.debug(f'Type:{type}')
                        # Get computer infos
                        res = self.get_computer_infos(pillaged_from_computerid)
                        for index_, res2 in enumerate(res):
                            ip_res, hostname = res2
                        computer_info = f"{ip_res} | {hostname}"
                        # pillaged_from_userid
                        if pillaged_from_userid is not None:
                            res = self.get_user_infos(pillaged_from_userid)
                            for index_, pillaged_username in enumerate(res):
                                pillaged_from_userid = pillaged_username[0]
                        else:
                            pillaged_from_userid = str(pillaged_from_userid)

                        if groupindex % 2 == 0:
                            data += f"""<TR class=tableau_resultat_row0 {current_type}=1>"""
                        else:
                            data += f"""<TR class=tableau_resultat_row1 {current_type}=1>"""

                        # Print block
                        name_list = [
                            'estsauthpersistant', 'estsauth', 'sid',
                            'aws-userinfo', 'aws-credz', 'osid', 'hsid', 'ssid',
                            'apisid', 'sapisid', 'lsid', 'sub_session_onelogin',
                            'sub_session_onelogin.com', 'user_session']
                        if name.lower() in name_list:
                            special_style = '''class="cracked"'''
                        else:
                            special_style = ""
                            # On supprime les cookies expirés
                            for info in [name, value]:
                                data += f"""<td {special_style} ><a title="{info}">"""
                                data += f"""{str(info)[:48]}</a></td>"""
                            # Formule a change si on intègre des cookies venant
                            # d'autre chose que Chrome
                            for info in [expires_utc]:
                                try:
                                    if type_cred == "browser-chrome":
                                        date_time = (datetime(1601, 1, 1) +
                                                     timedelta(microseconds=info))
                                        data_time = date_time.strftime('%b %d %Y %H:%M:%S')
                                        data += f"""<td {special_style} ><a title="{info}">"""
                                        data += f"""{data_time} </a></td>"""
                                    else:
                                        date_time = self.datetime_to_time(info)
                                        data += f"""<td {special_style} ><a title="{info}"> """
                                        data += f"""{date_time} </a></td>"""
                                except OSError:
                                    data += f"""<td {special_style} ><a title="{info}"> """
                                    data += f"""{info} </a></td>"""

                            # check for known providers
                            special_ref = ""
                            if '.microsoftonline.com' in target:
                                special_ref = '''href="https://myaccount.microsoft.com/?ref='''
                                special_ref += '''MeControl" target="_blank" "'''
                            elif '.okta.com' in target:  # should be yourdomain.okta.com
                                special_ref = '''href="https://{target}" target="_blank" '''
                            elif ".google.com" in target:
                                special_ref = '''href="https://console.cloud.google.com/" '''
                            elif ".amazon.com" in target:
                                special_ref = '''href="https://console.aws.amazon.com/" "'''
                            elif ".onelogin.com" in target:
                                special_ref = '''href="https://app.onelogin.com/login" "'''
                            elif ".github.com" in target:
                                special_ref = '''href="https://github.com/login" "'''

                            special_ref += f'''title="{target}"'''
                            data += f"""<td {special_style} ><a {special_ref}> """
                            data += f"""{str(target)[:48]} </a></td>"""

                            for info in [type_cred, computer_info, pillaged_from_userid]:
                                data += f"""<TD {special_style} ><A title="{info}"> """
                                data += f"""{str(info)[:48]} </a></td>"""

                            data += f"""<td {special_style} ><button onclick"""
                            data += f"""="CopyToClipboard('{temp_cookie}')">Copy</button></td>"""
                            data += """</tr>\n"""

                    temp = []
                    temp.append((index_, cred_))
                    temp_cookie = f"document.cookie=\\'{name_}={value_}\\'"

            data += """</table><br>"""
            self.add_to_resultpage(data)

        # List gathered files
        if 'files' in report_content:
            results = self.get_file()

            data = """<table class="statistics" id="Files">
                    <tr><th><a class="firstletter">F</a><a>ilename</a></th>
                    <th><a class="firstletter">T</a><a>ype</a></th>
                    <th><a class="firstletter">U</a><a>ser</a></th>
                    <th><a class="firstletter">I</a><a>p</a></th></tr>\n"""
            for index, myfile in enumerate(results):
                try:
                    file_path, filename, extension, \
                               pillaged_from_computerid, pillaged_from_userid = myfile

                    res = self.get_computer_infos(pillaged_from_computerid)
                    for index, res2 in enumerate(res):
                        ip_res, hostname = res2
                    computer_info = f"{ip_res} | {hostname}"
                    res = self.get_user_infos(pillaged_from_userid)
                    for index, res2 in enumerate(res):
                        username = res2[0]
                    special_ref = f'href="file://{file_path}" target="_blank" title="{filename}"'
                    data += f"""<tr><td><A {special_ref}> {filename} </a></td>"""
                    data += f"""<td> {extension} </td><td> {username} </td>"""
                    data += f"""<td> {computer_info} </td></tr>\n"""
                except OSError as ex:
                    error = f" Exception {bcolors.WARNING}  in getting File for"
                    error += f" {file_path} {bcolors.ENDC}"
                    self.logging.debug(error)
                    self.logging.debug(ex)
                    return False
            data += """</table><br>"""
            self.add_to_resultpage(data)

        # Identify user / IP relations
        # Confirm audited scope :
        if 'connected_user' in report_content:
            results = self.get_connected_user()

            data = """<table class="statistics" id="Connected-users"><tr>
            <th><a class="firstletter">U</a><a>sername</a></th>
            <th><a class="firstletter">I</a><a>P</a></th></tr>\n"""

            for index, cred in enumerate(results):
                try:
                    data += f"""<tr><td> {cred[1]} </td><td> {cred[0]} </td></tr>\n"""
                except OSError as ex:
                    error = f" Exception {bcolors.WARNING}  in Identify user "
                    error += f"/ IP relations for {cred} {bcolors.ENDC}"
                    self.logging.debug(error)
                    self.logging.debug(ex)
                    return False
            data += """</table><br>"""
            self.add_to_resultpage(data)

        # Identify Local hash reuse
        if 'hash_reuse' in report_content:
            results = self.get_credz_sam()
            data = """<table class="statistics" id="Local_account_reuse"><tr>
            <th><a class="firstletter">L</a><a>ocal account reuse : </th></tr>\n"""
            for index, cred in enumerate(results):
                username, password, cred_type, pillaged_from_computerid = cred
                res = self.get_computer_infos(pillaged_from_computerid)
                for index, res2 in enumerate(res):
                    ip_res, hostname = res2
                computer_info = f"{ip_res} | {hostname}"
                data += f"""<tr><td> {username} </td><td> {password} </td>"""
                data += f"""<td> {cred_type} </td><td> {computer_info} </td></tr>"""
            data += """</table><br>"""
            self.add_to_resultpage(data)

        # Confirm audited scope :
        if 'audited_scope' in report_content:
            results = self.get_computers()
            data = """<table class="statistics" id="Scope_Audited">
            <tr><th><a class="firstletter">S</a><a>cope Audited : </th></tr>
            <tr><th><a class="firstletter">I</a><a>p</a></th>
            <th><a class="firstletter">H</a><a>ostname</a></th>
            <th><a class="firstletter">D</a><a>omain</a></th>
            <th><a class="firstletter">O</a><a>S</a></th>
            <th><a class="firstletter">S</a><a>mb signing enabled</a></th>
            <th><a class="firstletter">S</a><a>mb v1</a></th>
            <th><a class="firstletter">I</a><a>s Admin</a></th>
            <th><a class="firstletter">C</a><a>onnectivity</a></th>
            </tr>\n"""

            for index, cred in enumerate(results):
                ip_cred, hostname, domain, my_os, \
                         smb_signing_enabled, smbv1_enabled, is_admin, connectivity = cred
                data += "<tr>"
                for info in [ip_cred, hostname, domain, my_os]:
                    data += f"""<td> {info} </td>"""
                if smb_signing_enabled:
                    data += "<td> Ok </td>"
                else:
                    data += """<td><a class="firstletter"> NOT required </a></td>"""
                if smbv1_enabled:
                    data += "<td> Yes </td>"
                else:
                    data += "<td> No </td>"
                if is_admin:
                    data += """<td> Admin </a></td>"""
                else:
                    data += """<td><a class="firstletter"> No </a></td>"""
                for info in [connectivity]:
                    data += f"""<td> {info} </td>"""
                data += "</tr>\n"
            data += """</table><br>\n"""
            self.add_to_resultpage(data)

        # Etat des masterkeyz
        if self.options.debug and 'masterkeys' in report_content:
            results = self.get_masterkeys()
            data = """<table class="statistics" id="Scope_Audited"><tr>
            <th><a class="firstletter">M</a><a>asterkeys : </th></tr>\n"""
            data += """<tr><th><a class="firstletter">G</a><a>uid</a></th>
            <th><a class="firstletter">S</a><a>tatus</a></th>
            <th><a class="firstletter">D</a><a>ecrypted_with</a></th>
            <th><a class="firstletter">D</a><a>ecrypted_value</a></th>
            <th><a class="firstletter">C</a><a>omputer</a></th>
            <th><a class="firstletter">U</a><a>ser</a></th>
            </tr>\n"""

            for index, cred in enumerate(results):
                _cred_id, file_path, guid, status, pillaged_from_computerid, \
                          pillaged_from_userid, decrypted_with, decrypted_value = cred
                data += "<tr>"
                for info in [guid, status, decrypted_with]:
                    data += f"""<td> {info} </td>"""
                for info in [decrypted_value]:
                    data += f"""<td><A title="{info}"> {str(info)[:12]}</a></td>"""

                res = self.get_computer_infos(pillaged_from_computerid)
                for index, res2 in enumerate(res):
                    ip_res, hostname = res2
                computer_info = f"{ip_res} | {hostname}"
                data += f"""<td> {computer_info} </td>"""
                res = self.get_user_infos(pillaged_from_userid)
                for index, res2 in enumerate(res):
                    username = res2[0]
                data += f"""<td> {username} </td>"""
            data += "</tr>\n"
            data += """</table><br>\n"""
            self.add_to_resultpage(data)
        # finalise result page
        data = "</body></html>"
        self.add_to_resultpage(data)

    def datetime_to_time(self,timestamp_utc) -> str:
        return (datetime(1601, 1, 1) + timedelta(microseconds=timestamp_utc)).strftime('%b %d %Y %H:%M:%S')

    def get_dpapi_hashes(self):
        """Get DPAPI hashes from database."""
        user_hashes = []
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT sid,hash FROM dpapi_hash")
        results = cur.fetchall()
        for line in results:
            sid = line[0]
            hash_data = line[1]
            with self.conn:
                cur = self.conn.cursor()
                cur.execute(f"SELECT user_id FROM user_sid WHERE LOWER(sid)=LOWER('{sid}')")
            res1 = cur.fetchall()
            if len(res1) > 0:
                result = res1[0]
                user_id = result[0]
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute(f"SELECT username FROM users WHERE id={user_id}")
                res2 = cur.fetchall()
                if len(res2) > 0:
                    result = res2[0]
                    username = result[0]
                    user_hashes.append((username, hash_data))
        return user_hashes

    def export_mkf_hashes(self):
        """Export MKF hashes."""
        user_hashes = self.get_dpapi_hashes()
        debug_log = f"Exporting {len(user_hashes)} MKF Dpapi hash to "
        debug_log += f"{self.options.output_directory}"
        self.logging.debug(debug_log)

        for algo_type in [1, 2]:
            for context in [1, 2, 3]:
                filename = Path(self.options.output_directory, f"MKFv{algo_type}_type_{context}")
                if os.path.exists(filename):
                    os.remove(filename)
        for entry in user_hashes:
            try:
                username = entry[0]
                hash_data = entry[1]
                # on retire les hash "MACHINE$"
                if username != "MACHINE$":
                    # Pour le moment on copie juste les hash.
                    # Voir pour faire evoluer CrackHash et prendrre username:hash
                    algo_type = int(hash_data.split('*')[0][-1])
                    context = int(hash_data.split('*')[1])
                    filename = Path(self.options.output_directory,
                                    f"MKFv{algo_type}_type_{context}")
                    filename2 = Path(self.options.output_directory,
                                     f"MKFv{algo_type}_type_{context}_WITH_USERNAME")
                    with open(filename, 'ab') as hashfile:
                        hashfile.write(f"{hash_data}\n".encode('utf-8'))
                    with open(filename2, 'ab') as hashfile:
                        hashfile.write(f"{username}:{hash_data}\n".encode('utf-8'))
            except OSError as ex:
                self.logging.error(f"Exception in export dpapi hash to {filename}")
                self.logging.debug(ex)

    def get_dcc2_hashes(self):
        """Return DCC hashes."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT DISTINCT username,password FROM credz "
                        "WHERE LOWER(type)=LOWER('DCC2') ORDER BY username ASC")
        results = cur.fetchall()
        return results

    def export_dcc2_hashes(self):
        """Export DCC hashes."""
        user_hashes = self.get_dcc2_hashes()
        filename = Path(self.options.output_directory, 'hash_DCC2')
        debug_log = f"Exporting {len(user_hashes)} DCC2 hash to {self.options.output_directory}"
        self.logging.debug(debug_log)
        if os.path.exists(filename):
            os.remove(filename)
        for entry in user_hashes:
            try:
                username = entry[0]
                hash_data = entry[1]
                with open(filename, 'ab') as dcc2_file:
                    dcc2_file.write(f"{username}:{hash_data}\n".encode('utf-8'))
            except OSError as ex:
                self.logging.error(f"Exception in export DCC2 hash to {filename}")
                self.logging.debug(ex)
        self.logging.debug("Export Done!")

    def export_credz(self, distinct=True):
        """Export credentials."""
        user_credz = self.get_credz(distinct=distinct)
        filename = Path(self.options.output_directory, 'raw_credz')
        self.logging.info(f"Exporting {len(user_credz)} credz to {self.options.output_directory}")
        if os.path.exists(filename):
            os.remove(filename)
        for _index, cred in enumerate(user_credz):
            username, password = cred
            try:
                with open(filename, 'ab') as raw_file:
                    raw_file.write(f"{username}:{password}\n".encode('utf-8'))
            except OSError as ex:
                self.logging.error(f"Exception in export raw credz to {filename}")
                self.logging.debug(ex)
        self.logging.debug("Export Done!")

    def export_sam(self):
        """Export SAM credentials."""
        user_credz = self.get_credz(distinct_sam=True)
        filename = os.path.join(self.options.output_directory, 'raw_sam')
        debug_log = f"Exporting {len(user_credz)} NTLM credz to {self.options.output_directory}"
        self.logging.info(debug_log)
        if os.path.exists(filename):
            os.remove(filename)
        for _index, cred in enumerate(user_credz):
            username, password = cred
            try:
                with open(filename, 'ab') as sam_file:
                    sam_file.write(f"{username}:{password}\n".encode('utf-8'))
            except OSError as ex:
                self.logging.error(f"Exception in export raw sam to {filename}")
                self.logging.debug(ex)
        self.logging.debug("Export Done!")

    def export_cookies(self):
        """Export cookies."""
        user_credz = self.get_cookies()
        filename = Path(self.options.output_directory, 'raw_cookies')
        self.logging.info(f"Exporting {len(user_credz)} cookies to {self.options.output_directory}")
        if os.path.exists(filename):
            os.remove(filename)
        for _index, cred in enumerate(user_credz):
            name, value, _expires_utc, target, _cred_type, \
                  _pillaged_from_computerid, _pillaged_from_userid = cred
            try:
                with open(filename, 'ab') as cookies_file:
                    cookies_file.write(f"{target}:{name}:{value}\n".encode('utf-8'))
            except OSError as ex:
                self.logging.error(f"Exception in export raw credz to {filename}")
                self.logging.debug(ex)
        self.logging.debug("Export Done!")

    def export_lsa(self):  # TODO not used ?
        """Export LSA credentials."""
        user_credz = self.get_credz(credz_type='LSA')
        filename = Path(self.options.output_directory, 'raw_lsa.csv')
        debug_log = f"Exporting {len(user_credz)} LSA secrets to {self.options.output_directory}"
        self.logging.info(debug_log)
        if os.path.exists(filename):
            os.remove(filename)
        for _index, cred in enumerate(user_credz):
            _cred_id, _file_path, username, password, _target, \
                      _cred_type, pillaged_from_computerid, _pillaged_from_userid = cred
            # Get computer infos
            res = self.get_computer_infos(pillaged_from_computerid)
            if '#' in username:
                service = username.split('#')[0]
                username = username[len(service) + 1:]
            else:
                service = ''
            try:
                for _index, res2 in enumerate(res):
                    cred_ip, hostname = res2
                with open(filename, 'ab') as lsa_file:
                    data = f"{hostname},{cred_ip},{service},{username},{password}\n"
                    lsa_file.write(data.encode('utf-8'))
            except OSError as ex:
                self.logging.error(f"Exception in export raw LSA Secrets to {filename}")
                self.logging.debug(ex)
        self.logging.debug("Export Done!")

    def get_credz_count(self, current_type, extra_conditions=''):
        """Return credentials count for a given type."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT count(id) FROM credz "
                        f"WHERE LOWER(type)=LOWER('{current_type}') {extra_conditions}")
            results = cur.fetchall()
        return results

    def get_certificates(self, distinct=False):
        """Return certificates from Database"""
        if distinct:
            with self.conn:
                cur = self.conn.cursor()
                cur.execute("SELECT DISTINCT subject, issuer, guid FROM certificates "
                            "ORDER BY subject DESC, (case when client_auth then 1 else 2 end) ASC")
        else:
            with self.conn:
                cur = self.conn.cursor()
                cur.execute("SELECT * FROM certificates "
                            "ORDER BY subject DESC, (case when client_auth then 1 else 2 end) ASC")
        results = cur.fetchall()
        return results

    def get_credz(self, filter_term=None, credz_type=None, distinct=False, distinct_sam=False):
        """Return credentials from the database."""
        if credz_type:
            with self.conn:
                cur = self.conn.cursor()
                cur.execute(f"SELECT * FROM credz WHERE LOWER(type)=LOWER('{credz_type}')")

        # if we're filtering by username
        elif filter_term and filter_term != '':
            with self.conn:
                cur = self.conn.cursor()
                cur.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)",
                            [f'%{filter_term}%'])
        elif distinct:
            with self.conn:
                cur = self.conn.cursor()
                cur.execute("SELECT DISTINCT username,password FROM credz WHERE "
                            "LOWER(type) NOT IN ('sam','lsa','dcc2') AND password NOT IN ('')")
        elif distinct_sam:
            with self.conn:
                cur = self.conn.cursor()
                cur.execute("SELECT DISTINCT username,password FROM credz WHERE "
                            "LOWER(type) IN ('sam') AND password NOT IN ('')")
        # otherwise return all credentials
        else:
            with self.conn:
                cur = self.conn.cursor()
                cur.execute("SELECT * FROM credz ORDER BY type DESC, target ASC ")

        results = cur.fetchall()
        return results

    def get_credz_sam(self):
        """Return SAM credentials."""
        credentials = []
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT count(DISTINCT pillaged_from_computerid), password FROM credz "
                        "WHERE LOWER(type)=LOWER('SAM') AND "
                        "LOWER(password) != LOWER('31d6cfe0d16ae931b73c59d7e0c089c0') "
                        "GROUP BY password ORDER BY username ASC")
        results = cur.fetchall()

        for _index, res in enumerate(results):
            count, passw = res
            if count > 1:
                with self.conn:
                    cur = self.conn.cursor()
                    cur.execute("SELECT DISTINCT username, password, type, "
                                "pillaged_from_computerid FROM credz "
                                "WHERE LOWER(type)=LOWER('SAM') AND LOWER(password)"
                                f"=LOWER('{passw}') ORDER BY password ASC, username ASC ")
                credentials += cur.fetchall()
        return credentials

    def get_computers(self):
        """Return all computers."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT ip, hostname, domain, os, smb_signing_enabled, smbv1_enabled, "
                        "is_admin, connectivity from computers ORDER BY ip")
        results = cur.fetchall()
        return results

    def get_browser_version(self, browser_type, pillaged_from_computerid, pillaged_from_userid):
        """Return all browser versions."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(f"SELECT version from browser_version WHERE browser_type "
                        f"LIKE '{browser_type}' AND pillaged_from_computerid="
                        f"'{pillaged_from_computerid}' AND pillaged_from_userid="
                        f"'{pillaged_from_userid}' LIMIT 1")
        results = cur.fetchall()
        return results

    def get_masterkeys(self):
        """Return all master keys."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT id, file_path, guid, status, pillaged_from_computerid, "
                        "pillaged_from_userid, decrypted_with, decrypted_value "
                        "FROM masterkey ORDER BY pillaged_from_computerid ASC, "
                        "pillaged_from_userid ASC")
        results = cur.fetchall()
        return results

    def get_computer_infos(self, computer_id):
        """Return computer informations for a given id. """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(f"SELECT ip,hostname FROM computers WHERE id={computer_id} LIMIT 1")
            results = cur.fetchall()
        return results

    def get_user_infos(self, user_id):
        """Return user informations for a given id. """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(f"SELECT username FROM users WHERE id={user_id} LIMIT 1")
            results = cur.fetchall()
        return results

    def get_user_id(self, username):
        """Return user id for a given username. """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(f"SELECT id FROM users WHERE username={username} LIMIT 1")
            results = cur.fetchall()
        return results

    def get_connected_user(self):
        """Return connected users. """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT ip, username FROM connected_user ORDER BY username ASC, ip ASC")
            results = cur.fetchall()
        return results

    def get_os_from_ip(self, user_ip):
        """Return OS for a given IP."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute(f"SELECT os FROM computers WHERE ip={user_ip} LIMIT 1")
            results = cur.fetchall()
        return results

    def get_file(self):
        """Return extracted files."""
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT file_path, filename, extension, pillaged_from_computerid, "
                        "pillaged_from_userid  FROM files ORDER BY "
                        "pillaged_from_computerid ASC, extension ASC")
            results = cur.fetchall()
        return results

    def get_cookies(self):
        """Return extracted cookies. """
        with self.conn:
            cur = self.conn.cursor()
            cur.execute("SELECT name, value, expires_utc, target,type, "
                        "pillaged_from_computerid, pillaged_from_userid "
                        "FROM cookies ORDER BY pillaged_from_computerid ASC, "
                        "pillaged_from_userid ASC, target ASC, expires_utc DESC")
            results = cur.fetchall()
        return results
