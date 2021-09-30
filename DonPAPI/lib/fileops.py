import copy
import ntpath
import os
from datetime import time
import time as time2
from pathlib import Path
from impacket.smbconnection import SMBConnection
#from impacket.examples.secretsdump import RemoteOperations
from DonPAPI.lib.reg import RegHandler

from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.dtypes import NULL
from DonPAPI.lib.toolbox import bcolors
from DonPAPI.lib.wmi import WMI

class MyFileOps:
	def __init__(self, smb,logger,options):
		self.smb=smb
		self.logging = logger
		self.options=options
		self.pwd = '\\'
		self.share = None

	def do_use(self, line):
		self.share = line
		self.tid = self.smb.connectTree(line)
		self.pwd = '\\'
		self.do_ls('' ,'', False)

	def get_shares(self):
		try:
			self.logging.debug(f"[{self.options.target_ip}] Listing Shares")
			resp = self.smb.listShares()
			result = []
			for i in range(len(resp)):
				self.logging.debug(resp[i]['shi1_netname'][:-1])
				result.append(resp[i]['shi1_netname'][:-1])
			return result
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception  Listing Shares {bcolors.ENDC}")
			self.logging.debug(ex)

	def do_ls(self, directory='', wildcard='*', display=True):
		if self.tid is None:
			self.logging.debug("No share selected")
			return
		if directory=='':
			directory =self.pwd
		if wildcard == '':
			wildcard='*'
			pwd = ntpath.join(directory, '*')
		else:
			pwd = ntpath.join(directory, wildcard)
		completion = []
		pwd = pwd.replace('/', '\\')
		pwd = ntpath.normpath(pwd)
		self.logging.debug(	f"[{self.options.target_ip}] Listing directories and files in {self.share} // {pwd} with filter {wildcard}")
		try:
			for f in self.smb.listPath(self.share, pwd):
				if display is True:
					self.logging.debug("%crw-rw-rw- %10d  %s %s" % ('d' if f.is_directory() > 0 else '-', f.get_filesize(), time2.ctime(float(f.get_mtime_epoch())),	f.get_longname()))
				completion.append((f.get_longname(), f.is_directory()))
			return copy.deepcopy(completion)
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception in Do_ls {bcolors.ENDC}")
			self.logging.debug(ex)
			return copy.deepcopy(completion)


	def get_file(self, filesource, filedest='',allow_access_error=False):
		self.logging.debug("Downloading file %s" % os.path.basename(filesource))
		if self.tid is None:
			self.logging.debug("No share selected")
			return None
		if filedest == "":
			# on stock dans ./self.options.target_ip/meme path
			filedest = os.path.join(os.path.join(self.options.output_directory,self.options.target_ip), filesource).replace('\\', '/')
			Path(os.path.join(os.path.join(self.options.output_directory,self.options.target_ip), os.path.split(filesource.replace('\\', '/'))[0])).mkdir(parents=True, exist_ok=True)
		try:
			fh = open(filedest, 'wb')
			filesource = filesource.replace('/', '\\')
			self.smb.getFile(self.share, filesource, fh.write)
			fh.close()
			return filedest
		except Exception as ex:
			self.logging.debug(f"Error downloading file {filesource}")
			self.logging.debug(ex)
			if allow_access_error and 'STATUS_SHARING_VIOLATION' in str(ex):
				self.logging.debug(f"[{self.options.target_ip}] [+] files Might not be accessible - trying to duplicate it with esentutl.exe ")
				return self.get_file2(filesource, filedest='')
			else:
				return None

	def get_file2(self, filesource, filedest=''):
		try:
			#full_path=self.share
			filesource_tmp = filesource + '.tmp'
			self.logging.debug("Copying file %s to %s" % (os.path.basename(filesource),os.path.basename(filesource_tmp)))
			my_wmi=WMI(self.smb,self.logging,self.options)
			self.logging.debug(f'"running esentutl.exe /y "C:\\{filesource}" /d "C:\\{filesource_tmp}"')
			my_wmi.execute(commands=[f'cmd.exe /Q /c esentutl.exe /y "C:\\{filesource}" /d "C:\\{filesource_tmp}"'])
			# esentutl.exe /y source /d dest
			time2.sleep(1)

		except Exception as ex:
			self.logging.debug(f"Error in WMI copy file : {filesource}")
			self.logging.debug(ex)
			#return None

		if self.tid is None:
			self.logging.debug("No share selected")
			return None
		if filedest == "":
			# on stock dans ./self.options.target_ip/meme path
			filedest = os.path.join(os.path.join(self.options.output_directory,self.options.target_ip), filesource).replace('\\', '/')
			Path(os.path.join(os.path.join(self.options.output_directory,self.options.target_ip), os.path.split(filesource.replace('\\', '/'))[0])).mkdir(parents=True, exist_ok=True)
		try:
			fh = open(filedest, 'wb')
			filesource_tmp = filesource_tmp.replace('/', '\\')
			self.logging.debug(f"Downloading file2 {filesource_tmp}")
			self.smb.getFile(self.share, filesource_tmp, fh.write)
			'''
			myremotefile=RemoteFile(smbConnection=self.smb,fileName=filesource_tmp, share=self.share, access=FILE_READ_DATA)
			myremotefile.open()
			data=' '
			while data!=b'':
				data=myremotefile.read(4096)
				fh.write(data)
				print(f"{data}")'''
			fh.close()
			#Deleting temp file
			self.logging.debug(f'"running del "C:\\{filesource_tmp}"')
			my_wmi = WMI(self.smb, self.logging, self.options)
			my_wmi.execute(commands=[f'cmd.exe /Q /c del "C:\\{filesource_tmp}"'])
			return filedest
		except Exception as ex:
			self.logging.debug(f"Error downloading file {filesource}")
			self.logging.debug(ex)
			return None

	def get_reccursive_files(self,path,wildcard='*'):
		try:
			blacklist = ['.', '..']
			my_directory = self.do_ls(path, wildcard=wildcard, display=False)
			for infos in my_directory:
				longname, is_directory = infos
				self.logging.debug("ls returned file %s" % longname)
				if longname not in blacklist :
					if is_directory : # and longname == 'profiles.ini':
						self.get_reccursive_files(ntpath.join(path, longname),wildcard=wildcard)
					else:
						self.get_file(ntpath.join(path, longname))
		except Exception as ex:
			self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception  get_reccursive_files of {path} {bcolors.ENDC}")
			self.logging.debug(ex)

	def get_download_directory(self,filesource=''):
		return os.path.join(os.path.join(self.options.output_directory, self.options.target_ip), filesource).replace('\\','/')

class MyRegOps():
	def __init__(self, logger,options):
		self.logging = logger
		self.options=copy.deepcopy(options)

		self.options.action='QUERY'
		self.options.keyName = None
		self.options.s = None
		self.options.v = None
		self.options.ve = None
		self.options.target_ip = self.options.target_ip
		self.myRegHandler = None


	def reg_init(self):
		self.logging.debug(f"[{self.options.target_ip}] Reg Init")
		options=copy.deepcopy(self.options)
		self.myRegHandler = RegHandler(self.options.username, self.options.password, self.options.domain, options)
		self.logging.debug(f"[{self.options.target_ip}] Reg Handler Initialised Ok")

	def close(self):
		if self.myRegHandler is not None :
			self.myRegHandler.close()

	def get_reg_value(self,reg_path,reg_key=None):
		try:
			# self.myRegHandler.__options.action='QUERY'
			self.options.keyName = reg_path
			self.options.s = False
			if reg_key == None:
				self.options.v = None
				self.options.ve = True
			else:
				self.options.v = reg_key
				self.options.ve = False

			self.reg_init()
			self.logging.debug(f"[{self.options.target_ip}] Querying reg : {self.options.keyName}")
			#self.myRegHandler=RegHandler(self.options.username, self.options.password, self.options.domain, self.options)
			value=self.myRegHandler.run(self.options.target_ip,self.options.target_ip)
			return value
		except Exception as ex:
				self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception get_reg_value {bcolors.ENDC}")
				self.logging.debug(ex)

	def get_reg_list(self,reg_path):
		try:
			#self.myRegHandler.__options.action='QUERY'
			self.options.keyName = reg_path
			self.options.s = True
			self.options.v = False
			self.options.ve = False
			self.reg_init()
			self.logging.debug(f"[{self.options.target_ip}] Querying reg : {self.options.keyName}")
			#self.myRegHandler=RegHandler(self.options.username, self.options.password, self.options.domain, self.options)
			self.myRegHandler.run(self.options.target_ip,self.options.target_ip)

		except Exception as ex:
				self.logging.debug(f"[{self.options.target_ip}] {bcolors.WARNING}Exception get_reg_list {bcolors.ENDC}")
				self.logging.debug(ex)


from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

class RemoteFile:
    def __init__(self, smbConnection, fileName, share='ADMIN$', access = FILE_READ_DATA | FILE_WRITE_DATA ):
        self.__smbConnection = smbConnection
        self.__share = share
        self.__access = access
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess= self.__access)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__fid = None

    def delete(self):
        self.__smbConnection.deleteFile(self.__share, self.__fileName)

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return "\\\\{}\\{}\\{}".format(self.__smbConnection.getRemoteHost(), self.__share, self.__fileName)