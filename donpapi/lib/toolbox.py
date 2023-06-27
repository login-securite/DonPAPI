#!/usr/bin/env python
# coding:utf-8
import re, os, ipaddress
import logging
from impacket.structure import pretty_print

ipv4_re=r'^(?:[0-9,\-]{1,}\.){3}[0-9,\-]{1,}$'
def split_targets(target: str):
	all_ips = []
	if os.path.exists(target) and not os.path.isdir(target):
		f = open(target)
		targets = f.read().split('\n')
		f.close()
	elif ";" in target:
		targets = target.split(';')
	else:
		targets = [target]

	tmp_target = []
	for target in targets:
		if len(target)<=2:
			continue
		try:
			if target.count('/') == 1:  # CIDR Notation
				target,cidr = target.split('/')
			else:
				cidr = '32'

			if re.fullmatch(ipv4_re,target)!=None:
				tmp = target.split('.')
				tmp2 = [[], [], [], []]
				for index, subtmp in enumerate(tmp):
					if ',' in subtmp:
						tmp2[index] = subtmp.split(',')
					elif '-' in subtmp:
						start, stop = subtmp.split('-')
						start = int(start)
						stop = int(stop)
						for val in range(start, stop + 1):
							tmp2[index].append(str(val))
					else:
						tmp2[index] = [subtmp]

				for ip0 in tmp2[0]:
					for ip1 in tmp2[1]:
						for ip2 in tmp2[2]:
							for ip3 in tmp2[3]:
								all_ips+=[str(ip) for ip in ipaddress.IPv4Network('{ip0}.{ip1}.{ip2}.{ip3}/{cidr}'.format(ip0=ip0, ip1=ip1, ip2=ip2, ip3=ip3,cidr=cidr))]
			else :
				all_ips.append(target)
				#machine name

				logging.error("IP {ip} not a correct ip or is a machine name ... lets try it ".format(ip=target))
		except Exception as e:
			if logging.getLogger().level == logging.DEBUG:
				import traceback
				traceback.print_exc()
				logging.error(str(e))
	return all_ips

def is_guid(value: str):
	UUIDv4 = '/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i'
	GUID = re.compile(r'^(\{{0,1}([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})\}{0,1})$')
	if GUID.match(value):
		return True
	else:
		return False

class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

def reg_parser(data,logging,remote_data):
	basereg='\\'
	for line in data:
		try:
			if not '\t' in line:
				basereg = line
			else:
				values = line.split('\t')
				logging.debug(f"[{basereg}{values[0]}] : {values[1]} -> {values[2]} ")
				remote_data[f"{basereg}{values[0]}"] = [f"{values[1]}", f"{values[2]}"]
		except :
			continue

def reg_finder(entry=None, type=None, value=None,logging='',remote_data=[]):
	res = []
	# Search per KeyName
	if entry != None:
		for _entry in remote_data:
			if entry in _entry:
				res.append(_entry)
	elif value != None:
		# Search per KeyValue
		for _entry in remote_data:
			if value in remote_data[_entry][1]:
				if type == None or type == remote_data[_entry][0]:
					res.append(_entry)
	return res


def hexdump(data, indent = '\t'):
	try:
		result = ''
		if data is None:
			return result
		if isinstance(data, int):
			data = str(data).encode('utf-8')
		if data[:2]=="b'":
			x=data[2:-1].encode()
		else:
			x=bytearray(data)
		strLen = len(x)
		i = 0
		while i < strLen:
			line = " %s%04x   " % (indent, i)
			for j in range(16):
				if i+j < strLen:
					line += "%02X " % x[i+j]
				else:
					line += u"   "
				if j%16 == 7:
					line += " "
			line += "  "
			line += ''.join(pretty_print(x) for x in x[i:i+16] )
			result += ''.join(pretty_print(x) for x in x[i:i + 16])
			#result+=f'{line}\n'
			i += 16
	except Exception as ex:
		print(f'Hexdump exception for data {data} \n {ex}')
	return result