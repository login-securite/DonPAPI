#!/usr/bin/env python
# coding:utf-8
import re, os, ipaddress
import logging


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
