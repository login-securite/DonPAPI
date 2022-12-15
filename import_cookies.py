import sys
import re
import json

f=open(sys.argv[1],'r').readlines()
domain=sys.argv[2]

reg="""\[Chrome Cookie\]\s+for\s+([A-Za-z0-9-.]+)\s+\[\s*([^:]+):([^\s]*)\s*]"""

#cookieJSON=[]

for line in f:
	if "[Chrome Cookie]" in line and domain in line:

		res=re.search(reg,line)
		host=res.group(1)
		name=res.group(2)
		val=res.group(3)

		#cookieJSON.append({"name":name,"value":val,"domain":host,"secure":True,"path":"/"})
		print("document.cookie='%s=%s;path=/'"%(name,val))

#print(json.dumps(cookieJSON))