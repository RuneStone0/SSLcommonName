#!/usr/bin/python2

import ssl,sys,os,socket
global filename

### Description ###
# The purpose of this script is to quickly enumerate hostnames out from a list of IPs.
# We first extract the CN (commonName) in all SSL cert. from our list of IPs. Output
# example:
#   127.0.0.1 localhost
#   127.0.0.2 router.local
#   127.0.0.3 [www.google.com]
# Note: Hostnames written in hard brackets could not be resolved to the IP from which 
# the hostname was extracted.
###################

### TODO ###
# * Support input file with both hostnames and IPs
# * Support input file with IP:PORT formatting
############

def pscan(address, port): 
	'''Simple port scanner'''
	s = socket.socket() 
	s.settimeout(2)
	try:
		s.connect((address, port))
		return 1
	except socket.error, e: return 0 

def get_commonName(host,port=443):
	if not pscan(host,port) == 1: return "" # Check if port is open

	# Get CN from cert.
	try:
		cert=ssl.get_server_certificate((host,port))
		cert = ssl.PEM_cert_to_DER_cert(cert)
		begin = cert.rfind('\x06\x03\x55\x04\x03') + 7
		end = begin + ord(cert[begin - 1])
		return str(cert[begin:end])
	except: return ""

def read_input():
	if (len(sys.argv) < 2): print "Usage: getcn.py {filename}" # Print help
	else:
		global filename
		filename = sys.argv[1]
		if not os.path.isfile(filename): sys.exit("Input file not found")


def nslookup(hostname):
	''' Resolves hostname to IP '''
	try:	return socket.gethostbyname(hostname)
	except: return None

def check_cn(cn, ip):
	''' Checks if CN resolves to the same IP we got the CN from'''
	res =  nslookup(cn)
	if not res == None:
		if res == "ip": return True
		else:	return False

def __main__():
	read_input()
	fread = open(filename, 'r') # Read input file
	for ip in fread:
		if len(ip)>3: # Ignore blank lines
			ip = ip.strip()
			ip_cn = get_commonName(ip)
			res = ""
			
			# Output result
			if str(nslookup(ip_cn)) == ip: 	res = ip_cn
			else:
				if len(ip_cn)>1: res = "["+str(ip_cn)+"]"
			print ip + "\t" + res
			
__main__()
