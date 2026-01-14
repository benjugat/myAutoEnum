import requests
import os
import ssl
import OpenSSL
import socket
import sys
import shodan
from concurrent import futures
from src.DNSLookuper.dnslookuper import DNSLookuper
from controller.util import *

#
# ------------------------
# Domain discovery modules
# ------------------------
#

def reverse_ip(ip):
	# Return a set() of DNS names from a reverse DNS IP resolution.
	# Usage of viewdns.info API.
	# API KEY is needed!
	results = set()
	if os.environ.get('VIEWDNS_API_KEY'):
		r = requests.get('https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json' % (ip, os.environ.get('VIEWDNS_API_KEY')), proxies=get_proxy())
		if r.status_code == 200 and 'limit' not in r.text:
			print(r.text)
			r_json = r.json()
			if int(r_json['response']['domain_count']) > 0:		
				for name in r_json['response']['domains']:
					if '*.' in name['name']:
						results.add(name['name'][2:])
					else:
						results.add(name['name'])
	else:
		print_error("No ViewDNS API key was provided!")
	return results


def read_subject_from_certificate(ip, port):
	# Read Subject from server certificate and obtain a DNS name
	# Usage of OpenSSL
	# No API KEY.
	socket.setdefaulttimeout(2)
	dns_names = set()
	try:
		cert = ssl.get_server_certificate((ip, port))
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		for i in x509.get_subject().get_components():
			if i[0] == b"CN":
				dns_names.add(i[1].decode())
		print_debug("	OpenSSL %s:%s - %s" % (ip, str(port), i[1].decode()))
		return dns_names
	except socket.timeout:
		print_error("	Timeout %s:%s" % (ip, str(port)))
		return None
	except :
		return None

def read_certificate(ip):
	# Check certificates from a lot of ports and get a list of domain names
	# Usage of OpenSSL
	# No API KEY.
	PORTS = [443,8443,4443,5000,5443,6443,7443,9443]
	dns_names = set()
	for port in PORTS:
		subject = read_subject_from_certificate(ip, port)
		if subject:
			for sub in subject:
				if sub:
					if '*.' in sub:
						dns_names.add(str(sub[2:]))
					else:
						dns_names.add(str(sub))
	return dns_names

#
# ---------------------------
# SubDomain discovery modules
# ---------------------------
#


def similar_certificate(domain_name):
	# Return a set() of DNS names looking similar certificates from a domain.
	# Usage of crt.sh
	# No API KEY needed.
	r = requests.get('https://crt.sh/?q=%s&output=json' % domain_name, proxies=get_proxy())
	dns_names = set()
	if r.status_code == 200:
		r_json = r.json()
		# Parse Common Name
		for i in r_json:
			if i['common_name'] and '@' not in i['common_name'] and domain_name in i['common_name']:
				if '*.' in i['common_name']:
					dns_names.add('.'.join(i['common_name'].split('.')[1:]))
				else:
					dns_names.add(i['common_name'])
		# Parse Matching Identities
			data = i['name_value']
			for j in data.split():
				if '@' not in j and domain_name in j:
					if '*.' in j:
						dns_names.add('.'.join(j.split('.')[1:]))
					else:
						dns_names.add(j)
	return dns_names


def wayback_domains(domain_name):
	# Get a list of domain names from wayback machine.
	# Based on https://gist.github.com/mhmdiaa/adf6bff70142e5091792841d4b372050
	# No API KEY needed
	r = requests.get('http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % domain_name, proxies=get_proxy())
	dns_names = set()

	if r.status_code == 200:
		r_json = r.json()		
		if len(r_json) > 1:
			# Delete "original" from the list
			r_json.pop(0)

			for i in r_json:
				for url in i:
					domain = str_get_domain_from_url(url)
					if domain and domain_name in domain:
						dns_names.add(domain)
	return dns_names

def fuzz_dns(domain_name, dictfile='./src/subdomains-top1mil-5000.txt'):
	# Return a set() of subdomains doing bruteforcing A queries. 
	# Based on https://github.com/mvc1009/DNSLookuper
	# No API KEY needed.
	# dictfile='./src/subdomains-top1mil-5000.txt'
	results = set()
	fuzz = list()

	if os.path.isfile(dictfile):
		with open(dictfile) as fd:
			fuzz = [f"{sub.rstrip()}.{domain_name}" for sub in fd]
		dnslook = DNSLookuper(domains=fuzz)
		lookup = dnslook.resolve()
		for l in lookup:
			if l['IP'] != 'None':
				results.add(l['DNS'])

	return results

def shodan_domain(domain_name):
	dns_names = set()
	if os.environ.get('SHODAN_API_KEY'):
		sh = shodan.Shodan(os.environ.get('SHODAN_API_KEY'))
		try:
			rjson = sh.dns.domain_info(domain_name, history=True)
			for subdomain_name in rjson['subdomains']:
				if subdomain_name and subdomain_name != '*':
					dns_names.add(subdomain_name + '.' + domain_name)
					print(subdomain_name + '.' + domain_name)
		except:
			pass
	else:
		print_error("No Shodan API key was provided!")
	return dns_names