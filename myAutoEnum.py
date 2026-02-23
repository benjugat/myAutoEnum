import os,sys
import config

from datetime import datetime

from model.scope import Scope
from model.host import Host
from model.domain import Domain
from model.subdomain import SubDomain
from model.webpage import WebPage
from controller.db import *
from controller.util import *
from discovery.discovery import *
from discovery.modules import *
from compare.comparer import *
from enumerate.enumeration import *
from enumerate.modules import *
from export.parser import *

try:
	import argparse
except:
	print_error('argparse is not installed. Try "pip install argparse"')
	sys.exit(0)

try:
	import mongoengine as db
except:
	print_error('mongoengine is not installed. Try "pip install mongoengine"')
	sys.exit(0)
try:
	from dotenv import load_dotenv
except:
	print_error('python-dotenv is not installed. Try "pip install python-dotenv"')

try:
	import shodan
except:
	print_error('shodan is not isntalled. Try "pip install shodan"')

def init():
	try:
		# Loading .env variables
		load_dotenv()
		# Connecting to the Database
		print_status("Connecting to the Database")
		db.connect(host=os.environ.get("DB_URL"))
		print(os.environ.get("DB_URL"))
	except:
		print_error("Err while connecting to mongodb")
		sys.exit(0)


def read_scope():

	# Scope
	new_scope(config.name)

	if config.ip_file:
		# IPs
		for ip in open(config.ip_file):
			new_host(config.name, ip.rstrip())

	if config.domain_file:
		# Domains
		for domain_name in open(config.domain_file):
			new_domain(config.name, domain_name.rstrip())

	if config.subdomain_file:
		# Subdomains
		for subdomain_name in open(config.subdomain_file):
			new_subdomain(config.name, subdomain_name.rstrip())


def discover(discovery_modules):

	# Getting Domains/SubDomains from IPs
	ips = get_all_ips()
	for ip in ips:
		if ip:
			find_domains(discovery_modules, args.name, ip)

	# Getting SubDomains from Domains
	domain_names = get_all_domain_names()
	if domain_names:
		for domain_name in domain_names:
			find_subdomains(discovery_modules, args.name, domain_name)

def discover_websites():
	subdomain_names = get_scope_subdomain_names()
	for subdomain_name in subdomain_names:
		find_websites(subdomain_name)

def compare():
	# Compare the Subdomains with the IPs in scope, and store the IP address of the subdomain in scope.
	# Note: if the is a load balancer present, it can cause some problems.
	ips = get_all_ips()
	subdomain_names = get_all_subdomain_names()
	compare_scope(ips, subdomain_names)

def enum(enum_modules):

	ips = get_all_ips()
	for ip in ips:
		enum_hosts(enum_modules, ip)
	
	domain_names = get_all_domain_names()
	for domain_name in domain_names:
		enum_domains(enum_modules, domain_name)
	
	subdomain_names = get_scope_subdomain_names()
	for subdomain_name in subdomain_names:
		enum_subdomains(enum_modules, subdomain_name)
	
	urls = get_all_webpages_urls()
	for url in urls:
		enum_webpages(enum_modules, url)

'''
# Cherry Tree output format
# Made with https://asciiflow.com/#/
#
# Scope
#   │
#   ├─► Host
#   │   │
#   │   └─► SubDomain
#   │
#   ├─► Domain
#   │
#   │
#   └─► Vulnerabilities
'''
def export():

	# Parse Scope
	scope = get_scope(config.name)
	results_json =	parse_scope(config.name)

	# Parse Domains
	domain_names = get_all_domain_names()
	for domain_name in domain_names:
		results_json['sub_node'][1]['sub_node'].append(parse_domain(domain_name))

	# Parse Hosts
	ips = get_all_ips()
	subdomain_names = get_scope_subdomain_names()
	for ip in ips:
		host_parsed = parse_host(ip)
		
		# Parse Subdomains
		for subdomain_name in subdomain_names:
			if ip in get_subdomain_ip(subdomain_name):
				subdomain_parsed = parse_subdomain(subdomain_name)
				# Parse Webs
				urls = get_subdomain_urls(subdomain_name)
				for url in urls:
					webpage_parsed = parse_webpage(url)
					subdomain_parsed['sub_node'].append(webpage_parsed)
				host_parsed['sub_node'].append(subdomain_parsed)
		results_json['sub_node'][0]['sub_node'].append(host_parsed)




	# Parse Webs
	urls = get_all_webpages_urls()
	for url in urls:
		parse_webpage(url)

	# Export json
	date = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
	filename = '/tmp/myautoenum_results_%s.json' % date
	export_json(results_json, filename)
	
	# Create cherry
	outputfile = '%s.ctd' % config.name

	create_cherry(filename, outputfile)

def main():
	
	# Initialize
	init()
	
	discovery_modules = [
		'reverse_ip',
		'shodan_domain',
		'similar_certificate',
		'read_certificate',
		'wayback_domains',
		#'fuzz_dns'
	]
	
	enum_modules = [
		'ip_history',
		'wayback_urls',
		'shodan_host',
		'whois_ip',
		'gowitness'
	]
	
	# Defining the scope
	print("")
	print_status("Defining the Scope")
	print("----------------------")
	read_scope()
		
	# Discovery
	print("")
	print_status("Starting Discovery")
	print("----------------------")
	discover(discovery_modules)

	# Compare
	print("")
	print_status("Comparing")
	print("----------------------")
	#compare()

	# Websites Discovery
	print("")
	print_status("WebSite Discovery")
	print("----------------------")
	#discover_websites()

	# Enum
	print("")
	print_status("Starting Enumeration")
	print("----------------------")
	#enum(enum_modules)
	
	# Export
	print("")
	print_status("Starting Exports")
	print("----------------------")
	#export()

	# Exit
	print("")
	print("----------------------")
	print_status("Finished")

try:
	if __name__ == "__main__":
		parser = argparse.ArgumentParser(description='myAutoEnum is a tool that automate some task when a new pentest is started.')
		parser.add_argument('-n', '--name', action='store', dest='name', help='Name of the pentest', type=str, required=True)
		parser.add_argument('-i', '--ips', action='store', dest='ip_file', help='File with IPs list', type=str)
		parser.add_argument('-d', '--domains', action='store', dest='domain_file', help='File with Domains list', type=str)
		parser.add_argument('-s', '--subdomains', action='store', dest='subdomain_file', help='File with SubDomains list', type=str)
		parser.add_argument('-m', '--modules', action='store', dest='modules', help='Modules to use: reverse_ip,similar_certificate,read_certificate,wayback_domains,fuzz_dns,ip_history,wayback_urls', type=str)
		parser.add_argument('-p', '--proxy', action='store', dest='proxy', help='Proxy to use. ej: socks5://localhost:9080', type=str)
		parser.add_argument('-a', '--ask', action='store_true', dest='ask', help='Ask to add new found domain to the discovery')
		global args
		args =  parser.parse_args()

		config.name = args.name
		config.ip_file = args.ip_file
		config.domain_file = args.domain_file
		config.subdomain_file = args.subdomain_file
		config.modules = args.modules
		config.proxy = args.proxy
		config.ask = args.ask


		if len(sys.argv) < 2:
			parser.print_help()
			sys.exit(0)

		main()

except KeyboardInterrupt:
	print_error("Keyboard Interrupt. Shutting down")
