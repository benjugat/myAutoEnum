from src.dnslookuper import DNSLookuper
from controller.db import *
from enumerate.modules import *

def enum_hosts(enum_modules, ip):
	print("")
	print_debug("Enumerating host %s" % ip)

	# Modules
	if 'shodan_host' in enum_modules:
		print_status("	Shodan Host module")
		shodan_results = shodan_host(ip)
		set_shodan_host(ip, shodan_results)

	if 'whois' in enum_modules:
		print_status("	Whois IP module")
		whois_results = whois_ip(ip)
		set_whois_host(ip, whois_results)

def enum_domains(enum_modules, domain_name):
	print("")
	print_debug("Enumerating domain %s" % domain_name)
	
	# Modules
	print_status('	Resolving DNS address')
	ip = resolve(domain_name)
	set_domain_ip(domain_name, ip)

	if 'ip_history' in enum_modules:
		print_status('	IP History module')
		ip_history_results = ip_history(domain_name)
		print(ip_history_results)
		set_ip_history(domain_name, ip_history_results)

def enum_subdomains(enum_modules, subdomain_name):
	print("")
	print_debug("Enumerating subdomain %s" % subdomain_name)

	# Modules
	print_status('	Resolving DNS address')
	ip = resolve(subdomain_name)
	set_subdomain_ip(subdomain_name, ip)


def enum_webpages(enum_modules, url):
	print("")
	print_debug("Enumerating webpage %s" % url)

	# Modules
	if 'wayback_urls' in enum_modules:
		print_status('	Wayback URLS module')
		way_urls = wayback_urls(subdomain_name)
		set_wayback_urls(url, way_urls)