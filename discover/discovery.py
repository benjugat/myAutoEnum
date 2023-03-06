import requests
from controller.db import *
from discover.modules import *

def find_domains(ip):
	return


def find_subdomains(scope_name, domain_name):
	# Return Domain / Subdomain
	print("[!] Finding Subdomains of %s" % domain_name)
	results = set()

	# Modules
	print('	[!] Similar Certificates module')
	results.update(similar_certificate(domain_name))
	print(results)
	print('	[!] Wayback module')
	results.update(get_subdomains_with_wayback(domain_name))
	print('	[+] Joining results')
	for r in results:
		print("		- Found %s" % r)
		if str_is_domain(r):
			new = new_domain(scope_name, r)
			if new:
				find_subdomains(scope_name, r)

		elif str_is_subdomain(r):
			(dom, subdom) = new_subdomain(scope_name ,r)
			if dom:
				find_subdomains(scope_name, dom.name)
	return results