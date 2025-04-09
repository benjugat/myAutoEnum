
from src.DNSLookuper.dnslookuper import DNSLookuper
from controller.db import *

def compare_scope(ips, subdomain_names):
	# Mark is_scope from SubDomain object to True if the DNS resolution is in scope.
	# Usage of DNSLookuper
	for subdomain_name in subdomain_names:
		dnslook = DNSLookuper(domains=[subdomain_name])
		out = dnslook.resolve()
		if out and out != 'None':
			r = [o['IP'] for o in out if o['IP'] in ips]
			#r = [o['IP'] for o in out]
			if r:
				mark_as_scope(subdomain_name)
				set_subdomain_ip(subdomain_name, [o['IP'] for o in out])
