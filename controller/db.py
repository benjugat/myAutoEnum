import os,sys
import config
from model.scope import Scope
from model.host import Host
from model.domain import Domain
from model.subdomain import SubDomain
from model.webpage import WebPage
from controller.util import *
#
# ----------------------
# Scope class interaction
# ----------------------
#

def add_scope(scope_name):
	# Add a new scope to the collection
	scope = Scope(name=scope_name)
	scope.save()
	print_good("Scope added: %s" % scope_name)
	return scope

def add_host_to_scope(scope_name, host):
	# Append the given Host object to the given scope
	scope = get_scope(scope_name)
	if scope:
		scope.hosts.append(host)
		scope.save()

def add_domain_to_scope(scope_name, domain):
	# Append the given Doamin object to the given scope
	scope = get_scope(scope_name)
	if scope:
		scope.domains.append(domain)
		scope.save()

def check_scope(scope_name):
	# Check if the scope exists on the collection
	results = Scope.objects(name=scope_name)
	return bool(results)

def get_scope(scope_name):
	# Get a Scope of the collection
	return Scope.objects(name=scope_name).first()

def new_scope(scope_name):
	if not check_scope(scope_name):
		return add_scope(scope_name)
	return None

#
# ----------------------
# Host class interaction
# ----------------------
#

def add_host(ip):
	# Add a new Host to the collection
	host = Host(ip=ip)
	host.save()
	print_good("Host added: %s" % ip)
	return host


def check_host(ip):
	# Check if the IP exists on the collection
	results = Host.objects(ip=ip)
	return bool(results)

def get_host(ip):
	# Get a Host of the collection
	return Host.objects(ip=ip).first()

def new_host(scope_name, ip):
	if not check_host(ip):
		host = add_host(ip)
		add_host_to_scope(scope_name, host)
		return host
	return None

def get_all_ips():
	# Get a list of domain names (str)
	hosts = Host.objects()
	return [o.ip for o in hosts]

def set_shodan_host(ip, shodan_results):
	host = get_host(ip)
	if host and not host.shodan:
		host.shodan = shodan_results
		host.save()
		print_good("Shodan results added to %s" % ip)
		return True
	return False

def set_whois_host(ip, whois_results):
	host = get_host(ip)
	if host and not host.whois:
		host.whois = whois_results
		host.save()
		print_good("Whois results added to %s" % ip)
		return True
	return False

#
# ----------------------
#  Domain class interaction
# ----------------------
#

def add_domain(domain_name):
	# Add a new domain to the collection
	dom = Domain(name=domain_name)
	dom.save()
	print_good("Domain added: %s" % domain_name)
	return dom


def add_subdomain_to_domain(domain_name, subdomain):
	# Add the object SubDomain() to a given domain name.
	dom = get_domain(domain_name)
	if dom:
		dom.subdomains.append(subdomain)
		dom.save()
	
def check_domain(domain_name):
	# Check if a domain exists with a given domain name
	results = Domain.objects(name=domain_name)
	return bool(results)

def check_domain_from_subdomain(subdomain):
	# Check if a domain exists with a given subdomain name
	domain = str_domain_from_subdomain(subdomain)
	results = Domain.objects(name=domain)
	return bool(results)

def get_domain(domain_name):
	# Get a Domain from the collection
	return Domain.objects(name=domain_name).first()

def get_all_domain_names():
	# Get a list of domain names (str)
	domains = Domain.objects()
	return [o.name for o in domains if str_is_domain(o.name)]

def new_domain(scope_name, domain_name):
	if not check_domain(domain_name):
		if config.ask:
			r = input('\t[?] You want to add %s to the list? [y/n]' % domain_name)
			if r.lower() == 'y':
				domain = add_domain(domain_name)
				add_domain_to_scope(scope_name, domain)
				return domain
		else:
			domain = add_domain(domain_name)
			add_domain_to_scope(scope_name, domain)
			return domain
	return None

def set_domain_ip(domain_name, ip):
	domain = get_domain(domain_name)
	if domain and not domain.ip:
		domain.ip = ip
		domain.save()
		print_good("Resolution DNS added to %s" % domain_name)
		return True
	return False

def set_domain_ip_history(domain_name, ip_history):
	domain = get_domain(domain_name)
	if domain and not domain.ip_history:
		domain.ip_history = ip_history
		domain.save()
		print_good("IP history added to %s" % domain_name)
		return True
	return False


#
# ----------------------
# SubDomain class interaction
# ----------------------
#

def add_subdomain(subdomain_name):
	# Add a new subdomain to the collection
	subdomain = SubDomain(name=subdomain_name)
	subdomain.save()
	print_good("Subdomain added: %s" % subdomain_name)
	return subdomain


def check_subdomain(subdomain_name):
	# Check if a subdomain exists with a given subdomain name
	results = SubDomain.objects(name=subdomain_name)
	return bool(results)

def get_subdomain(subdomain_name):
	# Get a SubDomain from the collection
	return SubDomain.objects(name=subdomain_name).first()

def get_all_subdomain_names():
	# Get a list of subdomain names (str)
	subdomains = SubDomain.objects()
	return [o.name for o in subdomains]

def get_scope_subdomain_names():
	subdomains = SubDomain.objects(is_scope=True)
	return [o.name for o in subdomains]

def get_subdomain_ip(subdomain_name):
	return SubDomain.objects(name=subdomain_name).first().ip

def get_subdomain_urls(subdomain_name):
	subdomain = get_subdomain(subdomain_name)
	if subdomain:
		return [o.url for o in subdomain.pages]
	return list()

def new_subdomain(scope_name, subdomain_name):
	if not check_subdomain(subdomain_name):
		subdomain = add_subdomain(subdomain_name)
		domain_name = str_domain_from_subdomain(subdomain_name)
		domain = get_domain(domain_name)
		new_dom = None
		if not domain:
			new_dom = new_domain(scope_name, domain_name)
		add_subdomain_to_domain(domain_name, subdomain)
		return new_dom, subdomain
	return None, None

def add_webpage_to_subdomain(subdomain_name, webpage):
	# Add the object WebPage() to a given subdomain name.
	subdomain = get_subdomain(subdomain_name)
	if subdomain:
		subdomain.pages.append(webpage)
		subdomain.save()

def mark_as_scope(subdomain_name):
	subdomain = get_subdomain(subdomain_name)
	if subdomain and not subdomain.is_scope:
		subdomain.is_scope = True
		subdomain.save()
		print_good("SubDomain in Scope: %s" % subdomain_name)
		return True
	return False

def set_subdomain_ip(subdomain_name, ip):
	subdomain = get_subdomain(subdomain_name)
	if subdomain and not subdomain.ip:
		subdomain.ip = ip
		subdomain.save()
		print_good("Resolution DNS added to %s" % subdomain_name)
		return True
	return False

def set_subdomain_ip_history(subdomain_name, ip_history):
	subdomain = get_subdomain(subdomain_name)
	if subdomain and not subdomain.ip_history:
		subdomain.ip_history = ip_history
		subdomain.save()
		print_good("IP history added to %s" % subdomain_name)
		return True
	return False


#
# ----------------------
# WebPage class interaction
# ----------------------
#

def add_webpage(url):
	# Add a new WebPage to the collection
	webpage = WebPage(url=url)
	webpage.save()
	print_good("WebPage added: %s" % url)
	return webpage

def check_webpage(url):
	# Check if a subdomain exists with a given subdomain name
	results = WebPage.objects(url=url)
	return bool(results)

def get_webpage(url):
	# Get a WebPage from the collection
	return WebPage.objects(url=url).first()

def get_all_webpages_urls():
	# Get a list of urls (str)
	webpage = WebPage.objects()
	return [o.url for o in webpage]	

def new_webpage(subdomain_name, url):
	if not check_webpage(url):
		webpage = add_webpage(url)
		add_webpage_to_subdomain(subdomain_name, webpage)
		return webpage
	return None

def set_wayback_urls(url, way_urls):
	webpage = get_webpage(url)
	if webpage and way_urls:
		webpage.wayback = way_urls
		webpage.save()
		print_good("Wayback URLS added to %s" % url)
		return True
	return False

def set_screenshot(url, image_path):
	webpage = get_webpage(url)
	if webpage and image_path:
		webpage.screenshot = image_path
		webpage.save()
		print_good("Screnshoot added to %s" % url)
		return True
	return False

def set_title(url, title):
	webpage = get_webpage(url)
	if webpage and title:
		webpage.title = title
		webpage.save()
		print_good("Title added to %s" % url)
		return True
	return False

def set_status(url, status):
	webpage = get_webpage(url)
	if webpage and status:
		webpage.status = status
		webpage.save()
		print_good("Status added to %s" % url)
		return True
	return False

def set_tags(url, tags):
	webpage = get_webpage(url)
	if webpage and tags:
		webpage.tags = tags
		webpage.save()
		print_good("Tags added to %s" % url)
		return True
	return False

def set_headers(url, headers):
	webpage = get_webpage(url)
	if webpage and headers:
		webpage.headers = headers
		webpage.save()
		print_good("Headers added to %s" % url)
		return True
	return False