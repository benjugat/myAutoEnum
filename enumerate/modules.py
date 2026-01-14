import os
from src.DNSLookuper.dnslookuper import DNSLookuper
from controller.util import *
import requests
import shodan
import ipwhois
import sqlite3

#
# ---------------------------
# Host enum modules
# ---------------------------
#

def shodan_host(ip):
	# Obtain information about a host from shodan.
	# Usage of Shodan API key.
	# Shodan API Key needed!
	if os.environ.get('SHODAN_API_KEY'):
		sh = shodan.Shodan(os.environ.get('SHODAN_API_KEY'))
		try:
			rjson = sh.host(ip)
			shodan_results ={
				"domains" : rjson["domains"], #list
				"hostnames" : rjson["hostnames"], #list
				"tags" : rjson["tags"], #list
				"region_code" : rjson["region_code"], #str
				"country_code" : rjson["country_code"], #str
				"city" : rjson["city"], #str
				"isp" : rjson["isp"], #str
				"organization" : rjson["org"], #str
				"os" : rjson["os"], #str
				"ports" : rjson["ports"], #list
				#"data_services" : rjson["data"] #list
				# problems with overflow in int 64bits
			}
			return shodan_results
		except shodan.exception.APIError as err:
			print_error("Shodan error: %s" % err)
			return None
	else:
		print_error("No Shodan API key was provided!")
		return None


def whois_ip(ip):
	# Return a the whois_result dict
	ipwh = ipwhois.IPWhois(ip)
	out = ipwh.lookup_whois()
	print(out)
	whois_result = {
		"asn_registry" : out["asn_registry"],
		"asn_cidr" : out["asn_cidr"],
		"asn_country_code" : out["asn_country_code"],
		"asn_date" : out["asn_date"],
		"nir" : "",#out["nir"],
		"nets" : out["nets"] #list
	}
	return whois_result



#
# ---------------------------
# Domain enum modules
# ---------------------------
#

def resolve(domain_name):
	# Resolve actual IP of domain_name
	# Usage of DNSLookuper
	dnslook = DNSLookuper(domains=[domain_name])
	out = dnslook.resolve()
	if out and out != 'None':
		return [o['IP'] for o in out]
	return None

def ip_history(domain_name):
	# Return a list() of records {"IP" : ip, "location" : location, "owner": owner, "lastseen" : lastseen}
	# Usage of viewdns.info API.
	# API KEY is needed!
	results = list()
	if os.environ.get('VIEWDNS_API_KEY'):
		r = requests.get("https://api.viewdns.info/iphistory/?domain=%s&apikey=%s&output=json" % (domain_name, os.environ.get('VIEWDNS_API_KEY')), proxies=get_proxy())
		if (r.status_code == 200) and ('limit reached' not in r.text):
			r_json = r.json()
			if "error" in r_json['response'].keys():
				return list()
			return r.json()['response']['records']
		else:
			print_error("Problems with ViewDNS API key")
	else:
		print_error("No ViewDNS API key was provided!")
	return list()

#
# ---------------------------
# WebPage enum modules
# ---------------------------
#

def wayback_urls(subdomain_name):
	# Get a list of domain names from wayback machine.
	# Based on https://gist.github.com/mhmdiaa/adf6bff70142e5091792841d4b372050
	# No API KEY needed
	try:
		r = requests.get('http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % subdomain_name, proxies=get_proxy())
		urls = set()

		if r.status_code == 200:
			r_json = r.json()		
			if len(r_json) > 1:
				# Delete "original" from the list
				r_json.pop(0)
				for i in r_json:
					for url in i:
						# Filtering css,woff,jpeg,jpg,png and gif files.
						if ('.css' not in url) and ('.woff' not in url) and ('.jpeg' not in url) and ('.jpg' not in url) and ('.png' not in url) and ('.gif' not in url):
							urls.add(url)
		return list(urls)[0:100]
	except:
		return None

def gowitness(url):
	# Get some information from the website with gowitness.
	# Need to set a env variable in the .env file:
	# GOWITNESS_BIN = "./src/gowitness-2.4.2-linux-amd64"
	if os.environ.get('GOWITNESS_BIN'):
		os.system("echo '%s' | %s file -f -" % (url, os.environ.get('GOWITNESS_BIN')))
		# Get gowtiness results from gowitness.sqlite3 database
		try:
			conn = sqlite3.connect("gowitness.sqlite3")
			sql = conn.cursor()
		except:
			print_error("Problems with gowitness database")

		# Getting: url_id, title,filename, response_reason
		# URLS table
		res = sql.execute("SELECT id,filename,title,response_reason from urls WHERE url='%s'" % url)
		try:
			a = res.fetchone()

			if a:
				url_id, filename, title, response_reason = a
				# Getting: technologies
				# TECHNOLOGIES table
				res = sql.execute("SELECT value from technologies where url_id=%d" % int(url_id))
				a = res.fetchall()	
				technologies = [o[0] for o in a if o[0]]

				# Getting: headers
				# HEADERS table
				res = sql.execute("SELECT key,value from headers where url_id=%d" % int(url_id))
				a = res.fetchall()
				headers = list()
				for i in a:
					if i:
						headers.append({"header" : i[0], "value" : i[1]})

				return {
						"title" : title,
						"status_code" : response_reason,
						"image_path" : os.getcwd() + '/screenshots/' + filename,
						"technologies" : technologies,
						"headers" : headers
					}
		except:
			return None

	return None