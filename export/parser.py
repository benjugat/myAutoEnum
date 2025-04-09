import json
from src.myCherryParser.myCherryParser import myCherryParser
from controller.db import *

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

def parse_scope(scope_name):
	
	scope_node = {
		"info_node" : {
			"node_name" : scope_name,
			"icon" : "redcherry",
			"bold" : True,
			"color" : "white"
		},
		"content_node" : [],
		"sub_node" : []
	}
	hosts_node = {
		"info_node" : {
			"node_name" : "Hosts",
			"icon" : "home",
			"bold" : True,
			"color" : "white"
		},
		"content_node" : [],
		"sub_node" : []
	}
	domains_node = {
		"info_node" : {
			"node_name" : "Domains",
			"icon" : "home",
			"bold" : True,
			"color" : "white"
		},
		"content_node" : [],
		"sub_node" : []
	}
	vulnerabilities_node = {
		"info_node" : {
			"node_name" : "Vulnerabilities",
			"icon" : "warning",
			"bold" : True,
			"color" : "red"
		},
		"content_node" : [],
		"sub_node" : []
	}

	rjson = scope_node
	rjson['sub_node'].append(hosts_node)
	rjson['sub_node'].append(domains_node)
	rjson['sub_node'].append(vulnerabilities_node)
	return rjson

def parse_host(ip):
	host = get_host(ip)
	rjson = {
		"info_node" : {
			"node_name" : ip,
			"icon" : "info",
			"bold" : False,
			"color" : "white"
		},
		"content_node" : [
			{
				"type" : "text",
				"string" : ip +"\n",
				"style" : [
					"h1",
					"bold"
				]
			}
		],
		"sub_node" : []
	}

	title_host = {
		"type" : "text",
		"string" : "IP: %s" % ip,
		"style" : [
			"h1",
			"bold"
		]
	}
	if host.shodan and host.shodan != '' and host.shodan != 'null':
		content = [
			{
				"type" : "text",
				"string" : "Shodan\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "table",
				"cells" : [
					["                  Result            ", "                                           Value                                                         "],
					["Domains",", ".join(host.shodan['domains'])],
					["Hostnames", ", ".join(host.shodan['hostnames'])],
					["ISP", str(host.shodan['isp'])],
					["City/Region/Country", str(host.shodan['city']) + " - " + str(host.shodan['region_code'])+ " - " + str(host.shodan['country_code'])],
					["Organization",str(host.shodan['organization'])],
					["OS",str(host.shodan['os'])],
					["Ports", ', '.join([str(i) for i in sorted(host.shodan['ports'])])],
					["Tags",', '.join(host.shodan['tags'])]
				]
			},
			{
				"type" : "text",
				"string" : "\n",
				"style" : [
				]
			}
		]
		rjson['content_node'] = rjson['content_node'] + content

	if host.whois and host.whois != '' and host.whois != 'null':
		nets = ''
		for i in host.whois['nets']:
			nets += str(i['cidr']) + '\n' + str(i['name']) + '\n' + str(i['handle']) + '\n' + str(i['country']) + '\n' + str(i['address']) + '\n' + str(i['created']) + '\n' + str(i['updated']) + '\n'
			nets += '\n'
		content = [
			{
				"type" : "text",
				"string" : "Whois\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "table",
				"cells" : [
					["                  Result            ", "                                           Value                                                         "],
					["ASN Registry", str(host.whois['asn_registry'])],
					["ASN Cidr", str(host.whois['asn_cidr'])],
					["ASN Country Code", str(host.whois['asn_country_code'])],
					["ASN Date", str(host.whois['asn_date'])],
					["Nets", nets],
					["Nir", str(host.whois['nir'])]


				]
			},
		]
		rjson['content_node'] = rjson['content_node'] + content


	return rjson

def parse_domain(domain_name):
	domain = get_domain(domain_name)
	rjson = {
		"info_node" : {
			"node_name" : domain_name,
			"icon" : "info",
			"bold" : False,
			"color" : "white"
		},
		"content_node" : [
			{
				"type" : "text",
				"string" : domain_name +"\n",
				"style" : [
					"h1",
					"bold"
				]
			}
		],
		"sub_node" : []
	}
	if domain.ip and domain.ip != '' and domain.ip != 'null':
		content = [
			{
				"type" : "text",
				"string" : "DNS Resolution\n",
				"style" : [
					"h2",
					"bold"
				]
			}			
		]
		for ip in domain.ip:
			content.append({
				"type" : "text",
				"string" : str(ip),
				"style" : [
					"h3"
				]
			})
		rjson['content_node'] = rjson['content_node'] + content

	if domain.ip_history and domain.ip_history != '' and domain.ip_history != 'null':
		content = [
			{
				"type" : "text",
				"string" : "\n\nIP History\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "table",
				"cells" : [
					["        IP Address        ", "        Location        ", "                Owner                ", "  Last seen on this IP  "]
				]
			}
		]
		for ip_result in domain.ip_history:
			a = [ str(ip_result['ip']), str(ip_result['location']), str(ip_result['owner']), str(ip_result['lastseen'])]
			content[1]['cells'].append(a)

		rjson['content_node'] = rjson['content_node'] + content


	return rjson

def parse_subdomain(subdomain_name):
	subdomain = get_subdomain(subdomain_name)
	rjson = {
		"info_node" : {
			"node_name" : subdomain_name,
			"icon" : "gray",
			"bold" : False,
			"color" : "white"
		},
		"content_node" : [
			{
				"type" : "text",
				"string" : subdomain_name +"\n",
				"style" : [
					"h1",
					"bold"
				]
			}
		],
		"sub_node" : []
	}

	if subdomain.ip and subdomain.ip != '' and subdomain.ip != 'null':
		content = [
			{
				"type" : "text",
				"string" : "DNS Resolution\n",
				"style" : [
					"h2",
					"bold"
				]
			}
		]
		for ip in subdomain.ip:
			content.append({
				"type" : "text",
				"string" : str(ip),
				"style" : [
					"h3"
				]
			})
		rjson['content_node'] = rjson['content_node'] + content

	if subdomain.ip_history and subdomain.ip_history != '' and subdomain.ip_history != 'null':
		content = [
			{
				"type" : "text",
				"string" : "\n\nIP History\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "table",
				"cells" : [
					["        IP Address        ", "        Location        ", "                Owner                ", "  Last seen on this IP  "]
				]
			}
		]
		for ip_result in subdomain.ip_history:
			a = [ str(ip_result['ip']), str(ip_result['location']), str(ip_result['owner']), str(ip_result['lastseen'])]
			content[1]['cells'].append(a)

		rjson['content_node'] = rjson['content_node'] + content

	return rjson

def parse_webpage(url):
	web = get_webpage(url)
	rjson = {
		"info_node" : {
			"node_name" : url,
			"icon" : "green",
			"bold" : False,
			"color" : "white"
		},
		"content_node" : [
			{
				"type" : "text",
				"string" : url +"\n",
				"style" : [
					"h1",
					"bold"
				]
			}
		],
		"sub_node" : []
	}
	if web.title and web.title != '' and web.title != 'null':
		content = [
			{
				"type" : "text",
				"string" : "Title\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "text",
				"string" : "%s\n" % web.title,
				"style" : [
				]
			}
		]
		rjson['content_node'] = rjson['content_node'] + content

	if web.status and web.status != '' and web.status != 'null':
		content = [
			{
				"type" : "text",
				"string" : "Status\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "text",
				"string" : "%s\n" % web.status,
				"style" : [
				]
			}
		]
		rjson['content_node'] = rjson['content_node'] + content

	if web.tags and web.tags != '' and web.tags != 'null':
		content = [
			{
				"type" : "text",
				"string" : "Tags\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "table",
				"cells" : [
					["                                                                  Tags                                                                  "]
				]
			}
		]
		for i in web.tags:
			content[1]['cells'].append([i])
	
		rjson['content_node'] = rjson['content_node'] + content

	if web.headers and web.headers != '' and web.headers != 'null':
		content = [
			{
				"type" : "text",
				"string" : "Headers\n",
				"style" : [
					"h2",
					"bold"
				]
			},
			{
				"type" : "table",
				"cells" : [
					["                                         Header                                      ", "                                                                   Value                                                                              "]
				]
			}
		]
		for i in web.headers:
			content[1]['cells'].append([i['header'], i['value']])
	
		rjson['content_node'] = rjson['content_node'] + content

		

	if web.screenshot and web.screenshot != '' and web.screenshot != 'null':
		content = {
			"type" : "image",
			"path" : web.screenshot
		}
		rjson['content_node'].append(content)

	if web.wayback and web.wayback != '' and web.wayback != 'null':
		content = [
			{
				"type" : "text",
				"string" : "Wayback Records\n",
				"style" : [
					"h2",
					"bold"
				]
			}
		]
		for r in web.wayback:
			content.append({
				"type" : "text",
				"string" : str(r),
				"style" : [
				]
			})
		rjson['content_node'] = rjson['content_node'] + content



	return rjson

def export_json(results_json, filename):
	# save json to export with myCherryParser
	with open(filename, 'w') as outfile:
		json.dump(results_json, outfile)

def create_cherry(filename, outputfile):
	# Usage of myCherryParser
	print_status("Parsing: %s " % filename)
	parser = myCherryParser(filename, outputfile)
	parser.parse()
	print_good("Results saved in %s" % outputfile)