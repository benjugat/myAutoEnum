import os
import re

tld_list_upper = ["AAA","ABB","ABC","AC","ACO","AD","ADS","AE","AEG","AF","AFL","AG","AI","AIG","AL","AM","ANZ","AO","AOL","APP","AQ","AR","ART","AS","AT","AU","AW","AWS","AX","AXA","AZ","BA","BAR","BB","BBC","BBT","BCG","BCN","BD","BE","BET","BF","BG","BH","BI","BID","BIO","BIZ","BJ","BM","BMS","BMW","BN","BO","BOM","BOO","BOT","BOX","BR","BS","BT","BUY","BV","BW","BY","BZ","BZH","CA","CAB","CAL","CAM","CAR","CAT","CBA","CBN","CBS","CC","CD","CEO","CF","CFA","CFD","CG","CH","CI","CK","CL","CM","CN","CO","COM","CPA","CR","CRS","CU","CV","CW","CX","CY","CZ","DAD","DAY","DDS","DE","DEV","DHL","DIY","DJ","DK","DM","DNP","DO","DOG","DOT","DTV","DVR","DZ","EAT","EC","ECO","EDU","EE","EG","ER","ES","ESQ","ET","EU","EUS","FAN","FI","FIT","FJ","FK","FLY","FM","FO","FOO","FOX","FR","FRL","FTR","FUN","FYI","GA","GAL","GAP","GAY","GB","GD","GDN","GE","GEA","GF","GG","GH","GI","GL","GLE","GM","GMO","GMX","GN","GOO","GOP","GOT","GOV","GP","GQ","GR","GS","GT","GU","GW","GY","HBO","HIV","HK","HKT","HM","HN","HOT","HOW","HR","HT","HU","IBM","ICE","ICU","ID","IE","IFM","IL","IM","IN","INC","ING","INK","INT","IO","IQ","IR","IS","IST","IT","ITV","JCB","JE","JIO","JLL","JM","JMP","JNJ","JO","JOT","JOY","JP","KE","KFH","KG","KH","KI","KIA","KIM","KM","KN","KP","KPN","KR","KRD","KW","KY","KZ","LA","LAT","LAW","LB","LC","LDS","LI","LK","LLC","LLP","LOL","LPL","LR","LS","LT","LTD","LU","LV","LY","MA","MAN","MAP","MBA","MC","MD","ME","MED","MEN","MG","MH","MIL","MIT","MK","ML","MLB","MLS","MM","MMA","MN","MO","MOE","MOI","MOM","MOV","MP","MQ","MR","MS","MSD","MT","MTN","MTR","MU","MV","MW","MX","MY","MZ","NA","NAB","NBA","NC","NE","NEC","NET","NEW","NF","NFL","NG","NGO","NHK","NI","NL","NO","NOW","NP","NR","NRA","NRW","NTT","NU","NYC","NZ","OBI","OM","ONE","ONG","ONL","OOO","ORG","OTT","OVH","PA","PAY","PE","PET","PF","PG","PH","PHD","PID","PIN","PK","PL","PM","PN","PNC","PR","PRO","PRU","PS","PT","PUB","PW","PWC","PY","QA","RE","RED","REN","RIL","RIO","RIP","RO","RS","RU","RUN","RW","RWE","SA","SAP","SAS","SB","SBI","SBS","SC","SCA","SCB","SD","SE","SEW","SEX","SFR","SG","SH","SI","SJ","SK","SKI","SKY","SL","SM","SN","SO","SOY","SPA","SR","SRL","SS","ST","STC","SU","SV","SX","SY","SZ","TAB","TAX","TC","TCI","TD","TDK","TEL","TF","TG","TH","THD","TJ","TJX","TK","TL","TM","TN","TO","TOP","TR","TRV","TT","TUI","TV","TVS","TW","TZ","UA","UBS","UG","UK","UNO","UOL","UPS","US","UY","UZ","VA","VC","VE","VET","VG","VI","VIG","VIN","VIP","VN","VU","WED","WF","WIN","WME","WOW","WS","WTC","WTF","XIN","XXX","XYZ","YE","YOU","YT","YUN","ZA","ZIP","ZM","ZW"]
tld_list = [x.lower() for x in tld_list_upper]

def print_status(message=""):
	print(f"\033[1;34m[*]\033[1;m {message}")


def print_good(message=""):
	print(f"\033[1;32m[+]\033[1;m {message}")


def print_error(message=""):
	print(f"\033[1;31m[-]\033[1;m {message}")


def print_debug(message=""):
	print(f"\033[1;31m[!]\033[1;m {message}")


def str_domain_from_subdomain(subdomain):
	return '.'.join(subdomain.split('.')[-2:])


def str_is_domain(entry):
	entry = entry.lower()
	le = entry.split('.')
	if len(le) == 2 and len(entry) > 3 and re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', entry) == None and le[-2] not in tld_list:
			return True
	elif (len(le) == 3) and (len(entry) > 5) and ('*' not in entry) and (le[-2] in tld_list) and (le[-1] in tld_list):
			return True
	return False

def str_is_subdomain(entry):
	entry = entry.lower()
	le = entry.split('.')
	if (len(le) > 2) and (len(entry) > 5) and ('*' not in entry) and (re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', entry) == None) and (le[-2] not in tld_list):
		return True
	return False

def str_get_domain_from_url(url):
	if 'http' in url:
		a = url.split('&')[0].split('?')[0].split('/')[2].split(':')[0].lower()
		if '@' not in a and len(a.split('.')) > 1 and a[-1] != '.':
			return a
	return None

def str_get_printable_url(url):
	proto = str(url.split(':')[0])
	domain = str_get_domain_from_url(url)
	port=str(url.split(':')[2])
	return "%s-%s-%s" % (proto,domain,port)

def get_proxy():
	if os.environ.get("PROXY") != '':
		return {"http" : os.environ.get("PROXY"), "https" : os.environ.get("PROXY")}
	else:
		return None