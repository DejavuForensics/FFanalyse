#!/usr/bin/python

"""
Domain analysis script. Performs a DNS query and examines the response to determine if domain is Fast-Flux.
Also performs a check using multiple methods to determine whether domain name was algorithmically generated (DGA).
Author: Etienne Stalmans
Version: 1.0 (2013)
"""

import sys,string
import getopt
import dns.resolver
from dns.exception import Timeout
import Geolocate
import pygeoip
import argparse
import URLAnalysis
from berserker_resolver import Resolver	

class ffanalyse():

	def filtra(self,test_list):	
		res = [] 
		for val in test_list: 
			if val != None : 
				res.append(val)
		return res
		
	def main(self,domain,verbose):
		self.defaults= { 'protocol':'udp', 'port':53, 'opcode':'query',
				'qtype':'A', 'rd':1, 'timing':1, 'timeout': 3,
				'server_rotate': 0,'server':[] }
		self.verbose = verbose
		self.domain = domain
		self.gl = Geolocate.Geolocate('GeoLiteCity.dat')
		self.geoIP = pygeoip.GeoIP('GeoIPASNum.dat')
		self.urla = URLAnalysis.urlanalyse()
		self.urla.main('output_b.dgt','output_m.dgt')
		self.resolve_nameservers(domain)
		self.analyse_function(domain)
		
	def resolve_nameservers(self,domain):
		import win32dns
		self.defaults['server']=win32dns.RegistryResolve(domain)
		count = len(self.defaults['server']) #number of IP
		print ("\nlist of IPs. Total: " + str(count))
		for i in range(0,count):			
			print('\t' + self.defaults['server'][i])

	def get_asn(self,ip):
		"""
		Method to return the country and ASN of an IP address
		@param ip to get data for
		@return [asn record, country]
		"""
		asnrec = self.geoIP.org_by_addr(ip)
		country = self.gl.getCountry(ip)	
		if self.verbose:
			print (asnrec,country)
		if asnrec == None:
			return [asnrec,country]
			#return ['Unknown','Unknown']
		else:
			return [asnrec.split(' ')[0],country]
	
	def analyse_function(self,domain):
		qname = domain	
		network_ranges = [] #A record responses
		nameserver_net_ranges = []
		a_count = 0
		ns_count = 0
		diff_count = 0
		ns_diff_count = 0
		a_ttl = 86400
		ns_ttl = 86400
		ar_count = -1
		country_count = 0
		asn_count = 0
		countries = []
		cities = []
		nameservers = []
		asns = []
		answers = []
		ttl_score = 0
		
		flag = 0
		while flag==0:
			try:
				resolver = Resolver()
				result = resolver.query(domain)
				a_ttl = result.rrset.ttl
				flag = 1
			except Timeout:
				flag = 0
			except:
				flag = 0
		
		a_count = len(self.defaults['server']) #the number of IP addresses returned		
		
		if a_count > 0:   
			for ip in self.defaults['server']:
				nameservers.append(ip)		
				city = self.gl.listCities(ip)	
				st = ip[:ip.rfind('.')]
				asnd = self.get_asn(ip)	
				if asnd: 
					asn,country = asnd
					if country not in countries:
						countries.append(country)				
					if asn not in asns:
						asns.append(asn)		
				if st not in network_ranges:
					network_ranges.append(st)
				if city not in cities:
					if city != None:
						cities.append(city)					
					
		network_ranges = self.filtra(network_ranges) #number of IP ranges we have
		countries= self.filtra(countries) #number of countries that host A records
		asns = self.filtra(asns) #number of netblocks	
		cities = self.filtra(cities) #number of cities
		nameservers = self.filtra(nameservers) #number of name servers
        
		diff_count = len(network_ranges) #number of IP ranges we have
		country_count= len(countries) #number of countries that host A records
		asn_count = len(asns) #number of netblocks	
		city_count = len(cities) #number of cities
		ns_count = len(nameservers) #number of name servers
        
		if a_ttl <= 300:
			ttl_score = 1
        
		#===================================================
		print("\nlist of IP ranges. Total: " + str(diff_count))
		for i in range(0,diff_count):			
			print('\t' + network_ranges[i])
		print("\nlist of ASN(Autonomous System Number)")
		for i in range(0,asn_count):			
			print('\t' + asns[i])
		print("\nlist of countries")
		for i in range(0,country_count):			
			print('\t' + countries[i])
		print("\nlist of cities")
		for i in range(0,city_count):			
			print(cities[i])
		#===================================================
		print ("\nQname{0:20}|TTL{0:5}|A Records{0:2}|Ranges{0:2}|ASNs{0:2}|Countries{0:2}|Cities{0:2}|NumServers{0:2} |".format(''))
		print ("{:25}|{:8}|{:11}|{:8}|{:6}|{:11}|{:8}|{:13}|".format(qname,a_ttl,a_count,diff_count,asn_count,country_count,city_count,ns_count))
		#calculate score according to Thorsten
		#===================================================
		t_score = (1.32*a_count+18.54*asn_count+0*ns_count+ttl_score*5)-50
		#===================================================
		
		#calculate Jaroslaw/Patrycja score
		#===================================================
		jp_score = a_count+ns_count+diff_count*1.5+asn_count*1.5+ttl_score+country_count*2
		#===================================================
		print ("\n---- Fast-Flux Scores ----")
		print ("Modified Thorsten/Holz: Score (%i) Classified (%s)"%(t_score,"\033[91mFast-Flux\033[0m" if t_score>0 else "\033[92mClean\033[0m"))
		print ("Modified Jaroslaw/Patrycja: Score (%i) Classified (%s)"%(jp_score,"\033[91mFast-Flux\033[0m" if jp_score>=18 else "\033[92mClean\033[0m"))
		print ("Rule Based: %s"%("\033[91mFast-Flux\033[0m" if diff_count!=0 and a_count>=2 or  ns_count>1 and ((diff_count>=1 and asn_count>1)or ttl_score == 1) else "\033[92mClean\033[0m"))
		print ("\n---- Geolocation ----")
		self.gl.calcValues(nameservers) #do geolocation check
		print ("\n---- URL Analysis ----")
		self.urla.checkDomain(qname) #do check for DGA	
	
def setOpts(argv):                         
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--domain',dest='domain',action='store',required=True,
		help="A Domain to analyse")
	parser.add_argument('-v', dest='verbose', action='store_true',default=False,
		help="Verbose output")
	arg = parser.parse_args()
    
	return (arg.__dict__['domain'],arg.__dict__['verbose'])		
if __name__ == "__main__":
	opts = setOpts(sys.argv[1:])
	ff = ffanalyse()
	ff.main(opts[0],opts[1])
