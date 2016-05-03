import shodan
import argparse
import re

SHODAN_API_KEY = ""
file = open('shodan.txt', 'w')
ip = []
url = []


api = shodan.Shodan(SHODAN_API_KEY)

parser = argparse.ArgumentParser(description='Look for info in Shodan')
parser.add_argument('-d', dest='domain',nargs='+', help='Domains/IP to lookup in Shodan')
parser.add_argument('-f', dest='filename', help='Path to load file with ips and domains')
args = parser.parse_args()

if args.filename is not None:
    with open(args.filename) as f:
       domain_list = f.readlines()
else:
    domain_list = args.domain

for domain in domain_list:
    pat_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    isIP = pat_ip.match(domain)
    if isIP:
        ip.append(domain)
        print "IP: %s" % domain
    else:
        url.append(domain)
        print "URL: %s" % domain


# Wrap the request in a try/ except block to catch errors
try:
    # Search Shodan
    for dom in url:
        results = api.search('dom')
        # Show the results
        for result in results['matches']:
            print 'IP: %s' % result['ip_str']
            print "Organization: %s" % result.get('org', 'n/a')
            print "Operating System: %s" % result.get('os', 'n/a')
            # Print all banners
        for item in result['data']:
            print "Port: %s" % item['port']
            print "Banner: %s" % item['data']
            print ''
except shodan.APIError, e:
        print 'Error: %s' % e

try:
# Lookup the host
    for i in ip:
        host = api.host(i)

        # Print general info
        print "IP: %s" % host['ip_str']
        print "Organization: %s" % host.get('org', 'n/a')
        print "Operating System: %s" % host.get('os', 'n/a')

        # Print all banners
        for item in host['data']:
            print "Port: %s" % item['port']
            print "Banner: %s" % item['data']

except shodan.APIError, e:
    print 'Error: %s' % e
