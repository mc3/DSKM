#!/usr/bin/env python3
#

"""\
Client of joker.com domain API DMAPI

https://dmapi.joker.com/request/login?username=axel.rau@chaos1.de&password=qswuiisr

Session-Count: 1
Status-Text: Command completed successfully
Status-Code: 0
Account-Balance: 142.86
Session-Timeout: 3600
Auth-Sid: 5b42b601586ee54392a5df44900c29fc
Version: 1.2.27
UID: 1685

tel
hn
name
mn
nl
cc
eu
vc
me.uk
mobi
ltd.uk
asia
ag
plc.uk
co.uk
lc
at
bz
org.uk
com
co.at
sc
net
tv
org
us
net.uk
biz
me
de
info
xxx
cn
or.at

https://dmapi.joker.com/request/query-domain-list?auth-sid=b42b601586ee54392a5df44900c29fc

Account-Balance: 142.86
Version: 1.2.27
Columns: domain,expiration_date
Status-Text: Command completed successfully
Status-Code: 0

bau-ing-klein.de 2012-07-02
chaos1.de 2012-07-01
framail.de 2012-04-25
lechner-rau.de 2012-07-01
lrau.net 2013-01-14
mailsec.net 2012-03-22
nussberg.de 2012-07-01
peter-ross-berlin.de 2013-01-26

"""

# -----------------------------------------
# Configurables
# -----------------------------------------
dmapi_server = 'dmapi.joker.com'
dmapi_account_name = 'axel.rau@chaos1.de'
dmapi_account_pw = 'qswuiisr'

DEBUG = True
# -----------------------------------------

# -----------------------------------------
import http.client
import sys
# -----------------------------------------

# -----------------------------------------
# Globals
# -----------------------------------------
theConnection = False

# -----------------------------------------
# classes
# -----------------------------------------
class Connection(object):
	"""Connection to Joker.com DMAPI server"""
	def __init__(self):
		self.myConnection = 0
		self.session = {}
	
		try:
			self.myConnection = http.client.HTTPSConnection(dmapi_server)
			self.myConnection.request("GET", '/request/login?username=' + dmapi_account_name + '&password=' + dmapi_account_pw)
		except Exception:
			print('?Failed to connect to Joker.com DMAPI server, because ', str(sys.exc_info()[1]))
			sys.exit(1)
		
		r1 = self.myConnection.getresponse()
		if r1.status != 200:
			print('?Failed to connect to Joker.com DMAPI server, because: ' + r1.reason)
		while not r1.closed:
			for line in r1.read().decode('ASCII').splitlines():
				if len(line) > 2:
					(k,v) = line.split(':')
					self.session[k] = v.strip()
				else:
					break
		if self.session['Status-Code'] != '0':
			print('?Failed to sign-on at Joker.com, because: ' + self.session['Status-Text'])
			for k in session.keys():
				print(k, ':	',  self.session[k])
			sys.exit(1)
	
	def conn(self):
		return self.myConnection
	
	def sid(self):
		return self.session['Auth-Sid']


# -----------------------------------------
# Functions
# -----------------------------------------
def request(query_string):
	status = {}
	result = []
	header_done = False
	global theConnection
	
	if not theConnection:
		theConnection = Connection()
	c = theConnection.conn()
	if '?' in query_string:
		s = '/request/' + query_string + '&auth-sid=' + theConnection.sid()
	else:
		s = '/request/' + query_string + '?auth-sid=' + theConnection.sid()
	if DEBUG: print('[' + s + ']')
	try:
		c.request("GET", s)
	except Exception:
	    print('?Request " + query_string + " to Joker.com DMAPI server failed, because: ', str(sys.exc_info()[1]))
	    sys.exit(1)
	r1 = c.getresponse()
	if r1.status != 200:
		print('?Request " + query_string + " to Joker.com DMAPI server failed, because: ' + r1.reason)
	while not r1.closed:
	    for line in r1.read().decode('ASCII').splitlines():
	    	if len(line) < 3:
	    		header_done = True
	    		continue
	    	if not header_done:
	    		(k,v) = line.split(':')
	    		status[k] = v.strip()
	    	else:
	    		result.append(line)
	if status['Status-Code'] != '0':
	    print('?Request " + query_string + " to Joker.com DMAPI server failed, because: ' + status['Status-Text'])
	    for k in status.keys():
	    	print(k, ':	',  status[k])
	    sys.exit(1)
	    
	return result
# -----------------------------------------
# Main
# -----------------------------------------

theConnection = Connection()
if DEBUG: print('[connected]')
cl = request('query-contact-list?tld=de&extended-format=1')
for c in cl:
	print(c)
cl = request('query-contact-list?tld=net&extended-format=1')
for c in cl:
	print(c)
cl = request('query-domain-list?showstatus=1&showgrants=1')
for c in cl:
	print(c)

cl = request('query-whois?domain=chaos1.de')
for c in cl:
	print(c)
cl = request('query-whois?domain=peter-ross-berlin.de')
for c in cl:
	print(c)
cl = request('query-whois?domain=lrau.net')
for c in cl:
	print(c)
cl = request('query-whois?contact=code-3464')
for c in cl:
	print(c)
cl = request('query-whois?host=ns4.lrau.net')
for c in cl:
	print(c)
