#!/usr/bin/env python3
#

"""
 Copyright (c) 2012 Axel Rau, axel.rau@chaos1.de
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

    - Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""

# -----------------------------------------
# Configurables
# -----------------------------------------
import dns_joker_conf as dmapi

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
			self.myConnection = http.client.HTTPSConnection(dmapi.server)
			self.myConnection.request("GET", '/request/login?username=' + dmapi.account_name + '&password=' + dmapi.account_pw)
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
cl = request('query-whois?domain=nussberg.de')
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
