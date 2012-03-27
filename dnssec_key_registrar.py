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
##import dns_joker_conf as dmapi

##DEBUG = True
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
class ConnectionJoker(object):
	"""Connection to Joker.com DMAPI server"""
	global DEBUG
	def __init__(self):
		self.myConnection = 0
		self.session = {}
	
		try:
			self.myConnection = http.client.HTTPSConnection(conf.registrar['Joker']['Server'])
			self.myConnection.request("GET", '/request/login?username=' + 
				conf.registrar['Joker']['account_name'] + '&password=' + conf.registrar['Joker']['account_pw'])
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
def requestJoker(query_string):
	
	status = {}
	result = []
	header_done = False
	global theConnection, DEBUG
	
	if not theConnection:
		theConnection = ConnectionJoker()
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

def regRemoveAllDS(zone):
	if zone.split('.')[-1] not in 'arpa':
		cl = request('domain-modify?domain=' + zone + '&dnssec=0')
		for c in cl:
			print(c)
		return True
	print('?Internal inconsitency: regRemoveAllDS(): DS-Removal of .arpa. not implemented')
	return False
	
def regAddDS(zone, index, tag, alg, digest_type, digest, flags, pubkey_base64):
	tld = zone.split('.')[-1]
	if tld not in 'arpa':
		if index not in range(1,6):
			print('?Internal inconsitency: regAddDS(): argument index is %d. This is out of range' % index)
			return False
		if tld != 'de':
			if (None, '') in (tag, alg, digest_type, digest):
				print('?Internal inconsitency: regAddDS(): at least one argument is empty: "%d","%d","%d","%s"'
					% (tag, alg, digest_type, str(digest)))
				return False
			cl = request('domain-modify?zone=%s&dnssec=1&ds-%d=%d:%d:%d:%s' % (zone, index, tag, alg, digest_type, digest))
			for c in cl:
				print(c)
			return True
		else:
			if DEBUG: print('[zone=%s, index=%d, tag=%d, alg=%d, digest_type=%d, digest=%s, flags=%d, pubkey_base64=%s]' 
				% (zone, index, tag, alg, digest_type, digest, flags, pubkey_base64))
			return True
			if (None, '') in (alg, flags, pubkey_base64):
				print('?Internal inconsitency: regAddDS(): at least one argument is empty: "%d","%d","%s"'
					% (alg, flags, pubkey_base64))
				return False
			cl = request('domain-modify?zone=%s&dnssec=1&ds-%d=3:%d:%d:%s' % (zone, alg, flags, pubkey_base64))
			for c in cl:
				print(c)
			return True
	return False	

# -----------------------------------------
# Main
# -----------------------------------------
