#!/usr/bin/env python3

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

import sys

from script import path, shell, opts
import script
import fnmatch
from datetime import date

# for salt
from Crypto import Random as rand
import binascii

import dns.resolver, dns.message, dns.query, dns.rdatatype, dns.rdtypes.ANY.DNSKEY, dns.rcode
import dns.dnssec

import json
import os

# -----------------------------------------
# Configurables
# -----------------------------------------
import dnssec_key_maintenance_conf as conf
#------------------------------------------------------------------------------
#	Adjustables
#--------------------------
##ROOT_PATH = '~/Developer/DNSsec/named/'
ROOT_PATH = '/var/named/master/signed'

#--------------------------
#	policy constants ( in days)
#--------------------------
TTL = 1							# ttl of SOA, NS and others; A/AAAA may be shorter
SOA_EXPIRE_INTERVAL = 7			#  SOA expire time
SOA_NEGATIVE_CACHE_INTERVAL = 1

# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
								# published immediately after generation
ZSK_P_A_INTERVAL = 0			# active (used to sign RRsets) 7 days after publish
ZSK_A_I_INTERVAL = 30			# inactive 30 days after active
ZSK_I_D_INTERVAL = 7			# deleted 7 days after inactive

# Double-RRset Method with KSK - cascaded intervals for timing metadata
								# published immediately after generation
KSK_P_A_INTERVAL = 0			# active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 360			# inactive 360 days after active
KSK_I_D_INTERVAL = 7			# deleted 7 days after inactive

# key algorithm
""" 2012-03-04 bind-users:

...Second, why do I get multiple DS records as response?

You will always get a 2 DS Records in response. One for SHA-1 and second
for SHA-256.

I was reading the RFCs, but according to that, there's no provision of
SHA-256. According to RFC 4034, 1 means MD5 and 2 means Diffie-Hellman
(appendix A1)

And RFC4024 is seven years old. No SHA256 back then.

See RFC6014 which allows IANA to assign new algorithm numbers as
needed without a new RFC. SHA256 is the current preferred algorithm,
while SHA-1 is still routinely used as some DNSSEC software may not
support SHA256 yet. Both MD5 and Diffie-Hellman are obsolete. I
suspect SHA-1 will be deprecated soon. I am unaware of any DNSSEC
software that does not support SHA256 at this time, but I suspect
someone, somewhere is running it.
-- 
R. Kevin Oberman, Network Engineer
E-mail: kob6558@gmail.com
"""
KEY_ALGO_NSEC = 'RSASHA256'
KEY_ALGO_NSEC3 = 'NSEC3RSASHA1'
## use both: DIGEST_ALGO_DS = '-2'			# SHA-256

KEY_SIZE_KSK = 2048
KEY_SIZE_ZSK = 1024

TTL_DNSKEY = 86400
TTL_DS = 86400

NS_TIMEOUT = 10					# name server timeout

#--------------------------
#	End Adjustables
#------------------------------------------------------------------------------


script.doc.purpose = \
	'Do maintenace of DNSsec keys.\n Create and delete them as necessary'
script.doc.args = 'FUNCT'
opts.add('verbose', action='store_true')
opts.add('debug', action='store_true')

current_timestamp = 0
master_resolver = dns.resolver.Resolver()
master_resolver.lifetime = NS_TIMEOUT
master_resolver.nameserversNS_ = (conf.master)
master_resolver.use_edns(edns=0, ednsflags=0, payload=4096)


#--------------------------
#	classes
#--------------------------
# exceptions

class AbortedZone(Exception):
	def __init__(self,x):
		self.data = x

class CompletedZone(Exception):
	pass

class SigningKey(object):
	"""SigningKey"""
	def __init__(self, task, name, file_name, sender, nsec3 = False):
		
		self.name = None
		self.file_name = None
		##self.pcfg = pcfg		# zone keeps cfg
		##self.pstat = pstat	# zone keeps state
		self.zone = sender
		self.nsec3 = nsec3

		self.type = None
		
		self.algo = KEY_ALGO_NSEC
		if nsec3: self.algo = KEY_ALGO_NSEC3
		
		# values read from key file
		self.timingData = {}
		self.keytag = ''		# key tag
		self.dnssec_flags = 0	# flags
		self.sepkey = 0			# sep flag =KSK)
		self.dnssec_alg = 0		# key algorithm

		self.mypath = path(ROOT_PATH + '/' + name)
		self.mypath.cd()

		# Read key meta data from key file
		def	readKey(keyFileName):
			
			#	Read timing meta data from key
			def	readKeyTimingData(keyFileName, type):
				result = None
				if not type in 'PAID':
					e = AbortedZone('?Internal inconsistency: readKeyTimingData called with wrong type ' 
						+ type + ' for key ' +keyFileName)
					raise e
				try:
					(rubbish, result) = str(shell('dnssec-settime 	-u -p ' + type + ' ' + keyFileName, stdout='PIPE').stdout).split(None)
				except script.CommandFailed:
					e = AbortedZone('?Error from dnssec_settime while reading timing data of '  +keyFileName)
					raise e
				if result == 'UNSET':
					return 0
				else:
					result = int(result) // ( 3600 * 24 ) * 3600 * 24
				return result

			try:
				fd = open(keyFileName, 'r')
			except IOError:
				e = AbortedZone('?Can\'t open key file ' + keyFileName)
				raise e
			flags = None
			for line in fd:
				(name, ttl, dns_class, rr, flags, x) = line.split(None, 5)
				if name == ';':
					continue
				if dns_class == 'IN' and rr == 'DNSKEY':
					self.name = name
					st = line.find('DNSKEY ')
					tok = dns.tokenizer.Tokenizer(line[st+7:])
					dnskey_rdata = dns.rdtypes.ANY.DNSKEY.DNSKEY.from_text(dns.rdataclass.ANY, dns.rdatatype.DNSKEY, tok, origin=name, relativize=False)
					self.keytag = dns.dnssec.key_id(dnskey_rdata)
					self.dnssec_flags = dnskey_rdata.flags
					self.sepkey = self.dnssec_flags & 0x1;
					self.dnssec_alg = dnskey_rdata.algorithm
					if opts.debug: print("[Read DNSSEC key id=%d with flags=%d alg=%d]" % (self.keytag, self.dnssec_flags, self.dnssec_alg))
				else:
					e = AbortedZone('?Unrecognized line in key file: ' + keyFileName)
					raise e
				if flags == '257':
					if opts.debug: print('[Key ' + keyFileName + ' is KSK]')
					if self.sepkey == 0:
						e = AbortedZone('?Inkonsistent sep flag found in %s' % (keyFileName))
						raise e
					self.type = 'KSK'
					break
				elif flags == '256':
					if opts.debug: print('[Key ' + keyFileName + ' is ZSK]')
					if self.sepkey == 1:
						e = AbortedZone('?Inkonsistent sep flag found in %s' % (keyFileName))
						raise e
					self.type = 'ZSK'
					break
				else:
					e = AbortedZone('?Key neither KSK not ZSK: ' + keyFileName)
					raise e

			fd.close()
			
			self.timingData['P'] = readKeyTimingData(keyFileName, 'P')
			self.timingData['A'] = readKeyTimingData(keyFileName, 'A')
			self.timingData['I'] = readKeyTimingData(keyFileName, 'I')
			self.timingData['D'] = readKeyTimingData(keyFileName, 'D')
			
			
		if opts.debug:
			print('[Creating SigningKey task=%s, name=%s, file_name=%s, nsec3=%s]' % (task, name, file_name, nsec3))
		if task == 'read':
			self.file_name = file_name
			readKey(file_name)
		elif task == 'ZSK':
			inactive_from_now = ZSK_P_A_INTERVAL + ZSK_A_I_INTERVAL
			delete_from_now = inactive_from_now + ZSK_I_D_INTERVAL
			s = 'dnssec-keygen -a ' + self.algo + ' -b ' + repr(KEY_SIZE_ZSK) + ' -n ZONE ' \
				+ '-A +' + repr(ZSK_P_A_INTERVAL) + 'd ' +'-I +' + repr(inactive_from_now) + 'd ' \
				+ '-D +' + repr(delete_from_now) +'d -L ' + repr(TTL_DNSKEY) + ' ' + name
			if opts.debug: print(s)
			try:
			    result = shell(s, stdout='PIPE').stdout.strip()
			except script.CommandFailed:
			    e = AbortedZone('?Error while creating ZSK for ' + name)
			    raise e
			self.file_name = result + '.key'
			print('[Key ' + self.file_name + ' created.]')
			readKey(self.file_name)
		elif task == 'KSK':
			inactive_from_now = KSK_P_A_INTERVAL + KSK_A_I_INTERVAL
			delete_from_now = inactive_from_now + KSK_I_D_INTERVAL
			s = 'dnssec-keygen -a ' + self.algo + ' -b ' + repr(KEY_SIZE_KSK) + ' -n ZONE -f KSK ' \
				+ '-A +' + repr(KSK_P_A_INTERVAL) + 'd -I +' + repr(inactive_from_now) + 'd ' \
				+ '-D +' + repr(delete_from_now) + 'd -L ' + repr(TTL_DNSKEY) + ' ' + name
			if opts.debug: print(s)
			try:
			    result = shell(s, stdout='PIPE').stdout.strip()
			except script.CommandFailed:
			    e = AbortedZone('?Error while creating KSK for ' + name)
			    raise e
			self.file_name = result + '.key'
			print('[Key ' + self.file_name + ' created.]')
			readKey(self.file_name)
			self.CreateDS()
		else:
			e = AbortedZone('?Internal inconsitency: SigningKey instantiating  with wrong task ' + task)
			raise e
		
	def __str__(self):
		def getKeyTimingData(type):
			if self.timingData[type] == 0:
				return 'UNSET'
			else:
				return date.fromtimestamp(self.timingData[type]).isoformat()
		
		return self.type + ':'+ self.name+ ': A:'+ getKeyTimingData('A') + ' I:'+ getKeyTimingData('I') + ' D:'+ getKeyTimingData('D')
	
	def CreateDS(self):			# create delegate signer RR from KSK
		self.mypath.cd()
		result = None
		
		if self.type != 'KSK':
			e = AbortedZone("?Can't create DS from ZSK (internal inconsitency)" + self.name)
			raise e
		
		if opts.verbose: print('[Creating DS-RR from KSK %s]' % self.file_name)
		s = 'dnssec-dsfromkey ' + self.file_name
		if opts.debug: print(s)					  
		try:									  
			result = shell(s, stdout='PIPE').stdout.strip()
		except script.CommandFailed:			  
		    e = AbortedZone('?Error while creating DS RR for ' + self.name)
		    raise e
		ds_file_name = ''
		if self.zone.pcfg['Registrar'] == 'Local' and self.zone.parent_dir != None:
			ds_file_name = self.zone.parent_dir + '/'
		if opts.debug: print('[DS-RR will be stored in "%s" (%s / %s)]' % (ds_file_name, self.zone.pcfg['Registrar'], self.zone.parent_dir))
		ds_file_name = ds_file_name + self.name + 'ds'
		with open(ds_file_name, 'w', encoding="ASCII") as fd:
		  fd.write(result + '\n')
		# increment SOA
			
	
	def state_transition(self, secondKey):
		
		"""
		r1 = ZSTT[0]['c']( ZSTT[0]['ca'])
		r2 = ZSTT[1]['c']( ZSTT[1]['ca'])
		print(r1,r2, ZSTT, '\n', KSTT)
		"""
		state = -1									# state is index into sate table
		stt = None									# state table
		key = ''									# key for accessing state
		if self.type == 'KSK':						# key signing key
			stt = KSTT								# use corresponding state table
			key = 'ksk'								# and state key
		else:										# zone signing key
			stt = ZSTT
			key = 'zsk'
		state = self.zone.pstat[key]['State']
		if state == -1:								# initial state: begin signing
		    self.zone.pstat[key]['State'] = 0		# we have an SigningKey instance advance state
		    return True
													# not initial state
		if stt[state]['c']( stt[state]['ca']):	# check condition for state transition
		    if 'a' in stt[state].keys():		# succeeded: action present?
		    	stt[state]['a']( stt[state]['aa'])	# yes, call it
		    if 'ns' in stt[state].keys():		# 'next state' key present?
		    	self.zone.pstat[key]['State'] =  stt[state]['ns']	# yes, use it
		    else:
		    	self.zone.pstat[key]['State'] = state + 1			# no, increment it
		    return True							# we had a transition
		return False							# we stay in current state

	def activeTime(self):
		return self.timingData['A']
	
	# -----------------------------
	# State tables in SigningKey
	# -----------------------------
	#		   s = state				 c = check cond. for transition, ca = argument for c,	 a = action	aa=arg		ns = next state
	ZSTT = (
			{ 's': 'ZSK1 created',		'c': test_if_included,		'ca': 'zsk',		    							},
			{ 's': 'ZSK1 active',		'c': test_if_time_reached, 	'ca': 'zsk_prepub',	'a': create_a,	'aa': 'zsk'		},
			{ 's': 'ZSK2 created',		'c': test_if_included,		'ca': 'zsk',		    							},
			{ 's': 'ZSK2 published',	'c': test_if_time_reached,	'ca': 'zsk_active',	    							},
			{ 's': 'ZSK2 active',		'c': test_if_time_reached, 	'ca': 'zsk_delete',	'a': delete_a,	'aa': 'zsk'		},
			{ 's': 'ZSK1 deleted',		'c': test_if_excluded,	 	'ca': 'zsk',		'a': rename_a,	'aa': 'zsk', 'ns': 1	},
	)
	
	KSTT = (
			{ 's': 'KSK1 created',		'c': test_if_included,		'ca': 'ksk',		    							}, # 0
			{ 's': 'KSK1 active',		'c': test_if_time_reached, 	'ca': 'ds1_submit',	'a': submit_ds,	'aa': 'publish'	}, # 1
			{ 's': 'DS1 submitted',		'c': test_if_included,		'ca': 'ds',			    							}, # 2
			{ 's': 'DS1 published',		'c': test_if_time_reached,	'ca': 'ksk_prepub',	'a': create_a,	'aa': 'ksk'		}, # 3
			{ 's': 'KSK2 created',		'c': test_if_included,	 	'ca': 'ksk',		'a': submit_ds,	'aa': 'publish'	}, # 4
			{ 's': 'KSK2 active',		'c': test_if_included,		'ca': 'ds',			'a': submit_ds,	'aa': 'retire'	}, # 4
			{ 's': 'DS2 published',		'c': test_if_excluded,		'ca': 'ds',			    							}, # 5
			{ 's': 'DS1 retired',		'c': test_if_time_reached,	'ca': 'ksk_inactive'    							}, # 6
			{ 's': 'KSK1 inactive',		'c': test_if_time_reached,	'ca': 'ksk_delete',	'a': delete_a,	'aa': 'ksk'		}, # 7
			{ 's': 'KSK1 deleted',		'c': test_if_excluded,	 	'ca': 'ksk',		'a': rename_a,	'aa': 'ksk', 'ns':1	},# 8
			{ 's': 'DS retire request submitted','c':test_if_excluded,'ca': 'ds',		'a': set_delete_time,			}, # 9
			{ 's': 'DS retired',		'c': test_if_time_reached,	'ca': 'ksk_delete',	'a': delete_a,	'aa': 'ksk', 'ns':-1}
	)

	#-----------------------------
	# functions in SigningKey
	#-----------------------------
	def createNSEC3PARAM():
		"""
		http://strotmann.de/roller/dnsworkshop/entry/take_your_dnssec_with_a
		"""
		salt = binascii.b2a_hex(rand.get_random_bytes(6)).decode('ASCII').upper()
	
	
	# -----------------------------
	# Actions on state transitions in SigningKey
	# -----------------------------
	def create_a(key_type):		# in case of DS, always create 2 DS (SHA1 and SHA256)
		if DEBUG: print('[create_a(key_type) called]')
		return True
	
	def delete_a(key_type):
		if DEBUG: print('[delete_a(key_type) called]')
		return True
	
	def rename_a(key_type):
		if DEBUG: print('[rename_a(key_type) called]')
		return True
	
	def submit_ds(activity):
		if DEBUG: print('[submit_ds(activity) called]')
		return True
	
	def set_delete_time():
		if DEBUG: print('[set_delete_time() called]')
		return True
	
	# -----------------------------
	# Tests for state transitions in SigningKey
	# -----------------------------
	def test_if_included(key_type):		# test, if included in zone by our master
		if DEBUG: print('[test_if_included(' + key_type + ') called]')
		"""
		global master_resolver
		
	    r = master_resolver
	    try:
	        res = r.query(self.name, 'DNSKEY')
	    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
	            dns.resolver.NoNameservers):
	        pass
	    except (dns.exception.Timeout):
	        (exc_type, exc_value, exc_traceback) = sys.exc_info()
	        errmsg = "%s: DNSKEY query timed out. %s, %s" % \
	            (zone, exc_type, exc_value)
	        zoneinfo.dprint(errmsg)
	    else:
	        zoneinfo.has_dnssec = True
	        for dnskey_rdata in res.rrset.items:
	            keytag = dns.dnssec.key_id(dnskey_rdata)
	            dnssec_flags = dnskey_rdata.flags
	            sepkey = dnssec_flags & 0x1;
	            dnssec_alg = dnskey_rdata.algorithm
	            zoneinfo.dprint("DNSSEC key id=%d with flags=%d alg=%d" %
	                            (keytag, dnssec_flags, dnssec_alg))
	            if sepkey:
	                zoneinfo.dnssec_alg_ksk.append((keytag, dnssec_alg))
	            else:
	                zoneinfo.dnssec_alg_zsk.append((keytag, dnssec_alg))
		"""
		return False
	
	def test_if_excluded(key_type):		# test, if excluded from zone by our master
		if DEBUG: print('[test_if_excluded(' + key_type + ') called]')
		return False
	
	def test_if_time_reached(time_type):# test, if arbitrary point in time reached
		if DEBUG: print('[test_if_time_reached(' + time_type + ') called]')
		return False

#------------------------------------------------------------------------------

class managedZone(object):
	"""managedZone"""

	def __init__(self, name):
		self.name = name
		
		self.pcfg = {'Method': 'unsigned',	# unsigned, NSEC or NSEC3 \
					'Registrar': 'Local'} 	# Local, Joker, Ripe	\
		
		self.pstat = {}
		self.pstat['ksk'] = {'State': -1,	# index into state table KSTT, \
						 	 'Retries': 0} 	# Number of retries in current state
		self.pstat['zsk'] = {'State': -1,	# index into state table ZSTT, \
						 	'Retries': 0} 	# Number of retries in current state
		self.pstat['OldMethod'] = 'unsigned'# NSEC or NSEC3 \
		self.pstat['OldRegistrar'] = 'Local'	# Joker, Ripe

		self.ksks = []
		self.zsks = []
	
		self.parent_dir = None
		
		self.mypath = path(ROOT_PATH + '/' + name)
		self.mypath.cd()
		
		def readConfig(cfg, domain_name, file_name):
			if opts.debug: print('[Opening ' + domain_name + '/' + file_name + ']')
			try:
				with open(file_name) as fd:		# open config/status file for read
					try:
						key = ''
						tstcfg = json.load(fd)
						for key in iter(cfg):	# do simple syntax check
							vt = tstcfg[key]	# raises if key missed
							vo = cfg[key]
							if isinstance(vo, dict):
								for key in iter(vo):
									x = vo[key] # raises if key missed
					except:						# missing key: syntax error in cfg file
						e = AbortedZone('?Garbage found/Missing option ' + key + ' in configuration/status file "' + domain_name + '/' + file_name + '"')
						raise e
					cfg = tstcfg	
			except IOError:						# file not found
				try:
					with open(file_name, 'w') as fd:
						json.dump(cfg, fd, indent=8)
				except IOError:					# no write permission
					(exc_type, exc_value, exc_traceback) = sys.exc_info()
					errmsg = "?Can't create file, because %s" % (exc_value)
					e = AbortedZone(1, errmsg)
					raise e
			if opts.debug:
				print('[Config/status ' + domain_name + '/' + file_name + ' contains:\n' + str(cfg) + ']')
			return cfg
				
		(x,y,parent) = self.name.partition('.')
		pd = path(ROOT_PATH + '/' + parent)
		if opts.debug: print('[Parent directory would be %s]' % (pd,))
		zl = ''
		if pd.exists:
			zl = ' <local>'
			self.parent_dir = pd
		if opts.verbose: print('[Working on ' + self.name + ' (' + parent + zl +')' + ']')

		try:
			cfg_file_name = 'dnssec-conf-' + self.name
			self.pcfg = readConfig(self.pcfg, name, cfg_file_name)
			stat_file_name = 'dnssec-stat-' + self.name
			self.pstat = readConfig(self.pstat, name, stat_file_name)
			if self.pcfg['Method'] not in ('unsigned', 'NSEC', 'NSEC3'):
			    e = AbortedZone('? Wrong Method "%s" in zone config of %s' % (self.pcfg['Method'], self.name))
			    raise e
			if self.pstat['OldMethod'] not in ('unsigned', 'NSEC', 'NSEC3'):
			    e = AbortedZone('? Wrong OldMethod "%s" in zone config of %s' % (self.pstat['Method'], self.name))
			    raise e
		
			self.ksks = []						# list of keys
			self.zsks = []
			
			if opts.debug:
			    print('[KSK state is %d]' % (self.pstat['ksk']['State']))
		
			for kf in path('.').list('*'):		# loop once per file in zone dir
			    if fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*'):
			    	if self.pstat['ksk']['State'] == -1:	# state idle
			    		try:
			    			os.remove(path(kf))	# remove all key files if we do not have one created
			    		except:
			    			(exc_type, exc_value, exc_traceback) = sys.exc_info()
			    			e = AbortedZone("?Can't delete keyfile, because %s" % (exc_value))
			    			raise e
			    	else:	
			    		k = SigningKey('read', '', kf, self)
			    		if k.type == 'KSK':
			    			self.ksks.append(k)
			    		elif k.type == 'ZSK':
			    			self.zsks.append(k)
			
			nsec3 = False
			if self.pstat['ksk']['State'] == -1: # IDLE state
			    if self.pcfg['Method'] == 'unsigned':
			    	raise CompletedZone()		# unsigned zone
			    elif self.pcfg['Method'] == 'NSEC3':
			    	nsec3 = True
			    								# Begin signing zone 1st time
			    k = (SigningKey('KSK', self.name, '', self, nsec3=nsec3))
			    self.ksks.append(k)
			    
			    self.zsks.append(SigningKey('ZSK', self.name, '', self, nsec3=nsec3))
			
			self.ksks.sort(key=SigningKey.activeTime, reverse=True)
			second = False
			for k in self.ksks:
				k.state_transition(second)
				second = True

			self.zsks.sort(key=SigningKey.activeTime, reverse=True)
			second = False
			for k in self.zsks:
				k.state_transition(second)
				second = True
			if opts.debug:
			    for key in self.ksks:
			    	print(key.__str__())
			if opts.debug:
			    for key in self.zsks:
			    	print(key.__str__())
		except AbortedZone:
			if self.pstat['ksk']['State'] == -1 or self.pstat['zsk']['State'] == -1:
				print('?Removing key files of %s' % (name))
				self.deleteKeyFiles
				raise
		
	#		if self.pcfg['Method'] != self.pstat['OldMethod']:
	#			print('[Method of domain %s has changed from %s to %s]' % (self.name, self.pstat['OldMethod'], self.pcfg['Method']))
	#			script.exit(1, '?Changing of methods not yet implemented')
	
			
	#-----------------------------
	# functions in managedZone
	#-----------------------------
	def deleteKeyFiles():
		for kf in self.mypath.list('*'):		# loop once per file in zone dir
		    if fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*'):
		    	try:
		    	    os.remove(path(kf))			# remove all key files if we do not have one created
		    	except:
		    	    (exc_type, exc_value, exc_traceback) = sys.exc_info()
		    	    e = AbortedZone("?Can't delete keyfile, because %s" % (exc_value))
		    	    raise e
	

#--------------------------
#	Functions
#--------------------------


#--------------------------
#	Main
#--------------------------
def main():
	try:
		current_timestamp = int(shell('date +%s', stdout='PIPE').stdout.strip())
	except script.CommandFailed:
		script.exit(1, '?Unable to obtain current timestamp' )
	current_timestamp = ( current_timestamp // ( 3600 * 24 )) * 3600 * 24
	if opts.debug: print('[Timestamp at 0:0 was %d]' % (current_timestamp,))
	
	root = path(ROOT_PATH)
	if opts.debug: opts.verbose = True
	if not root.exists:
		print('%No key root directory; creating one.')
		root.mkdir(mode=0o750)
		root = path(ROOT_PATH)
	if opts.verbose: print('[scanning ' + root + ']')
	root.cd()
	root = path('.')
	zone_dirs = []
	zones = {}
	for dir in root.list('*'):
		if dir.is_dir:
			zone_dirs.append(dir.name)
	zone_dirs.sort(key = len)
	zone_dirs.reverse()
	if opts.debug: print('[ Doing zones: ]')
	if opts.debug: print( zone_dirs )
	for zone_name in zone_dirs:
		try:
			zones[zone_name] = managedZone(zone_name)
		except AbortedZone as a:
			print(a.data)
			print('%Skipping zone ' + zone_name)
		except CompletedZone:
			pass

script.run(main)
