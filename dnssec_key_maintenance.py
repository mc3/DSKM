#!/usr/bin/env python3

from script import path, shell, opts
import script
import fnmatch
from datetime import date

# for salt
from Crypto import Random as rand
import binascii

import dns.resolver, dns.message, dns.query, dns.rdatatype, dns.rcode
import dns.dnssec

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
ZSK_P_A_INTERVAL = 7			# active (used to sign RRsets) 7 days after publish
ZSK_A_I_INTERVAL = 30			# inactive 30 days after active
ZSK_I_D_INTERVAL = 7			# deleted 7 days after inactive

# Double-RRset Method with KSK - cascaded intervals for timing metadata
								# published immediately after generation
KSK_P_A_INTERVAL = 7			# active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 360			# inactive 360 days after active
KSK_I_D_INTERVAL = 7			# deleted 7 days after inactive

# key algorithm
KEY_ALGO_KSK = 'RSASHA256'
KEY_ALGO_NSEC = 'RSASHA256'
KEY_ALGO_NSEC3 = 'NSEC3RSASHA1'
DIGEST_ALGO_DS = '-2'			# SHA-256

KEY_SIZE_KSK = 2048
KEY_SIZE_ZSK = 1024

#--------------------------
#	End Adjustables
#------------------------------------------------------------------------------


script.doc.purpose = \
	'Do maintenace of DNSsec keys.\n Create and delete them as necessary'
script.doc.args = 'FUNCT'
opts.add('verbose', action='store_true')
opts.add('debug', action='store_true')

current_timestamp = 0

#--------------------------
#	classes
#--------------------------
class SigningKey(object):
	"""SigningKey"""
	def __init__(self, action, name, file_name, nsec3 = None):
		
		self.name = None
		self.type = None
		self.nsec3 = None
		
		self.file_name = None
		self.timingData = {}


		# Read keytype from RR flags in key file
		def	readKey(keyFileName):
			
			#	Read timing meta data from key
			def	readKeyTimingData(keyFileName, type):
				result = None
				if not type in 'PAID':
					script.exit(1, '?Internal inconsistency: readKeyTimingData called with wrong type ' 
						+ type + ' for key ' +keyFileName)
				try:
					(rubbish, result) = str(shell('dnssec-settime 	-u -p ' + type + ' ' + keyFileName, stdout='PIPE').stdout).split(None)
				except script.CommandFailed:
					script.exit(1, '?Error from dnssec_settime while reading timing data of '  +keyFileName)
				if result == 'UNSET':
					return 0
				else:
					result = int(result) // ( 3600 * 24 ) * 3600 * 24
				return result

			try:
				fd = open(keyFileName, 'r')
			except IOError:
				script.exit(1, '?Can\'t open key file ' + keyFileName)
			flags = None
			for line in fd:
				(name, dns_class, rr, flags, x) = line.split(None, 4)
				if name == ';':
					continue
				if dns_class == 'IN' and rr == 'DNSKEY':
					self.name = name
				else:
					script.exit(1, '?Unrecognized line in key file: ' + keyFileName)
				if flags == '257':
					if opts.debug: print('[Key ' + keyFileName + ' is KSK]')
					self.type = 'KSK'
					break
				elif flags == '256':
					if opts.debug: print('[Key ' + keyFileName + ' is ZSK]')
					self.type = 'ZSK'
					break
				else:
					script.exit(1, '?Key neither KSK not ZSK: ' + keyFileName)

			self.timingData['P'] = readKeyTimingData(keyFileName, 'P')
			self.timingData['A'] = readKeyTimingData(keyFileName, 'A')
			self.timingData['I'] = readKeyTimingData(keyFileName, 'I')
			self.timingData['D'] = readKeyTimingData(keyFileName, 'D')

		if action == 'read':
			self.file_name = file_name
			readKey(file_name)
		elif action == 'ZSK':
			zsk_algo = KEY_ALGO_NSEC
			if nsec3: zsk_algo = KEY_ALGO_NSEC3
			inactive_from_now = ZSK_P_A_INTERVAL + ZSK_A_I_INTERVAL
			delete_from_now = inactive_from_now + ZSK_I_D_INTERVAL
			s = 'dnssec-keygen -a ' + zsk_algo + ' -b ' + repr(KEY_SIZE_ZSK) + ' -n ZONE ' \
				+ '-A +' + repr(ZSK_P_A_INTERVAL) + 'd ' +'-I +' + repr(inactive_from_now) + 'd ' \
				+ '-D +' + repr(delete_from_now) +'d ' + name
			if opts.debug: print(s)
			try:
			    result = shell(s, stdout='PIPE').stdout.strip()
			except script.CommandFailed:
			    script.exit(1, '?Error while creating ZSK for ' + name)
			self.file_name = result + '.key'
			print('[Key ' + self.file_name + ' created.]')
			readKey(self.file_name)
		elif action == 'KSK':
			inactive_from_now = KSK_P_A_INTERVAL + KSK_A_I_INTERVAL
			delete_from_now = inactive_from_now + KSK_I_D_INTERVAL
			s = 'dnssec-keygen -a ' + KEY_ALGO_KSK + ' -b ' + repr(KEY_SIZE_KSK) + ' -n ZONE -f KSK ' \
				+ '-A +' + repr(KSK_P_A_INTERVAL) + 'd -I +' + repr(inactive_from_now) + 'd ' \
				+ '-D +' + repr(delete_from_now) + 'd ' + name
			if opts.debug: print(s)
			try:
			    result = shell(s, stdout='PIPE').stdout.strip()
			except script.CommandFailed:
			    script.exit(1, '?Error while creating KSK for ' + name)
			self.file_name = result + '.key'
			print('[Key ' + self.file_name + ' created.]')
			readKey(self.file_name)
		else:
			script.exit(1, '?Internal inconsitency: SigningKey instantiating  with wrong action ' + action)
		
	def __str__(self):
		def getKeyTimingData(type):
			if self.timingData[type] == 0:
				return 'UNSET'
			else:
				return date.fromtimestamp(self.timingData[type]).isoformat()
		
		return self.type + ':'+ self.name+ ': A:'+ getKeyTimingData('A') + ' I:'+ getKeyTimingData('I') + ' D:'+ getKeyTimingData('D')
	
	def createNSEC3PARAM():
		salt = binascii.b2a_hex(rand.get_random_bytes(6)).decode('ASCII').upper()
		


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
	for dir in root.list('*'):
		if dir.is_dir:
			zone_dirs.append(dir.name)
	zone_dirs.sort(key = len)
	zone_dirs.reverse()
	if opts.debug: print('[ Doing zones: ]')
	if opts.debug: print( zone_dirs )
	for zone in zone_dirs:
		path(zone).cd()

		(x,y,parent) = zone.partition('.')
		parent_dir = path('../' + parent)
		zl = ''
		if parent_dir.exists:
			zl = ' <local>'
		if opts.verbose: print('[Working on ' + zone + ' (' + parent + zl +')' + ']')

		cfg_file = 'dnssec.' + zone
		cfg = 'None'
		if not path(cfg_file).exists:
			print('%Missing zone config for ' + zone + ' <creating...>')
			cfg_fd = open(cfg_file, "w")
			if opts.debug: print(cfg, file = cfg_fd)
		else:
			cfg_fd = open(cfg_file, "r")
			cfg = cfg_fd.readline().strip()
		if opts.debug: print('[Config is ' + cfg + ']')
		cfg_fd.close()
		
		ksks = []
		zsks = []
		for kf in path('.').list('*'):
			if fnmatch.fnmatch(kf, 'K' + zone + '.+*.key'):
				k = SigningKey('read', '', kf)
				if k.type == 'KSK':
					ksks.append(k)
				elif k.type == 'ZSK':
					zsks.append(k)
		if len(ksks) < 1:
			ksks.append(SigningKey('KSK', zone, ''))
		if len(zsks) < 1:
			zsks.append(SigningKey('ZSK', zone, ''))
		if opts.debug:
			for key in ksks:
				print(key.__str__())
		if opts.debug:
			for key in zsks:
				print(key.__str__())
		path('..').cd()
	

script.run(main)
