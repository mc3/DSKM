"""
 DSKM DNSsec Key Management
 
 Copyright (c) 2012 Axel Rau, axel.rau@chaos1.de

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

# -----------------------------------------
conf.py - configuration module - site specific configuration parameters
"""

#------------------------------------------------------------------------------
# DNS servers
# -----------------------------------------

# own dns servers
#	hidden master
master = ('127.0.0.1',)

external_secondaries = ('2.3.76.32', '2a02:33:1::142:1', '91.66.3.171', '2a02:33:2:18::77',
							'91.44.2.23', '2a02:33:2:2::77')

##external_recursives = ('bind.odvr.dns-oarc.net')
external_recursives = ('149.20.64.20', '2001:4f8:3:2bc:1::64:20')

#--------------------------
# registrars
#--------------------------

registrar = {}
registrar['my_registrar'] = {	'server': 'reg.my.registrar',
						'account_name': 'our_account',
						'account_pw': 'secret' }
registrar['Ripe'] = {  'server': 'apps.db.ripe.net',
                        'account_name': 'ME-MNT',
						'account_pw': 'my_secret',
						'changed_email': 'hostmaster@my.domain' }


#--------------------------
# Email addresses for mailing error messages
#--------------------------

sender = 'hostmaster@my.net'
recipients = ('me@my.net', )
mailRelay = 'localhost'

#------------------------------------------------------------------------------
#   Root of key management directories
#--------------------------
ROOT_PATH = '/var/named/master/signed'

#------------------------------------------------------------------------------
#   path to bind tools
#--------------------------
BIND_TOOLS = '/usr/local/sbin/'

#------------------------------------------------------------------------------
#   timing constans for state transition timeout
#--------------------------
CRON_FREQ = 24					# we are called by cron that many times per day
TIMEOUT_SHORT = 5				# short timeout in hours
TIMEOUT_PREPUB_ADDITION = 10	# how many hours to add to pre-pulish-interval to get timeout

#--------------------------
#   policy constants ( in days)
#--------------------------

SOA_EXPIRE_INTERVAL = 7         #  SOA expire time
SOA_NEGATIVE_CACHE_INTERVAL = 1

"""
# key timing default intervals in days
# Production
# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
                                # published immediately after generation
ZSK_P_A_INTERVAL = 4            # active (used to sign RRsets) 1 day after publish
ZSK_A_I_INTERVAL = 60           # inactive 60 days after active
ZSK_I_D_INTERVAL = 35           # deleted 35 days after inactive
ZSK_I1_A2_INTERVAL = 1          # active of followup key 1 day after inactive (rollover time)

# Double-RRset Method with KSK - cascaded intervals for timing metadata
                                # published immediately after generation
KSK_P_A_INTERVAL = 7            # active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 360          # inactive 360 days after active
KSK_I_D_INTERVAL = 35           # deleted 35 days after inactive
KSK_I1_A2_INTERVAL = 7          # active of followup key 7 days after inactive (rollover time)
"""

# During Testing phase
# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
                                # published immediately after generation
ZSK_P_A_INTERVAL = 1            # active (used to sign RRsets) 1 day after publish
ZSK_A_I_INTERVAL = 4            # inactive 4 days after active
ZSK_I_D_INTERVAL = 1            # deleted 35 days after inactive
ZSK_I1_A2_INTERVAL = 1          # active of followup key 1 day after inactive (rollover time)

# Double-RRset Method with KSK - cascaded intervals for timing metadata
                                # published immediately after generation
KSK_P_A_INTERVAL = 2            # active (used to sign DNSKEY RRsets) 2 days after publish
KSK_A_I_INTERVAL = 8            # inactive 8 days after active
KSK_I_D_INTERVAL = 2            # deleted 2 days after inactive
KSK_I1_A2_INTERVAL = 2          # active of followup key 2 days after inactive (rollover time)

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

DIGEST_ALGO_DS = '-2'          # '-1': SHA1, '-2': SHA-256, '': SHA1 + SHA256

KEY_SIZE_KSK = 2048
KEY_SIZE_ZSK = 1024

TTL_DNSKEY = 86400
TTL_DS = 86400

NS_TIMEOUT = 10                 # name server timeout
