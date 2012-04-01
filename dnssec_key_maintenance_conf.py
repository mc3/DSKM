#!/usr/bin/env python3
#

"""
 Copyright (c) 2006-2012 Axel Rau, axel.rau@chaos1.de
"""

#------------------------------------------------------------------------------
# DNS servers
# -----------------------------------------

# own dns servers
master = '127.0.0.1'

external_secondaries = ('ns2.my.domain', 'ns3.my.domain', 'ns4.my.domain')

external_recursives = ('bind.odvr.dns-oarc.net')

#--------------------------
# registrars
#--------------------------

registrar = {}
registrar['my_registrar'] = {	'server': 'reg.my.registrar',
						'account_name': 'our_account',
						'account_pw': 'secret' }

#------------------------------------------------------------------------------
#   Root of key management directories
#--------------------------
ROOT_PATH = '/var/named/master/signed'

#--------------------------
#   policy constants ( in days)
#--------------------------

SOA_EXPIRE_INTERVAL = 7         #  SOA expire time
SOA_NEGATIVE_CACHE_INTERVAL = 1

"""
# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
                                # published immediately after generation
ZSK_P_A_INTERVAL = 0            # active (used to sign RRsets) 7 days after publish
ZSK_A_I_INTERVAL = 30           # inactive 30 days after active
ZSK_I_D_INTERVAL = 7            # deleted 7 days after inactive

# Double-RRset Method with KSK - cascaded intervals for timing metadata
                                # published immediately after generation
KSK_P_A_INTERVAL = 0            # active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 360          # inactive 360 days after active
KSK_I_D_INTERVAL = 7            # deleted 7 days after inactive
"""
# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
                                # published immediately after generation
ZSK_P_A_INTERVAL = 0            # active (used to sign RRsets) 7 days after publish
ZSK_A_I_INTERVAL = 1            # inactive 30 days after active
ZSK_I_D_INTERVAL = 1            # deleted 7 days after inactive

# Double-RRset Method with KSK - cascaded intervals for timing metadata
                                # published immediately after generation
KSK_P_A_INTERVAL = 0            # active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 2            # inactive 360 days after active
KSK_I_D_INTERVAL = 1            # deleted 7 days after inactive

# key algorithm

KEY_ALGO_NSEC = 'RSASHA256'
KEY_ALGO_NSEC3 = 'NSEC3RSASHA1'

## use both: DIGEST_ALGO_DS = '-2'          # SHA-256

KEY_SIZE_KSK = 2048
KEY_SIZE_ZSK = 1024

TTL_DNSKEY = 86400
TTL_DS = 86400

NS_TIMEOUT = 10                 # name server timeout
