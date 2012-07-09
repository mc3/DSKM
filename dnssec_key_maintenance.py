#!/usr/bin/env python3

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
dnssec_key_maintenance.py - main module of DSKM
"""

import sys

from script import path, shell, opts
import script
import time

import DSKM.logger as logger
import DSKM.registrar as reg
import DSKM.zone as zone
import DSKM.misc as misc

# -----------------------------------------


# -----------------------------------------
# Configurables
# -----------------------------------------
import DSKM.conf as conf

"""
#------------------------------------------------------------------------------
# the import should define:
# -----------------------------------------

# -----------------------------------------
# DNS servers to query
# -----------------------------------------
# own dns servers
master = '2.3.4.5'
external_secondaries = ('ns2.my.domain', 'ns3.my.domain', 'ns4.my.domain')
external_recursives = ()

#--------------------------
# registrars
#--------------------------

registrar = {}
registrar['TwoCows'] = {'server': 'dmapi.twocows.net',
                        'account_name': 'my_user_name',
                        'account_pw': 'blahblah' }
registrar['Ripe'] = {  'server': 'apps.db.ripe.net',
                        'account_name': 'ME-MNT',
                        'account_pw': 'my_secret',
                        'changed_email': 'hostmaster@my.domain' }

#------------------------------------------------------------------------------
#   Root of key management directories
#--------------------------
ROOT_PATH = '/var/named/master/signed'

#------------------------------------------------------------------------------
#   timing constans for state transition timeout
#--------------------------
CRON_FREQ = 24                  # we are called by cron that many times per day
TIMEOUT_SHORT = 5               # short timeout in hours
TIMEOUT_PREPUB_ADDITION = 10    # how many hours to add to pre-pulish-interval to get timeout

#--------------------------
#   policy constants ( in days)
#--------------------------

SOA_EXPIRE_INTERVAL = 7         #  SOA expire time
SOA_NEGATIVE_CACHE_INTERVAL = 1

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

KEY_ALGO_NSEC = 'RSASHA256'
KEY_ALGO_NSEC3 = 'NSEC3RSASHA1'
## use both: DIGEST_ALGO_DS = '-2'          # SHA-256

KEY_SIZE_KSK = 2048
KEY_SIZE_ZSK = 1024

TTL_DNSKEY = 86400
TTL_DS = 86400

NS_TIMEOUT = 10                 # name server timeout
"""
#------------------------------------------------------------------------------
# end defines of import  dnssec_key_maintenance_conf as conf
#------------------------------------------------------------------------------

script.doc.purpose = \
    'Do maintenace of DNSsec keys.\n Create and delete them as necessary.\nSubmit/cancle DS-RR to/at parent registrar.'

opts.add('cron', action='store_true',
                    help="Run as cronjob. Each run increments timeout timer.")

opts.add('verbose', action='store_true')
opts.add('debug', action='store_true')

opts.add('stopSigningOfZone', type="string",
                  help="Initiate procedure to make a zone unsigned. Argument is zone name.")
opts.add('force', action='store_true',
                  help="Force deletion of keys (ignore delete time) while stopping signing of zone")

opts.add('registrar_status', action='store_true',
                  help="Query list of completed and pending requests of all registrars and terminate")

opts.add('query_status', type="string",
                  help="Give detailed registrar result status about <request-id>.")
                  

#--------------------------
#   Main
#--------------------------
def main():
    root = path(conf.ROOT_PATH)
    if opts.debug: opts.verbose = True
    l = logger.Logger(opts.verbose, opts.debug, opts.cron)
    
    if opts.registrar_status or opts.query_status:
        cl = reg.getResultList(opts.query_status)
        if not cl:
            l.logError('Failed')
            return 1
        if opts.registrar_status:
            print('----- timestamp ----- ---------- Tracking-Id ---------  Proc-ID task    domain    result')
            for line in cl['result']:
                print(line)
        else:
            for k in sorted(cl.keys()):
                if k != 'result':
                    print('%s:\t%s' % (k, cl[k]))
        return 0

    if not root.exists:
        l.logWarn('No key root directory; creating one.')
        root.mkdir(mode=0o750)
        root = path(conf.ROOT_PATH)
    l.logVerbose('Scanning ' + root)

    root.cd()
    root = path('.')
    zone_dirs = []
    zones = {}
    for dir in root.list('*'):
        if dir.is_dir:
            zone_dirs.append(dir.name)
    zone_dirs.sort(key = len)
    zone_dirs.reverse()
    
    if opts.stopSigningOfZone:
        zone_name = opts.stopSigningOfZone
        print('[Stopping signing of %s]' % zone_name)
        if zone_name in zone_dirs:
            try:
                z = zone.managedZone(zone_name)
                res1 = z.stopSigning(opts.force)
                print('[Do "cd <zone_dir>; rm *.jbk *.jnl *.signed ; sleep 1 ; rndc stop" ; rndc start]')
                print('[...repeat until no DNSKEYs and RRSIGs remain in zone]')
                return res1 and res2
            except misc.AbortedZone:
                print('?Failed to stop signing of zone ' + zone_name)
                return 1
            except misc.CompletedZone:
                print('%%Unsigned zone ' + zone_name)
                return 0
            pass
        else:
            print('?%s not a managed zone.' % opts.stopSigningOfZone)
        return 1
    
    l.logDebug('[ Doing zones: ]')
    l.logDebug( zone_dirs )
    for zone_name in zone_dirs:
        try:
            zones[zone_name] = zone.managedZone(zone_name)
            zones[zone_name].performStateTransition()
            zones[zone_name].validate()
        except misc.AbortedZone as a:
            print(a.data)
            print('%Skipping zone ' + zone_name)
        except misc.CompletedZone:
            pass
    l.mailErrors()

script.run(main)
