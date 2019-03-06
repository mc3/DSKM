"""
Copyright (C) 2015-2018  Axel Rau <axel.rau@chaos1.de>

This file is part of serverPKI.

serverPKI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Foobar is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with serverPKI.  If not, see <http://www.gnu.org/licenses/>.
"""

# commandline interface module

import time
import sys

from pathlib import Path

from DSKM.utils import options as opts
import DSKM.config as conf
            
import DSKM.logger as logger
import DSKM.registrar as reg
import DSKM.zone as zone
import DSKM.misc as misc

def execute_from_command_line():

    
    print('operate_dskm started.')
    ##print('External scondaries are {}.'.format(conf.external_secondaries))
    print('Options are {}.'.format(opts))
    
    
    root = Path(conf.ROOT_PATH)
    if opts.debug: opts.verbose = True
    l = logger.Logger(opts.verbose, opts.debug, opts.cron)
    
    
    if opts.registrar_status or opts.query_status or \
            opts.purge_all_registrar_completion_info:
        cl = reg.getResultList(opts.query_status)
        if not cl:
            l.logError('Failed')
            return 1
        if opts.purge_all_registrar_completion_info:
            for line in cl['result']:
                if len(line) < 10: continue
                tid = line.split(' ')[1]
                if reg.deleteResult(tid):
                    print('.', end='', flush=true)
            print()
        elif opts.registrar_status:
            print('- timestamp -- ---------- Tracking-Id --------- Proc-ID  --- task ---  domain    result')
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
    if opts.verbose:
        print('')
    l.logVerbose('Scanning ' + root)
    
    root.cd()
    root = path('.')
    for dir in root.list('*'):
        if dir.is_dir:
            misc.zone_dirs.append(dir.name)
    misc.zone_dirs.sort(key = len)
    misc.zone_dirs.reverse()
    
    if opts.stopSigningOfZone:
        zone_name = opts.stopSigningOfZone
        print('[Stopping signing of %s]' % zone_name)
        if zone_name in misc.zone_dirs:
            try:
                z = zone.managedZone(zone_name)
                res1 = z.stopSigning(opts.force)
                print('[Set dnssec-secure-to-insecure to yes in zone config of named.conf]')
                print('[Do "cd <zone_dir>; rm *.jbk *.jnl *.signed ; sleep 1 ; rndc stop ; rndc start"]')
                print('[...repeat until no DNSKEYs and RRSIGs remain in zone]')
                return res1
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
    l.logDebug( misc.zone_dirs )

    if opts.test_registrar_DS_submission:
        for zone_name in misc.zone_dirs:
            try:
                misc.zones[zone_name] = zone.managedZone(zone_name)
            except misc.AbortedZone as a:
                print(a.data)
                print('%Skipping zone ' + zone_name)
            except misc.CompletedZone:
                pass
            
            try:
                reg.regTest(misc.zones[zone_name], opts.dry_run)
            except misc.AbortedZone as a:
                print(a.data)
                print('%Skipping zone ' + zone_name)
            except misc.CompletedZone:
                pass
        return 0
    for zone_name in misc.zone_dirs:
        try:
            misc.zones[zone_name] = zone.managedZone(zone_name)
            if not misc.zones[zone_name].verifySerial(): continue
            misc.zones[zone_name].performStateTransition()
            misc.zones[zone_name].validate()
        except misc.AbortedZone as a:
            print(a.data)
            print('%Skipping zone ' + zone_name)
        except misc.CompletedZone:
            pass
    l.mailErrors()
    