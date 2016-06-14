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
registrar.py - common registrar functions
"""

# -----------------------------------------
import http.client
import time
import urllib.parse

import sys
# -----------------------------------------

# -----------------------------------------
# Globals
# -----------------------------------------
theConnection = None
# -----------------------------------------

import DSKM.logger as logger
l = logger.Logger()
# -----------------------------------------


# -----------------------------------------
# Configurables
# -----------------------------------------
import DSKM.conf as conf
import DSKM.REG.joker as reg_joker
import DSKM.REG.ripe as reg_ripe

#------------------------------------------------------------------------------

# -----------------------------------------
# Functions
# -----------------------------------------
def regRemoveAllDS(zone):
    zone_name = zone.name
    if zone.pcfg['Registrar'] == 'Joker':
        return reg_joker.regRemoveAllDS(zone_name)
    elif zone.pcfg['Registrar'] == 'Ripe':
        return reg_ripe.regRemoveAllDS(zone_name)
    elif zone.pcfg['Registrar'] == 'by hand':
        return handOverByEmail(zone_name, [], str('Deletion of DS-RR of zone %s required' % zone_name))
    else:
        l.logError('Internal inconsistency: Unknown registrar "%s" in config' % (zone.pcfg['Registrar']))
    return None
    
def regAddDS(zone, args):
    zone_name = zone.name
    if zone.pcfg['Registrar'] == 'Joker':
        return reg_joker.regAddDS(zone_name, args)
    elif zone.pcfg['Registrar'] == 'Ripe':
        return reg_ripe.regAddDS(zone_name, args, False, False)
    elif zone.pcfg['Registrar'] == 'by hand':
        return handOverByEmail(zone_name, args, str('DS-RR handover to parent of zone %s required' % zone_name))
    else:
        l.logError('Internal inconsistency: Unknown registrar "%s" in config' % (zone.pcfg['Registrar']))
    return None

def getResultList(rid):
    return reg_joker.getResultList(rid)
    l.logWarn('No resultlists at Ripe')

def deleteResult(transactionID):
    return reg_joker.deleteResult(transactionID)
    l.logWarn("Can't delete result info at Ripe")

def regTest(zone, dry_run):
    zone_name = zone.name
    if zone.pcfg['Registrar'] == 'Joker':
        ##return reg_joker.regTest(zone_name, dry_run)
        return
    elif zone.pcfg['Registrar'] == 'Ripe':
        args = zone.argsForDSsubmission()
        return reg_ripe.regAddDS(zone_name, args, True, dry_run)
    else:
        return

def handOverByEmail(zone_name, args, subject):
    body = ''
    if len(args) == 0:
        body = str('Please ask parent zone operator to remove all DS-RR for zone\n\t%s\n from parent zone.\n' % (zone_name))
    else:
        body = str('Please ask parent zone operator to adjust (delete/add) DS-RR / DNSKEY-RR for zone\n\t%s\n.\n' % (zone_name))
        body = body + '''Inspect the following list of DS-RR / DNSKEY-RR pairs carefully.
Any pairs, existing at parent and not in the following list must be deleted.
Any pairs, missing at parent, must be added.\n'''
        i = 1
        for arg in args:
            if (None, '') in (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])):
                l.logError('Internal inconsitency: regAddDS(): at least one argument of key %d is empty: "%d","%d","%s"'
                    % (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])))
                return None
            body = body + str('\n\nDS-RR / DNSKEY-RR %d -------------------------------------\n' % (i))
            body = body + str('DS\t%s %s %s\n' % (arg['tag'], arg['digest_type'], arg['digest']))
            body = body + str('DNSKEY\t%s 3 8 %s\n' % (arg['flags'], arg['pubkey']))

            i = i + 1
    body = body + str('\nEnd of message ----------------------------------\n')
    l.sendMail(subject, body)
    return {'TID': 'E-Mail sent'}
