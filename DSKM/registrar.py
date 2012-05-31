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
    else:
        l.logError('Internal inconsistency: Unknown registrar "%s" in config' % (zone.pcfg['Registrar']))
    return None
    
def regAddDS(zone, args):
    zone_name = zone.name
    if zone.pcfg['Registrar'] == 'Joker':
        return reg_joker.regAddDS(zone_name, args)
    elif zone.pcfg['Registrar'] == 'Ripe':
        return reg_ripe.regAddDS(zone_name, args)
    else:
        l.logError('Internal inconsistency: Unknown registrar "%s" in config' % (zone.pcfg['Registrar']))
    return None

def getResultList(rid):
    return reg_joker.getResultList(rid)

