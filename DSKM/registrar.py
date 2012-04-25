#!/usr/bin/env python3
#

"""
 DSKM DNSsec Key Management
 
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

