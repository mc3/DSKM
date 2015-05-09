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
misc.py - miscellaneous classes and functions
"""

import dns.resolver, dns.message, dns.query, dns.rdatatype, dns.rdtypes.ANY.DNSKEY, dns.rcode
import dns.dnssec, dns.zone

import sys

import DSKM.conf as conf
import DSKM.key

import DSKM.logger as logger
l = logger.Logger()


#--------------------------

auth_NS = {}
auth_resolver = {}

# names and instances of zones, setup by main
zone_dirs = []
zones = {}

#--------------------------
#   classes
#--------------------------
# exceptions

class AbortedZone(Exception):
    def __init__(self,x):
        self.data = x

class CompletedZone(Exception):
    pass
    


#--------------------------
#   functions
#--------------------------

def doQuery(theQuery, theRRtype):
    try:
        answer = DSKM.key.master_resolver.query(theQuery, theRRtype)
        return answer
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, KeyError):
        (exc_type, exc_value, exc_traceback) = sys.exc_info()
        l.logDebug('doQuery(): Query: %s failed with %s' % (theQuery, exc_type))
        return None
    except (dns.exception.Timeout):
        l.logError('Failed to query %s of zone %s' % (theRRtype, repr(theQuery)))
        raise

def authNS(theZone):        # return list of NS addresses, authoritative for theZone
    global auth_NS
    
    if theZone in auth_NS:
        return auth_NS[theZone]
    
    nslist = []
    ll = theZone.split('.')
    ll.append('')
    a1 = None
    while len(ll) > 1:
    	n = dns.name.Name(ll)
    	a1 = doQuery(n, 'NS')
    	if a1:
    		break
    	del(ll[0])
    if a1:
        for ns in a1:
            a2 = doQuery(ns.target, 'A')
            if a2:
                nslist.append(a2[0].address)
            a2 = doQuery(ns.target, 'AAAA')
            if a2:
                nslist.append(a2[0].address)
        auth_NS[theZone] = nslist
        return nslist
    l.logWarn("Unable to find NS of zone %s (or it's parent" % (repr(theQuery)))
    e = AbortedZone("")
    raise e

def authResolver(theZone):        # return a resolver bound to NS addresses, authoritative for theZone
    global auth_resolver
    if theZone in auth_resolver:
        return auth_resolver[theZone]
    my_resolver = dns.resolver.Resolver()
    my_resolver.lifetime = conf.NS_TIMEOUT
    my_resolver.nameservers = authNS(theZone)
    my_resolver.use_edns(edns=0, ednsflags=0, payload=4096)
    auth_resolver[theZone] = my_resolver
    return my_resolver
