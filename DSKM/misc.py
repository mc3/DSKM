#!/usr/bin/env python3

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

def authNS(theZone):
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

def authResolver(theZone):
    global auth_resolver
    if theZone in auth_resolver:
        return auth_resolver[theZone]
    my_resolver = dns.resolver.Resolver()
    my_resolver.lifetime = conf.NS_TIMEOUT
    my_resolver.nameservers = authNS(theZone)
    my_resolver.use_edns(edns=0, ednsflags=0, payload=4096)
    auth_resolver[theZone] = my_resolver
    return my_resolver
