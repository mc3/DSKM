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
import  xml.etree.ElementTree as etree
import http.client
import pprint
import ssl
import time
import urllib.parse

import sys
# -----------------------------------------

# -----------------------------------------
# Globals
# -----------------------------------------
theConnection = None
theSecureConnection = None
# -----------------------------------------

import DSKM.logger as logger
l = logger.Logger()
# -----------------------------------------


# -----------------------------------------
# Configurables
# -----------------------------------------
import DSKM.conf as conf
#------------------------------------------------------------------------------

#--------------------------
#   classes
#--------------------------
class ConnectionRipe():
    """Connection to Ripe.net whois-db server"""
    
    _singleton = None
    conn = 0
    
    
    def __new__(cls, *args, **kwargs):
        if not cls._singleton:
            cls._singleton = super(ConnectionRipe, cls ).__new__(cls, *args, **kwargs)
        return cls._singleton
    
    
    def __init__(self):
        
        ConnectionRipe.conn = http.client.HTTPConnection(conf.registrar['Ripe']['server'])
        ##ConnectionRipe.conn.set_debuglevel(1)
        ##print('[Connected.]')
        
    def conn(self):
        return ConnectionRipe.conn

class SecureConnectionRipe():
    """Connection to Ripe.net whois-db server"""
    
    _singleton = None
    conn = 0
    
    
    def __new__(cls, *args, **kwargs):
        if not cls._singleton:
            cls._singleton = super(SecureConnectionRipe, cls ).__new__(cls, *args, **kwargs)
        return cls._singleton
    
    
    def __init__(self):
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        SecureConnectionRipe.conn = http.client.HTTPSConnection(conf.registrar['Ripe']['server'], context = context)
        ##SecureConnectionRipe.conn.set_debuglevel(10)
        ##print('[Securely connected.]')
        
    def conn(self):
        return SecureConnectionRipe.conn

# -----------------------------------------
# Functions
# -----------------------------------------
def regRemoveAllDS(zone):

    ele = None
    
    if zone.split('.')[-1] not in 'arpa':
        l.logError('Internal inconsitency: regRemoveAllDS(): Zone not supported by Ripe: "%s"' % (zone))
        return None
        
    b = """<whois-modify>\r
    <remove attribute-type="ds-rdata"/>\r
</whois-modify>\r
"""
    h = {}
    h['Content-Type'] = 'application/xml'
    
    try:
        ele = request('POST', 'modify/ripe/domain/' + zone, body=b, headers=h)
    except:
        l.logError('Request remove all DS-RR of zone %s to Ripe failed' % (zone))
        raise
        return None
    logDomainAttributes(ele)
    d = domainAttributes(ele)
    if d and 'ds-rdata' not in d:   # all DS-RR deleted
        return d
    l.logError('Request remove all DS-RR of zone %s to Ripe returned still at least one ds-rdata or something else went wrong' % (zone))
    return None
    


def regAddDS(zone, args):

    ele = None
    
    if zone.split('.')[-1] not in 'arpa':
        l.logError('Internal inconsitency: regRemoveAllDS(): Zone not supported by Ripe: "%s"' % (zone))
        return None
        
    if not regRemoveAllDS(zone):		# remove any existing DS
    	return None
    
    b = """
<whois-modify>
    <add>
        <attributes>
    """
    for arg in args:
        if (None, '') in (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])):
            l.logError('Internal inconsitency: regAddDS(): at least one argument of key %d is empty: "%d","%d","%s"'
                % (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])))
            return None
        b = b + str('	    <attribute name="ds-rdata" value="%d %d %d %s"/>\n' %
            (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])))
    b = b + """
        </attributes>   
    </add>
</whois-modify>
"""
    h = {}
    h['Content-Type'] = 'application/xml'
    
    try:
        ele = request('POST', 'modify/ripe/domain/' + zone, body=b, headers=h)
    except:
        l.logError('Request update all DS-RR of zone %s to Ripe failed' % (zone))
        raise
        return None
    logDomainAttributes(ele)
    d = domainAttributes(ele)
    if d and 'ds-rdata' in d and d['ds-rdata'] == len(args):   # one DS-RR per item in args required
        return d
    l.logError('Request update DS-RR of zone %s to Ripe returned unexpected number of ds-rdata' % (zone))
    return None

def getResultList(rid):
    # no result list with Ripe
    return ''

# -----------------------------------------
# Internal functions
# -----------------------------------------

def query(url):
    
    c = ConnectionRipe().conn
    
    u = '/whois/' + url
    print('[Requesting.]')
    c.request('GET', u)
    
    with c.getresponse() as r1:
        if r1.status != 200:
            print('Query of RIPE.NET whois DB server failed , because: ' + r1.reason + ' - HTTP - status ' + repr(r1.status))
            return None
        t = etree.fromstring(r1.read())
        return t
    return 

def request(method, url, body=None, headers={}):
    
    c = SecureConnectionRipe().conn
    
    u = '/whois/' + url + '?password=' + conf.registrar['Ripe']['account_pw']
    ##print('[Requesting.]')
    c.request(method, u, body, headers)
    
    with c.getresponse() as r1:
        if r1.status != 200:
            print('Request to RIPE.NET whois DB server failed , because: ' + r1.reason + ' - HTTP - status ' + repr(r1.status))
            return None
        t = etree.fromstring(r1.read())
        return t
    return 

def domainAttributes(ele):      #return a dict with attribute names as keys and number of occurences as values
    if ele == None:
        return
    d = {}              		# result dict
    oe = ele.findall("objects/object/attributes/*")
    for o in oe:
        name = None
        value = None
        for (k,v) in o.attrib.items():
            if k == 'name':
                name = v
            if k == 'value':
                value = v
                if name in d:
                    d[name] = d[name] +1
                else:
                    d[name] = 1
    return d

def logDomainAttributes(ele):
    if ele == None:
        return
    oe = ele.findall("objects/object/attributes/*")
    for o in oe:
        name = None
        value = None
        for (k,v) in o.attrib.items():
            if k == 'name':
                name = v
            if k == 'value':
                value = v
                l.logDebug(str('  %s:\t%s' % (name, value)))

