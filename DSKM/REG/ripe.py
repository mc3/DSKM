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
REG/ripe.py - Interface module to the Regional Internet Registry RIPE's REST API 
          see https://labs.ripe.net/ripe-database/database-api/api-documentation
"""
# -----------------------------------------
from datetime import date, datetime
import http.client
import pprint
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as etree

import sys
# -----------------------------------------

# -----------------------------------------
# Globals
# -----------------------------------------
theConnection = None
theSecureConnection = None

newChangedValue = ''
updatedToday = False

newDSrdata = set()

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
        l.logDebug('Connected.')
        
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
        l.logDebug('Securely connected.')
        
    def conn(self):
        return SecureConnectionRipe.conn

# -----------------------------------------
# Functions
# -----------------------------------------
def regRemoveAllDS(zone_name):

    return makeRequest(zone_name, ())

def regAddDS(zone_name, args):

    return makeRequest(zone_name, args)


def getResultList(rid):
    # no result list with Ripe
    return ''

# -----------------------------------------
# Internal functions
# -----------------------------------------

def dbQuery(url):
    
    c = ConnectionRipe().conn
    
    u = '/whois/' + url
    ##print('[Requesting.]')
    c.request('GET', u)
    
    with c.getresponse() as r1:
        if r1.status != 200:
            print('Query of RIPE.NET whois DB server failed , because: ' + r1.reason + ' - HTTP - status' + repr(r1.status))
            return None
        t = etree.fromstring(r1.read())
        return t
    return 

def dbRequest(method, url, body=None, headers={}):
    
    c = SecureConnectionRipe().conn
    
    u = '/whois/' + url + '?password=' + conf.registrar['Ripe']['account_pw']
    l.logDebug('dbRequest(method,url,,,): %s %s' % (method, u))
    l.logDebug('dbRequest(,,,headers,): %s' % (repr(headers)))
    l.logDebug('dbRequest(,,body,,): %s' % (body))
    c.request(method, u, body, headers)
    
    with c.getresponse() as r1:
        if r1.status != 200:
            for line in r1.read().decode('ASCII').splitlines():
                l.logDebug(line)
            print('Request to RIPE.NET whois DB server failed , because: ' + r1.reason + ' - HTTP - status ' + repr(r1.status))
            return None
        t = etree.fromstring(r1.read())
        return t
    return 

def makeRequest(zone_name, args):   # construct and perform the request from Ripe
    global updatedToday
    ele = None
    addChanged = False
    
    if zone_name.split('.')[-1] not in 'arpa':
        l.logError('Internal inconsitency: Zone not supported by Ripe: "%s"' % (zone_name))
        return None

    changedTimestamp()              # sets up value of 'changed' attribute
    try:
        ele = dbQuery('lookup/ripe/domain/' + zone_name) # query current config
    except:
        l.logError('Request query DS-RR of zone %s at Ripe failed' % (zone_name))
        return None
    logDomainAttributes(ele)
    os = domainAttributeSet(ele)    # old (existing) set of ds-rdata
    ns = set()                      # new set of ds-rdata
    b = ''                          # request body

    for arg in args:
        if (None, '') in (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])):
            l.logError('Internal inconsitency: regAddDS(): at least one argument of key %d is empty: "%d","%d","%s"'
                % (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])))
            return None
        ns.add(str('%d %d %d %s' % (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest']))))
        
    if ns == os:
        l.logWarn('No changes needed at registrar Ripe')
        return {'TID': ''}
    if ns > os:
        b =  makeAppend(ns - os)
    else:
        if ns == set():
            b =  makeRemove()
            addChanged = True
        else:
            b =  makeReplace(ns)
            addChanged = True
    h = {}
    h['Content-Type'] = 'application/xml'
    ele = dbRequest('POST', 'modify/ripe/domain/' + zone_name, body=b, headers=h)
    if ele is None:
        l.logError('Request update DS-RR of zone %s to Ripe failed' % (zone_name))
        return None
    logDomainAttributes(ele)
    ts = domainAttributeSet(ele)
    if ns != ts:
        l.logError('DS-RR of zone %s returned from Ripe differ from request' % (zone_name))
        return None
    if addChanged and not updatedToday:
        b = makeAppend(set())
        h = {}
        h['Content-Type'] = 'application/xml'
        ele = dbRequest('POST', 'modify/ripe/domain/' + zone_name, body=b, headers=h)
        if ele is None:
            l.logWarn('Could not add "changed" attribute')
        logDomainAttributes(ele)
    return {'TID': newChangedValue}
    
def makeAppend(setOfDS_rdata):
    global updatedToday

    r = """
<whois-modify>
    <add>
        <attributes>"""
    for d in setOfDS_rdata:
        r = r + str('               <attribute name="ds-rdata" value="%s"/>\n' % (d))
    if not updatedToday:
        r = r + str('               <attribute name="changed" value="%s"/>\n' % (newChangedValue))
    r = r + """
        </attributes>
    </add>
</whois-modify>"""
    return r

    
def makeRemove():
    r = """
<whois-modify>
    <remove attribute-type="ds-rdata"/>
</whois-modify>"""
    return r
        

def makeReplace(setOfDS_rdata):
    r = """
<whois-modify>
    <replace attribute-type="ds-rdata">
        <attributes>"""
    for d in setOfDS_rdata:
        r = r + str('               <attribute name="ds-rdata" value="%s"/>\n' % (d))
    r = r + """
        </attributes>
    </replace>
</whois-modify>"""
    return r


def domainAttributeSet(ele):        # return a set with values of attributes 'ds-rdata' and 
                                    # and set global updatedToday, which is True, if changed today
    global updatedToday
    updatedToday = False
    s = set()                       # result set
    
    oe = ele.findall("objects/object/attributes/*")
    for o in oe:
        name = None
        value = None
        for (k,v) in o.attrib.items():
            if k == 'name':
                name = v
            if k == 'value':
                value = v
                if name == 'ds-rdata':
                    s.add(value)
                elif name == 'changed' and value == newChangedValue:
                    updatedToday = True
    return s

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

def changedTimestamp():
    global newChangedValue
    timestamp = datetime.now()
    newChangedValue = str('%s %s' % (conf.registrar['Ripe']['changed_email'], timestamp.strftime('%Y%m%d')))
    return

