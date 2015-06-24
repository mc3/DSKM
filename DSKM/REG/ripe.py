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

def regAddDS(zone_name, args, test_run, dry_run):

    return makeRequest(zone_name, args, test_run, dry_run)


def getResultList(rid):
    # no result list with Ripe
    return ''

# -----------------------------------------
# Internal functions
# -----------------------------------------

def dbQuery(url):
    
    c = SecureConnectionRipe().conn
    
    u = '/' + url
    l.logDebug('dbQuery: Host: %s GET %s' % (conf.registrar['Ripe']['server'], u))
    c.request('GET', u)
    
    with c.getresponse() as r1:
        t = etree.fromstring(r1.read())
        if r1.status != 200:
            l.logError('Query of RIPE.NET whois DB server failed , because: % - HTTP - status: %' %
                (r1.reason, repr(r1.status)))
    if l.debug:
        print('[Dumping XML tree of dbQuery response:]')
        etree.dump(t)
    return t

def dbRequest(method, url, dry_run, body=None, headers={}):
    
    c = SecureConnectionRipe().conn
    
    dr = ''
    if dry_run: dr = '&dry-run'
    u = '/' + url + '?password=' + conf.registrar['Ripe']['account_pw'] + dr
    # l.logDebug seems dysfunctional here:
    l.logDebug('dbRequest(method,url,,,): %s %s' % (method, u))
    l.logDebug('dbRequest(,,,headers,): %s' % (repr(headers)))
    l.logDebug('dbRequest(,,body,,): %s' % (body))
    l.logDebug('dbRequest(method,url,,,): %s %s' % (method, u))
    c.request(method, u, body, headers)
    
    with c.getresponse() as r1:
        t = etree.fromstring(r1.read())
        if r1.status != 200:
            l.logError('Update of RIPE.NET whois DB server failed , because: %s - HTTP - status: %s' %
                (r1.reason, repr(r1.status)))
    if l.debug:
        print('[Dumping XML tree of dbRequest response:]')
        etree.dump(t)
    return t

def makeRequest(zone_name, args, test_run, dry_run):   # construct and perform the request for Ripe
    newChangedValue = ''
    ns = set()

    received_tree = None
    domain_atts = {}
        
    if zone_name.split('.')[-1] not in 'arpa':
        l.logError('Internal inconsitency: Zone not supported by Ripe: "%s"' % (zone_name))
        return None

    newChangedValue = changedTimestamp()    # sets up value of 'changed' attribute
    try:
        # query current config
        received_tree = dbQuery('search?source=ripe&query-string=' + zone_name + '&flags=no-filtering')
        assert received_tree != None
    except:
        l.logError('Request query DS-RR of zone %s at Ripe failed' % (zone_name))
        return None
    
    domain_atts = extract_domain_atts(received_tree)
    if not extract_and_report_error_messages(received_tree):
        return None
    
    for arg in args:
        if (None, '') in (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])):
            l.logError('Internal inconsistency: regAddDS(): at least one argument of key %d is empty: "%d","%d","%s"'
                % (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])))
            return None
        ns.add(str('%d %d %d %s' % (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest']))))
        
    if test_run and len(ns) > 0:
        domain_atts['ds-rdata'] = list(ns)
    else:
        (changed_something, domain_atts) = updateDomainAtts(domain_atts, ns, newChangedValue)
        if not changed_something:
            l.logWarn('No changes needed at registrar Ripe')
            return {'TID': ''}
    
    h = {}
    h['Content-Type'] = 'application/xml'
    b = etree.tostring(create_new_tree(domain_atts), encoding="unicode")
    try:
        # request update of config
        received_tree = dbRequest('PUT', 'ripe/domain/' + zone_name, dry_run, body=b, headers=h)
        assert received_tree != None
    except:
        l.logError('Request update DS-RR of zone %s to Ripe failed' % (zone_name))
        return None
    domain_atts = extract_domain_atts(received_tree)
    if not extract_and_report_error_messages(received_tree):
        return None
    ts = set(domain_atts['ds-rdata'])
    if ns != ts:
        l.logError('DS-RR of zone %s returned from Ripe differ from request' % (zone_name))
        return None
    return {'TID': newChangedValue}
    
def extract_domain_atts(received_tree):
    domain_atts = {}
    for obj in received_tree.findall('objects/*'):
        for (k,v) in obj.attrib.items():
            if k == 'type' and v == 'domain':
                for att in obj.findall('attributes/*'):
                    name = att.get('name')
                    value = att.get('value')
                    ## RIPE-NCC introduced last-modified on 2015-06, which must not be provided
                    if name == 'last-modified':
                        continue
                    print('%s: %s' % (name, value))
                    if name in domain_atts:
                        domain_atts[name].append(value)
                    else:
                        domain_atts[name] = [value]
                        
    for k in domain_atts:
        domain_atts[k].sort()
    return domain_atts

def extract_and_report_error_messages(received_tree):
    error_messages = []
    no_error = True
    for em in received_tree.findall('errormessages/*'):
        if em.tag == 'errormessage':
            err = False
            severity = em.get('severity')
            if severity == 'Error':
                no_error = False
                err = True
            arg_list = []
            arg_list.append(em.get('text'))
            args = em.findall('args')
            if args:
                for arg in args:
                    a = arg.get('value')
                    arg_list.append(a)
            for arg in arg_list:
                if err:
                    l.logError(arg)
                else:
                    l.logWarn(arg)
    return no_error

def updateDomainAtts(domain_atts, ns, newChangedValue):
    os = set(domain_atts['ds-rdata'])
    if os == ns:
        return (False, domain_atts)
    else:
        domain_atts['ds-rdata'] = list(ns)
        ## RIPE-NCC removed changed on 2015-05
        ##if newChangedValue not in domain_atts['changed']:
        ##    domain_atts['changed'].append(newChangedValue)
        return (True, domain_atts)

def create_new_tree(domain_atts):
    root = etree.Element('whois-resources')
    ose = etree.SubElement(root, 'objects')
    oe = etree.SubElement(ose, 'object')
    oe.set('type', 'domain')
    se = etree.SubElement(oe, 'source')
    se.set('id', 'ripe')
    ase = etree.SubElement(oe, 'attributes')
    
    de = etree.Element('attribute')     #will become domain attribute
    for k in domain_atts:
        for v in domain_atts[k]:
            if k == 'domain':
                de.set('name', k)
                de.set('value', v)
            else:
                a = etree.SubElement(ase, 'attribute')
                a.set('name', k)
                a.set('value', v)
    ase.insert(0, de)                   #domain attribute must be first
    ##etree.dump(root)
    return root

def changedTimestamp():
    newChangedValue = ''
    timestamp = datetime.now()
    newChangedValue = str('%s %s' % (conf.registrar['Ripe']['changed_email'], timestamp.strftime('%Y%m%d')))
    return newChangedValue

