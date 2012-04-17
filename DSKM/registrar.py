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
#------------------------------------------------------------------------------

#--------------------------
#   classes
#--------------------------
class ConnectionJoker(object):
    """Connection to Joker.com DMAPI server"""
    global l
    def __init__(self):
        self.myConnection = 0
        self.session = {}
    
        try:
            self.myConnection = http.client.HTTPSConnection(conf.registrar['Joker']['server'])
            self.myConnection.request("GET", '/request/login?username=' + 
                conf.registrar['Joker']['account_name'] + '&password=' + conf.registrar['Joker']['account_pw'])
        except Exception:
            l.logError('Failed to connect to Joker.com DMAPI server, because ', str(sys.exc_info()[1]))
            return None
        
        r1 = self.myConnection.getresponse()
        if r1.status != 200:
            l.logError('Failed to connect to Joker.com DMAPI server, because: ' + r1.reason)
        while not r1.closed:
            for line in r1.read().decode('ASCII').splitlines():
                if len(line) > 2:
                    (k,v) = line.split(':')
                    self.session[k] = v.strip()
                else:
                    break
        if self.session['Status-Code'] != '0':
            l.logError('Failed to sign-on at Joker.com, because: ' + self.session['Status-Text'])
            for k in session.keys():
                print(k, ': ',  self.session[k])
            return None
    
    def conn(self):
        return self.myConnection
    
    def sid(self):
        return self.session['Auth-Sid']


# -----------------------------------------
# Functions
# -----------------------------------------
def requestJoker(query_string):
    
    status = {}
    result = []
    header_done = False
    global theConnection
    
    if not theConnection:
        theConnection = ConnectionJoker()
        if not theConnection: return None
    c = theConnection.conn()
    if not c:  return None
    if '?' in query_string:
        s = '/request/' + query_string + '&auth-sid=' + theConnection.sid()
    else:
        s = '/request/' + query_string + '?auth-sid=' + theConnection.sid()
    l.logDebug(s)
    try:
        c.request("GET", s)
    except Exception:
        l.logError('Request to Joker.com DMAPI server failed, because: ', str(sys.exc_info()[1]))
        l.logError('Query was: "' + query_string + '"')
        return None
    r1 = c.getresponse()
    if r1.status != 200:
        l.logError('Request to Joker.com DMAPI server failed , because: ' + r1.reason + ' - HTTP - status ' + repr(r1.status))
    while not r1.closed:
        for line in r1.read().decode('ASCII').splitlines():
            items = line.split(':')
            if len(items) == 2:
                (k,v) = line.split(':')
                status[k] = v.strip()
            else:
                result.append(line)
    if status['Status-Code'] != '0':
        lines = []
        for k in status.keys():
            lines.append(str('%s:\t%s\n' % (k, status[k])))
        l.logError('Request to Joker.com DMAPI server failed, because:\n%s' % ''.join(lines))
        l.logError('Query was: "' + query_string + '"')
        return None
    status['result'] = result        
    return status

def regRemoveAllDS(zone):
    if zone.split('.')[-1] not in 'arpa':
        try:
            q = 'domain-modify?domain=' + zone + '&dnssec=0'
            cl = requestJoker(q)
            if not cl: return None
            for c in cl:
                l.logDebug(c + ':   ' + str(cl[c]))
            if 'Tracking-Id' in cl:
                stat = getResult(cl['Tracking-Id'])
                if 'request_state' in stat and stat['request_state'] == 'SUCCESS':
                    return stat
            else:
                l.logError('Missing Tracking-Id in response from Joker while removing DS-RR of %s' % zone)
                return None
            l.logError('Request remove all DS-RR of zone %s to Joker failed, because: %s' % (zone, stat['result_msg']))
            l.logError('Order Number is %s, and request, sent to Joker was "%s"' % (stat['order number'], q))
            printStatus(stat, ('ds-', 'result_'))
            return None
        except (KeyError):
            l.logError('Request remove all DS-RR of zone %s to Joker failed' % (zone))
            return None
    l.logError('Internal inconsitency: regRemoveAllDS(): DS-Removal of .arpa. not implemented')
    return None
    
def regAddDS(zone, args):
    stat = None
    tld = zone.split('.')[-1]
    if tld not in 'arpa':
        try:
            if tld != 'de':
                q = str('domain-modify?domain=%s&dnssec=1' % zone)
                i = 1
                for arg in args:
                    if (None, '') in (arg['tag'], arg['alg'], arg['digest_type'], str(arg['digest'])):
                        l.logError('Internal inconsitency: regAddDS(): at least one argument of key %d is empty: "%d","%d","%s"'
                            % (arg['tag'], arg['alg'], arg['digest_type'], urllib.parse.quote(str(arg['digest']))))
                        return None
                    q = q + str('&ds-%d=%d:%d:%d:%s' %
                        (i, arg['tag'], arg['alg'], arg['digest_type'], urllib.parse.quote(str(arg['digest']))))
                    i = i + 1
                cl = requestJoker(q)
                if not cl: return None
                for c in cl:
                    l.logDebug(c + ':   ' + str(cl[c]))
                if 'Tracking-Id' in cl:
                    stat = getResult(cl['Tracking-Id'])
                    if 'request_state' in stat and stat['request_state'] == 'SUCCESS':
                        return stat
                else:
                    l.logError('Missing Tracking-Id in response from Joker while updating DS-RR for %s' % zone)
                    return None
                l.logError('Request update DS-RR of zone %s to Joker failed, because: %s' % (zone, stat['result_msg']))
                l.logError('Order Number is %s, and request, sent to Joker was "%s"' % (stat['order number'], q))
                printStatus(stat, ('ds-', 'result_'))
                return None
            else:
                q = str('domain-modify?domain=%s&dnssec=1' % zone)
                i = 1
                for arg in args:
                    if i % 2 == 0:
                        if (None, '') in (arg['alg'], arg['flags'], arg['pubkey']):
                            l.logError('Internal inconsitency: regAddDS(): at least one argument of key %d is empty: "%d","%d","%d","%s"'
                                % (arg['tag'], arg['alg'], arg['flags'], urllib.parse.quote(arg['pubkey'])))
                            return None
                        q = q + str('&ds-%d=3:%d:%d:%s' %
                            (i/2, arg['alg'], arg['flags'], urllib.parse.quote(arg['pubkey'])))
                    i = i + 1
                cl = requestJoker(q)
                if not cl: return None
                for c in cl:
                    l.logDebug(c + ':   ' + str(cl[c]))
                if 'Tracking-Id' in cl:
                    stat = getResult(cl['Tracking-Id'])
                    if 'request_state' in stat and stat['request_state'] == 'SUCCESS':
                        return stat
                else:
                    l.logError('Missing Tracking-Id in response from Joker while updating DS-RR for %s' % zone)
                    return None
                l.logError('Request update DS-RR of zone %s to Joker failed, because: %s' % (zone, stat['result_msg']))
                l.logError('Order Number is %s, and request, sent to Joker was "%s"' % (stat['order number'], q))
                printStatus(stat, ('ds-', 'result_'))
                return None
        except (KeyError):
            l.logError('Request update DS-RR of zone %s to Joker failed' % (zone))
            return None
    else:
        l.logError('Internal inconsitency: regAddDS(): submission of DS-RR of .arpa. not implemented')
        return None

def getResultList(rid):
    cl = ''
    if rid == None:
        cl = requestJoker('result-list')
    else:
        cl = requestJoker('result-retrieve?SvTrID=%s' % rid)
    if not cl: return False
    return cl

def getResult(transactionID):
    stat = requestJoker('result-retrieve?SvTrID=%s' % transactionID)
    while stat['Completion-Status'] == '?':
        l.logVerbose('Retrieving completion status from Joker...')
        time.sleep(15)
        stat = requestJoker('result-retrieve?SvTrID=%s' % transactionID)
    stat['TID'] = transactionID
    return stat        

def printStatus(stat, show):
    lines = []
    for k in stat:
        for s in show:
            if s in k:
                lines.append(str('%s:\t%s\n' % (k, status[k])))
                break
    l.logError(' DNSsec related status info follows: ------------\n%s? End of DNSsec related status info   ------------\n' % ''.join(lines))

