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

import sys

from script import path, shell, opts
import script
import fnmatch
from datetime import date, datetime
import time

# for salt
from Crypto import Random as rand
import binascii

import copy

import dns.resolver, dns.message, dns.query, dns.rdatatype, dns.rdtypes.ANY.DNSKEY, dns.rcode
import dns.dnssec, dns.zone

import json
import os

import re
import socket


# -----------------------------------------

import DSKM.registrar as reg
import DSKM.key as dnsKey

import DSKM.logger as logger
l = logger.Logger()

# -----------------------------------------

import DSKM.misc as misc

# -----------------------------------------
# Configurables
# -----------------------------------------
import DSKM.conf as conf
#------------------------------------------------------------------------------

ext_recursive_resolver = dns.resolver.Resolver()
ext_recursive_resolver.lifetime = conf.NS_TIMEOUT
ext_recursive_resolver.nameservers = conf.external_recursives
ext_recursive_resolver.use_edns(edns=0, ednsflags=0, payload=4096)

#--------------------------
#   classes
#--------------------------
    
#------------------------------------------------------------------------------
# class managedZone
#------------------------------------------------------------------------------
class managedZone(object):
    """managedZone"""

    def __init__(self, name):
        self.name = name
        
        self.icfg = {'Method': 'unsigned',  # unsigned, NSEC or NSEC3 \
                    'Registrar': 'Local'}   # Local, Joker, Ripe    \
        
        self.istat = {}
        self.istat['ksk'] = {'State': -1,   # index into state table KSTT, \
                             'Retries': 0}  # Number of retries in current state
        self.istat['zsk'] = {'State': -1,   # index into state table ZSTT, \
                            'Retries': 0}   # Number of retries in current state
        self.istat['OldMethod'] = 'unsigned'# NSEC or NSEC3 \
        self.istat['OldRegistrar'] = 'Local'    # Joker, Ripe

        self.istat['submitted_to_parent'] = []  # list of KSK tags, whose DS have been submitted to parent

        self.pcfg = copy.deepcopy(self.icfg)               # initialize
        self.pstat = copy.deepcopy(self.istat)
        
        self.ksks = []
        self.zsks = []
    
        self.parent = None
        self.parent_dir = None
        
        self.mypath = path(conf.ROOT_PATH + '/' + name)
        self.mypath.cd()
        
        self.remoteDSchanged = False
        self.keys_just_created = []
        
        #-----------------------------
        # functions in managedZone.__init__
        #-----------------------------
        def readConfig(cfg, domain_name, file_name):
            l.logDebug('Opening ' + domain_name + '/' + file_name)
            try:
                with open(file_name) as fd:     # open config/status file for read
                    try:
                        k = ''
                        tstcfg = json.load(fd)
                        for k in iter(cfg):   # do simple syntax check
                            vt = tstcfg[k]    # raises if key missed
                            vo = cfg[k]
                            if isinstance(vo, dict):
                                for k in iter(vo):
                                    x = vo[k] # raises if key missed
                    except:                     # missing key: syntax error in cfg file
                        l.logError('Garbage found/Missing option ' + k + ' in configuration/status file "' + domain_name + '/' + file_name + '"')
                        e = misc.misc.AbortedZone("")
                        raise e
                    cfg = tstcfg    
            except IOError:                     # file not found
                try:
                    with open(file_name, 'w') as fd:
                        json.dump(cfg, fd, indent=8)
                except IOError:                 # no write permission
                    (exc_type, exc_value, exc_traceback) = sys.exc_info()
                    l.logError("Can't create file, because %s" % (exc_value))
                    e = misc.misc.AbortedZone("")
                    raise e
            l.logDebug('Config/status ' + domain_name + '/' + file_name + ' contains:\n' + str(cfg))
            return cfg
                
        def deleteKeyFiles():
            self.mypath.cd()                    # change to zone directory
            for kf in os.listdir():             # loop once per file in zone dir
                if fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*'):
                    try:
                        os.remove(path(kf))     # remove all key files if we did not complete zone creation
                        l.logVerbose('Deleted: %s' % (kf))
                    except:
                        (exc_type, exc_value, exc_traceback) = sys.exc_info()
                        l.logError("Can't delete keyfile, because %s" % (exc_value))
                        e = misc.misc.AbortedZone("")
                        raise e
    
        def saveState():
            l.logDebug('New status of ' + self.name + ' contains:\n' + str(self.pstat))
            stat_file_name = 'dnssec-stat-' + self.name
            try:
                with open(stat_file_name, 'w') as fd:
                    json.dump(self.pstat, fd, indent=8)
            except:                  # no write permission
            ##except IOError:                 # no write permission
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                l.logError("Can't create status file, because %s" % (exc_value))
                e = misc.AbortedZone()
                raise e
            
        #-----------------------------
        # end of functions in managedZone.__init__
        #-----------------------------
        (x,y,self.parent) = self.name.partition('.')
        pd = path(conf.ROOT_PATH + '/' + self.parent)
        l.logDebug('Parent directory would be %s' % (pd,))
        zl = ''
        if pd.exists:
            zl = ' <local>'
            self.parent_dir = pd
        l.logVerbose('Working on %s (%s %s) at %s' % 
                (self.name, self.parent, zl, datetime.fromtimestamp(time.time()).isoformat()))

        try:
            cfg_file_name = 'dnssec-conf-' + self.name
            self.pcfg = readConfig(self.pcfg, name, cfg_file_name)
            stat_file_name = 'dnssec-stat-' + self.name
            self.pstat = readConfig(self.pstat, name, stat_file_name)
            if self.pcfg['Method'] not in ('unsigned', 'NSEC', 'NSEC3'):
                l.logError(' Wrong Method "%s" in zone config of %s' % (self.pcfg['Method'], self.name))
                e = misc.AbortedZone("")
                raise e
            if self.pstat['OldMethod'] not in ('unsigned', 'NSEC', 'NSEC3'):
                l.logError(' Wrong OldMethod "%s" in zone config of %s' % (self.pstat['Method'], self.name))
                e = misc.AbortedZone("")
                raise e
            
            l.logDebug('KSK state is %d' % (self.pstat['ksk']['State']))
            
            if self.pstat['ksk']['State'] == -1:    # state idle
                deleteKeyFiles()               # delete any key files
            else:
                if self.pstat['OldMethod'] != self.pcfg['Method']:  # don't allow config change if not state idle for now
                    l.logError('Method changed from %s to %s in zone %s' % (self.pstat['OldMethod'], self.pcfg['Method'], self.name))
                    e = misc.AbortedZone('')
                    raise e
                if self.pstat['OldRegistrar'] != self.pcfg['Registrar']:  # don't allow config change if not state idle for now
                    l.logError('Registrar changed from %s to %s in zone %s' % (self.pstat['OldRegistrar'], self.pcfg['Registrar'], self.name))
                    e = misc.AbortedZone('')
                    raise e
                for kf in path('.').list('*'):      # loop once per public key file in zone dir
                    if fnmatch.fnmatch(kf, 'K' + self.name + '.+*.key'):
                        k = dnsKey.SigningKey('read', self.name, kf, self) # and create instance from it
                        if k.type == 'KSK':
                            self.ksks.append(k)
                        elif k.type == 'ZSK':
                            self.zsks.append(k)
            
            nsec3 = False
            if self.pstat['ksk']['State'] == -1: # IDLE state
                if self.pcfg['Method'] == 'unsigned':
                    raise misc.CompletedZone()       # unsigned zone
                elif self.pcfg['Method'] == 'NSEC3':
                    nsec3 = True
                                                # Begin signing zone 1st time
                k = (dnsKey.SigningKey('KSK', self.name, '', self, nsec3=nsec3))
                self.ksks.append(k)
                
                self.zsks.append(dnsKey.SigningKey('ZSK', self.name, '', self, nsec3=nsec3))
            
            for key in self.ksks:
                l.logDebug(key.__str__())
            for key in self.zsks:
                l.logDebug(key.__str__())

            self.pstat['OldMethod'] = self.pcfg['Method']
            self.pstat['OldRegistrar'] = self.pcfg['Registrar']
            
        except misc.AbortedZone:
            l.logError('Aborting zone ' + self.name)
            """
            if self.pstat['ksk']['State'] == -1 or self.pstat['zsk']['State'] == -1:
                try:                # we had an error during read of state/conf
                    saveState()
                except:
                    pass
                l.logError('Removing key files of %s' % (name))
                deleteKeyFiles
                raise
            """
            raise
        pass
    
    #       if self.pcfg['Method'] != self.pstat['OldMethod']:
    #           print('[Method of domain %s has changed from %s to %s]' % (self.name, self.pstat['OldMethod'], self.pcfg['Method']))
    #           script.exit(1, '?Changing of methods not yet implemented')
    #------------------------------------------------------------------------------
    # end of ManagedZone.__init__
    #------------------------------------------------------------------------------
        
    def performStateTransition(self):
        self.keys_just_created = []
        self.remoteDSchanged = False
        
        try:
            self.ksks.sort(key=dnsKey.SigningKey.activeTime)
            second = False
            for k in self.ksks:
                if k.state_transition(second):
                    break
                second = True
            
            self.zsks.sort(key=dnsKey.SigningKey.activeTime)
            second = False
            for k in self.zsks:
                if k.state_transition(second):
                    break
                second = True
            
            if self.remoteDSchanged:
                l.logDebug('About to call registrar . submitted_to_parent contains now: %s ' % (repr(self.pstat['submitted_to_parent'])))

                if len(self.pstat['submitted_to_parent']) == 0: # removed all DS from remote parents
                    res = reg.regRemoveAllDS(self.name)
                    if not res:
                        l.logError("Failed to delete all DS-RR of %s at registrar %s" % (self.name, self.pcfg['Registrar']))
                        e = misc.AbortedZone()
                        raise e
                    l.logVerbose("DS-RRs of %s at registrar %s deleted" % (
                            self.name, self.pcfg['Registrar']))
                    for c in res.keys():
                        if c in ('Proc-ID', 'Tracking-Id'):
                            print(c + ':   ' + res[c])
                else:
                    args = []
                    for tag in self.pstat['submitted_to_parent']:
                        for key in self.ksks:
                            if key.keytag == tag:
                                arg = {}
                                arg['tag'] = tag
                                arg['alg'] = key.dnssec_alg
                                arg['digest_type'] = 1
                                arg['digest'] = key.dsHash[0]
                                arg['flags'] = key.dnssec_flags
                                arg['pubkey'] = key.pubkey_base64
                                args.append(arg)
                                
                                arg = {}
                                arg['tag'] = tag
                                arg['alg'] = key.dnssec_alg
                                arg['digest_type'] = 2
                                arg['digest'] = key.dsHash[1]
                                arg['flags'] = key.dnssec_flags
                                arg['pubkey'] = key.pubkey_base64
                                args.append(arg)
                                
                                break
                    if len(args) > 0:
                        res = reg.regAddDS(self.name, args)
                        if not res:
                            l.logError("Failed to update DS-RRs for keys %s of %s at registrar %s" % (
                                repr(self.pstat['submitted_to_parent']), self.name, self.pcfg['Registrar']))
                            e = misc.AbortedZone('')
                            raise e
                        l.logVerbose("DS-RRs for keys %s of %s at registrar %s updated" % (
                                repr(self.pstat['submitted_to_parent']), self.name, self.pcfg['Registrar']))
                        for c in res.keys():
                            if c in ('Your mail was received at ......', 'TID'):
                                print(c + ':   ' + res[c])
    
        except misc.AbortedZone:
            l.logError('Aborting zone ' + self.name)
            try:
                for k in self.keys_just_created:
                    k.delete_a('one key', False)
            except:
                raise
                l.logError('Error while deleting recent key files while borting zone ' + self.name)
        else:                               # don't save state if aborted by exception
            self.saveCfgOrState('state')

    
    def createFollowUpKey(self, sender):    # usually called by action routine to create a new key
        nsec3 = False
        if self.pcfg['Method'] == 'NSEC3':
            nsec3 = True
        k = (dnsKey.SigningKey(sender.type, self.name, sender.file_name, self, nsec3=nsec3, cloneFromKeyInactiveAt=sender.inactiveTime()))
        if k.type == 'KSK':
             self.ksks.append(k)
        elif k.type == 'ZSK':
             self.zsks.append(k)
        self.keys_just_created.append(k)
        return True
    
    
    def UpdateRemoteDS(self, activity, keytag):
        l.logDebug('UpdateRemoteDS called. submitted_to_parent contains: %s ' % (repr(self.pstat['submitted_to_parent'])))
        if activity == 'retire':
        	for k in self.pstat['submitted_to_parent']:
        		if k != keytag:
        			self.pstat['submitted_to_parent'].remove(k)
        elif activity == 'delete':
            self.pstat['submitted_to_parent'] = []
        elif 'publish' in activity:
            self.pstat['submitted_to_parent'].append(keytag)
        else:
            raise AssertionError('?Wrong activity "%s" in UpdateRemoteDS() with zone %s' % (activity, self.name))
        self.remoteDSchanged = True
        l.logDebug('submitted_to_parent contains now: %s ' % (repr(self.pstat['submitted_to_parent'])))
        return True   
    
    def saveCfgOrState(self, action):       # action is 'config' or 'state'
        if action == 'config':
            cfg = self.pcfg
            filename = 'dnssec-conf-' + self.name
        elif action == 'state':
            cfg = self.pstat
            filename = 'dnssec-stat-' + self.name
        else:
            raise AssertionError('?Wrong action "%s" in saveCfgOrState() with zone %s' % (action, self.name))
        
        l.logDebug('New %s of %s contains:\n %s ' % (action, self.name, str(cfg)))
        try:
            with open(filename, 'w') as fd:
                json.dump(cfg, fd, indent=8)
        except:                  # no write permission
        ##except IOError:                 # no write permission
            (exc_type, exc_value, exc_traceback) = sys.exc_info()
            l.logError("Can't create status file, because %s" % (exc_value))
            e = misc.AbortedZone('')
            raise e
    
    def validate(self):                     # validate zone
        global ext_recursive_resolver
         
        if self.pstat['ksk']['State'] < 3 or self.pstat['ksk']['State'] > 10 or self.pcfg['Registrar'] == 'Local':
            return True
        
        l.logVerbose('Validating %s...' % (self.name))
        r = ext_recursive_resolver
        try:
            qname = dns.name.from_text(self.name)
            request = dns.message.make_query(qname, rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.ANY)
            request.use_edns(r.edns, r.ednsflags, r.payload)
            request.want_dnssec(True)
            response = None
            nameservers = r.nameservers[:]
            for nameserver in nameservers[:]:
                try:
                    response = dns.query.udp(request, nameserver, conf.NS_TIMEOUT)
                    if response.flags & dns.flags.TC:
                        # Response truncated; retry with TCP.
                        timeout = self._compute_timeout(start)
                        response = dns.query.tcp(request, nameserver, conf.NS_TIMEOUT)

                except (socket.error, dns.exception.Timeout, dns.query.UnexpectedSource, dns.exception.FormError, EOFError):
                    response = None
                    continue
                rcode = response.rcode()
                if rcode == dns.rcode.NOERROR or \
                       rcode == dns.rcode.NXDOMAIN:
                    break
                response = None
            ## end of for nameserver in r.nameservers

            if response is None:
                e = dns.resolver.NoAnswer
                raise e
            ans = dns.resolver.Answer(qname, dns.rdatatype.SOA, dns.rdataclass.ANY, response, False)

            l.logDebug('Flags are %x; %x should be set' % (ans.response.flags, dns.flags.AD))
            if ans.response.flags & dns.flags.AD:
                l.logVerbose('OK')
                return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except (dns.exception.Timeout):
            (exc_type, exc_value, exc_traceback) = sys.exc_info()
            errmsg = "%s: DS query timed out. %s, %s" % \
                (self.name, exc_type, exc_value)
            l.logError('Validation of %s FAILED' % (self.name))
            l.logError(errmsg)
        l.logError('Validation of %s FAILED' % (self.name))
        return False
    
    def stopSigning(self, force):
        ##import pdb;pdb.set_trace()
        if not force:
            if self.pstat['ksk']['State'] < 2:
                l.logError("Can't stop signing in state %s" % (self.pstat['ksk']['State']))
                return 1
            if self.pstat['ksk']['State'] > 10:
                print("%%Termination of signing already in progress (state=%s)" % (self.pstat['ksk']['State']))
                return 0
        secondKey = False
        for k in self.ksks:
            k.UpdateDS('delete', False) # remove all DS-RR in parent zone
            l.logVerbose("DS-RRs of %s at registrar %s deleted" % (
                            self.name, self.pcfg['Registrar']))
            k.set_delete_time(secondKey)
            secondKey = True
        secondKey = False
        for k in self.zsks:
            k.set_delete_time(secondKey)
            secondKey = True
        self.pstat['ksk']['State'] = 11
        if force:
            k = None
            if len(self.ksks) > 0:
                k = self.ksks[0]
            elif len(self.zsks) > 0:
                k = self.zsks[0]
            if k:
                k.delete_a('delete_all', False)
                k.updateSOA(k.mypath + '/' + self.name + '.zone')
        self.saveCfgOrState('state')
        return 0         

