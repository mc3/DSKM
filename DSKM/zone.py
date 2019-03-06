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
zone.py - the managedZone class module
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
import DSKM.config as conf
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
        
        self.icfg = {'Method': 'unsigned',  # unsigned, NSEC or NSEC3       \
                    'Registrar': 'Local',   # Local, Joker, Ripe            \
                    'Timing': {'ksk': { 'pa': conf.KSK_P_A_INTERVAL,        \
                                        'ai': conf.KSK_A_I_INTERVAL,        \
                                        'id': conf.KSK_I_D_INTERVAL,        \
                                        'i1a2': conf.KSK_I1_A2_INTERVAL     \
                                        },                                  \
                               'zsk': { 'pa': conf.ZSK_P_A_INTERVAL,        \
                                        'ai': conf.ZSK_A_I_INTERVAL,        \
                                        'id': conf.ZSK_I_D_INTERVAL,        \
                                        'i1a2': conf.ZSK_I1_A2_INTERVAL     \
                                        }                                   \
                                }                                           \
                    }
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
        
        self.keys_toBeDeleted = []
        
        self.master_DNSKEY_cache = []
        
        #-----------------------------
        # functions in managedZone.__init__
        #-----------------------------
        def readConfig(cfg, domain_name, file_name):
            self.mypath.cd()                    # change to zone directory
            l.logDebug('Opening ' + domain_name + '/' + file_name)
            timingAdded = False
            try:
                with open(file_name) as fd:     # open config/status file for read
                    try:
                        k = ''
                        tstcfg = json.load(fd)
                        for k in iter(cfg):   # do simple syntax check
                            if k == 'Timing' and k not in tstcfg:
                                timingAdded = True
                                tstcfg['Timing'] = copy.deepcopy(cfg['Timing'])
                            vt = tstcfg[k]    # raises if key missed
                            vo = cfg[k]
                            if isinstance(vo, dict):
                                for k in iter(vo):
                                    vo1 = vo[k] # raises if key missed
                                    if isinstance(vo1, dict):
                                        for k in iter(vo1):
                                            vo2 = vo1[k] # raises if key missed
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
            return (cfg, timingAdded)
                
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
            self.mypath.cd()                    # change to zone directory
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
        if l.verbose:
            print('')
        l.logVerbose('Working at %s on %s (%s %s)' % 
                (datetime.fromtimestamp(time.time()).isoformat(), self.name, self.parent, zl))

        try:
            cfg_file_name = 'dnssec-conf-' + self.name
            (self.pcfg, timingAdded) = readConfig(self.pcfg, name, cfg_file_name)
            if self.pcfg['Timing']['ksk']['ai'] <= self.pcfg['Timing']['ksk']['pa'] + \
                self.pcfg['Timing']['ksk']['i1a2'] + self.pcfg['Timing']['ksk']['id']:
                l.logError('Configuration error in %s: Timimg:ksk:ai must be greater than pa + i1a2 + id' % (cfg_file_name))
                e = misc.AbortedZone("")
                raise e
            if self.pcfg['Timing']['zsk']['ai'] <= self.pcfg['Timing']['zsk']['pa'] + \
                self.pcfg['Timing']['zsk']['i1a2'] + self.pcfg['Timing']['zsk']['id']:
                l.logError('Configuration error in %s: Timimg:zsk:ai must be greater than pa + i1a2 + id' % (cfg_file_name))
                e = misc.AbortedZone("")
                raise e
            if timingAdded:
                self.saveCfgOrState('config')

            stat_file_name = 'dnssec-stat-' + self.name
            (self.pstat, timingAdded) = readConfig(self.pstat, name, stat_file_name)
            if self.pcfg['Method'] not in ('unsigned', 'NSEC', 'NSEC3'):
                l.logError(' Wrong Method "%s" in zone config of %s' % (self.pcfg['Method'], self.name))
                e = misc.AbortedZone("")
                raise e
            if self.pcfg['Registrar'] not in ('Local', 'by hand', 'Joker', 'Ripe'):
                l.logError(' Wrong Registrar "%s" in zone config of %s' % (self.pcfg['Registrar'], self.name))
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
        self.keys_toBeDeleted = []
        
        zone_loaded = True
        try:
            if misc.doQuery(self.name, 'SOA') == None:
                zone_loaded = False
        except Exception:
            zone_loaded = False
        if not zone_loaded:
            l.logError('Master server does not serve {}.'.format(self.name))
            l.logError('Zone not loaded? Skipping zone.')
            return
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
                l.logVerbose('About to call registrar. List of keys to request DS-RR: %s ' % (repr(self.pstat['submitted_to_parent'])))
                
                args = self.argsForDSsubmission()
                if len(args) == 0: # removed all DS from remote parents
                    res = reg.regRemoveAllDS(self)
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
                    res = reg.regAddDS(self, args)
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
                    self.deleteKeys(k.keytag)
            except:
                raise
                l.logError('Error while deleting recent key files while aborting zone ' + self.name)
        else:                               # don't save state or delete keys if aborted by exception
            for kt in self.keys_toBeDeleted:
                self.deleteKeys(kt)
            self.saveCfgOrState('state')

    
    def argsForDSsubmission(self):
        args = []
        if len(self.pstat['submitted_to_parent']) == 0:
            return args
        for tag in self.pstat['submitted_to_parent']:
            for key in self.ksks:
                if key.keytag == tag:
                    if conf.DIGEST_ALGO_DS == '' or conf.DIGEST_ALGO_DS == '-1':
                        arg = {}
                        arg['tag'] = tag
                        arg['alg'] = key.dnssec_alg
                        arg['digest_type'] = 1
                        arg['digest'] = key.dsHash[0]
                        if conf.DIGEST_ALGO_DS == '-1':
                            arg['flags'] = key.dnssec_flags
                            arg['pubkey'] = key.pubkey_base64
                        args.append(arg)
                    
                    if conf.DIGEST_ALGO_DS == '' or conf.DIGEST_ALGO_DS == '-2':
                        arg = {}
                        arg['tag'] = tag
                        arg['alg'] = key.dnssec_alg
                        arg['digest_type'] = 2
                        arg['digest'] = key.dsHash[1]
                        arg['flags'] = key.dnssec_flags
                        arg['pubkey'] = key.pubkey_base64
                        args.append(arg)
                    
                    break
        return args        
    
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
    
    
    def markForDeletion(self, key_tag):
        self.keys_toBeDeleted.append(key_tag)
        return True

    def deleteKeys(self, key_tag):
        l.logVerbose('Deleting one/more of %s' % str(self.mypath.list('K*')))
        self.mypath.cd()              # change to zone directory
        for kf in os.listdir():       # loop once per key file in zone dir
            if key_tag == 0 and fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*') or \
                fnmatch.fnmatch(kf, 'K*' + str(key_tag) + '.*'): # delete all keyfiles or our keyfile
                ##l.logDebug('Matched for deleting: %s' % (kf))
                l.logVerbose('Matched for deleting: %s' % (kf))
                try:
                    os.remove(path(kf))
                    l.logVerbose('Deleted: %s' % (kf))
                except:
                    (exc_type, exc_value, exc_traceback) = sys.exc_info()
                    l.logError("Can't delete keyfile, because %s" % (exc_value))
        if key_tag == 0:
            self.pcfg = copy.deepcopy(self.icfg)               # initialize
            self.pstat = copy.deepcopy(self.istat)
            self.saveCfgOrState('config')
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
        self.mypath.cd()                    # change to zone directory
        if action == 'config':
            cfg = self.pcfg
            filename = 'dnssec-conf-' + self.name
        elif action == 'state':
            cfg = self.pstat
            filename = 'dnssec-stat-' + self.name
        else:
            raise AssertionError('?Wrong action "%s" in saveCfgOrState() with zone %s' % (action, self.name))
        
        l.logDebug('Saving config/state in file %s/%s\nNew %s of %s contains:\n %s ' %
                    (os.getcwd(), filename, action, self.name, str(cfg)))
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
         
        if self.pstat['ksk']['State'] < 3 or self.pstat['ksk']['State'] > dnsKey.SigningKey.ksk_state_max or self.pcfg['Registrar'] == 'Local':
            return True
        
        nsAliveTest(self.name)
        
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
                    l.logDebug('Querying %s via UDP' % (nameserver, ))
                    response = dns.query.udp(request, nameserver, conf.NS_TIMEOUT)
                    if response.flags & dns.flags.TC:
                        # Response truncated; retry with TCP.
                        l.logDebug('Querying %s via TCP' % (nameserver, ))
                        response = dns.query.tcp(request, nameserver, conf.NS_TIMEOUT)
                except (socket.error, dns.exception.Timeout, dns.query.UnexpectedSource, dns.exception.FormError, EOFError):
                    l.logDebug('Queryerror')
                    response = None
                    continue
                rcode = response.rcode()
                if rcode == dns.rcode.NOERROR or \
                       rcode == dns.rcode.NXDOMAIN:
                    l.logDebug('Query gave NOERROR or NXDOMAIN')
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
    
    # compare SOA serial of master with zone file (bind 9.11 may be out of sync) 
    def verifySerial(self):
        try:
            answer = misc.doQuery(self.name, 'SOA')
        except Exception:
            l.logError('Failed to compare serial with zone file')
            return False
        result = [ str(rdata) for rdata in answer ][0].split()[2]
        
        filename = self.mypath + '/' + self.name + '.zone'
        with open(filename, 'r', encoding="ASCII") as fd:
            try:
                zf = fd.read()
            except:                 # file not found or not readable
                raise Exception("verifySerial can't read zone file " + filename)
        sea = re.search('(\d{10})(\s*;\s*)(Serial number)', zf)
        serial = sea.group(1)
                
        l.logDebug('verifySerial of {}: file: {} dns: {}'.format(self.name, serial, result))
        if int(serial) > int(result):   # file more recent than master server?
            l.logError('Serial of {} out of sync: {} > {}'.format(self.name, serial, result))
            return False
        return True
    
    def stopSigning(self, force):
        ##import pdb;pdb.set_trace()
        if not force:
            if self.pstat['ksk']['State'] < 2:
                l.logError("Can't stop signing in state %s" % (self.pstat['ksk']['State']))
                return 1
            if self.pstat['ksk']['State'] > dnsKey.SigningKey.ksk_state_max:
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
        self.pstat['ksk']['State'] = dnsKey.SigningKey.ksk_state_max + 1
        if force:
            self.deleteKeys(0)
            try:
                res = str(shell(str('rndc loadkeys %s' % (self.name)), stderr='PIPE').stderr)
                l.logDebug('Rndc loadkeys returned: %s' % (res))
            except script.CommandFailed:
                l.logError('Error during rndc loadkeys after deleting keys of %s' % (self.name))
        self.pstat['ksk']['Retries'] = 0
        self.pstat['zsk']['Retries'] = 0
        self.saveCfgOrState('state')
        if self.remoteDSchanged and len(self.pstat['submitted_to_parent']) > 0:
            l.logVerbose('About to call registrar. List of keys to request DS-RR: %s ' % (repr(self.pstat['submitted_to_parent'])))
            res = reg.regRemoveAllDS(self)
            if not res:
                em = str("Failed to delete all DS-RR of %s at registrar %s" % (self.name, self.pcfg['Registrar']))
                l.logError(em)
                e = misc.AbortedZone(em)
                raise e
            l.logVerbose("DS-RRs of %s at registrar %s deleted" % (
                    self.name, self.pcfg['Registrar']))
            for c in res.keys():
                if c in ('Proc-ID', 'Tracking-Id'):
                    print(c + ':   ' + res[c])
        return 0         


def nsAliveTest(theZone):         # query all authoritative NS for SOA of zone
    global ext_recursive_resolver
        
    r = ext_recursive_resolver
    
    qname = dns.name.from_text(theZone)
    request = dns.message.make_query(qname, rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.ANY)
    request.use_edns(r.edns, r.ednsflags, r.payload)
    request.want_dnssec(True)
    response = None
    nameservers = misc.authNS(theZone)
    for nameserver in nameservers[:]:
        try:
            l.logDebug('Querying {} for SOA of {} via TCP'.format(nameserver, theZone))
            response = dns.query.tcp(request, nameserver, 10)
            rcode = response.rcode()
            if rcode == 0: continue
        except (socket.error, dns.exception.Timeout, dns.query.UnexpectedSource,
                dns.exception.FormError, EOFError, dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN):
            pass
        l.logError('NS {} did not answer SOA query for {}'.format(
                                                    nameserver, theZone))

"""
r = misc.authResolver('2.0.0.0.0.4.d.0.2.0.a.2.ip6.arpa')
for ns in r.nameservers:
    print(ns)
"""