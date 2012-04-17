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

KSK roll over best practice from ttp://tools.ietf.org/html/draft-ietf-dnsop-rfc4641bis-10

4.1.2.  Key Signing Key Rollovers

   For the rollover of a Key Signing Key, the same considerations as for
   the rollover of a Zone Signing Key apply.  However, we can use a
   Double Signature scheme to guarantee that old data (only the apex key
   set) in caches can be verified with a new key set and vice versa.
   Since only the key set is signed with a KSK, zone size considerations
   do not apply.

Kolkman & Mekking        Expires October 1, 2012               [Page 22]
 
Internet-Draft   DNSSEC Operational Practices, Version 2      March 2012


   ---------------------------------------------------------------------
    initial            new DNSKEY        DS change    DNSKEY removal
   ---------------------------------------------------------------------
   Parent:
    SOA_0 -----------------------------> SOA_1 ------------------------>
    RRSIG_par(SOA) --------------------> RRSIG_par(SOA) --------------->
    DS_K_1 ----------------------------> DS_K_2 ----------------------->
    RRSIG_par(DS) ---------------------> RRSIG_par(DS) ---------------->

   Child:
    SOA_0              SOA_1 -----------------------> SOA_2
    RRSIG_Z_10(SOA)    RRSIG_Z_10(SOA) -------------> RRSIG_Z_10(SOA)

    DNSKEY_K_1         DNSKEY_K_1 ------------------>
                       DNSKEY_K_2 ------------------> DNSKEY_K_2
    DNSKEY_Z_10        DNSKEY_Z_10 -----------------> DNSKEY_Z_10
    RRSIG_K_1(DNSKEY)  RRSIG_K_1 (DNSKEY) ---------->
                       RRSIG_K_2 (DNSKEY) ----------> RRSIG_K_2(DNSKEY)
   ---------------------------------------------------------------------

    Figure 4: Stages of Deployment for a Double Signature Key  Signing
                               Key Rollover

   initial:  Initial version of the zone.  The parental DS points to
      DNSKEY_K_1.  Before the rollover starts, the child will have to
      verify what the TTL is of the DS RR that points to DNSKEY_K_1 --
      it is needed during the rollover and we refer to the value as
      TTL_DS.

   new DNSKEY:  During the "new DNSKEY" phase, the zone administrator
      generates a second KSK, DNSKEY_K_2.  The key is provided to the
      parent, and the child will have to wait until a new DS RR has been
      generated that points to DNSKEY_K_2.  After that DS RR has been
      published on all servers authoritative for the parent's zone, the
      zone administrator has to wait at least TTL_DS to make sure that
      the old DS RR has expired from caches.

   DS change:  The parent replaces DS_K_1 with DS_K_2.

   DNSKEY removal:  DNSKEY_K_1 has been removed.

   The scenario above puts the responsibility for maintaining a valid
   chain of trust with the child.  It also is based on the premise that
   the parent only has one DS RR (per algorithm) per zone.  An
   alternative mechanism has been considered.  Using an established
   trust relation, the interaction can be performed in-band, and the
   removal of the keys by the child can possibly be signaled by the
   parent.  In this mechanism, there are periods where there are two DS
   RRs at the parent.

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

import pprint

# -----------------------------------------

import DSKM.logger as logger
l = logger.Logger()
import DSKM.misc as misc

# -----------------------------------------


# -----------------------------------------
# Configurables
# -----------------------------------------
import DSKM.conf as conf
#------------------------------------------------------------------------------

master_resolver = dns.resolver.Resolver()
master_resolver.lifetime = conf.NS_TIMEOUT
master_resolver.nameservers = conf.master
master_resolver.use_edns(edns=0, ednsflags=0, payload=4096)

secondary_resolver = dns.resolver.Resolver()
secondary_resolver.lifetime = conf.NS_TIMEOUT
secondary_resolver.nameservers = conf.external_secondaries
secondary_resolver.use_edns(edns=0, ednsflags=0, payload=4096)

#--------------------------
#   classes
#--------------------------


class SigningKey(object):
    """SigningKey"""

    global KSTT, ZSTT, l
    l = logger.Logger()                  # the logger
    
    def __init__(self, task, name, file_name, sender, nsec3=False, cloneFromKeyInactiveAt=0):
        
        self.name = name
        self.file_name = None
        self.zone = sender
        self.nsec3 = nsec3

        self.type = None
        
        self.algo = conf.KEY_ALGO_NSEC
        if nsec3: self.algo = conf.KEY_ALGO_NSEC3
        
        # values read from key file
        self.timingData = {}
        self.keytag = ''        # key tag
        self.dnssec_flags = 0   # flags
        self.sepkey = 0         # sep flag =KSK)
        self.dnssec_alg = 0     # key algorithm
        self.pubkey_base64 = ''

        self.dsHash = [None,None]  # 2 DS hashes
        
        self.mypath = path(conf.ROOT_PATH + '/' + name)
        self.mypath.cd()
        l.logDebug('Instantiating SigningKey; pwd=%s.' % (self.mypath))

        #-----------------------------
        # functions in SigningKey.__init__
        #-----------------------------
        # Read key meta data from key file
        def readKey(keyFileName):
            
            #   Read timing meta data from key
            def readKeyTimingData(keyFileName, type):
                result = None
                if not type in 'PAID':
                    l.logError('Internal inconsistency: readKeyTimingData called with wrong type ' 
                        + type + ' for key ' +keyFileName)
                    e = misc.AbortedZone("")
                    raise e
                try:
                    (rubbish, result) = str(shell(conf.BIND_TOOLS + 'dnssec-settime   -u -p ' + type + ' ' + keyFileName, stdout='PIPE').stdout).split(None)
                except script.CommandFailed:
                    l.logError('Error from dnssec_settime while reading timing data of '  +keyFileName)
                    e = misc.AbortedZone("")
                    raise e
                if result == 'UNSET':
                    return 0
                else:
                    return int(result)
            
            fd = None
            try:
                fd = open(keyFileName, 'r')
            except IOError:
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                errmsg = "?Can't open key file, because %s" % (exc_value)
                print(errmsg)
                e = misc.AbortedZone(errmsg)
                raise e
            flags = None
            l.logDebug('readKey(%s) opened file.' % (keyFileName))
            for line in fd:
                ##l.logDebug('Keyfile line is %s' % (line, ))
                (name, ttl, dns_class, rr, flags, x) = line.split(None, 5)
                if name == ';':
                    continue
                ##l.logDebug('Keyfile line found with name=%s ttl=%s class=%s RR=%s flags=%s\n%s' % (name, ttl, dns_class, rr, flags, x))
                if dns_class == 'IN' and rr == 'DNSKEY':
                    if __debug__:
                        if not self.name == name[:-1]: raise AssertionError('?Wrong domain name in keyfile %s (%s/%s)' % (keyFileName, name, self.name))
                    st = line.find('DNSKEY ')
                    tok = dns.tokenizer.Tokenizer(line[st+7:])
                    dnskey_rdata = dns.rdtypes.ANY.DNSKEY.DNSKEY.from_text(dns.rdataclass.ANY, dns.rdatatype.DNSKEY, tok, origin=name, relativize=False)
                    self.keytag = dns.dnssec.key_id(dnskey_rdata)
                    self.dnssec_flags = dnskey_rdata.flags
                    self.sepkey = self.dnssec_flags & 0x1;
                    self.dnssec_alg = dnskey_rdata.algorithm
                    ##self.pubkey_base64 = dns.rdata._base64ify(dnskey_rdata.key)
                    self.pubkey_base64 = dns.rdata._base64ify(dnskey_rdata.key, chunksize=2000)
                    
                    l.logDebug('Read DNSSEC key id=%d with flags=%d alg=%d' % (self.keytag, self.dnssec_flags, self.dnssec_alg))
                else:
                    l.logError('Unrecognized line "%s" in key file: ' % (line, keyFileName))
                    e = misc.AbortedZone("")
                    raise e
                if flags == '257':
                    l.logDebug('Key ' + keyFileName + ' is KSK')
                    if self.sepkey == 0:
                        l.logError('Inkonsistent sep flag found in %s' % (keyFileName))
                        e = misc.AbortedZone("")
                        raise e
                    self.type = 'KSK'
                    break
                elif flags == '256':
                    l.logDebug('Key ' + keyFileName + ' is ZSK')
                    if self.sepkey == 1:
                        l.logError('Inkonsistent sep flag found in %s' % (keyFileName))
                        e = misc.AbortedZone("")
                        raise e
                    self.type = 'ZSK'
                    break
                else:
                    l.logError('Key neither KSK not ZSK: ' + keyFileName)
                    e = misc.AbortedZone("")
                    raise e
            
            fd.close()
            
            self.timingData['P'] = readKeyTimingData(keyFileName, 'P')
            self.timingData['A'] = readKeyTimingData(keyFileName, 'A')
            self.timingData['I'] = readKeyTimingData(keyFileName, 'I')
            self.timingData['D'] = readKeyTimingData(keyFileName, 'D')
            
            if self.type == 'KSK' and self.zone.pcfg['Registrar'] != 'Local':
                self.digestOfDS()

        #-----------------------------
        # end of functions in SigningKey.__init__
        #-----------------------------

        l.logDebug('Creating SigningKey instance task=%s, name=%s, file_name=%s, nsec3=%s, cloneFromKeyInactiveAt=%d' % (task, name, file_name, nsec3, cloneFromKeyInactiveAt))
        if task == 'read':
            self.file_name = file_name
            readKey(file_name)
        elif task == 'ZSK':             # active when predecessor inactive
            inactive_from_now = conf.ZSK_P_A_INTERVAL + conf.ZSK_A_I_INTERVAL
            delete_from_now = inactive_from_now + conf.ZSK_I_D_INTERVAL
            s = conf.BIND_TOOLS + 'dnssec-keygen -a ' + self.algo + ' -b ' + repr(conf.KEY_SIZE_ZSK) + ' -n ZONE ' \
                + '-A +' + repr(conf.ZSK_P_A_INTERVAL) + 'd ' +'-I +' + repr(inactive_from_now) + 'd ' \
                + '-D +' + repr(delete_from_now) +'d -L ' + repr(conf.TTL_DNSKEY) + ' ' + name
            if cloneFromKeyInactiveAt != 0:
                prepublishInterval = cloneFromKeyInactiveAt - int(time.time()) - 60  # publish  one minute from now (seconds)
                if prepublishInterval > 0:      # did we wait too long? (new active > old inactive ?)
                    inactive_from_now = conf.ZSK_I_D_INTERVAL + conf.ZSK_A_I_INTERVAL # prepublish + inactive - active
                    delete_from_now = inactive_from_now + conf.ZSK_I_D_INTERVAL
                    s = conf.BIND_TOOLS + 'dnssec-keygen -S ' + file_name + ' -i +' + repr(prepublishInterval) + ' -I +' \
                    + repr(inactive_from_now) + 'd ' \
                        + '-D +' + repr(delete_from_now) +'d -L ' + repr(conf.TTL_DNSKEY)
                else:                           # yes
                    print('%%Failed timely key rollover of %s before %s' % (file_name, datetime.fromtimestamp(cloneFromKeyInactiveAt).isoformat()))
            l.logDebug(s)
            try:
                result = shell(s, stdout='PIPE').stdout.strip()
            except script.CommandFailed:
                l.logError('Error while creating ZSK for ' + name)
                e = misc.AbortedZone("")
                raise e
            self.file_name = result + '.key'
            print('[Key ' + self.file_name + ' created.]')
            readKey(self.file_name)
        elif task == 'KSK':         # active now
            inactive_from_now = conf.KSK_P_A_INTERVAL + conf.KSK_A_I_INTERVAL
            delete_from_now = inactive_from_now + conf.KSK_I_D_INTERVAL
            s = conf.BIND_TOOLS + 'dnssec-keygen -a ' + self.algo + ' -b ' + repr(conf.KEY_SIZE_KSK) + ' -n ZONE -f KSK ' \
                + '-A +' + repr(conf.KSK_P_A_INTERVAL) + 'd -I +' + repr(inactive_from_now) + 'd ' \
                + '-D +' + repr(delete_from_now) + 'd -L ' + repr(conf.TTL_DNSKEY) + ' ' + name
            if cloneFromKeyInactiveAt != 0 and cloneFromKeyInactiveAt < int(time.time()):
                l.logWarn('Failed timely key rollover of %s before %s' % (file_name, datetime.fromtimestamp(cloneFromKeyInactiveAt).isoformat()))
            l.logDebug(s)
            try:
                result = shell(s, stdout='PIPE').stdout.strip()
            except script.CommandFailed:
                l.logError('Error while creating KSK for ' + name)
                e = misc.AbortedZone("")
                raise e
            self.file_name = result + '.key'
            print('[Key ' + self.file_name + ' created.]')
            readKey(self.file_name)
        else:
            l.logError('Internal inconsitency: SigningKey instantiating  with wrong task ' + task)
            e = misc.AbortedZone("")
            raise e
        l.logVerbose('%s' % self.__str__())
        l.logDebug('Instantiated public key %s' % self.pubkey_base64)

    def __str__(self):
        def getKeyTimingData(type):
            if self.timingData[type] == 0:
                return 'UNSET'
            else:
                return datetime.fromtimestamp(self.timingData[type]).isoformat()
        
        return str('%s/%s/%d/%d(A:%s, I:%s, D:%s)' % (self.name, self.type, self.keytag, self.zone.pstat[self.type.lower()]['State'],
                    getKeyTimingData('A'), getKeyTimingData('I'), getKeyTimingData('D')))
    
    def digestOfDS(self):
        def read1DS(i):
            digest = ''
            s = str(conf.BIND_TOOLS + 'dnssec-dsfromkey -%d %s' % (i, self.file_name))
            try:                                      
                result = shell(s, stdout='PIPE').stdout.strip()
                l.logDebug('digestOfDS(): dnssec-dsfromkey returned: "%s"' % (result,))
                rr = result.split(None)
                if len(rr) == 7:
                    digest = rr[6]
                elif len(rr) == 8:
                    digest = rr[6]+rr[7]
                else:
                    assert('?Wrong result from dnssec-dsfromkey: %s' % (rr,))
                l.logDebug('digestOfDS(): returning: "%s"' % digest)
                return digest                
            except script.CommandFailed:              
                l.logError('Error while creating DS RR for ' + self.name)
                e = misc.AbortedZone("")
                raise e
        
        if self.type != 'KSK':
            l.logError("Can't create/delete DS from ZSK (internal inconsitency)" + self.name)
            e = misc.AbortedZone("")
            raise e
        if not self.dsHash[0]:
            self.dsHash[0] = read1DS(1)
            self.dsHash[1] = read1DS(2)
        return self.dsHash
    
    def UpdateDS(self, activity, secondKey):    # create/submit/retire signer RR from KSK
        l.logDebug('UpdateDS(%s, %s) called' % (activity, repr(secondKey)))
        if self.type != 'KSK':
            l.logError("Can't create/delete DS from ZSK (internal inconsitency)" + self.name)
            e = misc.AbortedZone("")
            raise e
        if self.zone.pcfg['Registrar'] == 'Local':
            if self.zone.parent_dir != None:
                return self.UpdateLocalDS(activity, secondKey)
            return True                         # nothing to do with local domain w/o parent
        else:
            l.logDebug('Calling UpdateRemoteDS(%s) called' % (activity))
            return self.zone.UpdateRemoteDS(activity, self.keytag)
    
    def UpdateLocalDS(self, activity, secondKey):    # create/submit/retire signer RR from KSK
        self.mypath.cd()
        result = ''
        
        if activity != 'retire' and activity != 'delete':
            l.logVerbose('Creating DS-RR from KSK %s' % self.__str__())
            s = conf.BIND_TOOLS + 'dnssec-dsfromkey ' + self.file_name
            l.logDebug(s)                   
            try:                                      
                result = shell(s, stdout='PIPE').stdout.strip()
                result = result + '\n'
            except script.CommandFailed:              
                l.logError('Error while creating DS RR for ' + self.name)
                e = misc.AbortedZone("")
                raise e
        elif activity == 'retire':
            l.logVerbose('Deleting local DS-RR from KSK %s' % self.__str__())
        else:
            l.logVerbose('Deleting all local DS-RRs from zone %s' % self.name)
        
        ds_file_name = self.zone.parent_dir + '/' + self.name + '.ds'
        l.logDebug('Updating local DS-RR stored in "%s"' % (ds_file_name,))
        old = ''
        try:
            if secondKey:
                with open(ds_file_name, 'r', encoding="ASCII") as fd:
                    if activity == 'retire':
                        lines = fd.readlines()
                        old = ''.join(lines[2:])
                    elif activity == 'delete':
                        pass
                    else:
                        old = fd.read()
            with open(ds_file_name, 'w', encoding="ASCII") as fd:
                fd.write(old + result)
        except:
            (exc_type, exc_value, exc_traceback) = sys.exc_info()
            l.logError('Error while reading/writing local DS-RR file for KSK %s \n\tbecause %s' % (self.__str__(), exc_value))
            e = misc.AbortedZone("")
            raise e
        self.updateSOA(self.zone.parent_dir + '/' + self.zone.parent + '.zone')
        return True        
    
    def updateSOA(self, filename): # update serial of SOA in zone file
        timestamp = datetime.now()
        current_date = timestamp.strftime('%Y%m%d')
        
        zf = ''
        with open(filename, 'r', encoding="ASCII") as fd:
            try:
                zf = fd.read()
            except:                 # file not found or not readable
                l.logError("Can't read zone file " + filename)
                e = misc.AbortedZone('')
                raise e
        ##l.logDebug('Updating SOA: zone file before update:' + zf)
        sea = re.search('(\d{8})(\d{2})(\s*;\s*)(Serial number)', zf)
        old_date = sea.group(1)
        daily_change = sea.group(2)
        if old_date == current_date:
           daily_change = str('%02d' % (int(daily_change) +1, ))
        else:
            daily_change = '01'
        zf = re.sub('\d{10}', current_date + daily_change, zf, count=1)
        ##l.logDebug('Updating SOA: zone file after update:' + zf)
        with open(filename, 'w', encoding="ASCII") as fd:
            try:
                fd.write(zf)
            except:                 # file not found or not readable
                l.logError("Can't write zone file " + filename)
                e = misc.AbortedZone('')
                raise e
        try:
             res = str(shell('rndc reload', stderr='PIPE').stderr)
             l.logDebug('Rndc reload returned: %s' % (res))
        except script.CommandFailed:
             l.logError('Error while reloading zones after updating SOA of %s ( %s )' % (self.name, res))
             e = misc.AbortedZone("")
             raise e
                                                    # check if condition for state transition is true and do action if so
    def state_transition(self, secondKey):          # secondKey is true if we are 2nd KSK/ZSK
        
        l.logDebug('state_transition(%s) called for %s %s' % (secondKey, self.keytag, self.type))
        state = -1                                  # state is index into sate table
        stt = None                                  # state table
        key = ''                                    # key for accessing state
        if self.type == 'KSK':                      # key signing key
            stt = KSTT                              # use corresponding state table
            key = 'ksk'                             # and state key
        else:                                       # zone signing key
            stt = ZSTT
            key = 'zsk'
        state = self.zone.pstat[key]['State']
        l.logDebug('State is %d (%s)' % (self.zone.pstat[key]['State'],stt[state]['s']))
        if state == -1:                             # initial state: begin signing
            state = 0
            self.zone.pstat[key]['State'] = state   # we have an SigningKey instance advance state
            l.logDebug('New state is %d (%s)' % (self.zone.pstat[key]['State'],stt[state]['s']))
            l.logVerbose('State transition of %s/%s from -1 to %d(%s) after %s retries' %
                (self.name, self.type, self.zone.pstat[key]['State'], stt[state]['s'], self.zone.pstat[key]['Retries']))
            return True
                                                    # not initial state
        if stt[state]['c'](self, stt[state]['ca'], secondKey):      # check condition for state transition
            if 'a' in stt[state].keys():                            # succeeded: action present?
                if 'aa' in stt[state].keys():                       # yes, call it - arg present?
                    stt[state]['a'](self, stt[state]['aa'], secondKey)  # yes, call it with arg
                else:
                    stt[state]['a'](self, secondKey)
            if 'ns' in stt[state].keys():           # action routine returned True or none called: 'next state' key present?
                state =  stt[state]['ns']           # yes, use it
            else:
                state = state + 1                   # no, increment it
            l.logVerbose('State transition of %s/%d from %d to %d (%s) after %s retries' %
                (self.type, self.keytag,
                self.zone.pstat[key]['State'], state, stt[state]['s'], self.zone.pstat[key]['Retries']))
            self.zone.pstat[key]['State'] = state
            self.zone.pstat[key]['Retries'] = 0
            return True                             # we had a transition
        self.zone.pstat[key]['Retries'] = str(int(self.zone.pstat[key]['Retries']) + 1)
        l.logDebug('New state is %d (%s)' % (self.zone.pstat[key]['State'],stt[state]['s']))
        return False                                # we stay in current state
    
    def activeTime(self):
        return self.timingData['A']
    
    def inactiveTime(self):
        return self.timingData['I']
    
    # -----------------------------
    # Actions on state transitions in SigningKey (immediately after one test below returns true)
    # -----------------------------
    def create_a(self, key_type, secondKey):     # create follow up KSK or ZSK
        l.logDebug('create_a(key_type)')
        return self.zone.createFollowUpKey(self)
    
    def delete_a(self, key_type, secondKey):
        l.logDebug('delete_a(key_type) called')
        l.logDebug('Deleting one/more of %s' % self.mypath.list('K*'))
        self.mypath.cd()                        # change to zone directory
        for kf in os.listdir():       # loop once per key file in zone dir
            if key_type == 'delete_all' and fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*') or \
                fnmatch.fnmatch(kf, 'K*' + str(self.keytag) + '.*'): # delete all keyfiles or our keyfile
                l.logDebug('Matched for deleting: %s' % (kf))
                try:
                    os.remove(path(kf))
                    l.logVerbose('Deleted: %s' % (kf))
                except:
                    (exc_type, exc_value, exc_traceback) = sys.exc_info()
                    l.logError("Can't delete keyfile, because %s" % (exc_value))
                    e = misc.AbortedZone("")
                    raise e
        if key_type == 'delete_all':
            self.zone.pcfg = copy.deepcopy(self.zone.icfg)               # initialize
            self.zone.pstat = copy.deepcopy(self.zone.istat)
            self.zone.saveCfgOrState('config')
        return True
    
    def rename_a(self, key_type, secondKey):
        l.logDebug('rename_a(key_type) called')
        return True   # nothing to do (keyfile 1 deleted previously and next round only key file 2 present)
    
    def submit_ds(self, activity, secondKey):
        l.logDebug('submit_ds(%s) called' % (activity))
        return self.UpdateDS(activity, secondKey)
    
    def set_delete_time(self, secondKey):
        l.logDebug('set_delete_time() called')
        self.mypath.cd()                        # change to zone directory
        try:
             (rubbish, result) = str(shell(conf.BIND_TOOLS + 'dnssec-settime   -D +' + str(conf.KSK_I_D_INTERVAL) + 'd ' + self.file_name, stdout='PIPE').stdout).split(None)
        except script.CommandFailed:
             l.logError('Error from dnssec_settime while setting delete time of '  +keyFileName)
             e = misc.AbortedZone("")
             raise e
        return True
    
    # -----------------------------
    # Tests for state transitions in SigningKey
    # -----------------------------
    def test_if_included(self, key_type, secondKey):    # test, if included in zone by our master
        global master_resolver,secondary_resolver       # included means: used for signing
        
        if '1' in key_type and secondKey or '2' in key_type and not secondKey:
            return False
       
        l.logDebug('test_if_included(' + key_type + ') called with name %s' % (self.name))
        
        r = master_resolver
        if 'ds' in key_type:
            if self.zone.pcfg['Registrar'] != 'Local':  # DS maintained by registrar?
                r = dns.resolver.Resolver()             # yes - do not bind resolver to our master
                r.lifetime = conf.NS_TIMEOUT
                r.use_edns(edns=0, ednsflags=0, payload=4096)
            elif not self.zone.parent_dir:              # locally maintained - do we have a parent?
                return True                             # no - no parent: no DS - state test always succeeds
            try:
                res = r.query(self.name, 'DS')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except (dns.exception.Timeout):
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                errmsg = "%s: DS query timed out. %s, %s" % \
                    (self.name, exc_type, exc_value)
                l.logError(errmsg)
                e = misc.AbortedZone('? ' + errmsg)
                raise e
            else:
                for ds in res.rrset.items:
                    keytag = ds.key_tag
                    if keytag == self.keytag:
                        return True
            return False
        else:                                           # testing for signed DNSKEY or SOA 
            try:
                if self.zone.pcfg['Registrar'] == 'Local':  # zone maintained local?
                    s = conf.master[0]
                else:
                    s = conf.external_secondaries[-2]       # use 2nd to last of our secondaries for now **FIXME**
                zone = dns.zone.from_xfr(dns.query.xfr(s, self.name, relativize=False, lifetime=30.0), relativize=False)
                my_covers = dns.rdatatype.DNSKEY        # DNSKEYs signed by KSK
                if self.type == 'ZSK':
                   my_covers = dns.rdatatype.SOA        # others signed by ZSK
                ##import pdb;pdb.set_trace()
                rds = zone.find_rrset(self.name + '.', 'RRSIG', covers=my_covers)
                
                if False:                               # need to leard how redirect pprint to string
                    dbgmsg1 = 'zone.find.rrset:\n'
                    dbgmsg2 = ''
                    pp = pprint.PrettyPrinter(indent=4,stream=dbgmsg2)
                    pp.pprint(rds)
                    l.logDebug(dbgmsg1 + dbgmsg2)
                
                for rrsig_rdata in rds.items:
                    key_tag = rrsig_rdata.key_tag
                    l.logDebug('test_if_included(key_type, secondKey) matching keytag: %s == %s' % (key_tag, self.keytag))
                    if key_tag == self.keytag:
                        l.logDebug('test_if_included(key_type, secondKey) RRSIG matched ourselves')
                        return True                 # at least one RR signed by ourselves
            except (dns.resolver.NoAnswer, KeyError): # KeyError if no RRSIGs exist
                pass
            except (dns.resolver.NXDOMAIN):
                errmsg = "%s: RRSIG query returned domain %s none-existent" % (self.name,)
                l.logError(errmsg)
                e = misc.AbortedZone('? ' + errmsg)
                raise e
            except (dns.exception.Timeout, IOError):
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                errmsg = "%s: RRSIG query network error: (Timeout or connection refused). %s, %s" % \
                    (self.name, exc_type, exc_value)
                l.logError(errmsg)
                e = misc.AbortedZone('? ' + errmsg)
                raise e
        return False
    
    def test_if_excluded(self, key_type, secondKey):       # test, if excluded from zone by our master
        l.logDebug('test_if_excluded(' + key_type + ') called') # (no longer used for signing)
        return not self.test_if_included(key_type, secondKey)
    
    def test_if_time_reached(self, time_type, secondKey):  # test, if arbitrary point in time reached
        
        if '1' in time_type and secondKey or '2' in time_type and not secondKey:
            return False
        
        myTime = 0
        l.logDebug('test_if_time_reached(' + time_type + ') called')
        if time_type == 'zsk1_followup':
                myTime = self.timingData['I'] - conf.ZSK_I_D_INTERVAL * 3600 * 24   # ZSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'zsk1_inactive':
            myTime = self.timingData['I']                                           # ZSK1 inactive = ZSK2 active
        elif time_type == 'zsk1_delete':
            myTime = self.timingData['D']                                           # ZSK1 delete time reached
        
        elif time_type == 'ds1_submit':                         # DS to be submitted prepublish interval after active
            myTime = self.timingData['A'] + conf.KSK_I_D_INTERVAL * 3600 * 24       # KSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'ksk1_followup':
            myTime = self.timingData['I'] - conf.KSK_I_D_INTERVAL * 3600 * 24   # KSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'ds2_submit':                         # DS to be submitted prepublish interval after active
            myTime = self.timingData['A'] + conf.KSK_I_D_INTERVAL * 3600 * 24       # KSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'ksk1_inactive':
            myTime = self.timingData['I']                                           # KSK1 inactive
        elif time_type == 'ksk1_delete':
            myTime = self.timingData['D']                                           # KSK1 to be deleted
        elif time_type == 'ksk_delete':
            myTime = self.timingData['D'] + conf.KSK_I_D_INTERVAL * 3600 * 24       # prepub interval after DS retirement
        else:
            if __debug__:
                raise AssertionError('?Internal error: test_if_time_reached called with wrong argument "%s"' % (time_type,))
            return False
        
        now = int(time.time())
        l.logDebug('test_if_time_reached: myTime=%s; now=%s' % (
                        datetime.fromtimestamp(myTime).isoformat(), datetime.fromtimestamp(now).isoformat()))
        if myTime <= now:
            return True
        return False 
    
    # -----------------------------
    # State tables in SigningKey
    # -----------------------------
    #          s = state                 c = check cond. for transition, ca = argument for c, a = action aa=arg  ns = next state
    ZSTT = (
            { 's': 'ZSK1 created',      'c': test_if_included,      'ca': 'zsk1',                                        },
            { 's': 'ZSK1 active',       'c': test_if_time_reached,  'ca': 'zsk1_followup','a': create_a,  'aa': 'zsk'     },
            { 's': 'ZSK2 created',      'c': test_if_included,      'ca': 'zsk2',                                        },
            { 's': 'ZSK2 published',    'c': test_if_time_reached,  'ca': 'zsk1_inactive',                               },
            { 's': 'ZSK2 active',       'c': test_if_time_reached,  'ca': 'zsk1_delete', 'a': delete_a,  'aa': 'zsk'     },
            { 's': 'ZSK1 deleted',      'c': test_if_excluded,      'ca': 'zsk1',        'a': rename_a,  'aa': 'zsk', 'ns': 1},
    )
    
    KSTT = (
            { 's': 'KSK1 created',      'c': test_if_included,      'ca': 'ksk1',                                        }, # 0
            { 's': 'KSK1 active',       'c': test_if_time_reached,  'ca': 'ds1_submit',  'a': submit_ds, 'aa': 'publish1'}, # 1
            { 's': 'DS1 submitted',     'c': test_if_included,      'ca': 'ds1',                                         }, # 2
            { 's': 'DS1 published',     'c': test_if_time_reached,  'ca': 'ksk1_followup','a': create_a,  'aa': 'ksk'    }, # 3
            { 's': 'KSK2 created',      'c': test_if_included,      'ca': 'ksk2',        'a': submit_ds, 'aa': 'publish2'}, # 4
            { 's': 'KSK2 active',       'c': test_if_included,      'ca': 'ds2',         'a': submit_ds, 'aa': 'retire'  }, # 5
            { 's': 'DS2 published',     'c': test_if_excluded,      'ca': 'ds1',                                         }, # 6
            { 's': 'DS1 retired',       'c': test_if_time_reached,  'ca': 'ksk1_inactive'                                }, # 7
            { 's': 'KSK1 inactive',     'c': test_if_time_reached,  'ca': 'ksk1_delete', 'a': delete_a,  'aa': 'ksk'     }, # 8
            { 's': 'KSK1 deleted',      'c': test_if_excluded,      'ca': 'ksk1',        'a': rename_a,  'aa': 'ksk', 'ns':1 },# 9
            { 's': 'DS retire request submitted','c':test_if_excluded,'ca':'ds',         'a': set_delete_time,           }, # 10
            { 's': 'DS retired',        'c': test_if_time_reached,  'ca': 'ksk_delete',  'a': delete_a,  'aa': 'delete_all','ns':-1}
    )


    
    #-----------------------------
    # functions in SigningKey
    #-----------------------------
    def createNSEC3PARAM():
        """
        http://strotmann.de/roller/dnsworkshop/entry/take_your_dnssec_with_a
        """
        salt = binascii.b2a_hex(rand.get_random_bytes(6)).decode('ASCII').upper()
