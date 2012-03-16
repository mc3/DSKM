#!/usr/bin/env python3

"""
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


# for salt
from Crypto import Random as rand
import binascii

import dns.resolver, dns.message, dns.query, dns.rdatatype, dns.rdtypes.ANY.DNSKEY, dns.rcode
import dns.dnssec

import json
import os

import re

# -----------------------------------------
# Configurables
# -----------------------------------------
import dnssec_key_maintenance_conf as conf
"""
# -----------------------------------------
# the import should define:
# -----------------------------------------
# own dns servers
master = '2.3.4.5'
external_secondaries = ('ns2.my.domain', 'ns3.my.domain', 'ns4.my.domain')
external_recursives = ()
# registrars
registrar = {}
registrar['TwoCows'] = {'server': 'dmapi.twocows.net',
				        'account_name': 'my_user_name',
				        'account_pw': 'blahblah' }
"""
#------------------------------------------------------------------------------
#   Adjustables
#--------------------------
##ROOT_PATH = '~/Developer/DNSsec/named/'
ROOT_PATH = '/var/named/master/signed'

#--------------------------
#   policy constants ( in days)
#--------------------------
TTL = 1                         # ttl of SOA, NS and others; A/AAAA may be shorter
SOA_EXPIRE_INTERVAL = 7         #  SOA expire time
SOA_NEGATIVE_CACHE_INTERVAL = 1

"""
# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
                                # published immediately after generation
ZSK_P_A_INTERVAL = 0            # active (used to sign RRsets) 7 days after publish
ZSK_A_I_INTERVAL = 30           # inactive 30 days after active
ZSK_I_D_INTERVAL = 7            # deleted 7 days after inactive

# Double-RRset Method with KSK - cascaded intervals for timing metadata
                                # published immediately after generation
KSK_P_A_INTERVAL = 0            # active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 360          # inactive 360 days after active
KSK_I_D_INTERVAL = 7            # deleted 7 days after inactive
"""
# Pre-Publication Method with ZSK - cascaded intervals for timing metadata
                                # published immediately after generation
ZSK_P_A_INTERVAL = 0            # active (used to sign RRsets) 7 days after publish
ZSK_A_I_INTERVAL = 1            # inactive 30 days after active
ZSK_I_D_INTERVAL = 1            # deleted 7 days after inactive

# Double-RRset Method with KSK - cascaded intervals for timing metadata
                                # published immediately after generation
KSK_P_A_INTERVAL = 0            # active (used to sign DNSKEY RRsets) 7 days after publish
KSK_A_I_INTERVAL = 2            # inactive 360 days after active
KSK_I_D_INTERVAL = 1            # deleted 7 days after inactive

# key algorithm
""" 2012-03-04 bind-users:

...Second, why do I get multiple DS records as response?

You will always get a 2 DS Records in response. One for SHA-1 and second
for SHA-256.

I was reading the RFCs, but according to that, there's no provision of
SHA-256. According to RFC 4034, 1 means MD5 and 2 means Diffie-Hellman
(appendix A1)

And RFC4024 is seven years old. No SHA256 back then.

See RFC6014 which allows IANA to assign new algorithm numbers as
needed without a new RFC. SHA256 is the current preferred algorithm,
while SHA-1 is still routinely used as some DNSSEC software may not
support SHA256 yet. Both MD5 and Diffie-Hellman are obsolete. I
suspect SHA-1 will be deprecated soon. I am unaware of any DNSSEC
software that does not support SHA256 at this time, but I suspect
someone, somewhere is running it.
-- 
R. Kevin Oberman, Network Engineer
E-mail: kob6558@gmail.com
"""
KEY_ALGO_NSEC = 'RSASHA256'
KEY_ALGO_NSEC3 = 'NSEC3RSASHA1'
## use both: DIGEST_ALGO_DS = '-2'          # SHA-256

KEY_SIZE_KSK = 2048
KEY_SIZE_ZSK = 1024

TTL_DNSKEY = 86400
TTL_DS = 86400

NS_TIMEOUT = 10                 # name server timeout

#--------------------------
#   End Adjustables
#------------------------------------------------------------------------------


script.doc.purpose = \
    'Do maintenace of DNSsec keys.\n Create and delete them as necessary'
script.doc.args = 'FUNCT'
opts.add('verbose', action='store_true')
opts.add('debug', action='store_true')

current_timestamp = 0
master_resolver = dns.resolver.Resolver()
master_resolver.lifetime = NS_TIMEOUT
master_resolver.nameservers = (conf.master,)
master_resolver.use_edns(edns=0, ednsflags=0, payload=4096)


#--------------------------
#   classes
#--------------------------
# exceptions

class AbortedZone(Exception):
    def __init__(self,x):
        self.data = x

class CompletedZone(Exception):
    pass

class SigningKey(object):
    """SigningKey"""
    global KSTT, ZSTT
    
    def __init__(self, task, name, file_name, sender, nsec3 = False, clone = False):
        
        self.name = name
        self.file_name = None
        self.zone = sender
        self.nsec3 = nsec3

        self.type = None
        
        self.algo = KEY_ALGO_NSEC
        if nsec3: self.algo = KEY_ALGO_NSEC3
        
        # values read from key file
        self.timingData = {}
        self.keytag = ''        # key tag
        self.dnssec_flags = 0   # flags
        self.sepkey = 0         # sep flag =KSK)
        self.dnssec_alg = 0     # key algorithm

        self.mypath = path(ROOT_PATH + '/' + name)
        self.mypath.cd()
        if opts.debug: print("[Instantiating SigningKey; pwd=%s.]" % (self.mypath))

        #-----------------------------
        # functions in SigningKey.__init__
        #-----------------------------
        # Read key meta data from key file
        def readKey(keyFileName):
            
            #   Read timing meta data from key
            def readKeyTimingData(keyFileName, type):
                result = None
                if not type in 'PAID':
                    print('?Internal inconsistency: readKeyTimingData called with wrong type ' 
                        + type + ' for key ' +keyFileName)
                    e = AbortedZone("")
                    raise e
                try:
                    (rubbish, result) = str(shell('dnssec-settime   -u -p ' + type + ' ' + keyFileName, stdout='PIPE').stdout).split(None)
                except script.CommandFailed:
                    print('?Error from dnssec_settime while reading timing data of '  +keyFileName)
                    e = AbortedZone("")
                    raise e
                if result == 'UNSET':
                    return 0
                else:
                    result = int(result) // ( 3600 * 24 ) * 3600 * 24
                return result
            
            fd = None
            try:
                fd = open(keyFileName, 'r')
            except IOError:
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                errmsg = "?Can't open key file, because %s" % (exc_value)
                print(errmsg)
                e = AbortedZone(errmsg)
                raise e
            flags = None
            if opts.debug: print("[readKey(%s) opened file.]" % (keyFileName))
            for line in fd:
                ##if opts.debug: print('[Keyfile line is %s]' % (line, ))
                (name, ttl, dns_class, rr, flags, x) = line.split(None, 5)
                if name == ';':
                    continue
                ##if opts.debug: print("[Keyfile line found with name=%s ttl=%s class=%s RR=%s flags=%s\n%s]" % (name, ttl, dns_class, rr, flags, x))
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
                    if opts.debug: print("[Read DNSSEC key id=%d with flags=%d alg=%d]" % (self.keytag, self.dnssec_flags, self.dnssec_alg))
                else:
                    print('?Unrecognized line in key file: ' + keyFileName)
                    e = AbortedZone("")
                    raise e
                if flags == '257':
                    if opts.debug: print('[Key ' + keyFileName + ' is KSK]')
                    if self.sepkey == 0:
                        print('?Inkonsistent sep flag found in %s' % (keyFileName))
                        e = AbortedZone("")
                        raise e
                    self.type = 'KSK'
                    break
                elif flags == '256':
                    if opts.debug: print('[Key ' + keyFileName + ' is ZSK]')
                    if self.sepkey == 1:
                        print('?Inkonsistent sep flag found in %s' % (keyFileName))
                        e = AbortedZone("")
                        raise e
                    self.type = 'ZSK'
                    break
                else:
                    print('?Key neither KSK not ZSK: ' + keyFileName)
                    e = AbortedZone("")
                    raise e
            
            fd.close()
            
            self.timingData['P'] = readKeyTimingData(keyFileName, 'P')
            self.timingData['A'] = readKeyTimingData(keyFileName, 'A')
            self.timingData['I'] = readKeyTimingData(keyFileName, 'I')
            self.timingData['D'] = readKeyTimingData(keyFileName, 'D')
            
        #-----------------------------
        # end of functions in SigningKey.__init__
        #-----------------------------

        if opts.debug:
            print('[Creating SigningKey instance task=%s, name=%s, file_name=%s, nsec3=%s, clone=%s]' % (task, name, file_name, nsec3, clone))
        if task == 'read':
            self.file_name = file_name
            readKey(file_name)
        elif task == 'ZSK':
            inactive_from_now = ZSK_P_A_INTERVAL + ZSK_A_I_INTERVAL
            delete_from_now = inactive_from_now + ZSK_I_D_INTERVAL
            s = 'dnssec-keygen -a ' + self.algo + ' -b ' + repr(KEY_SIZE_ZSK) + ' -n ZONE ' \
                + '-A +' + repr(ZSK_P_A_INTERVAL) + 'd ' +'-I +' + repr(inactive_from_now) + 'd ' \
                + '-D +' + repr(delete_from_now) +'d -L ' + repr(TTL_DNSKEY) + ' ' + name
            if clone:
                inactive_from_now = ZSK_I_D_INTERVAL + ZSK_A_I_INTERVAL # prepublish + inactive - active
                delete_from_now = inactive_from_now + ZSK_I_D_INTERVAL
                s = 'dnssec-keygen -S ' + file_name + ' -i +0 -I +' + repr(inactive_from_now) + 'd ' \
                    + '-D +' + repr(delete_from_now) +'d -L ' + repr(TTL_DNSKEY)
            if opts.debug: print(s)
            try:
                result = shell(s, stdout='PIPE').stdout.strip()
            except script.CommandFailed:
                print('?Error while creating ZSK for ' + name)
                e = AbortedZone("")
                raise e
            self.file_name = result + '.key'
            print('[Key ' + self.file_name + ' created.]')
            readKey(self.file_name)
        elif task == 'KSK':
            inactive_from_now = KSK_P_A_INTERVAL + KSK_A_I_INTERVAL
            delete_from_now = inactive_from_now + KSK_I_D_INTERVAL
            s = 'dnssec-keygen -a ' + self.algo + ' -b ' + repr(KEY_SIZE_KSK) + ' -n ZONE -f KSK ' \
                + '-A +' + repr(KSK_P_A_INTERVAL) + 'd -I +' + repr(inactive_from_now) + 'd ' \
                + '-D +' + repr(delete_from_now) + 'd -L ' + repr(TTL_DNSKEY) + ' ' + name
            if clone:
                inactive_from_now = KSK_I_D_INTERVAL + KSK_A_I_INTERVAL # prepublish + inactive - active
                delete_from_now = inactive_from_now + KSK_I_D_INTERVAL
                s = 'dnssec-keygen -S ' + file_name + ' -i +0 -I +' + repr(inactive_from_now) + 'd ' \
                    + '-D +' + repr(delete_from_now) +'d -L ' + repr(TTL_DNSKEY)
            if opts.debug: print(s)
            try:
                result = shell(s, stdout='PIPE').stdout.strip()
            except script.CommandFailed:
                print('?Error while creating KSK for ' + name)
                e = AbortedZone("")
                raise e
            self.file_name = result + '.key'
            print('[Key ' + self.file_name + ' created.]')
            readKey(self.file_name)
        else:
            print('?Internal inconsitency: SigningKey instantiating  with wrong task ' + task)
            e = AbortedZone("")
            raise e
        
    def __str__(self):
        def getKeyTimingData(type):
            if self.timingData[type] == 0:
                return 'UNSET'
            else:
                return date.fromtimestamp(self.timingData[type]).isoformat()
        
        return self.type + ':'+ self.name+ ': A:'+ getKeyTimingData('A') + ' I:'+ getKeyTimingData('I') + ' D:'+ getKeyTimingData('D')
    
    def CreateDS(self):         # create delegate signer RR from KSK
        self.mypath.cd()
        result = None
        
        if self.type != 'KSK':
            print("?Can't create DS from ZSK (internal inconsitency)" + self.name)
            e = AbortedZone("")
            raise e
        
        if opts.verbose: print('[Creating DS-RR from KSK %s]' % self.file_name)
        s = 'dnssec-dsfromkey ' + self.file_name
        if opts.debug: print(s)                   
        try:                                      
            result = shell(s, stdout='PIPE').stdout.strip()
        except script.CommandFailed:              
            print('?Error while creating DS RR for ' + self.name)
            e = AbortedZone("")
            raise e
        ds_file_name = ''
        if self.zone.pcfg['Registrar'] == 'Local' and self.zone.parent_dir != None:
            ds_file_name = self.zone.parent_dir + '/'
            self.updateSOA(ds_file_name + self.zone.parent + '.zone')
        if opts.debug: print('[DS-RR will be stored in "%s"]' % (ds_file_name,))
        ds_file_name = ds_file_name + self.name + '.ds'
        with open(ds_file_name, 'w', encoding="ASCII") as fd:
          fd.write(result + '\n')
            
    def updateSOA(self, filename): # update serial of SOA in zone file
        timestamp = datetime.now()
        current_date = timestamp.strftime('%Y%m%d')
        
        zf = ''
        with open(filename, 'r', encoding="ASCII") as fd:
            try:
                zf = fd.read()
            except:                 # file not found or not readable
                print("?Can't read zone file " + filename)
                e = AbortedZone('')
                raise e
        ##if opts.debug: print('[Updating SOA: zone file before update:]' + zf)
        sea = re.search('(\d{8})(\d{2})(\s*;\s*)(Serial number)', zf)
        old_date = sea.group(1)
        daily_change = sea.group(2)
        if old_date == current_date:
           daily_change = str('%02d' % (int(daily_change) +1, ))
        else:
            daily_change = '01'
        zf = re.sub('\d{10}', current_date + daily_change, zf, count=1)
        ##if opts.debug: print('[Updating SOA: zone file after update:]' + zf)
        with open(filename, 'w', encoding="ASCII") as fd:
            try:
                fd.write(zf)
            except:                 # file not found or not readable
                print("?Can't write zone file " + filename)
                e = AbortedZone('')
                raise e
        try:
             res = str(shell('rndc reload', stderr='PIPE').stderr)
             if DEBUG: print('[Rndc reload returned: %s]' % (str))
        except script.CommandFailed:
             print('?Error while reloading zones after updating SOA of %s ( %s )' % (self.name, res))
             e = AbortedZone("")
             raise e
                                                    # check if condition for state transition is true and do action if so
    def state_transition(self, secondKey):          # secondKey is true if we are 2nd KSK/ZSK
        
        if DEBUG: print('[state_transition(%s) called for %s %s]' % (secondKey, self.keytag, self.type))
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
        if DEBUG: print('[State is %d (%s)]' % (self.zone.pstat[key]['State'],stt[state]['s']))
        if state == -1:                             # initial state: begin signing
            state = 0
            self.zone.pstat[key]['State'] = state   # we have an SigningKey instance advance state
            if DEBUG: print('[New state is %d (%s)]' % (self.zone.pstat[key]['State'],stt[state]['s']))
            if opts.verbose: print('[State transition of %s/%s from -1 to %d(%s) after %s retries]' %
                (self.name, self.type, self.zone.pstat[key]['State'], stt[state]['s'], self.zone.pstat[key]['Retries']))
            return True
                                                    # not initial state
        if stt[state]['c'](self, stt[state]['ca'], secondKey):      # check condition for state transition
            if 'a' in stt[state].keys():                            # succeeded: action present?
                stt[state]['a'](self, stt[state]['aa'], secondKey)  # yes, call it
            if 'ns' in stt[state].keys():           # 'next state' key present?
                state =  stt[state]['ns']           # yes, use it
            else:
                state = state + 1           # no, increment it
            if DEBUG: print('[New state is %d (%s)]' % (state, stt[state]['s']))
            if opts.verbose: print('[State transition of %s/%s/%s(A:%s) from %d to %d (%s) after %s retries]' %
                (self.name, self.type, self.keytag, date.fromtimestamp(self.timingData['A']).isoformat(),
                self.zone.pstat[key]['State'], state, stt[state]['s'], self.zone.pstat[key]['Retries']))
            self.zone.pstat[key]['State'] = state
            self.zone.pstat[key]['Retries'] = str(0)
            return True                         # we had a transition
        self.zone.pstat[key]['Retries'] = str(int(self.zone.pstat[key]['Retries']) + 1)
        if DEBUG: print('[New state is %d (%s)]' % (self.zone.pstat[key]['State'],stt[state]['s']))
        return False                            # we stay in current state
    
    def activeTime(self):
        return self.timingData['A']
    
    # -----------------------------
    # Actions on state transitions in SigningKey (immediately after one test below returns true)
    # -----------------------------
    def create_a(self, key_type, secondKey):     # in case of DS, always create 2 DS (SHA1 and SHA256)
        if secondKey:
            return False                         # only primary key can create second key/ds
        if DEBUG: print('[create_a(key_type) called]')
        return self.zone.createFollowUpKey(self)
    
    def delete_a(self, key_type, secondKey):
        if secondKey:
            return False                         # only primary key can create second key/ds
        if DEBUG: print('[delete_a(key_type) called]')
        self.mypath.cd()                        # change to zone directory
        for kf in self.mypath.list('*'):        # loop once per file in zone dir
            if key_type == 'delete_all' and fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*') or \
                fnmatch.fnmatch(kf, 'K*' + self.keytag + '.+*'): # delete all keyfiles or our keyfile
                try:
                    os.remove(path(kf))
                except:
                    (exc_type, exc_value, exc_traceback) = sys.exc_info()
                    print("?Can't delete keyfile, because %s" % (exc_value))
                    e = AbortedZone("")
                    raise e
        return True
    
    def rename_a(self, key_type, secondKey):
        if DEBUG: print('[rename_a(key_type) called]')
        return True   # nothing to do (keyfile 1 deleted previously and next round only key file 2 present)
    
    def submit_ds(self, activity, secondKey):
        if DEBUG: print('[submit_ds(activity) called]')
        self.CreateDS()
        return True
    
    def set_delete_time(self, secondKey):
        if DEBUG: print('[set_delete_time() called]')
        self.mypath.cd()                        # change to zone directory
        try:
             (rubbish, result) = str(shell('dnssec-settime   -D +' + str(KSK_I_D_INTERVAL) + 'd ' + self.file_name, stdout='PIPE').stdout).split(None)
        except script.CommandFailed:
             print('?Error from dnssec_settime while setting delete time of '  +keyFileName)
             e = AbortedZone("")
             raise e
        return True
    
    # -----------------------------
    # Tests for state transitions in SigningKey
    # -----------------------------
    def test_if_included(self, key_type, secondKey):     # test, if included in zone by our master
        global master_resolver
        
        if '1' in key_type and secondKey or '2' in key_type and not secondKey:
            return False
       
        if DEBUG: print('[test_if_included(' + key_type + ') called with name %s]' % (self.name))
        
        r = master_resolver
        if 'ds' in key_type:
            if self.zone.pcfg['Registrar'] != 'Local':       # DS maintained by registrar?
                r = dns.resolver.Resolver()             # yes - do not bind resolver to our master
                r.lifetime = NS_TIMEOUT
                r.use_edns(edns=0, ednsflags=0, payload=4096)
            try:
                res = r.query(self.name, 'DS')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except (dns.exception.Timeout):
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                errmsg = "%s: DS query timed out. %s, %s" % \
                    (self.name, exc_type, exc_value)
                print('? ' + errmsg)
                e = AbortedZone('? ' + errmsg)
                raise e
            else:
                for ds in res.rrset.items:
                    keytag = ds.key_tag
                    if keytag == self.keytag:
                        return True
            return False
        else:
            try:
                res = r.query(self.name, 'DNSKEY')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except (dns.exception.Timeout):
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                errmsg = "%s: DNSKEY query timed out. %s, %s" % \
                    (self.name, exc_type, exc_value)
                print('? ' + errmsg)
                e = AbortedZone('? ' + errmsg)
                raise e
            else:
                for dnskey_rdata in res.rrset.items:
                    keytag = dns.dnssec.key_id(dnskey_rdata)
                    if keytag == self.keytag:
                        return True
        return False
    
    def test_if_excluded(self, key_type, secondKey):       # test, if excluded from zone by our master
        if DEBUG: print('[test_if_excluded(' + key_type + ') called]')
        return not self.test_if_included(key_type, secondKey)
    
    def test_if_time_reached(self, time_type, secondKey):  # test, if arbitrary point in time reached
        
        if secondKey:
            return False                                   # !!!???!!!
        
        myTime = 0
        if DEBUG: print('[test_if_time_reached(' + time_type + ') called]')
        if time_type == 'zsk2_prepub':
            myTime = self.timingData['I'] - ZSK_I_D_INTERVAL * 3600 * 24   # ZSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'zsk2_active':
            myTime = self.timingData['I']                                  # ZSK1 inactive = ZSK2 active
        elif time_type == 'zsk1_delete':
            myTime = self.timingData['D']                                  # ZSK1 delete time reached
        
        elif time_type == 'ds1_submit':                         # DS to be submitted prepublish interval after active
            myTime = self.timingData['A'] + KSK_I_D_INTERVAL * 3600 * 24   # KSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'ksk2_prepub':
            myTime = self.timingData['I'] - KSK_I_D_INTERVAL * 2 * 3600 * 24 # KSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'ds2_submit':                         # DS to be submitted prepublish interval after active
            myTime = self.timingData['I'] - KSK_I_D_INTERVAL * 3600 * 24   # KSK_I_D_INTERVAL is pre publish interval
        elif time_type == 'ksk1_inactive':
            myTime = self.timingData['I']                                  # KSK1 inactive
        elif time_type == 'ksk1_delete':
            myTime = self.timingData['D']                                  # KSK1 to be deleted
        elif time_type == 'ksk_delete':
            myTime = self.timingData['D'] + KSK_I_D_INTERVAL * 3600 * 24   # prepub interval after DS retirement
        else:
            if __debug__:
                raise AssertionError('?Internal error: test_if_time_reached called with wrong argument "%s"' % (time_type,))
            return False
        
        if DEBUG: print('[test_if_time_reached: myTime=%s; current_timestamp=%s]' %(str(myTime), str(current_timestamp)))
        if myTime <= current_timestamp:
            return True
        return False 
    
    # -----------------------------
    # State tables in SigningKey
    # -----------------------------
    #          s = state                 c = check cond. for transition, ca = argument for c, a = action aa=arg  ns = next state
    ZSTT = (
            { 's': 'ZSK1 created',      'c': test_if_included,      'ca': 'zsk1',                                        },
            { 's': 'ZSK1 active',       'c': test_if_time_reached,  'ca': 'zsk2_prepub', 'a': create_a,  'aa': 'zsk'     },
            { 's': 'ZSK2 created',      'c': test_if_included,      'ca': 'zsk2',                                        },
            { 's': 'ZSK2 published',    'c': test_if_time_reached,  'ca': 'zsk2_active',                                 },
            { 's': 'ZSK2 active',       'c': test_if_time_reached,  'ca': 'zsk1_delete', 'a': delete_a,  'aa': 'zsk'     },
            { 's': 'ZSK1 deleted',      'c': test_if_excluded,      'ca': 'zsk1',        'a': rename_a,  'aa': 'zsk', 'ns': 1},
    )
    
    KSTT = (
            { 's': 'KSK1 created',      'c': test_if_included,      'ca': 'ksk1',                                        }, # 0
            { 's': 'KSK1 active',       'c': test_if_time_reached,  'ca': 'ds1_submit',  'a': submit_ds, 'aa': 'publish1'}, # 1
            { 's': 'DS1 submitted',     'c': test_if_included,      'ca': 'ds1',                                         }, # 2
            { 's': 'DS1 published',     'c': test_if_time_reached,  'ca': 'ksk2_prepub', 'a': create_a,  'aa': 'ksk'     }, # 3
            { 's': 'KSK2 created',      'c': test_if_included,      'ca': 'ksk2',                                        }, # 4
            { 's': 'KSK2 active',       'c': test_if_time_reached,  'ca': 'ds2_submit',  'a': submit_ds, 'aa': 'publish2'}, # 5
            { 's': 'DS2 submitted',     'c': test_if_included,      'ca': 'ds2',         'a': submit_ds, 'aa': 'retire'  }, # 6
            { 's': 'DS2 published',     'c': test_if_excluded,      'ca': 'ds1',                                         }, # 7
            { 's': 'DS1 retired',       'c': test_if_time_reached,  'ca': 'ksk1_inactive'                                }, # 8
            { 's': 'KSK1 inactive',     'c': test_if_time_reached,  'ca': 'ksk1_delete', 'a': delete_a,  'aa': 'ksk'     }, # 9
            { 's': 'KSK1 deleted',      'c': test_if_excluded,      'ca': 'ksk1',        'a': rename_a,  'aa': 'ksk', 'ns':1 },# 10
            { 's': 'DS retire request submitted','c':test_if_excluded,'ca':'ds',         'a': set_delete_time,           }, # 11
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
    
#------------------------------------------------------------------------------

class managedZone(object):
    """managedZone"""

    def __init__(self, name):
        self.name = name
        
        self.pcfg = {'Method': 'unsigned',  # unsigned, NSEC or NSEC3 \
                    'Registrar': 'Local'}   # Local, Joker, Ripe    \
        
        self.pstat = {}
        self.pstat['ksk'] = {'State': -1,   # index into state table KSTT, \
                             'Retries': 0}  # Number of retries in current state
        self.pstat['zsk'] = {'State': -1,   # index into state table ZSTT, \
                            'Retries': 0}   # Number of retries in current state
        self.pstat['OldMethod'] = 'unsigned'# NSEC or NSEC3 \
        self.pstat['OldRegistrar'] = 'Local'    # Joker, Ripe

        self.ksks = []
        self.zsks = []
    
        self.parent = None
        self.parent_dir = None
        
        self.mypath = path(ROOT_PATH + '/' + name)
        self.mypath.cd()
        
        #-----------------------------
        # functions in managedZone.__init__
        #-----------------------------
        def readConfig(cfg, domain_name, file_name):
            if opts.debug: print('[Opening ' + domain_name + '/' + file_name + ']')
            try:
                with open(file_name) as fd:     # open config/status file for read
                    try:
                        key = ''
                        tstcfg = json.load(fd)
                        for key in iter(cfg):   # do simple syntax check
                            vt = tstcfg[key]    # raises if key missed
                            vo = cfg[key]
                            if isinstance(vo, dict):
                                for key in iter(vo):
                                    x = vo[key] # raises if key missed
                    except:                     # missing key: syntax error in cfg file
                        print('?Garbage found/Missing option ' + key + ' in configuration/status file "' + domain_name + '/' + file_name + '"')
                        e = AbortedZone("")
                        raise e
                    cfg = tstcfg    
            except IOError:                     # file not found
                try:
                    with open(file_name, 'w') as fd:
                        json.dump(cfg, fd, indent=8)
                except IOError:                 # no write permission
                    (exc_type, exc_value, exc_traceback) = sys.exc_info()
                    print("?Can't create file, because %s" % (exc_value))
                    e = AbortedZone("")
                    raise e
            if opts.debug:
                print('[Config/status ' + domain_name + '/' + file_name + ' contains:\n' + str(cfg) + ']')
            return cfg
                
        def deleteKeyFiles():
            for kf in self.mypath.list('*'):        # loop once per file in zone dir
                if fnmatch.fnmatch(kf, 'K' + self.name + '.+*.*'):
                    try:
                        os.remove(path(kf))         # remove all key files if we do not have one created
                    except:
                        (exc_type, exc_value, exc_traceback) = sys.exc_info()
                        print("?Can't delete keyfile, because %s" % (exc_value))
                        e = AbortedZone("")
                        raise e
    
        def saveState():
            if opts.debug:
                print('[New status of ' + self.name + ' contains:\n' + str(self.pstat) + ']')
            stat_file_name = 'dnssec-stat-' + self.name
            try:
                with open(stat_file_name, 'w') as fd:
                    json.dump(self.pstat, fd, indent=8)
            except:                  # no write permission
            ##except IOError:                 # no write permission
                (exc_type, exc_value, exc_traceback) = sys.exc_info()
                print("?Can't create status file, because %s" % (exc_value))
                e = AbortedZone()
                raise e
            
        #-----------------------------
        # end of functions in managedZone.__init__
        #-----------------------------
        (x,y,self.parent) = self.name.partition('.')
        pd = path(ROOT_PATH + '/' + self.parent)
        if opts.debug: print('[Parent directory would be %s]' % (pd,))
        zl = ''
        if pd.exists:
            zl = ' <local>'
            self.parent_dir = pd
        if opts.verbose: print('[Working on ' + self.name + ' (' + self.parent + zl +')' + ']')

        try:
            cfg_file_name = 'dnssec-conf-' + self.name
            self.pcfg = readConfig(self.pcfg, name, cfg_file_name)
            stat_file_name = 'dnssec-stat-' + self.name
            self.pstat = readConfig(self.pstat, name, stat_file_name)
            if self.pcfg['Method'] not in ('unsigned', 'NSEC', 'NSEC3'):
                print('? Wrong Method "%s" in zone config of %s' % (self.pcfg['Method'], self.name))
                e = AbortedZone("")
                raise e
            if self.pstat['OldMethod'] not in ('unsigned', 'NSEC', 'NSEC3'):
                print('? Wrong OldMethod "%s" in zone config of %s' % (self.pstat['Method'], self.name))
                e = AbortedZone("")
                raise e

            if opts.debug:
                print('[KSK state is %d]' % (self.pstat['ksk']['State']))
        
            if self.pstat['ksk']['State'] == -1:    # state idle
                deleteKeyFiles()               # delete any key files
            else:
                if self.pstat['OldMethod'] != self.pcfg['Method']:  # don't allow config change if not state idle for now
                    print('?Method changed from %s to %s in zone %s' % (self.pstat['OldMethod'], self.pcfg['Method'], self.name))
                    e = AbortedZone('')
                    raise e
                if self.pstat['OldRegistrar'] != self.pcfg['Registrar']:  # don't allow config change if not state idle for now
                    print('?Registrar changed from %s to %s in zone %s' % (self.pstat['OldRegistrar'], self.pcfg['Registrar'], self.name))
                    e = AbortedZone('')
                    raise e
                for kf in path('.').list('*'):      # loop once per public key file in zone dir
                    if fnmatch.fnmatch(kf, 'K' + self.name + '.+*.key'):
                        k = SigningKey('read', self.name, kf, self) # and create instance from it
                        if k.type == 'KSK':
                            self.ksks.append(k)
                        elif k.type == 'ZSK':
                            self.zsks.append(k)
            
            nsec3 = False
            if self.pstat['ksk']['State'] == -1: # IDLE state
                if self.pcfg['Method'] == 'unsigned':
                    raise CompletedZone()       # unsigned zone
                elif self.pcfg['Method'] == 'NSEC3':
                    nsec3 = True
                                                # Begin signing zone 1st time
                k = (SigningKey('KSK', self.name, '', self, nsec3=nsec3))
                self.ksks.append(k)
                
                self.zsks.append(SigningKey('ZSK', self.name, '', self, nsec3=nsec3))
            
            self.ksks.sort(key=SigningKey.activeTime, reverse=True)
            second = False
            for k in self.ksks:
                k.state_transition(second)
                second = True

            self.zsks.sort(key=SigningKey.activeTime, reverse=True)
            second = False
            for k in self.zsks:
                k.state_transition(second)
                second = True
            if opts.debug:
                for key in self.ksks:
                    print(key.__str__())
            if opts.debug:
                for key in self.zsks:
                    print(key.__str__())

            self.pstat['OldMethod'] = self.pcfg['Method']
            self.pstat['OldRegistrar'] = self.pcfg['Registrar']
            
            saveState()
                
        except AbortedZone:
            print('?Aborting zone ' + self.name)
            if self.pstat['ksk']['State'] == -1 or self.pstat['zsk']['State'] == -1:
                try:
                    saveState()
                except:
                    pass
                print('?Removing key files of %s' % (name))
                deleteKeyFiles
                raise
        pass
    
    #       if self.pcfg['Method'] != self.pstat['OldMethod']:
    #           print('[Method of domain %s has changed from %s to %s]' % (self.name, self.pstat['OldMethod'], self.pcfg['Method']))
    #           script.exit(1, '?Changing of methods not yet implemented')
    
    
    def createFollowUpKey(self, sender):    # usually called by action routine to create a new key
        nsec3 = False
        if self.pcfg['Method'] == 'NSEC3':
            nsec3 = True
        k = (SigningKey(sender.type, self.name, sender.file_name, self, nsec3=nsec3, clone=True))
        if k.type == 'KSK':
             self.ksks.append(k)
        elif k.type == 'ZSK':
             self.zsks.append(k)
        return True
        
    

#--------------------------
#   Functions
#--------------------------


#--------------------------
#   Main
#--------------------------
def main():
    global DEBUG, current_timestamp
    DEBUG = opts.debug
    
    try:
        current_timestamp = int(shell('date +%s', stdout='PIPE').stdout.strip())
    except script.CommandFailed:
        script.exit(1, '?Unable to obtain current timestamp' )
    current_timestamp = ( current_timestamp // ( 3600 * 24 )) * 3600 * 24
    if opts.debug: print('[Timestamp at 0:0 was %d]' % (current_timestamp,))
        
    root = path(ROOT_PATH)
    if opts.debug: opts.verbose = True
    if not root.exists:
        print('%No key root directory; creating one.')
        root.mkdir(mode=0o750)
        root = path(ROOT_PATH)
    if opts.verbose: print('[scanning ' + root + ']')
    root.cd()
    root = path('.')
    zone_dirs = []
    zones = {}
    for dir in root.list('*'):
        if dir.is_dir:
            zone_dirs.append(dir.name)
    zone_dirs.sort(key = len)
    zone_dirs.reverse()
    if opts.debug: print('[ Doing zones: ]')
    if opts.debug: print( zone_dirs )
    for zone_name in zone_dirs:
        try:
            zones[zone_name] = managedZone(zone_name)
        except AbortedZone as a:
            print(a.data)
            print('%Skipping zone ' + zone_name)
        except CompletedZone:
            pass

script.run(main)