DSKM DNSsec Key Management
 
 Copyright (c) 2012-2019 Axel Rau, axel.rau@chaos1.de

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


Purpose:
    DNSsec key management add-on to ISC bind 9.9.x for zones with
        auto-dnssec maintain;
        inline-signing yes;
    .Creates and deletes keys, submits delegation signer (DS) resource records
    or public DNSKEYs to parent.
    Zones may be local, public or reverse (IP4 or IP6).

Requirements:
    bind 9.12+      http://www.isc.org/software/bind
    python 3.6+
    pycryptodome    pypi.org
    ecdsa           pypi.org
    dnspython       pypi.org, http://www.dnspython.org/
    script          http://lamb.cc/script/ (must be installed manually)

Installation:
    Optionally create a virtual environment.
    Download the script package from http://lamb.cc/script/,
    extract it to /usr/local/src and install it as
        pip install /usr/local/src/script-1.7.2
    Then install DSKM as
        pip install DSKM
    
    After installation of the required software, query usage of the main program
    at top level::
    
        # operate_dskm -h
        Usage: operate_dskm [options]
        
        DSKM DNSsec Key Management Do maintenace of DNSsec keys. Create and delete
        them as necessary. Submit/cancle DS-RR to/at parent registrar.
        
        Options:
          -h, --help            show this help message and exit
          -c, --cron            Run as cronjob. Each run increments timeout timer.
          -S STOPSIGNINGOFZONE, --stopSigningOfZone=STOPSIGNINGOFZONE
                                Initiate procedure to make a zone unsigned. Argument
                                is zone name.
          -f, --force           Force deletion of keys (ignore delete time) while
                                stopping signing of zone.
          -r, --registrar_status
                                Query list of completed and pending requests of all
                                registrars and terminate.
          -p, --purge_all_registrar_completion_info
                                Purge all completion info of completed and pending
                                requests of all registrars and terminate.
          -q QUERY_STATUS, --query_status=QUERY_STATUS
                                Give detailed registrar result status about <request-
                                id>.
          -t, --test_registrar_DS_submission
                                Delete and re-submit current DS-RR to registrar.
          -n, --dry-run         Do not really change any data at registrar with
                                --test_registrar_DS_submission.
          -d, --debug           Turn on debugging.
          -v, --verbose         Be more verbose.
    
    Configuration:
    
    named.conf  DSKM requires all managed zones to share a common root.
                There is one directory per zone, which contains zone file,
                keys, bind journal files and DSKM config and status files, e.g.:
                    /var/named/master/signed/example.com
                    /var/named/master/signed/sub.example.com
                Corresponding named.conf fragments could look like:
                    options {
                        dnssec-enable yes;
                        dnssec-validation yes;
                        directory "/var/named";
                        ...
                    }
                    
                    zone "example.com" IN {
                        type master;
                        file "master/signed/example.com/example.com.zone";
                        key-directory "master/signed/example.com/";
                        auto-dnssec maintain;
                        inline-signing yes;
                        allow-query {
                            any;
                        };
                    };
                    
                    zone "sub.example.com" IN {
                        type master;
                        file "master/signed/sub.example.com/sub.example.com.zone";
                        key-directory "master/signed/sub.example.com/";
                        auto-dnssec maintain;
                        inline-signing yes;
                        allow-query {
                            any;
                        };
                    };
    
    zone file   In case you have a local subdomain, insert something like
                    sub                 IN  NS  localhost.
                    $include "master/signed/example.com/sub.example.com.ds"
                The included file must be empty (will be updated by DSKM).
                Local domain, means an internal domain with local trust anchor
                ("Registrar = Local" in example.com/dnssec-stat-example.com - see below)
                
    $VIRTUAL_ENV/etcdskm_conf.py or /usr/local/etc/dskm_conf.py:
      
                Please review the DSKM config file carefully:
                master
                    A list of IPs where the (hidden) master may be reached by the script
                external_secondaries
                    A list of NS addresses of your public secondaries
                external_recursives
                    A list of NS addresses of public, validating NS
                registrar
                    Dict of dicts with account data, one per registrar.
                    Initially implemented is
                        Joker for Joker.com see http://www.joker.com and
                        Ripe (not really a registrar, but European
                            Regional Internet Registry)
                        (Names must be written literally as above)
                sender, recipients, mailRelay for alarming mails, if run as cron job.
                ROOT_PATH
                    root of zone directories
                
                The other timing and crypto constants should be self explaining.
		The key timing constants are 'sticky': Changing them in DSKM/conf.py
		does not affect active zones.
		The secure way to apply changed timing data to active zones would be
		to stop signing and start over with a vanilla conf file ( see below).
        
    example.com/dnssec-conf-example.com
                If you run the script with an empty zone directory (example.com),
                it creates 2 files there:
                    example.com/dnssec-conf-example.com
                    example.com/dnssec-stat-example.com
                You must then put the zone file there and edit the dnssec-conf-*
                file, which initial content is:
                    {
                        "Registrar": "Local", 
                        "Method": "unsigned"
                    }
                'Registrar' may be one of 'Local', 'by hand', 'Joker' or 'Ripe'.
                	'Local' is zone with local trust anchor (private net etc.)
                	'by hand' is zone for which handover of DS-RR/DNSKEY-RR to
                		parent is done by human on behalf of an email sent by DSKM.
                'Method must be changed to 'NSEC' (currently only).
                If you then run the script, it will create the initial keys and
                named will start signing the zone:
        # operate_dskm -v
        [Scanning /var/named/master/signed]
        [Working at 2012-05-31T15:01:33.932455 on example.com (com )]
        Generating key pair..............+++ ...........+++ 
        [Key Kexample.com.+008+26482.key created.]
        [example.com/KSK/26482/-1(A:2012-05-31T15:01:33, I:2012-06-02T15:01:33, D:2012-06-03T15:01:33)]
        Generating key pair.....................++++++ .............++++++ 
        [Key Kexample.com.+008+27330.key created.]
        [example.com/ZSK/27330/-1(A:2012-05-31T15:01:34, I:2012-06-01T15:01:34, D:2012-06-02T15:01:34)]
        [State transition of example.com/KSK from -1 to 0(KSK1 created) after 0 retries]
        [State transition of example.com/ZSK from -1 to 0(ZSK1 created) after 0 retries]
        # 
                Debug- and informal messages are in square brackets, warnings start with '%' and
                errors start with '?'.
                The 3 timestamps per key are Active (start signing with this key), 
                Inactive(stop using this key for sigs) and Delete (remove key from DNSKEY rset).
    
    crontab:    Something like
                    # hourly DNSsec key maintenance
                    55  *   *   *   *   root    /usr/local/bin/python3 \
                    /usr/local/cronscripts/dnssec_key_maintenance.py \
                    -v -c >>/var/log/DSKM/dnssec_key_maintenance.log >&1
                will do.
                