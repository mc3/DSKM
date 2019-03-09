=========
Changelog
=========

.. toctree::

pre.0.9.0
------------------

- Check if SOA serial in zone file and master server are in sync
- BUGFIX: Allow ":" in value of Joker response
- BUGFIX: Fix keyError on 1st DS-RR submission of new zone
- Poll all auth NS for each zone to prevent from registrar error
- Implemented purge_all_registrar_completion_info
- :BUGFIX: If key timing data trashed, create uncloned key
- RIPE NCC introduced "last-modified" which must not be supplied
- Make sure master server has loaded zone before querying DNSKEY
- RIPE NCC introduced "last-modified" which must not be supplied
- Make sure master server has loaded zone before querying DNSKEY
- Merge branch 'master' of git.chaos1.de:DSKM
- Exit if master servers fails in masters_DNSKEYs
- Fixed handover for de-domains with Joker.com
- BUGFIX: Change to correct dir before file operations
- BUGFIX: New conf variable OWNER_OF_PRIVATE_KEY set, if bind not running as root
- Completed implementation of test_registrar_DS_submission for RIPE
- Implemented --test_registrar_DS_submission for RIPE
- New command "test_registrar_DS_submission". Moving zone_dirs and zones into misc
- New command "test_registrar_DS_submission". Moving zone_dirs and zones into misc
- Add TLS support for joker.com (required now)
- Add TLS support for joker.com (required now)
- Add config for certificate authority store, to allow for cert validation
- Converted RIPE module to REST API
- New key timing interval for rollover time, to allow for longer I_D interval (until sigs expired). Allow for changing of timing parameters while zones are active (changed applied to zones, becoming active). Adjusted default configuration. Bugfixes.
- Implemented registrar 'by hand'. DSKM/key.test_if_included: replaced axfr by query
- Make sure query timeout, FORMERR and NXDOMAIN abort zone, treat NoAnswer as missing RR. Explain config of local sub domains in README
- Removed state 6 (DS2 submitted immediately after KSK2 active) KSK2 immediately active, (no longerwaiting for KSK1 inactive)
- Bug fixes: "DS2 submit time reached" now A+ppt and "DS1 retire request" retires now the right DS
- Refactored - now a package with 6 modules - bugfixes - email interface - running as cronjob
- fixed test_if_included timestamps now with resolution of seconds. Fixed delete_a
- added 'stopSigning', 'validate', performStateTransition, fixed test_if_included to check if key used for signing
- keys being created, ds being created, local ds submitted and soa incremented and zone reloaded
- State table logic - work in progress
- reworked state diagram, based on NIST 800-81r1. clarifications and simplifications
- incorporated comments from bind-users into diagram
- State diagram for key rollover created (dnssec_key_maintenance.py)
- Initial creation of keys plus DS done.
- Initial public release.

0.9.0 (2019-03-09)
------------------

- SECURITY-FIX: replaced module pycrypto by pycryptodome
- DSKM now run as shellscript operate_dskm (installed in $prefix/bin)
- config file now called dskm_conf.py. Expected in $VIRTUAL_ENV/etc or /usr/local/etc
- Now compatible with Python 3.6
- License change: Now GPLv3.
