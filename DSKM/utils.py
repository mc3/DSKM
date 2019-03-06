"""
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

# -----------------------------------------
# utility module of serverPKI (commandline parsing, logging ...)
# -----------------------------------------
"""



#--------------- imported modules --------------
import optparse


#--------- globals ***DO WE NEED THIS?*** ----------

global options


#--------------- command line options --------------

parser = optparse.OptionParser(description='DSKM DNSsec Key Management\n'
                    'Do maintenace of DNSsec keys.\n'
                    'Create and delete them as necessary.\n'
                    'Submit/cancle DS-RR to/at parent registrar.')

parser.add_option('--cron', '-c', dest='cron', action='store_true',
                   default=False,
                   help='Run as cronjob. Each run increments timeout timer.')

parser.add_option('--stopSigningOfZone', '-S', action='store',
                   help=('Initiate procedure to make a zone unsigned. '
                   'Argument is zone name.'))
                   
parser.add_option('--force', '-f', action='store_true',
                   default=False,
                   help='Force deletion of keys (ignore delete time) while stopping signing of zone.'),

parser.add_option('--registrar_status', '-r', action='store_true',
                   default=False,
                   help='Query list of completed and pending requests of all registrars and terminate.'),

parser.add_option('--purge_all_registrar_completion_info', '-p', action='store_true',
                   default=False,
                   help='Purge all completion info of completed and pending requests of all registrars and terminate.'),

parser.add_option('--query_status', '-q', action='store',
                   help='Give detailed registrar result status about <request-id>.'),

parser.add_option('--test_registrar_DS_submission', '-t', action='store_true',
                   default=False,
                   help='Delete and re-submit current DS-RR to registrar.')

parser.add_option('--dry-run', '-n', dest='dry_run', action='store_true',
                   default=False,
                   help=('Do not really change any data at registrar with '
                        '--test_registrar_DS_submission.')),

parser.add_option('--debug', '-d', action='store_true',
                   default=False,
                   help='Turn on debugging.'),
parser.add_option('--verbose', '-v', dest='verbose', action='store_true',
                   default=False,
                   help='Be more verbose.')

options, args = parser.parse_args()

if options.debug: options.verbose = True


