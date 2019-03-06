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
logger.py - Logger class module - centraliced logging and alarming
"""

import pprint
import smtplib
from email.mime.text import MIMEText

# -----------------------------------------
import DSKM.config as conf

#--------------------------
#   classes
#--------------------------

class Logger():
    """Log"""
    
    _singleton = None
    debug = False
    verbose = False
    cron = False
    debugText = ''
    verboseText = ''
    lastError = ''
    lastWarning = ''
    
    def __new__(cls, *args, **kwargs):
        if not cls._singleton:
            cls._singleton = super(Logger, cls ).__new__(cls, *args, **kwargs)
        return cls._singleton
    
    
    def __init__(self, verbose=True, debug=False, cron=False):
        
        Logger.debug = debug
        Logger.verbose = verbose
        Logger.cron = cron    
    
    def logError(self, text):           # Fatal error
        Logger.lastError = '?%s' % (text)
        print(Logger.lastError)
        Logger.debugText = Logger.debugText + Logger.lastError + '\n'

    
    def logWarn(self, text):            # Warning
        Logger.lastWarning = '%%%s' % (text)
        print(Logger.lastWarning)
        Logger.verboseText = Logger.verboseText + Logger.lastWarning + '\n'
        Logger.debugText = Logger.debugText + Logger.lastWarning + '\n'
    
    def logVerbose(self, text):
        im = '[%s]' % (text)            # informal message
        if Logger.verbose:
            print(im)
        Logger.verboseText = Logger.verboseText + im + '\n'
        Logger.debugText = Logger.debugText + im + '\n'
    
    def logDebug(self, text, level=0):
        dm = '[%s]' % (text)            # debug message
        if Logger.debug:
            print(dm)
        Logger.debugText = Logger.debugText + dm + '\n'
    
    def mailErrors(self):               # called by main on exit
        if len(Logger.lastError) > 0:
            self.sendMail(Logger.lastError, Logger.debugText, True)
        elif len(Logger.lastWarning) > 0:
            self.sendMail(Logger.lastWarning, Logger.verboseText, True)
        

    def sendMail(self, subject, body, onlyCron=False):
        if not conf.mailRelay:           # done, if not configured
            return
        if onlyCron and not Logger.cron: # mail only if cronjob, if so requested
            return
        msg = MIMEText(body)
        msg['Subject'] = '[DSKM] ' + subject
        msg['From'] = conf.sender
        msg['To'] = ', '.join(conf.recipients)
        s = smtplib.SMTP(conf.mailRelay)
        s.send_message(msg)
        s.quit
    
    def cronjob(self):
        return Logger.cron
