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

import pprint
import smtplib
from email.mime.text import MIMEText

# -----------------------------------------
import DSKM.conf as conf

#--------------------------
#   classes
#--------------------------

class Logger():
    """Log"""
    
    _singleton = None
    debug = False
    verbose = False
    debugText = ''
    
    def __new__(cls, *args, **kwargs):
        if not cls._singleton:
            cls._singleton = super(Logger, cls ).__new__(cls, *args, **kwargs)
        return cls._singleton
    
    
    def __init__(self, verbose=True, debug=False):
        
        Logger.debug = debug
        Logger.verbose = verbose
    
    
    def logError(self, text):
        print('?%s' % (text))
        Logger.debugText = Logger.debugText + '?' + text + '\n'
        self.sendMail('?' + text, Logger.debugText)
    
    def logWarn(self, text):
        print('%%%s' % (text))
        Logger.debugText = Logger.debugText + '%' + text + '\n'
    
    def logVerbose(self, text):
        if Logger.verbose:
            print('[%s]' % (text))
        Logger.debugText = Logger.debugText + '[' + text + ']\n'
    
    def logDebug(self, text, level=0):
        if Logger.debug:
            print('[%s]' % (text))
        Logger.debugText = Logger.debugText + '[' + str(text) + ']\n'
    
    def sendMail(self, subject, body):
        if not conf.mailRelay:
            return
        msg = MIMEText(body)
        msg['Subject'] = '[DSKM] ' + subject
        msg['From'] = conf.sender
        msg['To'] = ', '.join(conf.recipients)
        s = smtplib.SMTP(conf.mailRelay)
        s.send_message(msg)
        s.quit

