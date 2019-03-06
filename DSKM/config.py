"""
Copyright (C) 2015-2017  Axel Rau <axel.rau@chaos1.de>

This file is part of serverPKI.

serverPKI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Foobar is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with serverPKI.  If not, see <http://www.gnu.org/licenses/>.
"""


# Module to make config settings available to members of package

import sys

# name of our config module
CONFIG_MODULE = 'config'

# place where to find it (sys.prefix point at venve if we are in a venv)
CONFIG_MODULE_DIRS =(   sys.prefix + '/etc',
                        '/usr/local/etc/DSKM')

sys.path.append(CONFIG_MODULE_DIRS[0])
sys.path.append(CONFIG_MODULE_DIRS[1])

from dskm_conf import *
