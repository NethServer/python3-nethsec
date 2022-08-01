#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
General utilities
'''

import re

def sanitize(name):
    '''
    Replace illegal chars with _ char.
    UCI identifiers and config file names may contain only the characters a-z, 0-9 and _
    '''
    name = re.sub(r'[^\x00-\x7F]+','_', name)
    name = re.sub('[^0-9a-zA-Z]', '_', name)
    return name
