#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
General utilities
'''

import re

def get_id(name):
    '''
    Return a valid UCI id based on the given string.
    All auto-generated NextSecurity ids:
    - have a maximum length of 15 characters
    - are sanitized accordingly to UCI conventions (see 'sanitize' function)
    - start with 'ns_' prefix

    Arguments:
      name -- the name of the section

    Returns:
      a valid UCI identifier as string
    '''
    sname = f'ns_{sanitize(name)}'
    return sname[0:15]

def sanitize(name):
    '''
    Replace illegal chars with _ char.
    UCI identifiers and config file names may contain only the characters a-z, 0-9 and _

    Arguments:
      name -- the name of the section
    
    Returns:
      a string with valid chachars for UCI
    '''
    name = re.sub(r'[^\x00-\x7F]+','_', name)
    name = re.sub('[^0-9a-zA-Z]', '_', name)
    return name
