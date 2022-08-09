#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
General utilities
'''

import re

def get_id(name, length = 100):
    '''
    Return a valid UCI id based on the given string.
    All auto-generated NextSecurity ids:
    - have a maximum length of 100 characters
    - are sanitized accordingly to UCI conventions (see 'sanitize' function)
    - start with 'ns_' prefix

    Arguments:
      name -- the name of the section
      length -- maximum id length, default is 100. Maximum lenght for firewall zones is 15.

    Returns:
      a valid UCI identifier as string
    '''
    sname = f'ns_{sanitize(name)}'
    return sname[0:length]

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

def get_all_by_type(uci, config, utype):
    '''
    Return all section of the given utype from the given config

    Arguments:
      uci -- EUci pointer
      config -- Configuration database name
      utype -- Section type

    Returns:
      a dictionary of all matched sections, None in case of error
    '''
    ret = dict()
    try:
        for section in uci.get(config):
            if uci.get(config, section) == utype:
                ret[section] = uci.get_all(config, section)
        return ret
    except:
        return None
