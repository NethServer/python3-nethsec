#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
IPSec utilities
'''

import os
from nethsec import utils

IPSEC_ZONE='ipsec'

def init_ipsec(uci):
    '''
    Initialize IPSec global configuration, if needed.

    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
    '''
    # Make sure the config file exists
    conf = os.path.join(uci.confdir(), 'ipsec')
    if not os.path.isfile(conf):
        with open(conf, 'a'):
            pass

        # Setup global options
        gsettings = utils.get_id("ipsec_global")
        uci.set("ipsec", gsettings, IPSEC_ZONE)
        uci.set("ipsec", gsettings, "debug", '0')
        uci.set("ipsec", gsettings, "zone", 'ipsec')
        uci.set("ipsec", gsettings, "interface", ['wan'])
        uci.commit('ipsec')
