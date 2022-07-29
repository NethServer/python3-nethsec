#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

import json
import subprocess
from euci import EUci

# Retrieve the physical device name given the MAC address
def get_device_name(hwaddr):
    interfaces = json.loads(subprocess.run(["/sbin/ip", "--json", "address", "show"], check=True, capture_output=True).stdout)
    for interface in interfaces:
        if interface["address"] == hwaddr:
            return interface["ifname"]

    return None

# Retrieve the logical UCI interface name given the MAC address
def get_interface_name(uci, hwaddr):
    name = get_device_name(hwaddr)
    for section in uci.get("network"):
        if  uci.get("network", section) == "interface" and (uci.get("network", section, "device") == name):
            return section

    return None

