#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
Firewall utilities
'''

import json
import subprocess
from nethsec import utils

def add_to_zone(uci, device, zone):
    '''
    Add given device to a firewall zone.
    The device is not added if the firewall zone does not exists

    Arguments:
      uci -- EUci pointer
      device -- Device name
      zone -- Firewall zone name

    Returns:
      If the firewall zone exists, the name of the section where the device has been added.
      None, otherwise.
    '''
    for section in uci.get("firewall"):
        s_type = uci.get("firewall", section)
        if s_type == "zone":
            zname = uci.get("firewall", section, "name")
            if zname == zone:
                try:
                    devices = list(uci.get_all("firewall", section, "device"))
                except:
                    devices = []
                if not device in devices:
                    devices.append(device)
                    uci.set("firewall", section, "device", devices)
                return section

    return None

def add_to_lan(uci, device):
    '''
    Shortuct to add a device to lan zone

    Arguments:
      uci -- EUci pointer
      device -- Device name

    Returns:
      The name of section or None
    '''
    return add_to_zone(uci, device, 'lan')

def add_to_wan(uci, device):
    '''
    Shortuct to add a device to wan zone

    Arguments:
      uci -- EUci pointer
      device -- Device name

    Returns:
      The name of the configuration section or None
    '''
    return add_to_zone(uci, device, 'wan')

def add_vpn_interface(uci, name, device):
    '''
    Create a network interface for the given device.
    The interface can be used for PBR (Policy Based Routing).
    This function automatically commits the network database.

    Arguments:
      uci -- EUci pointer
      name -- Interface name
      device -- Device name

    Returns:
      The name of the configuration section or None in case of error
    '''
    iname = utils.get_id(name)
    uci.set('network', iname, 'interface')
    uci.set('network', iname, 'proto', 'none')
    uci.set('network', iname, 'device', device)
    uci.commit('network')
    return iname

def add_trusted_zone(uci, name, networks = []):
    '''
    Create a trusted zone. The zone will:
    - be able to access lan and wan zone
    - be accessible from lan zone

    Arguments:
      uci -- EUci pointer
      name -- Zone name, maximum length is 12
      network -- A list of interfaces to be added to the zone (optional)

    Returns:
      The name of the configuration section or None in case of error
    '''

    if len(name) > 12:
        return None

    zname = utils.get_id(name)
    name = utils.sanitize(name)
    uci.set("firewall", zname, 'zone')
    uci.set("firewall", zname, 'name', name)
    uci.set("firewall", zname, 'input', 'ACCEPT')
    uci.set("firewall", zname, 'output', 'ACCEPT')
    uci.set("firewall", zname, 'forward', 'REJECT')
    if networks:
        uci.set("firewall", zname, 'network', networks)

    flan = f"{zname}2lan"
    uci.set("firewall", flan, "forwarding")
    uci.set("firewall", flan, "src", name)
    uci.set("firewall", flan, "dest", "lan")

    flan = f"lan2{zname}"
    uci.set("firewall", flan, "forwarding")
    uci.set("firewall", flan, "src", "lan")
    uci.set("firewall", flan, "dest", name)

    flan = f"{zname}2wan"
    uci.set("firewall", flan, "forwarding")
    uci.set("firewall", flan, "src", name)
    uci.set("firewall", flan, "dest", "wan")

    return zname

def add_service(uci, name, port, proto):
    '''
    Create an ACCEPT traffic rile for the given service

    Arguments:
      uci -- EUci pointer
      name -- Service name
      port -- Service port number as string
      proto -- List of service protocols

    Returns:
      The name of the configuration section
    '''
    rname = utils.get_id(f"allow_{name}")
    uci.set("firewall", rname, "rule")
    uci.set("firewall", rname, "name", f"Allow-{name}")
    uci.set("firewall", rname, "src", "wan")
    uci.set("firewall", rname, "dest_port", port)
    uci.set("firewall", rname, "proto", proto)
    uci.set("firewall", rname, "target", "ACCEPT")
    uci.set("firewall", rname, "enabled", "1")
    return rname

def remove_service(uci, name):
    '''
    Remove the ACCEPT traffic rule for the given service

    Arguments:
      uci -- EUci pointer
      name -- Service name

    Returns:
      The name of the configuration section
    '''
    rname = utils.get_id(f"allow_{name}")
    uci.delete("firewall", rname)
    return rname

def disable_service(uci, name):
    '''
    Disable the ACCEPT rule traffic for the given service.

    Arguments:
      uci -- EUci pointer
      name -- Service name

    Returns:
      The name of the configuration section if found, None otherwise
    '''
    rname = utils.get_id(f"allow_{name}")
    try:
        uci.set("firewall", rname, "enabled", "0")
    except:
        return None
    return rname

def enable_service(uci, name):
    '''
    Disable the ACCEPT rule traffic for the given service

    Arguments:
      uci -- EUci pointer
      name -- Service name

    Returns:
      The name of the configuration section if found, None otherwise
    '''
    rname = utils.get_id(f"allow_{name}")
    try:
        uci.set("firewall", rname, "enabled", "0")
    except:
        return None
    return rname

def apply(uci):
    '''
    Apply firewall configuration:
    - commit changes to firewall config
    - reload the firewall service

    Arguments:
      uci -- EUci pointer
    '''
    uci.commit('firewall')
    subprocess.run(["/etc/init.d/firewall", "reload"], check=True)
