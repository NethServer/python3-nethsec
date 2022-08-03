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
from nextsec import utils

def get_device_name(hwaddr):
    '''
    Retrieve the physical device name given the MAC address

    Aarguments:
      hwaddr -- MAC address string

    Returns:
      The device name as a string if the network interface has been found, None otherwise.
    '''
    try:
        interfaces = json.loads(subprocess.run(["/sbin/ip", "--json", "address", "show"], check=True, capture_output=True).stdout)
        for interface in interfaces:
            if interface["address"] == hwaddr:
                return interface["ifname"]
    except:
        return None

    return None

def get_interface_name(uci, hwaddr):
    '''
    Retrieve the logical UCI interface name given the MAC address

    Arguments:
      uci -- EUci pointer
      hwaddr -- MAC address string

    Returns:
      The device name as a string if the interface has been found, None otherwise
    '''
    name = get_device_name(hwaddr)
    for section in uci.get("network"):
        if  uci.get("network", section) == "interface" and (uci.get("network", section, "device") == name):
            return section

    return None

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
