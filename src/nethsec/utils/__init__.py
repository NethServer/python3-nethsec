#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
General utilities
'''

import re
import json
import uuid
import hashlib
import subprocess

def get_random_id():
    '''
    Return a random valid UCI id.

    Random ids:
      - have a length of 11 characters
      - are sanitized accordingly to UCI conventions (see 'sanitize' function)
      - start with ns\_ prefix

    Arguments:
      - name -- the name of the section

    Returns:
      - a valid UCI identifier as string
    '''

    h = hashlib.new('sha1')
    h.update(uuid.uuid4().bytes)
    digest = h.hexdigest()
    return get_id(digest, 11)

def get_id(name, length = 100):
    '''
    Return a valid UCI id based on the given string.
    All auto-generated NethSecurity ids:

      - have a maximum length of 100 characters
      - start with ns\_ prefix
      - are sanitized accordingly to UCI conventions

    Arguments:
      - name -- the name of the section
      - length -- maximum id length, default is 100. Maximum lenght for firewall zones is 15.

    Returns:
      - a valid UCI identifier as string
    '''
    sname = f'ns_{sanitize(name)}'
    return sname[0:length]

def sanitize(name):
    '''
    Replace illegal chars with _ char.
    UCI identifiers and config file names may contain only the characters a-z, 0-9 and _

    Arguments:
      - name -- the name of the section
    
    Returns:
      - a string with valid chachars for UCI
    '''
    name = re.sub(r'[^\x00-\x7F]+','_', name)
    name = re.sub('[^0-9a-zA-Z]', '_', name)
    return name

def get_all_by_type(uci, config, utype):
    '''
    Return all sections of the given utype from the given config

    Arguments:
      - uci -- EUci pointer
      - config -- Configuration database name
      - utype -- Section type

    Returns:
      - A dictionary of all matched sections, None in case of error
    '''
    ret = dict()
    try:
        for section in uci.get(config):
            if uci.get(config, section) == utype:
                ret[section] = uci.get_all(config, section)
        return ret
    except:
        return None

def get_device_name(hwaddr):
    '''
    Retrieve the physical device name given the MAC address

    Aarguments:
      - hwaddr -- MAC address string

    Returns:
      - The device name as a string if the network interface has been found, None otherwise.
    '''
    try:
        interfaces = json.loads(subprocess.run(["/sbin/ip", "--json", "address", "show"], check=True, capture_output=True).stdout)
        for interface in interfaces:
            if interface["address"] == hwaddr:
                return interface["ifname"]
    except:
        return None

    return None

def get_interface_from_mac(uci, hwaddr):
    '''
    Retrieve the logical UCI interface name given the MAC address

    Arguments:
      - uci -- EUci pointer
      - hwaddr -- MAC address string

    Returns:
      - The device name as a string if the interface has been found, None otherwise
    '''
    device = get_device_name(hwaddr)
    return get_interface_from_device(uci, device)

def get_interface_from_device(uci, device):
    '''
    Retrieve the logical UCI interface name given the device name

    Arguments:
      - uci -- EUci pointer
      - hwaddr -- MAC address string

    Returns:
      - The device name as a string if the interface has been found, None otherwise
    '''
    for section in uci.get("network"):
        if uci.get("network", section) == "interface":
            try:
                proto = uci.get("network", section, 'proto')
            except:
                continue
            if proto == 'bonding' and section == device:
                return section
            try:
                sdevice = uci.get("network", section, 'device')
            except:
                continue
            if proto != 'bonding' and device == sdevice:
                return section

    return None

def get_all_by_option(uci, config, option, value, deep = True):
    '''
    Return all sections with the given option value

    Arguments:
      - uci -- EUci pointer
      - config -- Configuration database name
      - option -- Option name
      - value -- Option value
      - deep - If true, return a dict of all matched keys, otherwise return a list of section named

    Returns:
      - A dictionary or a list of all matched sections
    '''
    ret = dict()
    for section in uci.get(config, list=True, default=[]):
        if uci.get(config, section, option, default='') == value:
            if deep:
                ret[section] = uci.get_all(config, section)
            else:
                ret[section] = 1
    if deep:
        return ret
    else:
        return list(ret.keys())


def get_all_devices_by_zone(uci, zone):
    '''
    Retrieve all devices associated to the given zone

    Arguments:
      - uci -- EUci pointer
      - zone -- Firewall zone name

    Returns:
      - A list of device names
    '''
    devices = []
    for section in uci.get("firewall"):
        if uci.get("firewall", section, default='') == 'zone' and uci.get("firewall", section, "name", default='') == zone:
            devices = devices + list(uci.get("firewall", section, "device", list=True, default=[]))
            networks = uci.get("firewall", section, "network", list=True, default=[])
            for network in networks:
               device = uci.get("network", network, "device", default="")
               if device != "":
                   devices.append(device)
               else:
                   name = uci.get("network", network, "name", default="")
                   if name != "":
                       devices.append(name)

    # remove duplicates
    return list(set(devices))

def get_all_wan_devices(uci):
    '''
    Retrieve all devices associated to the wan zone

    Arguments:
      - uci -- EUci pointer

    Returns:
      - A list of device names
    '''
    return get_all_devices_by_zone(uci, 'wan')

def get_all_lan_devices(uci):
    '''
    Retrieve all devices associated to the lan zone

    Arguments:
      - uci -- EUci pointer

    Returns:
      - A list of device names
    '''
    return get_all_devices_by_zone(uci, 'lan')

def get_user_addresses(uci, user):
    '''
    Retrieve all IP addresses associated to given user

    Arguments:
      - uci -- EUci pointer
      - user -- User object id (UCI section)

    Returns a tuple of lists:
      - first element is a list of IPv4 addresses
      - second element is a list of IPv6 addresses
    '''
    ipv4 = []
    ipv6 = []
    # get addresses from plain ipaddr option
    for ip in uci.get('objects', user, 'ipaddr', list=True, default=[]):
        if ':' in ip:
            ipv6.append(ip)
        else:
            ipv4.append(ip)
    # get vpn reservation
    for v in uci.get('objects', user, 'vpn', list=True, default=[]): # vpn reservation
        ip = uci.get('openvpn', v, 'ipaddr', default='')
        if not ip:
            continue
        if ':' in ip:
            ipv6.append(ip)
        else:
            ipv4.append(ip)
    # get address from DNS record and DHCP reservation
    for st in ['host', 'domain']:
        for h in uci.get('objects', user, st, list=True, default=[]): # dhcp reservation
            ip = uci.get('dhcp', h, 'ip', default='')
            if not ip:
                continue
            if ':' in ip:
                ipv6.append(ip)
            else:
                ipv4.append(ip)

    return (ipv4, ipv6)

def get_user_macs(uci, user):
    '''
    Retrieve all MAC addresses associated to given user

    Arguments:
      - uci -- EUci pointer
      - user -- User object id (UCI section)

    Returns:
      - A list of MAC addresses
    '''
    return list(uci.get('objects', user, 'macaddr', list=True, default=[]))

def get_group_addresses(uci, group):
    '''
    Retrieve all IP addresses associated to given group

    Arguments:
      - uci -- EUci pointer
      - user -- Group object id (UCI section)

    Returns:
      - A tuple of lists:
        - first element is a list of IPv4 addresses
        - second element is a list of IPv6 addresses
    '''
    ipv4 = []
    ipv6 = []
    for u in uci.get('objects', group, 'user', list=True, default=[]):
        (uipv4, uipv6) = get_user_addresses(uci, u)
        ipv4 = ipv4 + uipv4
        ipv6 = ipv6 + uipv6
    return (ipv4, ipv6)

def get_group_macs(uci, group):
    '''
    Retrieve all MAC addresses associated to given user

    Arguments:
      - uci -- EUci pointer
      - group -- Group object id (UCI section)

    Returns:
      - A list of MAC addresses
    '''
    macs = []
    for u in uci.get('objects', group, 'user', list=True, default=[]):
        macs = macs + get_user_macs(uci, u)
    return macs
