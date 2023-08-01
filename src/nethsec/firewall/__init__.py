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
    Create an ACCEPT traffic rule for the given service

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


def add_default_forwarding(uci, name):
    '''
    Create a forwarding from ns-api default database.

    Arguments:
      uci -- EUci pointer
      name -- Name of the default forwarding from the ns-api database

    Returns a tuple:
      - The name of the configuration section for the forwarding or None in case of error
    '''

    frecord =  uci.get_all("ns-api", name)
    fname = utils.get_random_id()
    uci.set("firewall", fname, "forwarding")
    for section in frecord:
        uci.set("firewall", fname, section, frecord[section])
    uci.set("firewall", fname, "ns_tag", ["automated"])

    return fname

def add_default_zone(uci, name, networks = []):
    '''
    Create a zone from ns-api default database.

    Arguments:
      uci -- EUci pointer
      name -- Name of the default zone from the ns-api database
      network -- A list of interfaces to be added to the zone (optional)

    Returns a tuple:
      - The name of the configuration section for the zone or None in case of error
      - A list of configuration section names for the forwardings or None in case of error
    '''

    dzone = uci.get_all("ns-api", name)
    # Search for zones with the same "name"
    for zone in utils.get_all_by_type(uci, "firewall", "zone"):
        if uci.get("firewall", zone, "name") == dzone["name"]:
            return None, None

    forwardings = list()
    zname = utils.get_random_id()
    forward_list = dzone.pop("forwardings", list())
    uci.set("firewall", zname, "zone")
    for section in dzone:
        uci.set("firewall", zname, section, dzone[section])
    if len(networks) > 0:
        uci.set("firewall", zname, "network", networks)
    uci.set("firewall", zname, "ns_tag", ["automated"])

    for forward in forward_list:
        forwardings.append(add_default_forwarding(uci, forward))

    return (zname, forwardings)

def add_default_service_group(uci, name, src='lan', dest='wan'):
    '''
    Create all rules for the given service group

    Arguments:
      uci -- EUci pointer
      name -- Name of the default service group from the ns-api database
      src -- Source zone, default is 'lan'. The zone must already exists inside the firewall db
      dest -- Destination zone, default is 'wan'. The zone must already exists inside the firewall db

    Returns:
      - A list of configuration section names of each rule, None in case of error
    '''

    group = uci.get_all("ns-api", name)
    services = group.pop("services", list())

    if not services:
        return None

    rules = dict()
    sections = list()

    for service in services:
        (port, proto, sdesc) = service.split("/",2)
        if proto not in rules:
            rules[proto] = {"ports": list(), "description": ""}
        rules[proto]["ports"].append(port)
        rules[proto]["description"] = utils.sanitize(sdesc)

    for proto in rules:
        sname = utils.get_random_id()
        desc = rules[proto]["description"]
        uci.set("firewall", sname, "rule")
        uci.set("firewall", sname, "name", f"Allow-{name}-{proto}")
        uci.set("firewall", sname, "ns_description", f"{desc} - {proto}")
        uci.set("firewall", sname, "src", src)
        uci.set("firewall", sname, "dest", dest)
        uci.set("firewall", sname, "proto", proto)
        uci.set("firewall", sname, "dest_port", ",".join(rules[proto]["ports"]))
        uci.set("firewall", sname, "target", "ACCEPT")
        uci.set("firewall", sname, "enabled", "1")
        uci.set("firewall", sname, "ns_tag", ["automated"])
        sections.append(sname)

    return sections

def add_default_rule(uci, name, proto, port):
    '''
    Create a rule from ns-api default database.

    Arguments:
      uci -- EUci pointer
      name -- Name of the default rule from the ns-api database
      proto -- A valid UCI protocol
      ports -- A port or comma-separated list of ports

    Returns:
      - The name of the configuration section for the rule or None in case of error
    '''

    drule = uci.get_all("ns-api", name)
    rname = utils.get_random_id()
    uci.set("firewall", rname, "rule")
    for section in drule:
        drule[section] = drule[section].replace("__PORT__", port)
        drule[section] = drule[section].replace("__PROTO__", proto)
        uci.set("firewall", rname, section, drule[section])
    uci.set("firewall", rname, "ns_tag", ["automated"])

    return rname
