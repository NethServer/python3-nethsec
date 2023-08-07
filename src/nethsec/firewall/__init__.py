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
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - device -- Device name
      - zone -- Firewall zone name

    Returns:
      - If the firewall zone exists, the name of the section where the device has been added.
      - None, otherwise.
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
                    uci.save("firewall")
                return section

    return None

def add_to_lan(uci, device):
    '''
    Shortuct to add a device to lan zone

    Arguments:
      - uci -- EUci pointer
      - device -- Device name

    Returns:
      - The name of section or None
    '''
    return add_to_zone(uci, device, 'lan')

def add_to_wan(uci, device):
    '''
    Shortuct to add a device to wan zone

    Arguments:
      - uci -- EUci pointer
      - device -- Device name

    Returns:
      - The name of the configuration section or None
    '''
    return add_to_zone(uci, device, 'wan')

def add_vpn_interface(uci, name, device, link=""):
    '''
    Create a network interface for the given device.
    The interface can be used for PBR (Policy Based Routing).
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Interface name
      - device -- Device name
      - link -- A reference to an existing key in the format <database>/<keyname> (optional)

    Returns:
      - The name of the configuration section or None in case of error
    '''
    iname = utils.sanitize(name)
    uci.set('network', iname, 'interface')
    uci.set('network', iname, 'proto', 'none')
    uci.set('network', iname, 'device', device)
    uci.set('network', iname, 'ns_tag', ["automated"])
    if link:
        uci.set('network', iname, 'ns_link', link)
    uci.save('network')
    return iname

def add_trusted_zone(uci, name, networks = [], link = ""):
    '''
    Create a trusted zone. The zone will:
      - be able to access lan and wan zone
      - be accessible from lan zone
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Zone name, maximum length is 12
      - network -- A list of interfaces to be added to the zone (optional)
      - link -- A reference to an existing key in the format <database>/<keyname> (optional)

    Returns a tuple:
      - The name of the configuration section or None in case of error
      - A list of configuration sections or an empy list in case of error
    '''

    if len(name) > 12:
        return None, None

    forwardings = list()
    zname = utils.get_random_id()
    name = utils.sanitize(name)
    uci.set("firewall", zname, 'zone')
    uci.set("firewall", zname, 'name', name)
    uci.set("firewall", zname, 'input', 'ACCEPT')
    uci.set("firewall", zname, 'output', 'ACCEPT')
    uci.set("firewall", zname, 'forward', 'REJECT')
    if networks:
        uci.set("firewall", zname, 'network', networks)
    uci.set("firewall", zname, "ns_tag", ["automated"])
    if link:
        uci.set("firewall", zname, "ns_link", link)

    flan = utils.get_random_id()
    uci.set("firewall", flan, "forwarding")
    uci.set("firewall", flan, "src", name)
    uci.set("firewall", flan, "dest", "lan")
    uci.set("firewall", flan, "ns_tag", ["automated"])
    if link:
        uci.set("firewall", flan, "ns_link", link)
    forwardings.append(flan)

    flan = utils.get_random_id()
    uci.set("firewall", flan, "forwarding")
    uci.set("firewall", flan, "src", "lan")
    uci.set("firewall", flan, "dest", name)
    uci.set("firewall", flan, "ns_tag", ["automated"])
    if link:
        uci.set("firewall", flan, "ns_link", link)
    forwardings.append(flan)

    flan = utils.get_random_id()
    uci.set("firewall", flan, "forwarding")
    uci.set("firewall", flan, "src", name)
    uci.set("firewall", flan, "dest", "wan")
    uci.set("firewall", flan, "ns_tag", ["automated"])
    if link:
        uci.set("firewall", flan, "ns_link", link)
    forwardings.append(flan)

    uci.save("firewall")
    return zname, forwardings

def add_service(uci, name, port, proto, link = ""):
    '''
    Create an ACCEPT traffic rule for the given service
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Service name
      - port -- Service port number as string
      - proto -- List of service protocols
      - link -- A reference to an existing key in the format <database>/<keyname> (optional)

    Returns:
      - The name of the configuration section
    '''
    rname = utils.get_id(f"allow_{name}")
    uci.set("firewall", rname, "rule")
    uci.set("firewall", rname, "name", f"Allow-{name}")
    uci.set("firewall", rname, "src", "wan")
    uci.set("firewall", rname, "dest_port", port)
    uci.set("firewall", rname, "proto", proto)
    uci.set("firewall", rname, "target", "ACCEPT")
    uci.set("firewall", rname, "enabled", "1")
    uci.set("firewall", rname, "ns_tag", ["automated"])
    if link:
        uci.set("firewall", rname, "ns_link", link)
    uci.save("firewall")
    return rname

def remove_service(uci, name):
    '''
    Remove the ACCEPT traffic rule for the given service
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Service name

    Returns:
      - The name of the configuration section
    '''
    rname = utils.get_id(f"allow_{name}")
    uci.delete("firewall", rname)
    uci.save("firewall")
    return rname

def disable_service(uci, name):
    '''
    Disable the ACCEPT rule traffic for the given service.
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Service name

    Returns:
      - The name of the configuration section if found, None otherwise
    '''
    rname = utils.get_id(f"allow_{name}")
    try:
        uci.set("firewall", rname, "enabled", "0")
    except:
        return None
    uci.save("firewall")
    return rname

def enable_service(uci, name):
    '''
    Disable the ACCEPT rule traffic for the given service
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Service name

    Returns:
      - The name of the configuration section if found, None otherwise
    '''
    rname = utils.get_id(f"allow_{name}")
    try:
        uci.set("firewall", rname, "enabled", "0")
    except:
        return None
    uci.save("firewall")
    return rname

def apply(uci):
    '''
    Apply firewall configuration:
      - commit changes to firewall config
      - reload the firewall service

    Arguments:
      - uci -- EUci pointer
    '''
    uci.commit('firewall')
    subprocess.run(["/etc/init.d/firewall", "reload"], check=True)


def add_template_forwarding(uci, name):
    '''
    Create a forwarding from templates database.
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Name of the template forwarding from the templates database

    Returns a tuple:
      - The name of the configuration section for the forwarding or None in case of error
    '''

    frecord =  uci.get_all("templates", name)
    fname = utils.get_random_id()
    uci.set("firewall", fname, "forwarding")
    for section in frecord:
        uci.set("firewall", fname, section, frecord[section])
    uci.set("firewall", fname, "ns_tag", ["automated"])

    uci.save("firewall")
    return fname

def add_template_zone(uci, name, networks = []):
    '''
    Create a zone from templates database.
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Name of the zone from the templates database
      - network -- A list of interfaces to be added to the zone (optional)

    Returns a tuple:
      - The name of the configuration section for the zone or None in case of error
      - A list of configuration section names for the forwardings or None in case of error
    '''

    dzone = uci.get_all("templates", name)
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
        forwardings.append(add_template_forwarding(uci, forward))

    uci.save("firewall")
    return (zname, forwardings)

def add_template_service_group(uci, name, src='lan', dest='wan', link=""):
    '''
    Create all rules for the given service group
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Name of the service group from the templates database
      - src -- Source zone, default is 'lan'. The zone must already exists inside the firewall db
      - dest -- Destination zone, default is 'wan'. The zone must already exists inside the firewall db
      - link -- A reference to an existing key in the format <database>/<keyname> (optional)

    Returns:
      - A list of configuration section names of each rule, None in case of error
    '''

    group = uci.get_all("templates", name)
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
        if link:
            uci.set("firewall", sname, "ns_link", link)
        sections.append(sname)

    uci.save("firewall")
    return sections

def add_template_rule(uci, name, proto="", port="", link=""):
    '''
    Create a rule from templates database.
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Name of the template rule from the templates database
      - proto -- A valid UCI protocol (optional)
      - port -- A port or comma-separated list of ports (optional)
      - link -- A reference to an existing key in the format <database>/<keyname> (optional)

    Returns:
      - The name of the configuration section for the rule or None in case of error
    '''

    drule = uci.get_all("templates", name)
    rname = utils.get_random_id()
    uci.set("firewall", rname, "rule")
    for section in drule:
        if port:
            drule[section] = drule[section].replace("__PORT__", port)
        if proto:
            drule[section] = drule[section].replace("__PROTO__", proto)
        uci.set("firewall", rname, section, drule[section])
    uci.set("firewall", rname, "ns_tag", ["automated"])
    if link:
        uci.set("firewall", rname, "ns_link", link)

    uci.save("firewall")
    return rname

def get_all_linked(uci, link):
    '''
    Search all database, execpt templates one, for entities with the given link

    Arguments:
      - uci -- EUci pointer
      - link -- A reference to an existing key in the format <database>/<keyname>

    Returns:
      - A dictionary of all matched sections like
        {"db1": ["key1", "key2"], "db2": [...] }
    '''

    ret = dict()
    for config in uci.list_configs():
        if config == "templates":
            continue
        records = utils.get_all_by_option(uci, config, 'ns_link', link, deep = False)
        ret[config] = records

    return ret

def disable_linked_rules(uci, link):
    '''
    Disable all rules matching the given link
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - link -- A reference to an existing key in the format <database>/<keyname>

    Returns:
      - A list of disabled sections
    '''

    disabled = list()
    linked = get_all_linked(uci, link)
    if "firewall" in linked:
        for section in linked["firewall"]:
            if uci.get("firewall", section) == "rule":
                uci.set("firewall", section, "enabled", 0)
                disabled.append(section)

    uci.save("firewall")
    return disabled

def delete_linked_sections(uci, link):
    '''
    Delete all sections matching the given link.
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - link -- A reference to an existing key in the format <database>/<keyname>

    Returns:
      - A list of deleted sections
    '''

    deleted = list()
    linked = get_all_linked(uci, link)
    for db in linked:
        for section in linked[db]:
            uci.delete(db, section)
            deleted.append(section)
        uci.save(db)

    return deleted

def is_ipv6_enabled(uci):
    '''
    Search the network database for devices and interfaces using IPv6

    Arguments:
      - uci -- EUci pointer

    Returns:
      - True if IPv6 is enabled at least on a device or interface, False otherwise
    '''

    for interface in utils.get_all_by_type(uci, 'network', 'interface'):
        for option in uci.get_all('network', interface):
            if option.startswith("ip6") or option == "dhcpv6":
                return True
        if uci.get('network', interface, 'proto', default="") in ['6in4', '6to4', '6rd', 'grev6', 'grev6tap', 'vtiv6']:
            return True

    for device in utils.get_all_by_type(uci, 'network', 'device'):
        if uci.get_all('network', device, 'ipv6') == 1:
            return True
    return False

def disable_ipv6_firewall(uci):
    '''
    Disable all rules, forwarings, redirects, zones and ipsets for ipv6-only family
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer

    Returns:
      - A list of disabled sections
    '''

    disabled = list()
    for section_type in ["rule", "forwarding", "redirect", "zone", "ipset"]:
        for section in utils.get_all_by_type(uci, 'firewall', section_type):
            if uci.get("firewall", section, 'family', default="any") == "ipv6":
                uci.set("firewall", section, "enabled", "0")
                disabled.append(section)

    uci.save("firewall")
    return disabled
