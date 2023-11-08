#!/usr/bin/python3

#
# Copyright (C) 2022 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
Firewall utilities
'''
import subprocess

from nethsec import utils


def add_device_to_zone(uci, device, zone):
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

def add_interface_to_zone(uci, interface, zone):
    '''
    Add given interface to a firewall zone.
    The interface is not added if the firewall zone does not exists
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - interface -- Interface name
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
                    networks = list(uci.get_all("firewall", section, "network"))
                except:
                    networks = []
                if not interface in networks:
                    networks.append(interface)
                    uci.set("firewall", section, "network", networks)
                    uci.save("firewall")
                return section

    return None


def remove_interface_from_zone(uci, interface, zone):
    '''
    Remove the given interface from a firewall zone.
    The operation always succeed if the zone does not exists

    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - interface -- Interface name
      - zone -- Firewall zone name

    Returns:
      - If the firewall zone exists, the name of the section where the interface has been removed.
      - None, otherwise.
    '''
 
    for z in utils.get_all_by_type(uci, 'firewall', 'zone'):
        if uci.get('firewall', z, 'name') == zone:
            try:
                networks = list(uci.get_all("firewall", z, "network"))
            except:
                networks = []
            if interface in networks:
                networks.remove(interface)
                uci.set("firewall", z, "network", networks)
                uci.save("firewall")
                return z
    return None

def remove_device_from_zone(uci, device, zone):
    '''
    Remove the given device from a firewall zone.
    The operation always succeed if the zone does not exists

    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - device -- Device name
      - zone -- Firewall zone name

    Returns:
      - If the firewall zone exists, the name of the section where the device has been removed.
      - None, otherwise.
    '''
 
    for z in utils.get_all_by_type(uci, 'firewall', 'zone'):
        if uci.get('firewall', z, 'name') == zone:
            try:
                devices = list(uci.get_all("firewall", z, "device"))
            except:
                devices = []
            if device in devices:
                devices.remove(device)
                uci.set("firewall", z, "device", devices)
                uci.save("firewall")
                return z
    return None

def add_device_to_lan(uci, device):
    '''
    Shortuct to add a device to lan zone

    Arguments:
      - uci -- EUci pointer
      - device -- Device name

    Returns:
      - The name of section or None
    '''
    return add_device_to_zone(uci, device, 'lan')

def add_device_to_wan(uci, device):
    '''
    Shortuct to add a device to wan zone

    Arguments:
      - uci -- EUci pointer
      - device -- Device name

    Returns:
      - The name of the configuration section or None
    '''
    return add_device_to_zone(uci, device, 'wan')

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

def add_template_zone(uci, name, networks = [], link = ""):
    '''
    Create a zone from templates database.
    Changes are saved to staging area.

    Arguments:
      - uci -- EUci pointer
      - name -- Name of the zone from the templates database
      - network -- A list of interfaces to be added to the zone (optional)
      - link -- A reference to an existing key in the format <database>/<keyname> (optional)

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
    if link:
        uci.set("firewall", zname, "ns_link", link)

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
            if option.startswith("ip6") or option == "dhcpv6" or option == "ipv6":
                return True
        if uci.get('network', interface, 'proto', default="") in ['6in4', '6to4', '6rd', 'grev6', 'grev6tap', 'vtiv6']:
            return True

    for device in utils.get_all_by_type(uci, 'network', 'device'):
        try:
            if uci.get_all('network', device, 'ipv6') == 1:
                return True
        except:
            pass
    return False

def disable_ipv6_firewall(uci):
    '''
    Disable all rules, forwardings, redirects, zones and ipsets for ipv6-only family.
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


def list_zones(uci) -> dict:
    """
    Get all zones from firewall config

    Args:
        uci: EUci pointer

    Returns:
        dict with all zones
    """
    return utils.get_all_by_type(uci, 'firewall', 'zone')


def list_forwardings(uci) -> dict:
    """
    Get all forwardings from firewall config

    Args:
        uci: EUci pointer

    Returns:
        dict with all forwardings
    """
    return utils.get_all_by_type(uci, 'firewall', 'forwarding')


def add_forwarding(uci, src: str, dest: str) -> str:
    """
    Add forwarding from src to dest.

    Args:
        uci: EUci pointer
        src: source zone, must be zone name, not config name
        dest: destination zone, must be zone name, not config name

    Returns:
        name of forwarding config that was added
    """
    config_name = utils.get_id(f'{src}2{dest}')
    uci.set('firewall', config_name, 'forwarding')
    uci.set('firewall', config_name, 'src', src)
    uci.set('firewall', config_name, 'dest', dest)
    uci.save('firewall')
    return config_name


def zone_exists(u, zone_name):
    """
    Check if a zone with name zone_name already exists

    Args:
        u: EUci pointer
        zone_name: zone name to check

    Returns:
        true if a zone with name zone_name already exists, false otherwise
    """
    try:
        for h in utils.get_all_by_type(u, 'firewall', 'zone'):
            if u.get('firewall', h, 'name', default='') == zone_name:
                return True
    except:
        return False

    return False


def add_zone(uci, name: str, input: str, forward: str, traffic_to_wan: bool = False, forwards_to: list[str] = None,
             forwards_from: list[str] = None) -> {str, set[str]}:
    """
    Add zone to firewall config.

    Args:
        uci: EUci pointer
        name: name of zone
        input: rule for input traffic, must be one of 'ACCEPT', 'REJECT', 'DROP'
        forward: rule for forward traffic, must be one of 'ACCEPT', 'REJECT', 'DROP'
        traffic_to_wan: if True, add forwarding from zone to wan
        forwards_to: list of zones to forward traffic to
        forwards_from: list of zones to forward traffic from

    Returns:
        tuple of zone config name and set of added forwarding configs
    """

    # check if a zone with the same name already exists
    if zone_exists(uci, name):
        return utils.validation_error("name", "zone_already_exists", name)

    zone_config_name = utils.get_id(name)
    uci.set('firewall', zone_config_name, 'zone')
    uci.set('firewall', zone_config_name, 'name', name)
    uci.set('firewall', zone_config_name, 'input', input)
    uci.set('firewall', zone_config_name, 'forward', forward)
    uci.set('firewall', zone_config_name, 'output', 'ACCEPT')

    forwardings_added = set()

    if traffic_to_wan:
        forwardings_added.add(add_forwarding(uci, name, 'wan'))

    if forwards_to is not None:
        for forward_to in forwards_to:
            forwardings_added.add(add_forwarding(uci, name, forward_to))

    if forwards_from is not None:
        for forward_from in forwards_from:
            forwardings_added.add(add_forwarding(uci, forward_from, name))

    uci.save('firewall')
    return zone_config_name, forwardings_added


def edit_zone(uci, name: str, input: str, forward: str, traffic_to_wan: bool = False, forwards_to: list[str] = None,
             forwards_from: list[str] = None) -> {str, set[str]}:
    """
    Add zone to firewall config.

    Args:
        uci: EUci pointer
        name: name of zone to edit
        input: rule for input traffic, must be one of 'ACCEPT', 'REJECT', 'DROP'
        forward: rule for forward traffic, must be one of 'ACCEPT', 'REJECT', 'DROP'
        traffic_to_wan: if True, add forwarding from zone to wan
        forwards_to: list of zones to forward traffic to
        forwards_from: list of zones to forward traffic from

    Returns:
        tuple of zone config name and set of updated forwarding configs
    """
    zone_config_name = utils.get_id(name)
    uci.set('firewall', zone_config_name, 'input', input)
    uci.set('firewall', zone_config_name, 'forward', forward)
    uci.set('firewall', zone_config_name, 'output', 'ACCEPT')

    # delete old forwardings

    forwardings = list_forwardings(uci)
    to_delete_forwardings = set()
    for forwarding in forwardings:
        if forwardings[forwarding]['src'] == name:
            to_delete_forwardings.add(forwarding)
        if forwardings[forwarding]['dest'] == name:
            to_delete_forwardings.add(forwarding)

    for to_delete_forwarding in to_delete_forwardings:
        uci.delete('firewall', to_delete_forwarding)

    # create updated forwardings

    forwardings_added = set()

    if traffic_to_wan:
        forwardings_added.add(add_forwarding(uci, name, 'wan'))

    if forwards_to is not None:
        for forward_to in forwards_to:
            forwardings_added.add(add_forwarding(uci, name, forward_to))

    if forwards_from is not None:
        for forward_from in forwards_from:
            forwardings_added.add(add_forwarding(uci, forward_from, name))

    uci.save('firewall')
    return zone_config_name, forwardings_added


def delete_zone(uci, zone_config_name: str) -> {str, set[str]}:
    """
    Delete zone and all forwardings that are connected to it.

    Args:
        uci: EUci pointer
        zone_config_name: name of zone config to delete

    Returns:
        tuple of zone config name and set of deleted forwarding configs

    Raises:
        ValueError: if zone_config_name is not a valid zone config name
    """
    if zone_config_name not in list_zones(uci):
        raise ValueError
    zone_name = list_zones(uci)[zone_config_name]['name']
    forwardings = list_forwardings(uci)
    to_delete_forwardings = set()
    for forwarding in forwardings:
        if forwardings[forwarding]['src'] == zone_name:
            to_delete_forwardings.add(forwarding)
        if forwardings[forwarding]['dest'] == zone_name:
            to_delete_forwardings.add(forwarding)

    for to_delete_forwarding in to_delete_forwardings:
        uci.delete('firewall', to_delete_forwarding)

    uci.delete('firewall', zone_config_name)
    uci.save('firewall')
    return zone_config_name, to_delete_forwardings
