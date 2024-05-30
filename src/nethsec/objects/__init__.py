#!/usr/bin/python3

#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
Objects utilities
'''
import ipaddress
import json
import os
import subprocess

from euci import EUci

from nethsec import utils, firewall

# Generic

def is_object_id(id):
    """
    Check if an id is an object id.

    Args:
        id: id to check

    Returns:
        True if id is an object id, False otherwise
    """
    return id.startswith('objects/') or id.startswith('dhcp/') or id.startswith('users/')

def object_exists(uci, database_id):
    """
    Check if the object exists.

    Args:
        database_id: id to check in the form of `<database>/<id>`
    
    Returns:
        True if object exists, False otherwise
    """
    try:
        database, id = database_id.split('/')
        uci.get(database, id)
        return True
    except:
        return False

def get_object(uci, database_id):
    """
    Get object from objects config.

    Args:
        uci: EUci pointer
        id: id of the object in the form of `<database>/<id>`

    Returns:
        object from config or None if not found
    """
    try:
        database, id = database_id.split('/')
        return uci.get_all(database, id)
    except:
        return None

def is_used_object(uci, database_id):
    """
    Check if an object is used in:
     - firewall config
     - mwan3 config
     - dpi config

    Args:
        uci: EUci pointer
        id: id of the object in the form of `<database>/<id>`

    Returns:
        A tuple with:
        - True if domain set is used in firewall config, False otherwise
        - a list of firewall sections where domain set is used
    """
    matches = []
    for section in uci.get_all("firewall"):
        if uci.get('firewall', section, 'ns_src', default=None) == database_id or uci.get('firewall', section, 'ns_dst', default=None) == database_id:
            matches.append(f'firewall/{section}')
    for section in uci.get_all("mwan3"):
        if uci.get('mwan3', section, 'ns_src', default=None) == database_id or uci.get('mwan3', section, 'ns_dst', default=None) == database_id:
            matches.append(f'mwan3/{section}')
    for section in uci.get_all("dpi"):
        if uci.get('dpi', section, 'source', default=None) == database_id:
            matches.append(f'dpi/{section}')
    return len(matches) > 0, matches

def get_object_ips(uci, database_id):
    """
    Get all IP addresses from an object.

    Args:
        uci: EUci pointer
        id: id of the object in the form of `<database>/<id>`

    Returns:
        a list of unique IP addresses from the object
    """
    ips = []

    obj = get_object(uci, database_id)
    database, id = database_id.split('/')

    if not obj:
        return ips
    
    if database == 'dhcp':
        ip = obj.get('ip')
        if ip:
            ips.append(ip)
    elif database == 'users':
        openvpn_ipaddr = obj.get('openvpn_ipaddr')
        if openvpn_ipaddr:
            ips.append(openvpn_ipaddr)
    elif database == 'objects':
        ipaddr = obj.get('ipaddr')
        if ipaddr:
            for ip in ipaddr:
                if is_object_id(ip):
                    ips.extend(get_object_ips(uci, ip))
                else:
                    ips.append(ip)
    
    return list(set(ips))  # Convert the list to a set to remove duplicates, then convert it back to a list

def get_object_ip(uci, database_id):
    """
    Get the first IP address from an object.

    Args:
        uci: EUci pointer
        id: id of the object in the form of `<database>/<id>`

    Returns:
        the first IP address from the object
    """
    ips = get_object_ips(uci, database_id)
    if ips:
        return ips[0]
    return None

# Domain set

def is_domain_set(uci, database_id):
    """
    Check if an object is a domain set.

    Args:
        uci: EUci pointer
        id: id of the object in the form of `<database>/<id>`

    Returns:
        True if object is a domain set, False otherwise
    """
    try:
        database, id = database_id.split('/')
        obj_type = uci.get(database, id)
        return database =="objects" and obj_type == "domain"
    except:
        return False

def is_used_domain_set(uci, id):
    """
    Check if domain set is used in firewall config.

    Args:
        uci: EUci pointer
        id: id of domain set

    Returns:
        A tuple with:
        - True if domain set is used in firewall config, False otherwise
        - a list of firewall sections where domain set is used
    """
    return is_used_object(uci, f'objects/{id}')

def get_domain_set_ipsets(uci, id):
    """
    Get ipsets linked to domain set.

    Args:
        uci: EUci pointer
        id: id of domain set

    Returns:
        a dictionary with
        - `firewall`: the ipset id linked to domain set from firewall config
        - `dhcp`: the ipset id linked to domain set from dhcp config
    """
    ipsets = {"firewall": None, "dhcp": None}
    for section in utils.get_all_by_type(uci, "firewall", "ipset"):
        if uci.get('firewall', section, 'ns_link', default=None) == f'objects/{id}':
            ipsets["firewall"] = section
            break
    for section in utils.get_all_by_type(uci, "dhcp", "ipset"):
        if uci.get('dhcp', section, 'ns_link', default=None) == f'objects/{id}':
            ipsets["dhcp"] = section
            break
    return ipsets

def add_domain_set(uci, name: str, family: str, domains: list[str], timeout: int = 600) -> str:
    """
    Add domain set to objects config.

    Args:
        uci: EUci pointer
        name: name of domain set
        family: can be `ipv4` or `ipv6`
        domains: a list of valid DNS names
        timeout: the timeout in seconds for the DNS resolution, default is `600` seconds

    Returns:
        id of domain set config that was added
    """
    if len(name) > 16:
        raise utils.ValidationError('name', 'name_too_long', name)
    # check name contains only number and letters
    if not name.isalnum():
        raise utils.ValidationError('name', 'invalid_name', name)
    if family not in ['ipv4', 'ipv6']:
        raise utils.ValidationError('family', 'invalid_family', family)
    if timeout < 0:
        raise utils.ValidationError('timeout', 'invalid_timeout', timeout)
    id = utils.get_random_id()
    uci.set('objects', id, 'domain')
    uci.set('objects', id, 'name', name)
    uci.set('objects', id, 'family', family)
    uci.set('objects', id, 'timeout', timeout)
    uci.set('objects', id, 'domain', domains)
    uci.save('objects')

    # create ipset inside dhcp config
    ipset = utils.get_random_id()
    uci.set('dhcp', ipset, 'ipset')
    uci.set('dhcp', ipset, 'name', [name])
    uci.set('dhcp', ipset, 'domain', domains)
    uci.set('dhcp', ipset, 'table_family', 'inet')
    uci.set('dhcp', ipset, 'ns_link', f'objects/{id}')
    uci.save('dhcp')

    # create ipset inside firewall config
    ipset = utils.get_random_id()
    uci.set('firewall', ipset, 'ipset')
    uci.set('firewall', ipset, 'name', name)
    uci.set('firewall', ipset, 'family', family)
    uci.set('firewall', ipset, 'timeout', timeout)
    uci.set('firewall', ipset, 'counters', '1')
    uci.set('firewall', ipset, 'match', 'ip')
    uci.set('firewall', ipset, 'ns_link', f'objects/{id}')
    uci.save('firewall')
    return id

def edit_domain_set(uci, id: str, name: str, family: str, domains: list[str], timeout: int = 600) -> str:
    """
    Edit domain set in objects config.

    Args:
        uci: EUci pointer
        id: id of domain set to edit
        name: name of domain set
        family: can be `ipv4` or `ipv6`
        domains: a list of valid DNS names
        timeout: the timeout in seconds for the DNS resolution, default is `600` seconds

    Returns:
        id of domain set config that was edited
    """
    if not uci.get('objects', id, default=None):
        raise utils.ValidationError("id", "domain_set_does_not_exists", id)
    if len(name) > 16:
        raise utils.ValidationError('name', 'name_too_long', name)
    if family not in ['ipv4', 'ipv6']:
        raise utils.ValidationError('family', 'invalid_family', family)
    if timeout < 0:
        raise utils.ValidationError('timeout', 'invalid_timeout', timeout)
    uci.set('objects', id, 'name', name)
    uci.set('objects', id, 'family', family)
    uci.set('objects', id, 'timeout', timeout)
    uci.set('objects', id, 'domain', domains)
    uci.save('objects')

    # update ipset inside dhcp config
    for section in uci.get_all("dhcp"):
        if uci.get('dhcp', section, 'ns_link', default=None) == f'objects/{id}':
            uci.set('dhcp', section, 'name', [name])
            uci.set('dhcp', section, 'domain', domains)
            uci.set('dhcp', section, 'ns_tag', ['automated'])
            uci.save('dhcp')
            break
    for section in uci.get_all("firewall"):
        if uci.get('firewall', section, 'ns_link', default=None) == f'objects/{id}':
            uci.set('firewall', section, 'name', name)
            uci.set('firewall', section, 'family', family)
            uci.set('firewall', section, 'timeout', timeout)
            uci.set('firewall', section, 'ns_tag', ['automated'])
            uci.save('firewall')
            break
    return id

def delete_domain_set(uci, id: str) -> str:
    """
    Delete domain set from objects config.

    Args:
        uci: EUci pointer
        id: id of domain set to delete

    Returns:
        name of domain set config that was deleted
    """
    if not uci.get('objects', id, default=None):
        raise utils.ValidationError("id", "domain_set_does_not_exists", id)
    uci.delete('objects', id)
    uci.save('objects')
    for section in uci.get_all("dhcp"):
        if uci.get('dhcp', section, 'ns_link', default=None) == f'objects/{id}':
            uci.delete('dhcp', section)
            uci.save('dhcp')
            break
    for section in uci.get_all("firewall"):
        if uci.get('firewall', section, 'ns_link', default=None) == f'objects/{id}':
            uci.delete('firewall', section)
            uci.save('firewall')
            break
    return id

def list_domain_sets(uci) -> list:
    """
    Get all domain sets from objects config

    Args:
        uci: EUci pointer

    Returns:
        a list of all domain sets
    """
    sets = []
    for section in uci.get_all("objects"):
        if uci.get('objects', section) == 'domain':
            rule = uci.get_all('objects', section)
            rule['id'] = section
            used, matches = is_used_domain_set(uci, section)
            rule['used'] = used
            rule['matches'] = matches
            sets.append(rule)
    return sets

# Host set

def _validate_host_set_ipaddr(uci, ipaddr: str, family: str):
    if is_object_id(ipaddr):
        if not object_exists(uci, ipaddr):
            raise utils.ValidationError('ipaddr', 'object_does_not_exists', ipaddr)
        else:
            return # validation is ok
    if family == 'ipv4':
        return _validate_host_set_ipaddr_v4(ipaddr)
    elif family == 'ipv6':
        return _validate_host_set_ipaddr_v6(ipaddr)
    
def _validate_host_set_ipaddr_v4(ipaddr: str):
    if '/' in ipaddr:
        # validate CIDR
        try:
            ipaddress.IPv4Network(ipaddr)
        except ipaddress.AddressValueError:
            raise utils.ValidationError('ipaddr', 'invalid_ipaddr', ipaddr)
    elif '-' in ipaddr:
        start, end = ipaddr.split('-')
        try:
            ipaddress.IPv4Address(start)
            ipaddress.IPv4Address(end)
        except ipaddress.AddressValueError:
            raise utils.ValidationError('ipaddr', 'invalid_ipaddr', ipaddr)
    else:
        # validate IPv4
        try:
            ipaddress.IPv4Address(ipaddr)
        except ipaddress.AddressValueError:
            raise utils.ValidationError('ipaddr', 'invalid_ipaddr', ipaddr)
    return True

def _validate_host_set_ipaddr_v6(ipaddr: str):
    if '/' in ipaddr:
        # validate CIDR
        try:
            ipaddress.IPv6Network(ipaddr)
        except ipaddress.AddressValueError:
            raise utils.ValidationError('ipaddr', 'invalid_ipaddr', ipaddr)
    elif '-' in ipaddr:
        start, end = ipaddr.split('-')
        try:
            ipaddress.IPv6Address(start)
            ipaddress.IPv6Address(end)
        except ipaddress.AddressValueError:
            raise utils.ValidationError('ipaddr', 'invalid_ipaddr', ipaddr)
    else:
        # validate IPv6
        try:
            ipaddress.IPv6Address(ipaddr)
        except ipaddress.AddressValueError:
            raise utils.ValidationError('ipaddr', 'invalid_ipaddr', ipaddr)
    return True

def add_host_set(uci, name: str, family: str, ipaddrs: list[str]) -> str:
    """
    Add host set to objects config.

    Args:
        uci: EUci pointer
        name: name of host set
        family: can be `ipv4` or `ipv6`
        ipaddrs: a list of IP addresses

    Returns:
        id of host set config that was added
    """
    if len(name) > 16:
        raise utils.ValidationError('name', 'name_too_long', name)
    # check name contains only number and letters
    if not name.isalnum():
        raise utils.ValidationError('name', 'invalid_name', name)
    for ipaddr in ipaddrs:
        _validate_host_set_ipaddr(uci, ipaddr, family)
    id = utils.get_random_id()
    uci.set('objects', id, 'host')
    uci.set('objects', id, 'name', name)
    uci.set('objects', id, 'family', family)
    uci.set('objects', id, 'ipaddr', ipaddrs)
    uci.save('objects')
    return id

def edit_host_set(uci, id: str, name: str, family: str, ipaddrs: list[str]) -> str:
    """
    Edit host set in objects config.

    Args:
        uci: EUci pointer
        id: id of host set to edit
        name: name of host set
        family: can be `ipv4` or `ipv6`
        ipaddrs: a list of IP addresses

    Returns:
        id of host set config that was edited
    """
    if not uci.get('objects', id, default=None):
        raise utils.ValidationError("id", "host_set_does_not_exists", id)
    if len(name) > 16:
        raise utils.ValidationError('name', 'name_too_long', name)
    for ipaddr in ipaddrs:
        _validate_host_set_ipaddr(uci, ipaddr, family)
    uci.set('objects', id, 'name', name)
    uci.set('objects', id, 'family', family)
    uci.set('objects', id, 'ipaddr', ipaddrs)
    uci.save('objects')
    return id

def delete_host_set(uci, id: str) -> str:
    """
    Delete host set from objects config.

    Args:
        uci: EUci pointer
        id: id of host set to delete

    Returns:
        name of host set config that was deleted
    """
    if not uci.get('objects', id, default=None):
        raise utils.ValidationError("id", "host_set_does_not_exists", id)
    uci.delete('objects', id)
    uci.save('objects')
    return id

def is_used_host_set(uci, id):
    """
    Check if host set is used in firewall config.

    Args:
        uci: EUci pointer
        id: id of host set

    Returns:
        A tuple with:
        - True if host set is used in firewall config, False otherwise
        - a list of firewall sections where host set is used
    """
    return is_used_object(uci, f'objects/{id}')

def list_host_sets(uci) -> list:
    """
    Get all host sets from objects config

    Args:
        uci: EUci pointer

    Returns:
        a list of all host sets
    """
    sets = []
    for section in uci.get_all("objects"):
        if uci.get('objects', section) == 'host':
            rule = uci.get_all('objects', section)
            rule['id'] = section
            used, matches = is_used_host_set(uci, section)
            rule['used'] = used
            rule['matches'] = matches
            sets.append(rule)
    return sets

def is_host_set(uci, database_id):
    """
    Check if an object is a host set.

    Args:
        uci: EUci pointer
        id: id of the object in the form of `<database>/<id>`

    Returns:
        True if object is a host set, False otherwise
    """
    try:
        database, id = database_id.split('/')
        obj_type = uci.get(database, id)
        return database == "objects" and obj_type == "host"
    except:
        return False

# in mathematical terms, a singleton set is a set with exactly one element
def is_singleton_host_set(uci, database_id, allow_cidr=False):
    """
    Check if an object is a host set with a single IP address.
    The IP must not be an IP range.
    If `allow_cidr` is True, the IP can be in CIDR notation.

    Args:
        uci: EUci pointer
        database_id: id of the object in the form of `<database>/<id>`
        allow_cidr: allow CIDR notation

    Returns:
        True if object is a singleton host set, False otherwise
    """
    if is_host_set(uci, database_id):
        obj = get_object(uci, database_id)
        if obj and len(obj.get('ipaddr')) == 1:
            ip = obj.get('ipaddr')[0]
            if '-' in ip:
                return False
            if allow_cidr:
                return True
            else:
                return '/' not in ip
    return False

# Host

def is_host(uci, database_id):
    """
    Check if an object is a host.

    Args:
        uci: EUci pointer
        database_id: id of the object in the form of `<database>/<id>`

    Returns:
        True if object is a host, False otherwise
    """
    try:
        database, id = database_id.split('/')
        obj_type = uci.get(database, id)
        return database == "dhcp" and obj_type == "host"
    except:
        return False

# Domain

def is_domain(uci, database_id):
    """
    Check if an object is a domain.

    Args:
        uci: EUci pointer
        database_id: id of the object in the form of `<database>/<id>`

    Returns:
        True if object is a domain, False otherwise
    """
    try:
        database, id = database_id.split('/')
        obj_type = uci.get(database, id)
        return database == "dhcp" and obj_type == "domain"
    except:
        return False

# VPN user

def is_vpn_user(uci, database_id):
    """
    Check if an object is a VPN user.

    Args:
        uci: EUci pointer
        database_id: id of the object in the form of `<database>/<id>`

    Returns:
        True if object is a VPN user, False otherwise
    """
    try:
        database, id = database_id.split('/')
        obj_type = uci.get(database, id)
        return database == "users" and obj_type == "user" and uci.get(database, id, 'openvpn_ipaddr', default=None) != None
    except:
        return False