#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Library for common VPN functions.
"""

import json
import ipaddress
import random
import struct
import socket
import subprocess
from nethsec import utils

def get_local_networks(u):
    """
    Return a list of local networks.

    Arguments:
      - u -- EUci instance

    Returns:
      - a list of local networks
    """
    ret = []
    for l in utils.get_all_lan_devices(u):
        try:
            data = json.loads(subprocess.run(["ip", "--json", "address", "show", "dev", l], capture_output=True, text=True, check=True).stdout)
            if len(data) > 0:
                for addr in data[0].get('addr_info', []):
                    if addr.get("local", None) and addr.get("family", None) == "inet": # ipv4 only
                        net = ipaddress.ip_interface(f'{addr.get("local")}/{addr.get("prefixlen")}').network
                        ret.append(f'{net}')
        except:
            continue
    return ret

def get_public_addresses(u):
    """
    Return a list of public addresses.

    Arguments:
      - u -- EUci instance

    Returns:
      - a list of public addresses
    """
    ret = []
    for w in utils.get_all_wan_devices(u):
        try:
             data = json.loads(subprocess.run(["ip", "--json", "address", "show", "dev", w], capture_output=True, text=True, check=True).stdout)
        except:
            continue
        if len(data) > 0:
            for addr in data[0].get('addr_info', []):
                if addr.get("local", None):
                    try:
                        cmd = f"/usr/bin/dig -b {addr.get('local')} +short +time=1 myip.opendns.com @resolver1.opendns.com".split(" ")
                        output = subprocess.check_output(cmd, timeout=5)
                        ret.append(output.decode().strip())
                    except:
                        pass
    return ret

def to_cidr(netmask):
    """
    Convert a netmask to CIDR notation.

    Arguments:
      - netmask -- netmask in dotted decimal notation

    Returns:
      - CIDR notation

    """
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def to_netmask(prefix):
    """
    Convert a CIDR notation to netmask.

    Arguments:
      - prefix -- CIDR notation

    Returns:
      - netmask in dotted decimal notation
    """
    return socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - int(prefix))) & 0xffffffff))

def generate_random_network(u):
    """
    Generate a random network.

    Arguments:
      - u -- EUci instance

    Returns:
     - a random unused network
    """
    network = random_ip()
    while is_used_network(u, network):
        network = random_ip()
    return network

def random_ip():
    """
    Generate a random private IP address.

    Returns:
      - a random private IP address
    """
    return f"10.{random.randint(0, 254)}.{random.randint(0, 254)}.0/24"

def is_used_network(u, network):
    """
    Check if a network is already used by another OpenVPN.

    Arguments:
      - u -- EUci instance
      - network -- network to check

    Returns:
      - True if the network is already used, False otherwise
    """
    try:
        openvpn = u.get_all('openvpn')
    except:
        return False

    for v in openvpn:
        ifconfig = opt2cidr(u.get('openvpn', v, 'ifconfig', default=""))
        server = opt2cidr(u.get('openvpn', v, 'server', default=""))
        if network == ifconfig or network == server:
            return True
    return False

def opt2cidr(opt):
    """
    Convert an OpenVPN option to CIDR notation.

    Arguments:
      - opt -- OpenVPN option

    Returns:
      - CIDR notation
    """
    try:
        tmp = opt.split(" ")
        return f'{tmp[0]}/{to_cidr(tmp[1])}'
    except:
        return ""
    

def list_cipher():
    """
    Return a list of OpenVPN ciphers.

    Returns:
      - a list of OpenVPN ciphers, each element is a dicttionary with the following keys:
          - name: cipher name
          - description: cipher description (weak or strong)
    """
    ret = []
    try:
        result = subprocess.run(['/usr/sbin/openvpn', '--show-ciphers'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        for line in output_lines:
            if '(' in line:
                description = 'weak'
                tmp = line.split()
                cipher_name = tmp[0]
                try:
                    bits = int(cipher_name.split("-")[1])
                except:
                    bits = 0
                if bits in [192, 256, 384, 512]:
                    description = 'strong'
                ret.append({'name': cipher_name, 'description': description})
    except:
        return {"ciphers": []}
    return {"ciphers": ret}

def list_digest():
    """
    Return a list of OpenVPN digests.

    Returns:
      - a list of OpenVPN digests, each element is a dicttionary with the following keys:
        - name: digest name
        - description: digest description (weak or strong)
    """
    ret = []
    try:
        result = subprocess.run(['/usr/sbin/openvpn', '--show-digests'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        for line in output_lines:
            if 'bit' in line:
                description = 'weak'
                tmp = line.split()
                if tmp[1] in ['224', '256', '384', '512', 'whirlpool']:
                    description = 'strong'
                ret.append({'name': tmp[0], 'description': description})
    except:
        return {"digests": []}
    return {"digests": ret}