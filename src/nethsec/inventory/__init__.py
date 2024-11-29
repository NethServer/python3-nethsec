#!/usr/bin/python3

#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#


from euci import EUci
from nethsec import utils, mwan, users, firewall, objects
import os
import re
import subprocess
import configparser

# run a bash command and return the error code
def _run_status(cmd):
    try:
        proc = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return proc.returncode
    except:
        return 1

def fact_hotspot(uci: EUci):
    enabled = uci.get('dedalo', 'config', 'disabled', default='1') == '0'
    server = uci.get('dedalo', 'config', 'api_url', default='')
    interface = uci.get('dedalo', 'config', 'interface', default='')
    return { 'enabled': enabled, 'server': server, 'interface': interface }

def fact_netifyd(uci: EUci):
    try:
        config = configparser.ConfigParser()
        config.read('/etc/netifyd.conf')
        enable_sink = config.get('netifyd', 'enable_sink')
    except:
        enable_sink = 'no'
    return { 'enabled': enable_sink == 'yes' }

def fact_flashstart(uci: EUci):
    enabled = uci.get('flashstart', 'global', 'enabled', default='0') == '1'
    # number of bypass
    try:
        bypass = len(uci.get_all('flashstart', 'global', 'bypass'))
    except:
        bypass = 0
    return { 'enabled': enabled, 'bypass': bypass }

def fact_openvpn_rw(uci: EUci):
    ret = { 'enabled': 0, 'server': 0, 'instances': [] }
    for section in utils.get_all_by_type(uci, 'openvpn', 'openvpn'):
        if uci.get("openvpn", section, 'ns_auth_mode', default=''):
            ret["server"] += 1
            if uci.get("openvpn", section, 'enabled', default='0') == '1':
                ret["enabled"] += 1 
    for section in utils.get_all_by_type(uci, 'openvpn', 'openvpn'):
        vpn = uci.get_all("openvpn", section)
        if not section.startswith('ns_'):
            continue
        if "ns_auth_mode" in vpn:
            # we are in a ovpn_rw
            instance = {
                'section': section,
                'authentication': vpn.get('ns_auth_mode'),
                'user_database': vpn.get('ns_user_db'),
                'mode': vpn.get('dev_type')
            }
            ret['instances'].append(instance)
    return ret

def fact_openvpn_tun(uci: EUci):
    ret = { 'client': 0, 'server': 0, 'tunnels': [] }
    for section in utils.get_all_by_type(uci, 'openvpn', 'openvpn'):
        vpn = uci.get_all("openvpn", section)
        if 'ns_auth_mode' in vpn or not section.startswith('ns_'):
            continue
        if vpn.get("client", "0") == "1" or vpn.get("ns_client", "0") == "1":
            ret["client"] += 1
        else:
            ret["server"] += 1
        instance = {
            'section': section,
            'mode': vpn.get('dev_type')
        }
        ret['tunnels'].append(instance)
    return ret

def fact_certificates_info(uci: EUci):
    result = {
        "custom_certificates": {
            "count": 0
        },
        "acme_certificates": {
            "count": 0,
            "issued": 0,
            "pending": 0
        }
    }
    
    # Count custom certificates
    try:
        for entry in os.scandir('/etc/nginx/custom_certs'):
            if entry.is_file() and entry.name.endswith('.crt') and os.path.isfile(entry.path[:-4] + '.key'):
                result["custom_certificates"]["count"] += 1
    except Exception as e:
        # Handle exceptions appropriately
        pass

    # Count ACME certificates
    try:
        requested_certificates = utils.get_all_by_type(uci, 'acme', 'cert')
        enabled_certificates = [certificate for certificate in requested_certificates
                                if requested_certificates[certificate]['enabled'] == '1']
        for certificate in enabled_certificates:
            result["acme_certificates"]["count"] += 1
            domain = requested_certificates[certificate]['domains'][0]
            cert_path = f'/etc/ssl/acme/{domain}.fullchain.crt'
            if os.path.isfile(cert_path):
                result["acme_certificates"]["issued"] += 1
            else:
                result["acme_certificates"]["pending"] += 1
    except Exception as e:
        # Handle exceptions appropriately
        pass

    return result

def fact_subscription_status(uci: EUci):
    return { 'status': uci.get('ns-plug', 'config', 'type', default='no') }

def fact_controller(uci: EUci):
    if uci.get('ns-plug', 'config', 'server', default='') and uci.get('ns-plug', 'config', 'unit_id', default='') and uci.get('ns-plug', 'config', 'token', default=''):
        return { "enabled": True}
    else:
        return { "enabled": False}

def fact_threat_shield(uci: EUci):
    ret = { 'enabled': False, 'community': 0, 'enterprise': 0 }
    ret['enabled'] = uci.get('banip', 'global', 'ban_enabled', default='0') == '1'
    try:
        for feed in uci.get_all("banip", "global", "ban_feed"):
            if feed.startswith("nethesis") or feed.startswith("yoroi"):
                ret['enterprise'] += 1
            else:
                ret['community'] += 1
    except:
        pass
    return ret

def fact_ui(uci: EUci):
    ret = { 'luci': False, 'port443': False, 'port9090': False }
    ret['luci'] = uci.get('ns-ui', 'config', 'luci_enable', default='0') == '1'
    ret['port443'] = uci.get('ns-ui', 'config', 'nsui_enable', default='0') == '1'
    ret['port9090'] = uci.get('ns-ui', 'config', 'nsui_extra_enable', default='0') == '1' and uci.get('ns-ui', 'config', 'nsui_extra_port', default='0') == '9090'
    return ret

def fact_network(uci: EUci):
    result = {
        "zones": []
    }
    vlan_count = 0
    bridge_count = 0
    bond_count = 0
    zone_network_counts = {}
    route_info = {
        "count_ipv6_route": 0,
        "count_ipv4_route": 0
    }
    # Regex pattern to match interfaces that end with ".<integer>"
    vlan_pattern = re.compile(r'\.\d+$')
    interfaces = utils.get_all_by_type(uci, 'network', 'interface')

    # Loop through all firewall zones to gather network information
    for zone in utils.get_all_by_type(uci, 'firewall', 'zone').values():
        zone_info = {
                'name': zone['name'],
                'ipv4': 0,
                'ipv6': 0
            }
        devices = utils.get_all_devices_by_zone(uci, zone['name'], True)
        for device in devices:
            interface = utils.get_interface_from_device(uci, device)
            if interface is None:
                continue
            is_ipv6 = False
            for option in uci.get_all('network', interface):
                if option.startswith("ip6") or option == "dhcpv6" or option == "ipv6":
                    is_ipv6 = True
                    break
            if uci.get('network', interface, 'proto', default="") in ['dhcpv6', '6in4', '6to4', '6rd', 'grev6', 'grev6tap', 'vtiv6']:
                is_ipv6 = True
            if is_ipv6:
                zone_info['ipv6'] += 1
            else:
                zone_info['ipv4'] += 1
            # Count VLAN, bridge, and bond interfaces
            if 'device' in interfaces.get(interface, {}):
                device_name = interfaces[interface]['device']
                if vlan_pattern.search(device_name):
                    vlan_count += 1
                if device_name.startswith('br-'):
                    bridge_count += 1
                if device_name.startswith('bond-'):
                    bond_count += 1
        result["zones"].append(zone_info)
        # Count networks for each zone
        networks = uci.get('firewall', 'ns_'+zone['name'], 'network', list=True, default=[])
        network_count = len(networks)
        # Count devices for each zone (if networks are not defined, hotspot zones, openvpn zones, etc.)
        devices = utils.get_all_devices_by_zone(uci, zone['name'], True)
        # remove tun-dedalo if present (it's a virtual device, we count the real interface
        devices = [d for d in devices if not d.startswith('tun-dedalo')]
        devices_count = len(devices)
        zone_network_counts[zone['name']] = network_count or devices_count # Use the number of networks if available, otherwise use the number of devices
    # Get route information
    routes_ipv6 = utils.get_all_by_type(uci, 'network', 'route6')
    for _ in routes_ipv6:
        route_info["count_ipv6_route"] += 1

    routes_ipv4 = utils.get_all_by_type(uci, 'network', 'route')
    for _ in routes_ipv4:
        route_info["count_ipv4_route"] += 1

    # Add VLAN, bridge, and bond counts to the result
    result['interface_counts'] = {
        'vlans': vlan_count,
        'bridges': bridge_count,
        'bonds': bond_count
    }
    # Add network zone counts to the result
    result['zone_network_counts'] = zone_network_counts

    # Add route information to the result
    result['route_info'] = route_info

    return result

def fact_database_stats(uci: EUci):
    ret = {}
    databases = users.list_databases(uci)
    for db in databases:
        name = db["name"]
        number_users = len(users.list_users(uci, name))
        ret[name] = { "users": number_users }
    return ret

def fact_firewall_stats(uci: EUci):
    result = {
        "firewall": {
            "port_forward": 0,
            "nat": {"masquerade": 0, "snat": 0, "accept": 0},
            "netmap": {"source": 0, "destination": 0},
            "rules": {"forward": 0, "input": 0, "output": 0}
        },
        "objects": {
            "domains": 0,
            "hosts": 0,
            "port_forward": {"allowed_from": 0, "destination_to": 0},
            "mwan_rules": 0,
            "rules": {"forward": 0, "input": 0, "output": 0}
        }
    }

    # Firewall Information
    # Count port forward
    result["firewall"]["port_forward"] = len(utils.get_all_by_type(uci, 'firewall', 'redirect'))

    # Count NAT rules
    for rule in firewall.list_nat_rules(uci):
        if rule['target'] == 'ACCEPT':
            result["firewall"]["nat"]["accept"] += 1
        elif rule['target'] == 'MASQUERADE':
            result["firewall"]["nat"]["masquerade"] += 1
        elif rule['target'] == 'SNAT':
            result["firewall"]["nat"]["snat"] += 1

    # Count netmap rules
    for rule in firewall.list_netmap_rules(uci):
        if rule.get('dest', ''):
            result["firewall"]["netmap"]["source"] += 1
        elif rule.get('src', ''):
            result["firewall"]["netmap"]["destination"] += 1

    # Count rules
    result["firewall"]["rules"]["forward"] = len(firewall.list_forward_rules(uci))
    result["firewall"]["rules"]["input"] = len(firewall.list_input_rules(uci))
    result["firewall"]["rules"]["output"] = len(firewall.list_output_rules(uci))

    # Object Information
    # Count objects
    result["objects"]["domains"] = len(objects.list_domain_sets(uci))
    result["objects"]["hosts"] = len(objects.list_host_sets(uci))

    # Count object for port forward
    for key, value in utils.get_all_by_type(uci, 'firewall', 'redirect').items():
        if isinstance(value.get('ns_src'), str):
            result["objects"]["port_forward"]["allowed_from"] += 1
        if isinstance(value.get('ns_dst'), str):
            result["objects"]["port_forward"]["destination_to"] += 1

    # Count object for rules
    for value in firewall.list_forward_rules(uci):
        if isinstance(value.get('ns_dst'), str):
            result["objects"]["rules"]["forward"] += 1
    for value in firewall.list_input_rules(uci):
        if isinstance(value.get('ns_src'), str):
            result["objects"]["rules"]["input"] += 1
    for value in firewall.list_output_rules(uci):
        if isinstance(value.get('ns_dst'), str):
            result["objects"]["rules"]["output"] += 1
    for value in mwan.index_rules(uci):
        if isinstance(value.get('ns_src'), str):
            result["objects"]["mwan_rules"] += 1

    return result

def fact_storage(uci: EUci):
    return {"enabled": uci.get("fstab", "ns_data", "enabled", default="0") == "1"}

def fact_proxy_pass(uci: EUci):
    ret = { "count": 0}
    try:
        for l in utils.get_all_by_type(uci, 'nginx', 'location'):
            if uci.get('nginx', l, 'proxy_pass', default=''):
                ret["count"] += 1
    except:
        pass
    return ret

def fact_dpi(uci: EUci):
    ret = {"enabled": False, "rules": 0}
    ret["enabled"] = uci.get('dpi', 'config', 'enabled', default='0') == '1'
    for rule in utils.get_all_by_type(uci, 'dpi', 'rule'):
        if uci.get('dpi', rule, 'enabled', default='0') == '1':
            ret["rules"] += 1
    return ret

def fact_dhcp_server(uci: EUci):
    result = {
        'count': 0,  # Initialize the count for DHCP servers
        'static_leases': 0, 
        'dynamic_leases': 0, 
        'dns_records_count': 0, 
        'dns_forwarder_enabled': False
    }

    # Count DHCP servers
    for section in utils.get_all_by_type(uci, 'dhcp', 'dhcp'):
        if uci.get('dhcp', section, 'dhcpv4', default='') == 'server' or uci.get('dhcp', section, 'dhcpv6', default='') == 'server':
            result['count'] += 1  # Increment the count for DHCP servers
    
    # Count static leases
    result['static_leases'] = len(utils.get_all_by_type(uci, 'dhcp', 'host'))
    
    static_leases = []
    for l in utils.get_all_by_type(uci, 'dhcp', 'host'):
        ldata = uci.get_all('dhcp', l)
        if 'mac' in ldata and 'ip' in ldata:
            static_leases.append(ldata['mac'].lower())

    # Count dynamic leases, skipping static leases
    try:
        with open("/tmp/dhcp.leases", "r") as fp:
            for line in fp.readlines():
                tmp = line.split(" ")
                if tmp[1].lower() not in static_leases:
                    result['dynamic_leases'] += 1
    except FileNotFoundError:
        # Handle the case where the leases file doesn't exist
        pass

    # Count DNS records and check if DNS forwarder is enabled
    for section in utils.get_all_by_type(uci, 'dhcp', 'dnsmasq'):
        servers = uci.get('dhcp', section, 'server', default=[])
        if servers:
            result['dns_forwarder_enabled'] = True
        for r in utils.get_all_by_type(uci, 'dhcp', 'domain'):
            result['dns_records_count'] += 1
    
    return result

def fact_multiwan(uci: EUci):
    policies = mwan.index_policies(uci)
    result = {
        'enabled': len(policies) > 0,
        'policies': {
            'backup': 0,
            'balance': 0,
            'custom': 0
        },
        'rules': len(mwan.index_rules(uci))
    }
    for policy in policies:
        result['policies'][policy['type']] += 1
    return result

def fact_qos(uci: EUci):
    ret = {
        "count": 0,
        "rules": []
    }
    for key, interface in utils.get_all_by_type(uci, 'qosify', 'interface').items():
        if interface['disabled'] == '0':
            ret["count"] += 1
            rule = {
                'enabled': interface['disabled'] == '0',
                'upload': int(interface['bandwidth_up'].removesuffix('mbit')),
                'download': int(interface['bandwidth_down'].removesuffix('mbit')),
            }
            ret['rules'].append(rule)
    return ret

def fact_ipsec(uci: EUci):
    try:
        count = len(utils.get_all_by_type(uci, 'ipsec', 'remote'))
    except:
        count = -1
    return { 'count': count }

def fact_nathelpers(uci: EUci):
    # count the number of lines in the file
    try:
        with open('/etc/modules.d/ns-nathelpers') as f:
            count = len(f.readlines())
    except:
        count = 0
    return { 'count': count, 'enabled': count > 0 }

def fact_ddns(uci: EUci):
    ddns = _run_status("/etc/init.d/ddns enabled")
    return { 'enabled': ddns == 0 }

def fact_snmp (uci: EUci):
    snmp = _run_status("/etc/init.d/snmpd running")
    return { 'enabled': snmp == 0 }
