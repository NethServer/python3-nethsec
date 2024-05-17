#!/usr/bin/python3

#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#


from euci import EUci
from nethsec import utils, mwan

def fact_hotspot(uci: EUci):
    enabled = uci.get('dedalo', 'config', 'disabled', default='1') == '0'
    server = uci.get('dedalo', 'config', 'api_url', default='')
    return { 'enabled': enabled, 'server': server }
    
def fact_flashstart(uci: EUci):
    enabled = uci.get('flashstart', 'global', 'enabled', default='0') == '1'
    # number of bypass
    try:
        bypass = len(uci.get_all('flashstart', 'global', 'bypass'))
    except:
        bypass = 0
    return { 'enabled': enabled, 'bypass': bypass }

def fact_openvpn_rw(uci: EUci):
    ret = { 'enabled': 0, 'server': 0 }
    for section in utils.get_all_by_type(uci, 'openvpn', 'openvpn'):
        if uci.get("openvpn", section, 'ns_auth_mode', default=''):
            ret["server"] += 1
            if uci.get("openvpn", section, 'enabled', default='0') == '1':
                ret["enabled"] += 1 
    return ret

def fact_openvpn_tun(uci: EUci):
    ret = { 'client': 0, 'server': 0 }
    for section in utils.get_all_by_type(uci, 'openvpn', 'openvpn'):
        vpn = uci.get_all("openvpn", section)
        if 'ns_auth_mode' in vpn or not section.startswith('ns_'):
            continue
        if vpn.get("client", "0") == "1" or vpn.get("ns_client", "0") == "1":
            ret["client"] += 1
        else:
            ret["server"] += 1
    return ret

def fact_subscription_status(uci: EUci):
    return { 'status': uci.get('ns_plug', 'config', 'type', default='no') }

def fact_controller(uci: EUci):
    if uci.get('ns_plug', 'config', 'server', default='') and uci.get('ns_plug', 'config', 'unit_id', default='') and uci.get('ns_plug', 'config', 'token', default=''):
        return { "enabled": True}
    else:
        return { "enabled": False}

def fact_threat_shield(uci: EUci):
    ret = { 'enabled': False, 'community': 0, 'enterprise': 0 }
    ret['enabled'] = uci.get('banip', 'global', 'ban_enabled', default='0') == '1'
    for feed in uci.get_all("banip", "global", "ban_feed"):
        if feed.startswith("nethesis") or feed.startswith("yoroy"):
            ret['enterprise'] += 1
        else:
            ret['community'] += 1
    return ret

def fact_ui(uci: EUci):
    ret = { 'luci': False, 'port443': False, 'port9090': False }
    ret['luci'] = uci.get('ns-ui', 'config', 'luci_enable', default='0') == '1'
    ret['port443'] = uci.get('ns-ui', 'config', 'nsui_enable', default='0') == '1'
    ret['port9090'] = uci.get('ns-ui', 'config', 'nsui_extra_enable', default='0') == '1' and uci.get('ns-ui', 'config', 'nsui_extra_port', default='0') == '9090'
    return ret

def fact_network(uci: EUci):
    result = { "ipv6": 0, "ipv4": 0}
    for interface in utils.get_all_by_type(uci, 'network', 'interface'):
        is_ipv6 = False
        for option in uci.get_all('network', interface):
            if option.startswith("ip6") or option == "dhcpv6" or option == "ipv6":
                is_ipv6 = True
                break
        if uci.get('network', interface, 'proto', default="") in ['dhcpv6', '6in4', '6to4', '6rd', 'grev6', 'grev6tap', 'vtiv6']:
            is_ipv6 = True
        if is_ipv6:
            result["ipv6"] += 1
        else:
            result["ipv4"] += 1
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
    count = 0
    for section in utils.get_all_by_type(uci, 'dhcp', 'dhcp'):
        if uci.get('dhcp', section, 'dhcpv4', default='') == 'server' or uci.get('dhcp', section, 'dhcpv6', default='') == 'server':
            count += 1
    return { 'count': count }

def fact_multiwan(uci: EUci):
    type = ""
    for p in mwan.index_policies(uci):
        if p.get('name') == 'ns_default':
            type = p.get('type')
            break
    wans = len(utils.get_all_by_type(uci, 'mwan3', 'interface'))
    return {'wans' : wans, 'type': type}

def fact_qos(uci: EUci):
    count = 0
    for i in utils.get_all_by_type(uci, 'qosify', 'interface'):
        if uci.get('qosify', i, 'disabled', default='1') == '0':
            count += 1
    return {'count': count}

def fact_ipsec(uci: EUci):
    try:
        count = len(utils.get_all_by_type(uci, 'ipsec', 'remote'))
    except:
        count = -1
    return { 'count': count }
