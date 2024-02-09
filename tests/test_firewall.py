from nethsec import utils
from nethsec.utils import ValidationError
import pytest
from euci import EUci, UciExceptionNotFound

from nethsec import firewall
from pytest_mock import MockFixture

firewall_db = """
config zone lan1
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	list device 'eth0'

config zone grey
	option name 'grey'
	list network 'grey1'
	option input 'DROP'
	option output 'ACCEPT'
	option forward 'DROP'
	list device 'eth1'

config zone orange
	option name 'orange'
	list network 'orange1'
	option input 'DROP'
	option output 'DROP'
	option forward 'DROP'

config zone wan1f
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'

config forwarding fw1
	option src 'lan'
	option dest 'wan'

config rule 'v6rule'
    option name 'Allow-DHCPv6'
    option src 'wan'
    option proto 'udp'
    option dest_port '546'
    option family 'ipv6'
    option target 'ACCEPT'

config rule 'manrule'
    option name 'Not-Automated'
    option src 'wan'
    option proto 'tcp'
    option dest_port '1234'
    option family 'ipv4'
    option target 'ACCEPT'

config rule 'f1'
	option name 'r1'
	option dest 'wan'
	option dest_port '22'
	option target 'ACCEPT'
	option src 'lan'
	list src_ip '192.168.100.1'
	list src_ip '192.168.100.238'
	list dest_ip '192.168.122.1'
	list dest_ip '192.168.122.49'
    option log '1'
 
config rule 'o1'
	option name 'output1'
	list dest_ip '192.168.100.1'
	option target 'ACCEPT'
	option dest 'wan'

config rule 'i1'
	option name 'Allow-OpenVPNRW1'
	option src 'wan'
	option dest_port '1194'
	option proto 'udp'
	option target 'ACCEPT'
	list ns_tag 'automated'
	option ns_link 'openvpn/ns_roadwarrior1'

config nat
	option name 'source_NAT1_vpm'
	option src '*'
	option src_ip '192.168.55.0/24'
	option dest_ip '10.20.30.0/24'
	option target 'SNAT'
	option snat_ip '10.44.44.1'
	list proto 'all'

config nat
	option name 'masquerade'
	list proto 'all'
	option src 'lan'
	option src_ip '192.168.1.0/24'
	option dest_ip '10.88.88.0/24'
	option target 'MASQUERADE'

config nat
	option name 'cdn_via_router'
	list proto 'all'
	option src 'lan'
	option src_ip '192.168.1.0/24'
	option dest_ip '192.168.50.0/24'
	option target 'ACCEPT'

config nat
	option name 'SNAT_NSEC7_style'
	list proto 'all'
	option src 'wan'
	option src_ip '192.168.1.44'
	option target 'SNAT'
	option snat_ip '10.20.30.5'
"""

network_db = """
config interface lan
	option device 'vnet3'

config interface lan2
	option device 'vnet4'

config interface grey1
	option device 'vnet5'

config interface orange1
	option device 'vnet6'

config interface 'lan6'
    option device 'br-lan'
    option proto 'dhcpv6'

config device 'vlan6'
	option type '8021ad'
	option ifname 'eth2'
	option vid '1'
	option name 'eth2.1'
	option ipv6 '1'

config interface 'wan6'
    option device   eth1
    option proto    static
    option ip6addr  2001:db80::2/64
    option ip6gw    2001:db80::1
    option ip6prefix 2001:db80:1::/48
    option dns      2001:db80::1

config interface 'wan6b'
    option device   eth1
    option proto    vtiv6

config interface 'wan6c'
    option device   eth44
    option ipv6   1

config interface 'bond1'
	option proto 'bonding'
	option ipaddr '10.0.0.22'
	option netmask '255.255.255.0'
	list slaves 'eth3'
	option bonding_policy 'balance-rr'
	option packets_per_slave '1'
	option all_slaves_active '0'
	option link_monitoring 'off'

config interface 'lan'
	option device 'br-lan'
	option proto 'static'
	option ipaddr '192.168.100.238'
	option netmask '255.255.255.0'
"""

templates_db = """
# Service groups
config template_service_group 'ns_web_secure'
	option name 'Secure web navigation'
	list services '80/tcp/HTTP'
	list services '443/tcp/HTTP Secure'
	list services '53/udp/DNS'

# Blue zone
config template_zone 'ns_blue'
	option name 'blue'
	option forward 'DROP'
	option input 'DROP'
	option output 'ACCEPT'
	option ns_description 'Guest network with Internet access'
	list forwardings 'ns_blue2wan'
	list forwardings 'ns_blue2lan'
	# requires network option

config template_forwarding 'ns_blue2wan'
	option src 'blue'
	option dest 'wan'

config template_forwarding 'ns_blue2lan'
	option src 'blue'
	option dest 'lan'

# Default rule
config template_rule 'ns_test_rule'
	option name 'Test-rule'
	option src 'wan'
	option dest 'blue'
	option dest_port '__PORT__'
	option proto '__PROTO__'
	option target 'ACCEPT'
	option enabled '1'

# IPv6 rules

config template_rule 'ip6_dhcp'
	option name 'Allow-DHCPv6'
	option src 'wan'
	option proto 'udp'
	option dest_port '546'
	option family 'ipv6'
	option target 'ACCEPT'

config template_rule 'ip6_mld'
	option name 'Allow-MLD'
	option src 'wan'
	option proto 'icmp'
	option src_ip 'fe80::/10'
	list icmp_type '130/0'
	list icmp_type '131/0'
	list icmp_type '132/0'
	list icmp_type '143/0'
	option family 'ipv6'
	option target 'ACCEPT'

config template_rule 'ip6_icmp'
	option name 'Allow-ICMPv6-Input'
	option src 'wan'
	option proto 'icmp'
	list icmp_type 'echo-request'
	list icmp_type 'echo-reply'
	list icmp_type 'destination-unreachable'
	list icmp_type 'packet-too-big'
	list icmp_type 'time-exceeded'
	list icmp_type 'bad-header'
	list icmp_type 'unknown-header-type'
	list icmp_type 'router-solicitation'
	list icmp_type 'neighbour-solicitation'
	list icmp_type 'router-advertisement'
	list icmp_type 'neighbour-advertisement'
	option limit '1000/sec'
	option family 'ipv6'
	option target 'ACCEPT'

config template_rule 'ip6_icmp_forward'
	option name 'Allow-ICMPv6-Forward'
	option src 'wan'
	option dest '*'
	option proto 'icmp'
	list icmp_type 'echo-request'
	list icmp_type 'echo-reply'
	list icmp_type 'destination-unreachable'
	list icmp_type 'packet-too-big'
	list icmp_type 'time-exceeded'
	list icmp_type 'bad-header'
	list icmp_type 'unknown-header-type'
	option limit '1000/sec'
	option family 'ipv6'
	option target 'ACCEPT'

"""

zone_testing_db = """
config zone 'ns_lan'
    option name 'lan'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'
    list network 'GREEN_1'

config zone 'ns_wan'
    option name 'wan'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option masq '1'
    option mtu_fix '1'
    list network 'wan6'
    list network 'RED_2'
    list network 'RED_3'
    list network 'RED_1'
    
config zone 'ns_guests'
    option name 'guests'
    option input 'DROP'
    option forward 'DROP'
    option output 'ACCEPT'
    
config forwarding
    option src 'lan'
    option dest 'wan'

config forwarding 'ns_guests2wan'
    option src 'guests'
    option dest 'wan'
    
config forwarding 'ns_lan2guests'
    option src 'lan'
    option dest 'guests'
"""

dhcp_db = """
config domain
	option name 'test.name.org'
	option ip '192.168.100.1'

config host
	option name 'test2.giacomo.org'
	option mac '5c:87:9c:fa:69:5b'
	option ip '192.168.100.2'

config domain
	option name 'test3.test.org'
	option ip 'ac0d:b0e6:ee9e:172e:7f64:ea08:ed22:1543'
"""

services_file = """
ftp             21/tcp
ssh             22/tcp
ssh             22/udp
time            37/udp
www             80/tcp          http
kerberos        88/tcp          kerberos5 krb5 kerberos-sec
kerberos        88/udp          kerberos5 krb5 kerberos-sec
"""

lease_file = """
1704890657 9c:3d:cf:ea:94:9b 192.168.1.70 * *
1704885018 98:ed:5c:8c:73:2a 192.168.1.228 test1 *
1704874398 ac:57:26:00:24:8c 192.168.1.219 test2 01:dc:57:26:00:25:8c
"""

def _setup_db(tmp_path):
     # setup fake dbs
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
        fp.write(zone_testing_db)
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
    with tmp_path.joinpath('templates').open('w') as fp:
        fp.write(templates_db)
    with tmp_path.joinpath('dhcp').open('w') as fp:
        fp.write(dhcp_db)
    return EUci(confdir=tmp_path.as_posix())

def test_add_interface_to_zone(tmp_path):
    u = _setup_db(tmp_path)
    z1 = firewall.add_interface_to_zone(u, "interface1", "lan")
    assert z1 == 'lan1'
    assert 'interface1' in u.get_all('firewall', 'lan1', 'network')
    assert firewall.add_interface_to_zone(u, "interface1", "blue") == None
    z1 = firewall.add_interface_to_zone(u, "interface2", "lan")
    assert 'interface2' in u.get_all('firewall', 'lan1', 'network')

def test_remove_interface_from_zone(tmp_path):
    u = _setup_db(tmp_path)
    z1 = firewall.remove_interface_from_zone(u, 'interface1', "lan")
    assert(not 'interface1' in  u.get_all('firewall', 'lan1', 'network'))

def test_add_device_to_zone(tmp_path):
    u = _setup_db(tmp_path)
    z1 = firewall.add_device_to_zone(u, "vnet1", "lan")
    assert z1 == 'lan1'
    assert 'vnet1' in u.get_all('firewall', 'lan1', 'device')
    assert firewall.add_device_to_zone(u, "vnet1", "blue") == None

def test_add_device_to_lan(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_device_to_lan(u, "vnet1") == 'lan1'
    assert 'vnet1' in u.get_all('firewall', 'lan1', 'device')

def test_add_device_to_wan(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_device_to_wan(u, "vnet2") == 'wan1f'
    assert 'vnet2' in u.get_all('firewall', 'wan1f', 'device')

def test_remove_device_from_zone(tmp_path):
    u = _setup_db(tmp_path)
    firewall.remove_device_from_zone(u, 'vnet1', "lan")
    assert(not 'vnet2' in  u.get_all('firewall', 'lan1', 'device'))

def test_add_service(tmp_path):
    u = _setup_db(tmp_path)
    rule = firewall.add_service(u, "my_service", "443", "tcp", "nginx/_lan")
    assert rule is not None
    assert rule == "ns_allow_my_service"
    assert u.get('firewall', rule, 'dest_port') == '443'
    assert u.get('firewall', rule, 'proto') == 'tcp'
    assert u.get('firewall', rule, 'src') == 'wan'
    assert u.get('firewall', rule, 'name') == 'Allow-my_service'
    assert u.get('firewall', rule, 'ns_link') == "nginx/_lan"
    assert u.get('firewall', rule, 'ns_tag') == "automated"

    assert firewall.add_service(u, "my-service2", "456", ["tcp", "udp"]) == "ns_allow_my_service2"
    assert u.get_all('firewall', 'ns_allow_my_service2', 'proto') == ("tcp", "udp")

def test_block_service(tmp_path):
    u = _setup_db(tmp_path)
    firewall.add_service(u, "my-service", "443", "tcp")
    assert firewall.remove_service(u, "my-service") == "ns_allow_my_service"
    with pytest.raises(UciExceptionNotFound):
        u.get('firewall', 'ns_allow_my_service')

def test_disable_service(tmp_path):
    u = _setup_db(tmp_path)
    firewall.add_service(u, "my-service", "443", "tcp")
    assert firewall.disable_service(u, "my-service") == "ns_allow_my_service"
    assert u.get("firewall", "ns_allow_my_service", "enabled") == "0"
    assert firewall.disable_service(u, "non-existing") == None

def test_enable_service(tmp_path):
    u = _setup_db(tmp_path)
    firewall.add_service(u, "my-service", "1234", "tcp")
    firewall.disable_service(u, "my-service")
    assert firewall.enable_service(u, "my-service") == "ns_allow_my_service"
    assert u.get("firewall", "ns_allow_my_service", "enabled")
    assert firewall.enable_service(u, "non-existing") == None

def test_add_vpn_interface(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_vpn_interface(u, 'test!vpn', 'tuntest') == 'test_vpn'
    assert u.get('network', 'test_vpn') == 'interface'
    assert u.get('network', 'test_vpn', 'proto') == 'none'
    assert u.get('network', 'test_vpn', 'device') == 'tuntest'
    assert u.get('network', 'test_vpn', 'ns_tag') == 'automated'
    i = firewall.add_vpn_interface(u, 'p2p', 'ppp10', 'torrent/server1')
    assert u.get('network', 'p2p', 'ns_link') == 'torrent/server1'

def test_add_trusted_zone(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_trusted_zone(u, 'toolongnameforzone') == (None, None)

    (zone, forwardings) = firewall.add_trusted_zone(u, 'mytrusted')
    assert zone is not None
    assert len(forwardings) == 3
    assert u.get("firewall", zone) == "zone"
    assert u.get("firewall", zone, 'name') == "mytrusted"
    assert u.get("firewall", zone, 'input') == "ACCEPT"
    assert u.get("firewall", zone, 'output') == "ACCEPT"
    assert u.get("firewall", zone, 'forward') == "REJECT"
    assert u.get("firewall", forwardings[0]) == "forwarding"
    assert u.get("firewall", forwardings[0], 'src') == "mytrusted"
    assert u.get("firewall", forwardings[0], 'dest') == "lan"
    assert u.get("firewall", forwardings[0], 'ns_tag') == "automated"
    assert u.get("firewall", forwardings[1]) == "forwarding"
    assert u.get("firewall", forwardings[1], 'src') == "lan"
    assert u.get("firewall", forwardings[1], 'dest') == "mytrusted"
    assert u.get("firewall", forwardings[1], 'ns_tag') == "automated"
    assert u.get("firewall", forwardings[2]) == "forwarding"
    assert u.get("firewall", forwardings[2], 'src') == "mytrusted"
    assert u.get("firewall", forwardings[2], 'dest') == "wan"
    assert u.get("firewall", forwardings[2], 'ns_tag') == "automated"

    link = 'openvpn/instance1'
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked', link=link)
    assert u.get("firewall", zone, 'ns_link') == link
    assert u.get("firewall", forwardings[0], 'ns_link') == link
    assert u.get("firewall", forwardings[1], 'ns_link') == link
    assert u.get("firewall", forwardings[2], 'ns_link') == link

def test_duplicated_add_trusted_zone(tmp_path):
    u = _setup_db(tmp_path)
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mytrusted')
    assert zone is None
    assert forwardings is None

    trusted = 0
    for s in u.get_all('firewall'):
        if u.get('firewall', s) == 'forwarding':
            if u.get('firewall', s, 'src', default='') == "mytrusted" and u.get('firewall', s, 'dest', default='') == "lan":
                trusted = trusted + 1
    assert trusted == 1
 
def test_add_trusted_zone_with_networks(tmp_path):
    u = _setup_db(tmp_path)
    interface = firewall.add_vpn_interface(u, 'testvpn2', 'tuntest2')
    zone, forwardings = firewall.add_trusted_zone(u, 'mytrusted2', list(interface))
    assert u.get_all("firewall", zone, 'network') == tuple(interface)

def test_apply():
    # Already tested in pyuci
    assert 1

def test_add_template_rule(tmp_path):
    u = _setup_db(tmp_path)
    rule = firewall.add_template_rule(u, 'ns_test_rule', 'tcp', '443', 'test1/key1')
    assert u.get("firewall", rule) == "rule"
    assert u.get("firewall", rule, "proto") == "tcp"
    assert u.get("firewall", rule, "name") == "Test-rule"
    assert u.get("firewall", rule, "src") == "wan"
    assert u.get("firewall", rule, "dest") == "blue"
    assert u.get("firewall", rule, "dest_port") == "443"
    assert u.get("firewall", rule, "enabled") == "1"
    assert u.get("firewall", rule, "target") == "ACCEPT"
    assert u.get("firewall", rule, "ns_tag") == "automated"
    assert u.get("firewall", rule, "ns_link") == "test1/key1"

    rule = firewall.add_template_rule(u, 'ip6_dhcp')
    assert u.get("firewall", rule) == "rule"
    assert u.get("firewall", rule, "proto") == "udp"
    assert u.get("firewall", rule, "name") == "Allow-DHCPv6"
    assert u.get("firewall", rule, "src") == "wan"
    assert u.get("firewall", rule, "dest_port") == "546"
    assert u.get("firewall", rule, "family") == "ipv6"
    assert u.get("firewall", rule, "target") == "ACCEPT"
    assert u.get("firewall", rule, "ns_tag") == "automated"

def test_add_template_zone(tmp_path):
    u = _setup_db(tmp_path)
    (zone, forwardings) = firewall.add_template_zone(u, 'ns_blue', ["lan", "lan2"], link="mydb/mykey" )
    assert zone is not None
    assert u.get("firewall", zone) == "zone"
    assert u.get("firewall", zone, "name") == "blue"
    assert u.get("firewall", zone, "forward") == "DROP"
    assert u.get("firewall", zone, "input") == "DROP"
    assert u.get("firewall", zone, "output") == "ACCEPT"
    assert u.get("firewall", zone, "ns_description") == "Guest network with Internet access"
    assert u.get("firewall", zone, "ns_tag") ==  "automated"
    assert u.get("firewall", zone, "ns_link") ==  "mydb/mykey"
    assert "lan" in u.get("firewall", zone, "network", list=True)
    assert "lan2" in u.get("firewall", zone, "network", list=True)
    assert len(forwardings) == 2
    for f in forwardings:
        assert u.get("firewall", f) == "forwarding"
        assert u.get("firewall", f, "ns_tag") == "automated"
        assert u.get("firewall", f, "src") == "blue" or u.get("firewall", f, "dest") == "blue"
        assert u.get("firewall", f, "ns_link", default='') == "mydb/mykey"
    (zone, forwardings) = firewall.add_template_zone(u, 'ns_blue')
    assert zone is None
    assert forwardings is None

def test_add_template_service_group(tmp_path):
    u = _setup_db(tmp_path)
    sections = firewall.add_template_service_group(u, "ns_web_secure")
    assert len(sections) == 2
    assert u.get("firewall", sections[0]) == "rule"
    assert u.get("firewall", sections[0], "src") == "lan"
    assert u.get("firewall", sections[0], "dest") == "wan"
    assert u.get("firewall", sections[0], "proto") == "tcp"
    assert u.get("firewall", sections[0], "dest_port") == "80,443"
    assert u.get("firewall", sections[0], "ns_tag") ==  "automated"

    assert u.get("firewall", sections[1]) == "rule"
    assert u.get("firewall", sections[1], "src") == "lan"
    assert u.get("firewall", sections[1], "dest") == "wan"
    assert u.get("firewall", sections[1], "proto") == "udp"
    assert u.get("firewall", sections[1], "dest_port") == "53"
    assert u.get("firewall", sections[1], "ns_tag") ==  "automated"

    sections = firewall.add_template_service_group(u, "ns_web_secure", "grey", "orange")
    assert u.get("firewall", sections[0], "src") == "grey"
    assert u.get("firewall", sections[0], "dest") == "orange"
    assert u.get("firewall", sections[0], "proto") == "tcp"
    assert u.get("firewall", sections[1], "proto") == "udp"

    sections = firewall.add_template_service_group(u, "ns_web_secure", "blue", "yellow", link="db/mykey")
    assert u.get("firewall", sections[0], "ns_link") == "db/mykey"
    assert u.get("firewall", sections[1], "ns_link") == "db/mykey"

def test_get_all_linked(tmp_path):
    u = _setup_db(tmp_path)
    link = "mytestdb/mykey"
    sections = firewall.add_template_service_group(u, "ns_web_secure", "blue", "yellow", link=link)
    rule = firewall.add_service(u, "my_service", "443", "tcp", link=link)
    interface = firewall.add_vpn_interface(u, 'p2p', 'ppp10', link=link)
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked2', link=link)
    linked = firewall.get_all_linked(u, link)
    for s in sections:
        assert s in linked['firewall']
    assert rule in linked['firewall']
    assert zone in linked['firewall']
    for f in forwardings:
        assert f in linked['firewall']
    assert interface in linked['network']


def test_disable_linked_rules(tmp_path):
    u = _setup_db(tmp_path)
    link = "mytestdb/mykey"
    sections = firewall.add_template_service_group(u, "ns_web_secure", "blue", "yellow", link=link)
    rule = firewall.add_service(u, "my_service", "443", "tcp", link=link)
    interface = firewall.add_vpn_interface(u, 'p2p', 'ppp10', link=link)
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked4', link=link)
    disabled = firewall.disable_linked_rules(u, link)
    for s in sections:
        assert u.get("firewall", s, "enabled") == "0"
        assert s in disabled
    assert u.get("firewall", rule, "enabled") == "0"
    assert rule in disabled
    assert u.get("firewall", zone, "enabled", default="XX") == "XX" # option must not be set
    assert u.get("network", interface, "enabled", default="XX") == "XX" # option must not be set
    for f in forwardings:
        assert u.get("network", f, "enabled", default="XX") == "XX" # option must not be set

def test_delete_linked_sections(tmp_path):
    u = _setup_db(tmp_path)
    link = "mytestdb/mykey"
    sections = firewall.add_template_service_group(u, "ns_web_secure", "blue", "yellow", link=link)
    rule = firewall.add_service(u, "my_service", "443", "tcp", link=link)
    interface = firewall.add_vpn_interface(u, 'p2p', 'ppp10', link=link)
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked3', link=link)
    deleted = firewall.delete_linked_sections(u, link)
    assert len(deleted) > 0
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", rule)
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", zone)
    with pytest.raises(UciExceptionNotFound):
        for s in sections:
            u.get("firewall", s)
    with pytest.raises(UciExceptionNotFound):
        for f in forwardings:
            u.get("firewall", f)

def test_is_ipv6_enabled(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.is_ipv6_enabled(u) == True
    u.delete("network", 'lan6')
    assert firewall.is_ipv6_enabled(u) == True
    u.delete("network", 'wan6')
    assert firewall.is_ipv6_enabled(u) == True
    u.delete("network", 'vlan6')
    assert firewall.is_ipv6_enabled(u) == True
    u.delete("network", 'wan6b')
    assert firewall.is_ipv6_enabled(u) == True
    u.delete("network", 'wan6c')
    assert firewall.is_ipv6_enabled(u) == False

def test_disable_ipv6_firewall(tmp_path):
    u = _setup_db(tmp_path)
    assert u.get("firewall", "v6rule", "enabled", default="1") == "1"
    firewall.disable_ipv6_firewall(u)
    assert u.get("firewall", "v6rule", "enabled", default="1") == "0"


def test_list_zones(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.list_zones(u)["ns_lan"]["name"] == "lan"
    assert firewall.list_zones(u)["ns_lan"]["input"] == "ACCEPT"
    assert firewall.list_zones(u)["ns_lan"]["output"] == "ACCEPT"
    assert firewall.list_zones(u)["ns_lan"]["forward"] == "ACCEPT"
    assert firewall.list_zones(u)["ns_lan"]["network"] == ("GREEN_1",)
    assert firewall.list_zones(u)["ns_wan"]["name"] == "wan"
    assert firewall.list_zones(u)["ns_wan"]["input"] == "REJECT"
    assert firewall.list_zones(u)["ns_wan"]["output"] == "ACCEPT"
    assert firewall.list_zones(u)["ns_wan"]["forward"] == "REJECT"
    assert firewall.list_zones(u)["ns_wan"]["network"] == ("wan6", "RED_2", "RED_3", "RED_1")


def test_list_forwardings(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.list_forwardings(u)["ns_lan2guests"]["src"] == "lan"
    assert firewall.list_forwardings(u)["ns_lan2guests"]["dest"] == "guests"
    assert firewall.list_forwardings(u)["ns_guests2wan"]["src"] == "guests"
    assert firewall.list_forwardings(u)["ns_guests2wan"]["dest"] == "wan"


def test_add_zone(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_zone(u, "new_zone", "REJECT", "DROP", True, ["lan"], ["lan", "guest"]) == (
        "ns_new_zone", {"ns_new_zone2wan", "ns_new_zone2lan", "ns_lan2new_zone", "ns_guest2new_zone"})
    assert u.get("firewall", "ns_new_zone", "name") == "new_zone"
    assert u.get("firewall", "ns_new_zone", "input") == "REJECT"
    assert u.get("firewall", "ns_new_zone", "output") == "ACCEPT"
    assert u.get("firewall", "ns_new_zone", "forward") == "DROP"
    assert u.get("firewall", "ns_new_zone2wan", "src") == "new_zone"
    assert u.get("firewall", "ns_new_zone2wan", "dest") == "wan"
    assert u.get("firewall", "ns_new_zone2lan", "src") == "new_zone"
    assert u.get("firewall", "ns_new_zone2lan", "dest") == "lan"
    assert u.get("firewall", "ns_lan2new_zone", "src") == "lan"
    assert u.get("firewall", "ns_lan2new_zone", "dest") == "new_zone"
    assert u.get("firewall", "ns_guest2new_zone", "src") == "guest"
    assert u.get("firewall", "ns_guest2new_zone", "dest") == "new_zone"

def test_edit_zone(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.edit_zone(u, "new_zone", "DROP", "ACCEPT", False, ["lan"], ["lan", "guest"]) == (
        "ns_new_zone", {"ns_new_zone2lan", "ns_lan2new_zone", "ns_guest2new_zone"})
    assert u.get("firewall", "ns_new_zone", "name") == "new_zone"
    assert u.get("firewall", "ns_new_zone", "input") == "DROP"
    assert u.get("firewall", "ns_new_zone", "output") == "ACCEPT"
    assert u.get("firewall", "ns_new_zone", "forward") == "ACCEPT"
    assert u.get("firewall", "ns_new_zone2lan", "src") == "new_zone"
    assert u.get("firewall", "ns_new_zone2lan", "dest") == "lan"
    assert u.get("firewall", "ns_lan2new_zone", "src") == "lan"
    assert u.get("firewall", "ns_lan2new_zone", "dest") == "new_zone"
    assert u.get("firewall", "ns_guest2new_zone", "src") == "guest"
    assert u.get("firewall", "ns_guest2new_zone", "dest") == "new_zone"

def test_delete_zone(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.delete_zone(u, "ns_new_zone") == (
        "ns_new_zone", {"ns_new_zone2lan", "ns_guest2new_zone", "ns_lan2new_zone"})
    with pytest.raises(Exception) as e:
        firewall.delete_zone(u, "not_a_zone")

def test_get_rule_by_name(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.get_rule_by_name(u, "Allow-DHCPv6") == (
        "v6rule",
        {"name": "Allow-DHCPv6", "src": "wan", "proto": "udp", "dest_port": "546", "family": "ipv6", "target": "ACCEPT", "enabled": "0"}
    )
    assert firewall.get_rule_by_name(u, "Not-Automated") == (
        "manrule",
        {"name": "Not-Automated", "src": "wan", "proto": "tcp", "dest_port": "1234", "family": "ipv4", "target": "ACCEPT"}
    )
    assert firewall.get_rule_by_name(u, "not_a_rule") == (None, None)
    assert firewall.get_rule_by_name(u, "Not-Automated", "automated") == (None, None)

def test_add_default_ipv6_rules(tmp_path):
    u = _setup_db(tmp_path)
    # one rule should be skipped because it already exists
    assert len(firewall.add_default_ipv6_rules(u)) == 3
    assert firewall.add_default_ipv6_rules(u) == []

def test_resolve_address(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.resolve_address(u, "192.168.100.1") == {"value": "192.168.100.1", "type": "domain", "label": "test.name.org"}
    assert firewall.resolve_address(u, "192.168.100.2") == {"value": "192.168.100.2", "type": "host", "label": "test2.giacomo.org"}
    assert firewall.resolve_address(u, "192.168.100.238") == {"value": "192.168.100.238", "type": "interface", "label": "lan"}
    assert firewall.resolve_address(u, "ac0d:b0e6:ee9e:172e:7f64:ea08:ed22:1543") == {"value": "ac0d:b0e6:ee9e:172e:7f64:ea08:ed22:1543", "type": "domain", "label": "test3.test.org"}
    assert firewall.resolve_address(u, "10.0.0.22") == {"value": "10.0.0.22", "type": "interface", "label": "bond1"}
    assert firewall.resolve_address(u, "2001:db80::2/64") == {"value": "2001:db80::2/64", "type": "interface", "label": "wan6"}

def test_list_forward_rules(tmp_path):
    u = _setup_db(tmp_path)
    rules = firewall.list_forward_rules(u)
    assert len(rules) > 0
    for r in rules:
        # just check that only forwarded rules are returned
        assert r.get("src") and r.get("dest")
        # check all fields are presents
        assert 'log' in r
        assert 'enabled' in r
        assert 'ns_tag' in r
        assert 'proto' in r

def test_list_output_rules(tmp_path):
    u = _setup_db(tmp_path)
    rules = firewall.list_output_rules(u)
    assert len(rules) > 0
    for r in rules:
       # just check that only output rules are returned
       assert r.get("src") is None and r.get("dest")
       # check all fields are presents
       assert 'log' in r
       assert 'enabled' in r
       assert 'ns_tag' in r
       assert 'proto' in r


def test_list_input_rules(tmp_path):
    u = _setup_db(tmp_path)
    rules = firewall.list_input_rules(u)
    assert len(rules) > 0
    for r in rules:
       # just check that only input rules are returned
       assert r.get("dest") is None and r.get("src")
       # check all fields are presents
       assert 'log' in r
       assert 'enabled' in r
       assert 'ns_tag' in r
       assert 'proto' in r

def test_list_service_suggestions(mocker):
    mocker.patch('builtins.open', mocker.mock_open(read_data=services_file))
    mock_isfile = mocker.patch('os.path.isfile')
    mock_isfile.return_value = True
    services = firewall.list_service_suggestions()
    assert len(services) == 5
    assert services == [{'id': 'ftp', 'proto': ['tcp'], 'port': 21}, {'id': 'ssh', 'proto': ['tcp', 'udp'], 'port': 22}, {'id': 'time', 'proto': ['udp'], 'port': 37}, {'id': 'www', 'proto': ['tcp'], 'port': 80}, {'id': 'kerberos', 'proto': ['tcp', 'udp'], 'port': 88}]

def test_list_host_suggestions(mocker, tmp_path):
    u = _setup_db(tmp_path)
    mocker.patch('builtins.open', mocker.mock_open(read_data=lease_file))
    mock_isfile = mocker.patch('os.path.isfile')
    mock_isfile.return_value = True
    suggestions = firewall.list_host_suggestions(u)
    assert len(suggestions) == 8
    assert suggestions == [{'value': '192.168.100.1', 'label': 'test.name.org', 'type': 'domain'}, {'value': '192.168.100.2', 'label': 'test2.giacomo.org', 'type': 'host'}, {'value': 'ac0d:b0e6:ee9e:172e:7f64:ea08:ed22:1543', 'label': 'test3.test.org', 'type': 'domain'}, {'value': '192.168.100.238', 'label': 'lan', 'type': 'network'}, {'value': '2001:db80::2/64', 'label': 'wan6', 'type': 'network'}, {'value': '10.0.0.22', 'label': 'bond1', 'type': 'network'}, {'value': '192.168.1.228', 'label': 'test1', 'type': 'lease'}, {'value': '192.168.1.219', 'label': 'test2', 'type': 'lease'}]

def test_add_rule(tmp_path, mocker):
    u = _setup_db(tmp_path)
    mocker.patch('builtins.open', mocker.mock_open(read_data=services_file))
    mock_isfile = mocker.patch('os.path.isfile')
    mock_isfile.return_value = True
    rid = firewall.add_rule(u, 'myrule', 'lan', ['192.168.1.22'], 'wan', ['1.2.3.4'], ['tcp', 'udp'], '443', 'ACCEPT', "ssh", True, True, ['tag1'], False)
    assert u.get("firewall", rid, "name") == "myrule"
    assert u.get("firewall", rid, "src") == "lan"
    assert u.get("firewall", rid, "dest") == "wan"
    assert u.get_all("firewall", rid, "src_ip") == ("192.168.1.22",)
    assert u.get_all("firewall", rid, "dest_ip") == ("1.2.3.4",)
    assert u.get_all("firewall", rid, "proto") == ('tcp', 'udp')
    assert u.get("firewall", rid, "dest_port") == "22"
    assert u.get("firewall", rid, "target") == "ACCEPT"
    assert u.get("firewall", rid, "ns_service") == "ssh"
    assert u.get("firewall", rid, "enabled") == "1"
    assert u.get("firewall", rid, "log") == "1"
    assert u.get_all("firewall", rid, "ns_tag") == ("tag1",)
    assert u.get("firewall", rid, "ns_link", default="notpresent") == "notpresent"

def test_edit_rule(tmp_path, mocker):
    u = _setup_db(tmp_path)
    mocker.patch('builtins.open', mocker.mock_open(read_data=services_file))
    mock_isfile = mocker.patch('os.path.isfile')
    mock_isfile.return_value = True
    rid = firewall.add_rule(u, 'myrule2', 'lan', ['192.168.1.22'], 'wan', ['1.2.3.4'], ['tcp', 'udp'], '22', 'ACCEPT', "ssh", True, True, ['tag1'], False)
    with pytest.raises(ValidationError):
        firewall.edit_rule(u, 'notpresent', 'myrule3', 'lan', [], 'wan', [], [], '', 'ACCEPT', None, True, True, ['tag1'])
    rid2 = firewall.edit_rule(u, rid, 'myrule3', 'lan', [], 'blue', [], ['udp'], '22', 'DROP', "", False, False, ['tag2'])
    assert rid == rid2
    assert u.get("firewall", rid, "name") == "myrule3"
    assert u.get("firewall", rid, "src") == "lan"
    assert u.get("firewall", rid, "dest") == "blue"
    with pytest.raises(UciExceptionNotFound):
        u.get_all("firewall", rid, "src_ip")
    with pytest.raises(UciExceptionNotFound):
        u.get_all("firewall", rid, "dest_ip")
    with pytest.raises(UciExceptionNotFound):
        u.get_all("firewall", rid, "proto")
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", rid, "dest_port") == "22"
    assert u.get("firewall", rid, "target") == "DROP"
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", rid, "ns_service")
    assert u.get("firewall", rid, "enabled") == "0"
    assert u.get("firewall", rid, "log") == "0"
    assert u.get_all("firewall", rid, "ns_tag") == ("tag2",)
    rid3 = firewall.edit_rule(u, rid, 'myrule3', 'lan', [], 'blue', [], ['udp'], '22', 'DROP', "www", False, False, ['tag2'])
    assert u.get("firewall", rid, "ns_service") == "www"
    assert u.get_all("firewall", rid, "proto") == ('tcp',)
    assert u.get("firewall", rid, "dest_port") == "80"

def test_delete_rule(tmp_path):
    u = _setup_db(tmp_path)
    ids =  firewall.list_rule_ids(u)
    id_to_delete = ids.pop()
    firewall.delete_rule(u, id_to_delete)
    assert id_to_delete not in firewall.list_rule_ids(u)

def test_disable_rule(tmp_path):
    u = _setup_db(tmp_path)
    ids =  firewall.list_rule_ids(u)
    id_to_disable = ids.pop()
    firewall.disable_rule(u, id_to_disable)
    assert u.get("firewall", id_to_disable, "enabled") == "0"

def test_enable_rule(tmp_path):
    u = _setup_db(tmp_path)
    ids =  firewall.list_rule_ids(u)
    id_to_enable = ids.pop()
    firewall.disable_rule(u, id_to_enable)
    assert u.get("firewall", id_to_enable, "enabled") == "0"
    firewall.enable_rule(u, id_to_enable)
    assert u.get("firewall", id_to_enable, "enabled") == "1"

def test_order_rules(tmp_path, mocker):
    # The firewall.order_rules function uses the uci binary to reorder the rules
    # The test is usefull because uci behaves differently on a real machine
    assert True

def test_list_nat_rules(tmp_path):
    u = _setup_db(tmp_path)
    names = []
    for r in firewall.list_nat_rules(u):
        names.append(r.get("name"))
    assert "source_NAT1_vpm" in names
    assert "masquerade" in names
    assert "cdn_via_router" in names
    assert "SNAT_NSEC7_style" in names
    assert "Allow-DHCPv6" not in names
    
def test_add_nat_rule(tmp_path):
    u = _setup_db(tmp_path)
    id1 = firewall.add_nat_rule(u, "myrule", "SNAT", "lan", "1.2.3.4", "6.7.8.9", "1.1.1.1")
    assert u.get("firewall", id1, "name") == "myrule"
    assert u.get("firewall", id1, "target") == "SNAT"
    assert u.get("firewall", id1, "src") == "lan"
    assert u.get("firewall", id1, "src_ip") == "1.2.3.4"
    assert u.get("firewall", id1, "dest_ip") == "6.7.8.9"
    assert u.get_all("firewall", id1, "proto") == ("all",)
    with pytest.raises(ValidationError):
        firewall.add_nat_rule(u, "myrule", "REJECT")
    id2 = firewall.add_nat_rule(u, "myrule3", "ACCEPT", dest_ip="1.2.3.4")
    assert u.get("firewall", id2, "target") == "ACCEPT"
    assert u.get("firewall", id2, "dest_ip") == "1.2.3.4"
    assert u.get_all("firewall", id2, "proto") == ("all",)
    assert u.get("firewall", id2, "src") == "*"
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", id2, "src_ip")

def test_edit_nat_rule(tmp_path):
    u = _setup_db(tmp_path)
    id = firewall.add_nat_rule(u, "myrule4", "SNAT", "lan", "1.2.3.4", "6.7.8.9", "1.1.1.1")
    firewall.edit_nat_rule(u, id, "myrule4b", "SNAT", "lan", "1.2.3.4", "6.7.8.9", "3.3.3.3")
    assert u.get("firewall", id, "name") == "myrule4b"
    assert u.get("firewall", id, "snat_ip") == "3.3.3.3"
    assert u.get("firewall", id, "src_ip") == "1.2.3.4"
    assert u.get("firewall", id, "dest_ip") == "6.7.8.9"
    assert u.get("firewall", id, "target") == "SNAT"
    assert u.get_all("firewall", id, "proto") == ("all",)
    assert u.get("firewall", id, "src") == "lan"

def test_delete_nat_rule(tmp_path):
    u = _setup_db(tmp_path)
    with pytest.raises(ValidationError):
        firewall.delete_nat_rule(u, "notpresent")
    id = firewall.add_nat_rule(u, "myrule5", "SNAT", "lan", "1.2.3.4", "6.7.8.9", "1.1.1.1")
    assert firewall.delete_rule(u, id) == id
