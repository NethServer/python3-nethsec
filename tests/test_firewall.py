import pytest
from euci import EUci, UciExceptionNotFound

from nethsec import firewall

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

config template_rule 'ip6_dhcp'
	option name 'Allow-DHCPv6'
	option src 'wan'
	option proto 'udp'
	option dest_port '546'
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

def _setup_db(tmp_path):
     # setup fake dbs
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
        fp.write(zone_testing_db)
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
    with tmp_path.joinpath('templates').open('w') as fp:
        fp.write(templates_db)
    return EUci(confdir=tmp_path.as_posix())

def test_add_interface_to_zone(tmp_path):
    u = _setup_db(tmp_path)
    z1 = firewall.add_interface_to_zone(u, "interface1", "lan")
    assert z1 == 'lan1'
    assert 'interface1' in u.get_all('firewall', 'lan1', 'network')
    assert firewall.add_interface_to_zone(u, "interface1", "blue") == None
    z1 = firewall.add_interface_to_zone(u, "interface2", "lan")
    assert 'interface2' in u.get_all('firewall', 'lan1', 'network')

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
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked', link=link)
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
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked', link=link)
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
    (zone, forwardings) = firewall.add_trusted_zone(u, 'mylinked', link=link)
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
