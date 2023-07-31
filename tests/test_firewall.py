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

config zone wan1
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
"""

ns_api_db = """
# Service groups
config default_service_group 'ns_web_secure'
	option name 'Secure web navigation'
	list services '80/tcp/HTTP'
	list services '443/tcp/HTTP Secure'
	list services '53/udp/DNS'

# Blue zone
config default_zone 'ns_blue'
	option name 'blue'
	option forward 'DROP'
	option input 'DROP'
	option output 'ACCEPT'
	option ns_description 'Guest network with Internet access'
    list forwardings 'ns_blue2wan'
    list forwardings 'ns_blue2lan'
	# requires network option

config default_forwarding 'ns_blue2wan'
	option src 'blue'
	option dest 'wan'

config default_forwarding 'ns_blue2lan'
	option src 'blue'
	option dest 'lan'

# Default rule
config default_rule 'ns_allow_ui'
	option name 'Allow-ui'
	option src 'wan'
	option dest_port '__PORT__'
	option proto '__PROTO__'
	option target 'ACCEPT'
	option enabled '1'
"""

def _setup_db(tmp_path):
     # setup fake dbs
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
    with tmp_path.joinpath('ns-api').open('w') as fp:
        fp.write(ns_api_db)
    return EUci(confdir=tmp_path.as_posix())

def test_add_to_zone(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_to_zone(u, "vnet1", "lan") == 'lan1'
    assert 'vnet1' in u.get_all('firewall', 'lan1', 'device')
    assert firewall.add_to_zone(u, "vnet1", "blue") == None

def test_add_to_lan(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_to_lan(u, "vnet1") == 'lan1'
    assert 'vnet1' in u.get_all('firewall', 'lan1', 'device')

def test_add_to_wan(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_to_wan(u, "vnet2") == 'wan1'
    assert 'vnet2' in u.get_all('firewall', 'wan1', 'device')

def test_add_service(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_service(u, "my-service", "1234", "tcp") == "ns_allow_my_service"
    assert u.get('firewall', 'ns_allow_my_service', 'dest_port') == '1234'
    assert u.get('firewall', 'ns_allow_my_service', 'proto') == 'tcp'
    assert u.get('firewall', 'ns_allow_my_service', 'src') == 'wan'
    assert u.get('firewall', 'ns_allow_my_service', 'name') == 'Allow-my-service'

    assert firewall.add_service(u, "my-service2", "456", ["tcp", "udp"]) == "ns_allow_my_service2"
    assert u.get_all('firewall', 'ns_allow_my_service2', 'proto') == ("tcp", "udp")

def test_block_service(tmp_path):
    u = _setup_db(tmp_path)
    firewall.add_service(u, "my-service", "1234", "tcp")
    assert firewall.remove_service(u, "my-service") == "ns_allow_my_service"
    with pytest.raises(UciExceptionNotFound):
        u.get('firewall', 'ns_allow_my_service')

def test_disable_service(tmp_path):
    u = _setup_db(tmp_path)
    firewall.add_service(u, "my-service", "1234", "tcp")
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
    assert firewall.add_vpn_interface(u, 'testvpn', 'tuntest') == 'ns_testvpn'
    assert u.get('network', 'ns_testvpn') == 'interface'
    assert u.get('network', 'ns_testvpn', 'proto') == 'none'
    assert u.get('network', 'ns_testvpn', 'device') == 'tuntest'

def test_add_trusted_zone(tmp_path):
    u = _setup_db(tmp_path)
    assert firewall.add_trusted_zone(u, 'toolongnameforzone') == None

    assert firewall.add_trusted_zone(u, 'mytrusted') == 'ns_mytrusted'
    assert u.get("firewall", "ns_mytrusted") == "zone"
    assert u.get("firewall", "ns_mytrusted", 'name') == "mytrusted"
    assert u.get("firewall", "ns_mytrusted", 'input') == "ACCEPT"
    assert u.get("firewall", "ns_mytrusted", 'output') == "ACCEPT"
    assert u.get("firewall", "ns_mytrusted", 'forward') == "REJECT"
    assert u.get("firewall", "ns_mytrusted2lan") == "forwarding"
    assert u.get("firewall", "ns_mytrusted2lan", 'src') == "mytrusted"
    assert u.get("firewall", "ns_mytrusted2lan", 'dest') == "lan"
    assert u.get("firewall", "ns_mytrusted2wan") == "forwarding"
    assert u.get("firewall", "ns_mytrusted2wan", 'src') == "mytrusted"
    assert u.get("firewall", "ns_mytrusted2wan", 'dest') == "wan"

def test_add_trusted_zone_with_networks(tmp_path):
    u = _setup_db(tmp_path)
    interface = firewall.add_vpn_interface(u, 'testvpn2', 'tuntest2')
    zone = firewall.add_trusted_zone(u, 'mytrusted2', list(interface))
    assert u.get_all("firewall", zone, 'network') == tuple(interface)

def test_apply():
    # Already tested in pyuci
    assert 1

def test_add_default_rule(tmp_path):
    u = _setup_db(tmp_path)
    rule = firewall.add_default_rule(u, 'ns_allow_ui', 'tcp', '443')
    print(rule)
    assert u.get("firewall", rule) == "rule"
    assert u.get("firewall", rule, "proto") == "tcp"
    assert u.get("firewall", rule, "name") == "Allow-ui"
    assert u.get("firewall", rule, "src") == "wan"
    assert u.get("firewall", rule, "dest_port") == "443"
    assert u.get("firewall", rule, "enabled") == "1"
    assert u.get("firewall", rule, "target") == "ACCEPT"
    assert u.get("firewall", rule, "ns_tag") == "automated"

def test_add_default_zone(tmp_path):
    u = _setup_db(tmp_path)
    (zone, forwardings) = firewall.add_default_zone(u, 'ns_blue', ["lan", "lan2"] )
    assert zone is not None
    assert u.get("firewall", zone) == "zone"
    assert u.get("firewall", zone, "name") == "blue"
    assert u.get("firewall", zone, "forward") == "DROP"
    assert u.get("firewall", zone, "input") == "DROP"
    assert u.get("firewall", zone, "output") == "ACCEPT"
    assert u.get("firewall", zone, "ns_description") == "Guest network with Internet access"
    assert u.get("firewall", zone, "ns_tag") ==  "automated"
    assert "lan" in u.get("firewall", zone, "network", list=True)
    assert "lan2" in u.get("firewall", zone, "network", list=True)
    assert len(forwardings) == 2
    for f in forwardings:
        assert u.get("firewall", f) == "forwarding"
        assert u.get("firewall", f, "ns_tag") == "automated"
        assert u.get("firewall", f, "src") == "blue" or u.get("firewall", f, "dest") == "blue"
    (zone, forwardings) = firewall.add_default_zone(u, 'ns_blue')
    assert zone is None
    assert forwardings is None

def test_allow_default_service_group(tmp_path):
    u = _setup_db(tmp_path)
    sections = firewall.add_default_service_group(u, "ns_web_secure")
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
    
    sections = firewall.add_default_service_group(u, "ns_web_secure", "grey", "orange")
    assert u.get("firewall", sections[0], "src") == "grey"
    assert u.get("firewall", sections[0], "dest") == "orange"
    assert u.get("firewall", sections[0], "proto") == "tcp"
    assert u.get("firewall", sections[1], "proto") == "udp"
