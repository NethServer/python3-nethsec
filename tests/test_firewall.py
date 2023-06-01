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
"""

def _setup_db(tmp_path):
     # setup fake dbs
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
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
