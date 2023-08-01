import pytest
from nethsec import utils
from euci import EUci
from unittest.mock import MagicMock, patch

# Setup fake ip command output
ip_json='[{"ifindex":9,"ifname":"vnet3","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","master":"virbr2","operstate":"UNKNOWN","group":"default","txqlen":1000,"link_type":"ether","address":"fe:62:31:19:0b:29","broadcast":"ff:ff:ff:ff:ff:ff","addr_info":[{"family":"inet6","local":"fe80::fc62:31ff:fe19:b29","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]'
mock_ip_stdout = MagicMock()
mock_ip_stdout.configure_mock(**{"stdout": ip_json})

test_db = """
config mytype section1
	option name 'myname1'
	option opt2 'value2'

config mytype section2
	option name 'myname2'
	list opt1 'val1'
	list opt1 'val2'
	option opt2 'value2'

config mytype2 section3
	option name 'myname3'
"""

firewall_db = """
config zone wan1
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
	list device 'eth2.1'

config zone
	option name 'lan'
	list network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
"""

network_db = """
config interface lan
	option device 'vnet3'
	option proto 'static'

config device
	option type '8021q'
	option ifname 'eth2'
	option vid '1'
	option name 'eth2.1'

config interface 'wan'
	option device 'eth1'
	option proto 'dhcp'

config interface 'wan6'
	option device 'eth1'
	option proto 'dhcpv6'
"""

objects_db = """
config user 'goofy'
	option name "Goofy"
	option description 'Goofy Doe'
	list macaddr '52:54:00:9d:3d:e5'
	list ipaddr '192.168.100.23'
	list domain 'ns_goofy_name'
	list host 'ns_goofy_pc'
	list vpn 'goofy'

config user 'daisy'
	option name "Daisy"
	list ipaddr '192.168.100.22'
	list ipaddr '2001:db8:3333:4444:5555:6666:7777:8888'

config group 'vip'
	option description 'Very Important People'
	list user 'goofy'
	list user 'daisy'
"""

dhcp_db = """
config host 'ns_goofy_pc'
	option name 'goofypc'
    option mac '00:00:8c:16:b3:bd'
    option ip '192.168.100.36'
    option dns '1'

config domain 'ns_goofy_pc_nethserver_org'
	option ip '192.168.100.30'
    option name 'goofy.nethserver.org'
    option description 'Goofy Workstation'
"""

openvpn_db = """
config user 'goofy'
    option instance 'ns_roadwarrior'
    option ipaddr '10.9.9.38'
    option enabled '1'
"""

def _setup_db(tmp_path):
     # setup fake db
    with tmp_path.joinpath('test').open('w') as fp:
        fp.write(test_db)
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
    with tmp_path.joinpath('objects').open('w') as fp:
        fp.write(objects_db)
    with tmp_path.joinpath('dhcp').open('w') as fp:
        fp.write(dhcp_db)
    with tmp_path.joinpath('openvpn').open('w') as fp:
        fp.write(openvpn_db)
    return EUci(confdir=tmp_path.as_posix())

def test_sanitize():
    assert utils.sanitize("good") == "good"
    assert utils.sanitize("with-dash") == "with_dash"
    assert utils.sanitize('$%_()') == '_____'
    assert utils.sanitize('UPPER') == 'UPPER'
    assert utils.sanitize('numb3r') == 'numb3r'
    assert utils.sanitize('newline\n') == 'newline_'
    assert utils.sanitize('newline\r') == 'newline_'

def test_get_id():
    assert utils.get_id('no-good') == 'ns_no_good'
    assert utils.get_id('nospace ') == 'ns_nospace_'
    assert utils.get_id('t1234') == 'ns_t1234'
    # str with 97 chars
    long_str = "ihTSEf2Y5rl8TX96pWFFPMty9LFgH3GezhVueGoDB6_aaIFhDSKe1ZR64cV41iSVhfrm5wJCUPFfMGx2fBZyhDIW9cl9SCI43"
    assert utils.get_id(long_str) == f'ns_{long_str}'
    assert utils.get_id(long_str+"123") == f'ns_{long_str}'

def test_get_id_lenght():
    assert utils.get_id("123456789012345", 15) == "ns_123456789012"

def test_get_all_by_type(tmp_path):
    u = _setup_db(tmp_path)
    records = utils.get_all_by_type(u, 'test', 'mytype')
    assert records != None
    assert 'section1' in records.keys()
    assert 'section2' in records.keys()
    assert 'section3' not in records.keys()
    assert records['section1']['name'] == 'myname1'
    assert records['section2']['name'] == 'myname2'
    assert records['section2']['opt1'] == ('val1', 'val2')

@patch("nethsec.utils.subprocess.run")
def test_get_device_name_valid(mock_run):
    # setup mock
    mock_run.return_value = mock_ip_stdout

    assert utils.get_device_name("fe:62:31:19:0b:29") == 'vnet3'

def test_get_device_name_not_valid():
    assert utils.get_device_name("aa:bb:cc:dd:66:55") == None

@patch("nethsec.utils.subprocess.run")
def test_get_interface_from_mac(mock_run2, tmp_path):
    # setup mock
    mock_run2.return_value = mock_ip_stdout
    u = _setup_db(tmp_path)

    assert utils.get_interface_from_mac(u, "fe:62:31:19:0b:29") == 'lan'
    assert utils.get_interface_from_mac(u, "aa:bb:cc:dd:66:55") == None

def test_get_interface_from_device(tmp_path):
    u = _setup_db(tmp_path)

    assert utils.get_interface_from_device(u, "vnet3") == 'lan'
    assert utils.get_interface_from_device(u, "vnet4") == None

def test_get_all_by_option(tmp_path):
    u = _setup_db(tmp_path)
    return_map = {"section1": u.get_all("test", "section1"), "section2": u.get_all("test", "section2")}
    assert(utils.get_all_by_option(u, 'test', 'opt2', 'value2') == return_map)

def test_get_all_wan_devices(tmp_path):
    u = _setup_db(tmp_path)
    assert(set(utils.get_all_wan_devices(u)) == set(['eth1', 'eth2.1']))

def test_get_all_lan_devices(tmp_path):
    u = _setup_db(tmp_path)
    assert(set(utils.get_all_lan_devices(u)) == set(['vnet3']))

def test_get_user_addresses(tmp_path):
    u = _setup_db(tmp_path)
    (ipv4, ipv6) = utils.get_user_addresses(u, 'goofy')
    for ip in ipv4:
        assert(ip in ["192.168.100.36", "10.9.9.38", "192.168.100.30", "192.168.100.23"])
    (ipv4, ipv6) = utils.get_user_addresses(u, 'daisy')
    assert(ipv6 == ["2001:db8:3333:4444:5555:6666:7777:8888"])

def test_get_user_macs(tmp_path):
    u = _setup_db(tmp_path)
    assert(utils.get_user_macs(u, 'goofy') == ["52:54:00:9d:3d:e5"])
    assert(utils.get_user_macs(u, 'daisy') == [])

def test_get_group_addresses(tmp_path):
    u = _setup_db(tmp_path)
    (ipv4, ipv6) = utils.get_group_addresses(u, 'vip')
    for ip in ipv4:
        assert(ip in ["192.168.100.36", "10.9.9.38", "192.168.100.30", "192.168.100.23", "192.168.100.22"])
    assert(ipv6 == ["2001:db8:3333:4444:5555:6666:7777:8888"])

def test_get_group_macs(tmp_path):
    u = _setup_db(tmp_path)
    assert(utils.get_group_macs(u, 'vip') == ["52:54:00:9d:3d:e5"])

def test_get_random_id():
    id1 = utils.get_random_id()
    id2 = utils.get_random_id()
    assert len(id1) == 11
    assert id1[0:3] == "ns_"
    assert id1 != id2
