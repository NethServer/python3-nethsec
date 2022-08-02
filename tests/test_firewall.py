from euci import EUci
from nextsec import firewall
from unittest.mock import MagicMock, patch

# Setup fake ip command output
ip_json='[{"ifindex":9,"ifname":"vnet3","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","master":"virbr2","operstate":"UNKNOWN","group":"default","txqlen":1000,"link_type":"ether","address":"fe:62:31:19:0b:29","broadcast":"ff:ff:ff:ff:ff:ff","addr_info":[{"family":"inet6","local":"fe80::fc62:31ff:fe19:b29","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]'
mock_ip_stdout = MagicMock()
mock_ip_stdout.configure_mock(**{"stdout": ip_json})

@patch("nextsec.firewall.subprocess.run")
def test_get_device_name_valid(mock_run):
    # setup mock
    mock_run.return_value = mock_ip_stdout

    assert firewall.get_device_name("fe:62:31:19:0b:29") == 'vnet3'

def test_get_device_name_not_valid():
    assert firewall.get_device_name("aa:bb:cc:dd:66:55") == None

@patch("nextsec.firewall.subprocess.run")
def test_get_interface_name(mock_run2, tmp_path):
    # setup fake network db
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write("""
config interface lan
	option device 'vnet3'
""")

    # setup mock
    mock_run2.return_value = mock_ip_stdout

    u = EUci(confdir=tmp_path.as_posix())
    assert firewall.get_interface_name(u, "fe:62:31:19:0b:29") == 'lan'
    assert firewall.get_interface_name(u, "aa:bb:cc:dd:66:55") == None
