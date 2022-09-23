import pytest
from nextsec import utils
from euci import EUci
from unittest.mock import MagicMock, patch

# Setup fake ip command output
ip_json='[{"ifindex":9,"ifname":"vnet3","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","master":"virbr2","operstate":"UNKNOWN","group":"default","txqlen":1000,"link_type":"ether","address":"fe:62:31:19:0b:29","broadcast":"ff:ff:ff:ff:ff:ff","addr_info":[{"family":"inet6","local":"fe80::fc62:31ff:fe19:b29","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]'
mock_ip_stdout = MagicMock()
mock_ip_stdout.configure_mock(**{"stdout": ip_json})

test_db = """
config mytype section1
	option name 'myname1'

config mytype section2
	option name 'myname2'
	list opt1 'val1'
	list opt1 'val2'

config mytype2 section3
	option name 'myname3'
"""

network_db = """
config interface lan
	option device 'vnet3'
	option proto 'static'
"""

def _setup_db(tmp_path):
     # setup fake db
    with tmp_path.joinpath('test').open('w') as fp:
        fp.write(test_db)
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
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

@patch("nextsec.utils.subprocess.run")
def test_get_device_name_valid(mock_run):
    # setup mock
    mock_run.return_value = mock_ip_stdout

    assert utils.get_device_name("fe:62:31:19:0b:29") == 'vnet3'

def test_get_device_name_not_valid():
    assert utils.get_device_name("aa:bb:cc:dd:66:55") == None

@patch("nextsec.utils.subprocess.run")
def test_get_interface_name(mock_run2, tmp_path):
    # setup mock
    mock_run2.return_value = mock_ip_stdout
    u = _setup_db(tmp_path)

    assert utils.get_interface_name(u, "fe:62:31:19:0b:29") == 'lan'
    assert utils.get_interface_name(u, "aa:bb:cc:dd:66:55") == None
