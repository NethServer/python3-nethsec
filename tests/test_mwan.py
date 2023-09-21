import pathlib

import pytest
from euci import EUci

from nethsec import mwan

network_db = """
config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config interface 'GREEN_1'
        option proto 'static'
        option device 'eth0'
        option ipaddr '192.168.200.2'
        option netmask '255.255.255.0'

config interface 'RED_1'
        option proto 'static'
        option device 'eth1'
        option ipaddr '10.0.0.2'
        option netmask '255.255.255.0'
        option gateway '10.0.0.1'

config interface 'RED_2'
        option proto 'static'
        option device 'eth2'
        option ipaddr '10.0.1.2'
        option netmask '255.255.255.0'
        option gateway '10.0.1.1'

config interface 'RED_3'
        option proto 'static'
        option device 'eth3'
        option ipaddr '10.0.2.2'
        option netmask '255.255.255.0'
        option gateway '10.0.2.1'

config device
        option name 'eth0'

config device
        option name 'eth1'

config device
        option name 'eth2'

config device
        option name 'eth3'
"""

ns_api_db = """
config defaults_mwan 'defaults_mwan'
        option initial_state 'online'
        option protocol 'ipv4'
        list track_ip '8.8.8.8'
        list track_ip '208.67.222.222'
        option tracking_method 'ping'
        option tracking_reliability '1'
        option ping_count '1'
        option ping_size '56'
        option ping_max_ttl '60'
        option ping_timeout '4'
        option ping_interval '10'
        option ping_failure_interval '5'
        option ping_recovery_interval '5'
        option interface_down_threshold '5'
        option interface_up_threshold '5'
        option link_quality '0'
        option quality_failure_latency '1000'
        option quality_failure_packet_loss '40'
        option quality_recovery_latency '500'
        option quality_recovery_packet_loss '10'
"""


@pytest.fixture
def e_uci(tmp_path: pathlib.Path) -> EUci:
    conf_dir = tmp_path.joinpath('conf')
    conf_dir.mkdir()
    save_dir = tmp_path.joinpath('save')
    save_dir.mkdir()
    with conf_dir.joinpath('network').open('w') as fp:
        fp.write(network_db)
    with conf_dir.joinpath('ns-api').open('w') as fp:
        fp.write(ns_api_db)
    with conf_dir.joinpath('mwan3').open('w') as fp:
        fp.write('')
    return EUci(confdir=conf_dir.as_posix(), savedir=save_dir.as_posix())


def test_create_interface(e_uci):
    assert mwan.__store_interface(e_uci, 'RED_1') == (True, True)
    assert mwan.__store_interface(e_uci, 'RED_2') == (True, True)
    # assert every interface has defaults
    assert e_uci.get('mwan3', 'RED_1') == 'interface'
    assert e_uci.get('mwan3', 'RED_1', 'enabled') == '1'
    assert e_uci.get('mwan3', 'RED_1', 'initial_state') == 'online'
    assert e_uci.get('mwan3', 'RED_1', 'family') == 'ipv4'
    assert e_uci.get('mwan3', 'RED_1', 'track_ip', list=True) == ('8.8.8.8', '208.67.222.222')
    assert e_uci.get('mwan3', 'RED_1', 'track_method') == 'ping'
    assert e_uci.get('mwan3', 'RED_1', 'reliability') == '1'
    assert e_uci.get('mwan3', 'RED_1', 'count') == '1'
    assert e_uci.get('mwan3', 'RED_1', 'size') == '56'
    assert e_uci.get('mwan3', 'RED_1', 'max_ttl') == '60'
    assert e_uci.get('mwan3', 'RED_1', 'timeout') == '4'
    assert e_uci.get('mwan3', 'RED_1', 'interval') == '10'
    assert e_uci.get('mwan3', 'RED_1', 'failure_interval') == '5'
    assert e_uci.get('mwan3', 'RED_1', 'recovery_interval') == '5'
    assert e_uci.get('mwan3', 'RED_1', 'down') == '5'
    assert e_uci.get('mwan3', 'RED_1', 'up') == '5'
    # assert interface has metric
    assert e_uci.get('network', 'RED_1', 'metric') == '1'
    assert e_uci.get('network', 'RED_2', 'metric') == '2'
    assert mwan.__store_interface(e_uci, 'RED_1') == (False, False)


def test_fail_create_invalid_interface(e_uci):
    with pytest.raises(ValueError):
        mwan.__store_interface(e_uci, 'RED_4')


def test_interface_avoid_edit_of_metric(e_uci):
    e_uci.set('network', 'RED_1', 'metric', '10')
    assert mwan.__store_interface(e_uci, 'RED_1') == (True, False)


def test_create_member(e_uci):
    assert mwan.__store_member(e_uci, 'RED_1', 10, 100) == ('mwan3.ns_RED_1_M10_W100', True)
    assert mwan.__store_member(e_uci, 'RED_1', 10, 100) == ('mwan3.ns_RED_1_M10_W100', False)
    assert mwan.__store_member(e_uci, 'RED_1', 1, 100) == ('mwan3.ns_RED_1_M1_W100', True)


def test_create_default_mwan(e_uci):
    assert mwan.store_policy(e_uci, 'default', [
        {
            'name': 'RED_1',
            'metric': '10',
            'weight': '200',
        },
        {
            'name': 'RED_2',
            'metric': '20',
            'weight': '100',
        }
    ]) == ['mwan3.ns_default',
           'mwan3.RED_1',
           'network.RED_1',
           'mwan3.ns_RED_1_M10_W200',
           'mwan3.RED_2',
           'network.RED_2',
           'mwan3.ns_RED_2_M20_W100']

    assert e_uci.get('mwan3', 'ns_default') == 'policy'
    assert e_uci.get('mwan3', 'ns_default', 'name') == 'default'
    assert e_uci.get('mwan3', 'ns_default', 'use_member', list=True) == (
        'mwan3.ns_RED_1_M10_W100', 'mwan3.ns_RED_2_M10_W100')


def test_create_unique_mwan(e_uci):
    mwan.store_policy(e_uci, 'this', [])
    with pytest.raises(ValueError):
        mwan.store_policy(e_uci, 'this', [])


def test_metric_generation(e_uci):
    assert mwan.__generate_metric(e_uci) == 1
    assert mwan.__generate_metric(e_uci, [1, 4]) == 2
    assert mwan.__generate_metric(e_uci, [1, 2, 4]) == 3
    assert mwan.__generate_metric(e_uci, [4, 3, 1]) == 2
