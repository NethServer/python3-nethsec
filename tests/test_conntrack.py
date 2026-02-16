from subprocess import CalledProcessError
from xml.etree import ElementTree

import pytest
from pytest_mock import MockFixture

from nethsec import conntrack

conntrack_response = """<?xml version="1.0" encoding="utf-8"?>
<conntrack>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.234</src>
                <dst>31.14.133.122</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>41692</sport>
                <dport>123</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>31.14.133.122</src>
                <dst>192.168.122.234</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>123</sport>
                <dport>41692</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <timeout>47</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>1905826093</id>
        </meta>
    </flow>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.1</src>
                <dst>192.168.122.155</dst>
            </layer3>
            <layer4 protonum="1" protoname="icmp"></layer4>
            <counters>
                <packets>2</packets>
                <bytes>168</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.155</src>
                <dst>192.168.122.1</dst>
            </layer3>
            <layer4 protonum="1" protoname="icmp"></layer4>
            <counters>
                <packets>2</packets>
                <bytes>168</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <timeout>29</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>2860343346</id>
        </meta>
    </flow>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.234</src>
                <dst>212.6.50.243</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>45538</sport>
                <dport>123</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>212.6.50.243</src>
                <dst>192.168.122.234</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>123</sport>
                <dport>45538</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <timeout>48</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>3555926027</id>
        </meta>
    </flow>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.1</src>
                <dst>192.168.122.155</dst>
            </layer3>
            <layer4 protonum="6" protoname="tcp">
                <sport>36578</sport>
                <dport>22</dport>
            </layer4>
            <counters>
                <packets>73</packets>
                <bytes>7057</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.155</src>
                <dst>192.168.122.1</dst>
            </layer3>
            <layer4 protonum="6" protoname="tcp">
                <sport>22</sport>
                <dport>36578</dport>
            </layer4>
            <counters>
                <packets>54</packets>
                <bytes>10046</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <state>ESTABLISHED</state>
            <timeout>7440</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>1285239412</id>
            <assured/>
        </meta>
    </flow>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.234</src>
                <dst>93.49.6.247</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>50183</sport>
                <dport>123</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>93.49.6.247</src>
                <dst>192.168.122.234</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>123</sport>
                <dport>50183</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <timeout>1</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>3307146984</id>
        </meta>
    </flow>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.1</src>
                <dst>192.168.122.255</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>57621</sport>
                <dport>57621</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>72</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.255</src>
                <dst>192.168.122.1</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>57621</sport>
                <dport>57621</dport>
            </layer4>
            <counters>
                <packets>0</packets>
                <bytes>0</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <timeout>41</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>3294787936</id>
            <unreplied/>
        </meta>
    </flow>
    <flow>
        <meta direction="original">
            <layer3 protonum="2" protoname="ipv4">
                <src>192.168.122.234</src>
                <dst>212.45.144.206</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>41960</sport>
                <dport>123</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="reply">
            <layer3 protonum="2" protoname="ipv4">
                <src>212.45.144.206</src>
                <dst>192.168.122.234</dst>
            </layer3>
            <layer4 protonum="17" protoname="udp">
                <sport>123</sport>
                <dport>41960</dport>
            </layer4>
            <counters>
                <packets>1</packets>
                <bytes>76</bytes>
            </counters>
        </meta>
        <meta direction="independent">
            <timeout>48</timeout>
            <mark>16128</mark>
            <use>1</use>
            <id>1915971940</id>
        </meta>
    </flow>
</conntrack>
"""


def test_connection_info():
    # get the first flow
    flow = ElementTree.fromstring(conntrack_response).findall('flow')[0]
    result = conntrack.__parse_connection_info(flow)
    original = flow[0]
    reply = flow[1]
    assert result['source'] == '192.168.122.234'
    assert result['destination'] == '31.14.133.122'
    assert result['protocol'] == 'udp'
    assert result['source_port'] == '41692'
    assert result['destination_port'] == '123'
    assert result['source_stats']['packets'] == 1
    assert result['source_stats']['bytes'] == 76
    assert result['destination_stats']['packets'] == 1
    assert result['destination_stats']['bytes'] == 76
    assert result['timeout'] == '47'
    assert result['id'] == '1905826093'
    flow = ElementTree.fromstring(conntrack_response).findall('flow')[1]
    result = conntrack.__parse_connection_info(flow)
    assert 'source_port' not in result
    assert 'destination_port' not in result


def test_fetch_connection_list(mocker: MockFixture):
    process_result = mocker.stub('subprocess_return')
    process_result.stdout = conntrack_response
    mocker.patch('subprocess.run', return_value=process_result)
    result = conntrack.list_connections()
    assert len(result) == 7


def test_drop_connection(mocker: MockFixture):
    connections_list = [
        {
            'protocol': 'udp',
            'source': '10.20.30.40',
            'destination': '1.1.1.1',
            'source_port': '123',
            'destination_port': '456',
            'id': '1234'
        },
        {
            'protocol': 'icmp',
            'source': '1.1.1.1',
            'destination': '127.0.0.1',
            'id': '5678'
        }
    ]
    mocker.patch('nethsec.conntrack.list_connections', return_value=connections_list)
    command_line = mocker.patch('subprocess.run')
    conntrack.drop_connection('1234')
    command_line.assert_called_with([
        'conntrack', '-D', '-p', 'udp', '-s', '10.20.30.40', '-d', '1.1.1.1', '--sport', '123', '--dport', '456'
    ], check=True, capture_output=True)
    conntrack.drop_connection('5678')
    command_line.assert_called_with([
        'conntrack', '-D', '-p', 'icmp', '-s', '1.1.1.1', '-d', '127.0.0.1'
    ], check=True, capture_output=True)
    with pytest.raises(ValueError) as e:
        conntrack.drop_connection('9999')

    assert e.value.args[0] == "Connection with id 9999 not found."
    with pytest.raises(RuntimeError) as e:
        mocker.patch('subprocess.run', side_effect=CalledProcessError(1, 'conntrack'))
        conntrack.drop_connection('1234')

    assert e.value.args[0].startswith("Error running command:")


def test_drop_all_connections(mocker: MockFixture):
    command_line = mocker.patch('subprocess.run')
    conntrack.drop_all_connections()
    command_line.assert_called_with(['conntrack', '-F'], check=True, capture_output=True)
    with pytest.raises(RuntimeError) as e:
        mocker.patch('subprocess.run', side_effect=CalledProcessError(1, 'conntrack'))
        conntrack.drop_all_connections()

    assert e.value.args[0].startswith("Error running command:")