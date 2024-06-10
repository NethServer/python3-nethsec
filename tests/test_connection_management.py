from xml.etree import ElementTree

from pytest_mock import MockFixture

from nethsec import connection_management

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


def test_parse_meta_tag():
    # get first meta tag in first flow
    meta_tag = ElementTree.fromstring(conntrack_response).find('flow/meta')
    result = connection_management.__parse_meta_connection_tag(meta_tag)
    assert result['src'] == '192.168.122.234'
    assert result['dest'] == '31.14.133.122'
    assert result['protocol'] == 'udp'
    assert result['start_port'] == '41692'
    assert result['end_port'] == '123'
    assert result['packets'] == '1'
    assert result['bytes'] == '76'


def test_parse_meta_tag_without_ports():
    # get the meta tag with the ICMP protocol
    meta_tag = ElementTree.fromstring(conntrack_response).findall('flow')[1][1]
    result = connection_management.__parse_meta_connection_tag(meta_tag)
    assert result['src'] == '192.168.122.155'
    assert result['dest'] == '192.168.122.1'
    assert result['protocol'] == 'icmp'
    assert 'start_port' not in result
    assert 'end_port' not in result
    assert result['packets'] == '2'
    assert result['bytes'] == '168'


def test_connection_info():
    # get the first flow
    flow = ElementTree.fromstring(conntrack_response).findall('flow')[0]
    result = connection_management.__parse_connection_info(flow)
    original = flow[0]
    reply = flow[1]
    assert result['source'] == connection_management.__parse_meta_connection_tag(original)['src']
    assert result['destination'] == connection_management.__parse_meta_connection_tag(original)['dest']
    assert result['protocol'] == connection_management.__parse_meta_connection_tag(original)['protocol']
    assert result['source_port'] == connection_management.__parse_meta_connection_tag(original)['start_port']
    assert result['destination_port'] == connection_management.__parse_meta_connection_tag(original)['end_port']
    assert result['source_stats']['packets'] == connection_management.__parse_meta_connection_tag(original)['packets']
    assert result['source_stats']['bytes'] == connection_management.__parse_meta_connection_tag(original)['bytes']
    assert result['destination_stats']['packets'] == connection_management.__parse_meta_connection_tag(reply)['packets']
    assert result['destination_stats']['bytes'] == connection_management.__parse_meta_connection_tag(reply)['bytes']
    assert result['timeout'] == '47'
    assert result['id'] == '1905826093'
    flow = ElementTree.fromstring(conntrack_response).findall('flow')[1]
    result = connection_management.__parse_connection_info(flow)
    assert 'source_port' not in result
    assert 'destination_port' not in result


def test_fetch_connection_list(mocker: MockFixture):
    process_result = mocker.stub('subprocess_return')
    process_result.stdout = conntrack_response
    mocker.patch('subprocess.run', return_value=process_result)
    result = connection_management.list_connections()
    assert len(result) == 7
    assert 'download' in result[0]
    assert 'upload' in result[0]
    assert 'wan' in result[0]
