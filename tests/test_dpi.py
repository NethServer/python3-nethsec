import pathlib

import pytest
from euci import EUci
from pytest_mock import MockFixture

from nethsec import dpi
from nethsec.utils import ValidationError

applications_file = """
# Comment to avoid

# another comment to avoid

app:133:netify.netflix
app:10119:netify.linkedin
app:10552:netify.tesla
app:10195:netify.avira
app:10194:netify.sophos
app:10244:netify.bbc
app:10362:netify.hulu
app:10118:netify.lets-encrypt
app:199:netify.snapchat
dom:133:dualstack.apiproxy-device-prod-nlb-1-4d12762d4ba53e45.elb.eu-west-1.amazonaws.com
net:10852:208.118.237.0/24
net:124:208.117.254.0/24
nsd:-1:39:YXBwID09ICduZXRpZnkuc2lnbmFsJyAmJiBwcm90b2NvbF9pZCA9PSA3OCAmJiAob3RoZXJfcG9ydCA9PSA0NDMgfHwgbG9jYWxfcG9ydCA9PSA0NDMpOw==
nsd:-1:67:YXBwID09ICduZXRpZnkuZ29vZ2xlLWNoYXQnICYmIHByb3RvY29sX2lkICE9IDY3ICYmIChvdGhlcl9wb3J0ID09IDUyMjggfHwgbG9jYWxfcG9ydCA9PSA1MjI4KTs=
"""

applications = {
    133: 'netify.netflix',
    10119: 'netify.linkedin',
    10552: 'netify.tesla',
    10195: 'netify.avira',
    10194: 'netify.sophos',
    10244: 'netify.bbc',
    10362: 'netify.hulu',
    10118: 'netify.lets-encrypt',
    199: 'netify.snapchat'
}

protocols = {
    116: 'Warcraft3',
    117: 'LotusNotes',
    121: 'Dropbox',
    127: 'RPC',
    128: 'NetFlow',
    129: 'SFlow',
    130: 'HTTP/Connect'
}

categories_file = """
{
    "application_index": [
        [
            3,
            [
                10362,
                10194,
                10552
            ]
        ],
        [
            33,
            [
                133,
                10119,
                10195,
                10244
            ]
        ],
        [
            20,
            [
                199
            ]
        ]
    ],
    "application_tag_index": {
        "first-category": 3,
        "unknown": 33,
        "last": 20
    },
    "protocol_index": [
        [
            1,
            [
                121,
                127,
                128
            ]
        ],
        [
            2,
            [
                116
            ]
        ],
        [
            4,
            [
                129,
                130
            ]
        ]
    ],
    "protocol_tag_index": {
        "base": 1,
        "games": 2,
        "low": 4
    }
}
"""

application_categories = {
    10362: {
        'id': 3,
        'name': 'first-category'
    },
    10194: {
        'id': 3,
        'name': 'first-category'
    },
    10552: {
        'id': 3,
        'name': 'first-category'
    },
    133: {
        'id': 33,
        'name': 'unknown'
    },
    10119: {
        'id': 33,
        'name': 'unknown'
    },
    10195: {
        'id': 33,
        'name': 'unknown'
    },
    10244: {
        'id': 33,
        'name': 'unknown'
    },
    199: {
        'id': 20,
        'name': 'last'
    }
}

protocol_categories = {
    121: {
        'id': 1,
        'name': 'base'
    },
    127: {
        'id': 1,
        'name': 'base'
    },
    128: {
        'id': 1,
        'name': 'base'
    },
    116: {
        'id': 2,
        'name': 'games'
    },
    129: {
        'id': 4,
        'name': 'low'
    },
    130: {
        'id': 4,
        'name': 'low'
    }
}

protocol_output = """
   116: Warcraft3
   117: LotusNotes
   121: Dropbox
   127: RPC
   128: NetFlow
   129: SFlow
   130: HTTP/Connect
"""

dpi_db = """
config main 'config'
    option log_blocked '0'
    option firewall_exemption '0'
    option enabled '0'
    list popular_filters 'netify.netflix'
    list popular_filters 'netify.hulu'
    list popular_filters 'netify.sophos'
    list popular_filters 'HTTP/Connect'
    list popular_filters 'Dropbox'

config rule rule0
	option action 'block'
	list application 'netify.linkedin'
	list application 'netify.snapchat'
	list protocol 'HTTP/Connect'
	list source '192.168.100.1'
	list source '192.168.100.2'
	list source 'user:giacomo'
	list source 'group:g1'
	list category 'games'
	option device 'eth0'
	option enabled 1

config rule rule1
	option action 'block'
	list application 'netify.tesla'
	option device 'eth4'
	option enabled 0
	list exemption '192.168.100.3'

config rule rule2
	option action 'block'
	option criteria 'local_ip == 192.168.100.22 && application == "netify.facebook";'
	option enabled 1
	
config rule rule3
    option action 'video'
    list protocol 'HTTP/Connect'
    option device 'eth1'
    option enabled 1
"""

network_config = """
config interface 'RED_1'
        option proto 'dhcp'
        option device 'eth1'
        option metric '1'

config interface 'RED_2'
        option proto 'dhcp'
        option device 'eth2'
        option metric '2'

config interface 'RED_3'
        option proto 'dhcp'
        option device 'eth3'
        option metric '3'

config interface 'GREEN_1'
        option proto 'static'
        option device 'eth0'
        option ipaddr '192.168.200.2'
        option netmask '255.255.255.0'
        option gateway '192.168.200.1'

config interface 'GREEN_2'
        option proto 'static'
        option device 'eth4'
        option ipaddr '10.0.3.1'
        option netmask '255.255.255.0'
        option gateway '10.0.3.0'
"""

firewall_config = """
config zone 'ns_lan'
        option name 'lan'
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'
        list network 'GREEN_1'
        list network 'GREEN_2'

config zone 'ns_wan'
        option name 'wan'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'
        option masq '1'
        option mtu_fix '1'
        list network 'RED_1'
        list network 'RED_2'
        list network 'RED_3'
        
config zone 'ns_guests'
        option name 'guests'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'
        list network 'RED_1'
        list network 'GREEN_1'
        
config zone 'ns_empty'
        option name 'guests'
        option input 'REJECT'
        option output 'ACCEPT'
        option forward 'REJECT'
"""


@pytest.fixture
def e_uci(tmp_path: pathlib.Path) -> EUci:
    conf_dir = tmp_path.joinpath('conf')
    conf_dir.mkdir()
    save_dir = tmp_path.joinpath('save')
    save_dir.mkdir()
    with conf_dir.joinpath('dpi').open('w') as fp:
        fp.write("")
    with conf_dir.joinpath('network').open('w') as fp:
        fp.write(network_config)
    with conf_dir.joinpath('firewall').open('w') as fp:
        fp.write(firewall_config)
    return EUci(confdir=conf_dir.as_posix(), savedir=save_dir.as_posix())


@pytest.fixture
def e_uci_with_data(e_uci: EUci):
    with pathlib.Path(e_uci.confdir()).joinpath('dpi').open('w') as fp:
        fp.write(dpi_db)
    return e_uci


@pytest.fixture
def mock_load(mocker):
    mocker.patch('nethsec.dpi.__load_applications', return_value=applications)
    mocker.patch('nethsec.dpi.__load_application_categories', return_value=application_categories)
    mocker.patch('nethsec.dpi.__load_protocols', return_value=protocols)
    mocker.patch('nethsec.dpi.__load_protocol_categories', return_value=protocol_categories)


def test_load_applications(mocker: MockFixture):
    mocker.patch('builtins.open', mocker.mock_open(read_data=applications_file))
    assert dpi.__load_applications() == applications


def test_load_application_categories(mocker: MockFixture):
    mocker.patch('builtins.open', mocker.mock_open(read_data=categories_file))
    assert dpi.__load_application_categories() == application_categories


def test_load_protocol_categories(mocker: MockFixture):
    mocker.patch('builtins.open', mocker.mock_open(read_data=categories_file))
    assert dpi.__load_protocol_categories() == protocol_categories


def test_load_protocols(mocker: MockFixture):
    process_result = mocker.stub('subprocess_return')
    process_result.stdout = bytes(protocol_output, 'utf-8')
    mocker.patch('subprocess.run', return_value=process_result)
    assert dpi.__load_protocols() == protocols


@pytest.mark.parametrize('search', [None, ''])
def test_index_applications(mock_load, search):
    assert dpi.list_applications(search) == [
        {
            'id': 133,
            'name': 'netify.netflix',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10119,
            'name': 'netify.linkedin',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10552,
            'name': 'netify.tesla',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10195,
            'name': 'netify.avira',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10194,
            'name': 'netify.sophos',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10244,
            'name': 'netify.bbc',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10362,
            'name': 'netify.hulu',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10118,
            'name': 'netify.lets-encrypt',
            'type': 'application'
        },
        {
            'id': 199,
            'name': 'netify.snapchat',
            'type': 'application',
            'category': {
                'id': 20,
                'name': 'last'
            }
        },
        {
            'id': 116,
            'name': 'Warcraft3',
            'type': 'protocol',
            'category': {
                'id': 2,
                'name': 'games'
            }
        },
        {
            'id': 117,
            'name': 'LotusNotes',
            'type': 'protocol'
        },
        {
            'id': 121,
            'name': 'Dropbox',
            'type': 'protocol',
            'category': {
                'id': 1,
                'name': 'base'
            }
        },
        {
            'id': 127,
            'name': 'RPC',
            'type': 'protocol',
            'category': {
                'id': 1,
                'name': 'base'
            }
        },
        {
            'id': 128,
            'name': 'NetFlow',
            'type': 'protocol',
            'category': {
                'id': 1,
                'name': 'base'
            }
        },
        {
            'id': 129,
            'name': 'SFlow',
            'type': 'protocol',
            'category': {
                'id': 4,
                'name': 'low'
            }
        },
        {
            'id': 130,
            'name': 'HTTP/Connect',
            'type': 'protocol',
            'category': {
                'id': 4,
                'name': 'low'
            }
        }
    ]


def test_index_applications_search(mock_load):
    assert dpi.list_applications(search='l') == [
        {
            'id': 133,
            'name': 'netify.netflix',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10119,
            'name': 'netify.linkedin',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10552,
            'name': 'netify.tesla',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10362,
            'name': 'netify.hulu',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10118,
            'name': 'netify.lets-encrypt',
            'type': 'application'
        },
        {
            'id': 199,
            'name': 'netify.snapchat',
            'type': 'application',
            'category': {
                'id': 20,
                'name': 'last'
            }
        },
        {
            'id': 117,
            'name': 'LotusNotes',
            'type': 'protocol'
        },
        {
            'id': 128,
            'name': 'NetFlow',
            'type': 'protocol',
            'category': {
                'id': 1,
                'name': 'base'
            }
        },
        {
            'id': 129,
            'name': 'SFlow',
            'type': 'protocol',
            'category': {
                'id': 4,
                'name': 'low'
            }
        },
        {
            'id': 130,
            'name': 'HTTP/Connect',
            'type': 'protocol',
            'category': {
                'id': 4,
                'name': 'low'
            }
        }
    ]


def test_index_applications_paginate(mock_load):
    assert dpi.list_applications(limit=2, page=2) == [
        {
            'id': 10552,
            'name': 'netify.tesla',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10195,
            'name': 'netify.avira',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        }
    ]
    assert dpi.list_applications(limit=2, page=3) == [
        {
            'id': 10194,
            'name': 'netify.sophos',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10244,
            'name': 'netify.bbc',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        }
    ]


def test_list_empty_rules(e_uci, mock_load):
    assert dpi.list_rules(e_uci) == []


def test_list_rules(e_uci_with_data, mock_load):
    assert dpi.list_rules(e_uci_with_data) == [
        {
            'config-name': 'rule0',
            'enabled': True,
            'interface': 'GREEN_1',
            'device': 'eth0',
            'action': 'block',
            'criteria': [
                {
                    'id': 10119,
                    'name': 'netify.linkedin',
                    'type': 'application',
                    'category': {
                        'id': 33,
                        'name': 'unknown'
                    }
                },
                {
                    'id': 199,
                    'name': 'netify.snapchat',
                    'type': 'application',
                    'category': {
                        'id': 20,
                        'name': 'last'
                    }
                },
                {
                    'id': 130,
                    'name': 'HTTP/Connect',
                    'type': 'protocol',
                    'category': {
                        'id': 4,
                        'name': 'low'
                    }
                }
            ]
        },
        {
            'config-name': 'rule1',
            'enabled': False,
            'interface': 'GREEN_2',
            'device': 'eth4',
            'action': 'block',
            'criteria': [
                {
                    'id': 10552,
                    'name': 'netify.tesla',
                    'type': 'application',
                    'category': {
                        'id': 3,
                        'name': 'first-category'
                    }
                }
            ]
        },
        {
            'config-name': 'rule3',
            'enabled': True,
            'interface': 'RED_1',
            'device': 'eth1',
            'action': 'video',
            'criteria': [
                {
                    'id': 130,
                    'name': 'HTTP/Connect',
                    'type': 'protocol',
                    'category': {
                        'id': 4,
                        'name': 'low'
                    }
                }
            ]
        }
    ]


def test_store_rule(e_uci, mock_load):
    rule_created = dpi.add_rule(e_uci, True, 'eth0', 'best_effort',
                                ['netify.linkedin', 'netify.avira', 'netify.netflix'], ['LotusNotes', 'SFlow'])
    assert dpi.list_rules(e_uci) == [
        {
            'config-name': rule_created,
            'enabled': True,
            'interface': 'GREEN_1',
            'device': 'eth0',
            'action': 'best_effort',
            'criteria': [
                {
                    'id': 10119,
                    'name': 'netify.linkedin',
                    'type': 'application',
                    'category': {
                        'id': 33,
                        'name': 'unknown'
                    }
                },
                {
                    'id': 10195,
                    'name': 'netify.avira',
                    'type': 'application',
                    'category': {
                        'id': 33,
                        'name': 'unknown'
                    }
                },
                {
                    'id': 133,
                    'name': 'netify.netflix',
                    'type': 'application',
                    'category': {
                        'id': 33,
                        'name': 'unknown'
                    }
                },
                {
                    'id': 117,
                    'name': 'LotusNotes',
                    'type': 'protocol',
                },
                {
                    'id': 129,
                    'name': 'SFlow',
                    'type': 'protocol',
                    'category': {
                        'id': 4,
                        'name': 'low'
                    }
                }
            ]
        }
    ]


def test_delete_rule(e_uci_with_data, mock_load):
    dpi.delete_rule(e_uci_with_data, 'rule1')
    dpi.delete_rule(e_uci_with_data, 'rule0')
    assert dpi.list_rules(e_uci_with_data) == [
        {
            'config-name': 'rule3',
            'enabled': True,
            'interface': 'RED_1',
            'device': 'eth1',
            'action': 'video',
            'criteria': [
                {
                    'id': 130,
                    'name': 'HTTP/Connect',
                    'type': 'protocol',
                    'category': {
                        'id': 4,
                        'name': 'low'
                    }
                }
            ]
        }
    ]


def test_edit_rule(e_uci_with_data, mock_load):
    dpi.edit_rule(e_uci_with_data, 'rule0', False, 'eth0', 'voice', [],
                  ['HTTP/Connect', 'LotusNotes'])
    assert dpi.list_rules(e_uci_with_data) == [
        {
            'config-name': 'rule0',
            'enabled': False,
            'interface': 'GREEN_1',
            'device': 'eth0',
            'action': 'voice',
            'criteria': [
                {
                    'id': 130,
                    'name': 'HTTP/Connect',
                    'type': 'protocol',
                    'category': {
                        'id': 4,
                        'name': 'low'
                    }
                },
                {
                    'id': 117,
                    'name': 'LotusNotes',
                    'type': 'protocol',
                }
            ]
        },
        {
            'config-name': 'rule1',
            'enabled': False,
            'interface': 'GREEN_2',
            'device': 'eth4',
            'action': 'block',
            'criteria': [
                {
                    'id': 10552,
                    'name': 'netify.tesla',
                    'type': 'application',
                    'category': {
                        'id': 3,
                        'name': 'first-category'
                    }
                }
            ]
        },
        {
            'config-name': 'rule3',
            'enabled': True,
            'interface': 'RED_1',
            'device': 'eth1',
            'action': 'video',
            'criteria': [
                {
                    'id': 130,
                    'name': 'HTTP/Connect',
                    'type': 'protocol',
                    'category': {
                        'id': 4,
                        'name': 'low'
                    }
                }
            ]
        }
    ]


def test_edit_rule_with_missing_rule(e_uci):
    with pytest.raises(ValidationError) as err:
        dpi.edit_rule(e_uci, 'rule0', False, 'eth0', 'block', [], [])

    assert err.value.args[0] == 'config-name'
    assert err.value.args[1] == 'invalid'
    assert err.value.args[2] == 'rule0'


def test_list_interfaces(e_uci_with_data):
    assert dpi.list_devices(e_uci_with_data).index({
        'interface': 'GREEN_1',
        'device': 'eth0'
    }) != -1
    assert dpi.list_devices(e_uci_with_data).index({
        'interface': 'GREEN_2',
        'device': 'eth4'
    }) != -1
    assert dpi.list_devices(e_uci_with_data).index({
        'interface': 'RED_1',
        'device': 'eth1'
    }) != -1


def test_list_popular(e_uci_with_data, mock_load):
    assert dpi.list_popular(e_uci_with_data) == [
        {
            'id': 133,
            'name': 'netify.netflix',
            'type': 'application',
            'category': {
                'id': 33,
                'name': 'unknown'
            }
        },
        {
            'id': 10194,
            'name': 'netify.sophos',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 10362,
            'name': 'netify.hulu',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 121,
            'name': 'Dropbox',
            'type': 'protocol',
            'category': {
                'id': 1,
                'name': 'base'
            }
        },
        {
            'id': 130,
            'name': 'HTTP/Connect',
            'type': 'protocol',
            'category': {
                'id': 4,
                'name': 'low'
            }
        }
    ]


def test_list_popular_with_limits(e_uci_with_data, mock_load):
    assert dpi.list_popular(e_uci_with_data, limit=2, page=2) == [
        {
            'id': 10362,
            'name': 'netify.hulu',
            'type': 'application',
            'category': {
                'id': 3,
                'name': 'first-category'
            }
        },
        {
            'id': 121,
            'name': 'Dropbox',
            'type': 'protocol',
            'category': {
                'id': 1,
                'name': 'base'
            }
        }
    ]
    assert dpi.list_popular(e_uci_with_data, limit=2, page=3) == [
        {
            'id': 130,
            'name': 'HTTP/Connect',
            'type': 'protocol',
            'category': {
                'id': 4,
                'name': 'low'
            }
        }
    ]
