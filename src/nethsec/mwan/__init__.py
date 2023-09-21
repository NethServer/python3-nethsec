#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

from euci import EUci

from nethsec import utils


def __generate_metric(e_uci: EUci, interface_metrics: list[int] = None, metric: int = 1) -> int:
    """
    Generates a metric for an interface.
    Args:
        e_uci: EUci instance
        interface_metrics: list of metrics already used, will be generated if not provided
        metric: metric to start from

    Returns:
        first metric that is not present in interface_metrics
    """
    if interface_metrics is None:
        interface_metrics = list[int]()
        for interface in utils.get_all_by_type(e_uci, 'network', 'interface').values():
            if 'metric' in interface:
                interface_metrics.append(int(interface['metric']))

    if metric not in interface_metrics:
        return metric
    else:
        return __generate_metric(e_uci, interface_metrics, metric + 1)


def __store_interface(e_uci: EUci, name: str) -> tuple[bool, bool]:
    """
    Stores interface configuration for mwan3 and network, not suited to be used outside store_policy.
    Args:
        e_uci: EUci instance
        name: name of interface

    Returns:
        tuple of booleans, first one indicates if mwan interface was created, second one indicates if metric was added
        to network interface

    Raises:
        ValueError: if interface name is not defined in /etc/config/network
    """
    # checking if interface is configured
    available_interfaces = utils.get_all_by_type(e_uci, 'network', 'interface')
    if name not in available_interfaces.keys():
        raise ValueError(name, 'invalid')

    created_interface = False
    # if no interface with name exists, create one with defaults
    if name not in utils.get_all_by_type(e_uci, 'mwan3', 'interface').keys():
        created_interface = True
        # fetch default configuration and set interface
        default_interface_config = utils.get_all_by_type(e_uci, 'ns-api', 'defaults_mwan').get('defaults_mwan')
        e_uci.set('mwan3', name, 'interface')
        e_uci.set('mwan3', name, 'enabled', '1')
        e_uci.set('mwan3', name, 'initial_state', default_interface_config['initial_state'])
        e_uci.set('mwan3', name, 'family', default_interface_config['protocol'])
        e_uci.set('mwan3', name, 'track_ip', default_interface_config['track_ip'])
        e_uci.set('mwan3', name, 'track_method', default_interface_config['tracking_method'])
        e_uci.set('mwan3', name, 'reliability', default_interface_config['tracking_reliability'])
        e_uci.set('mwan3', name, 'count', default_interface_config['ping_count'])
        e_uci.set('mwan3', name, 'size', default_interface_config['ping_size'])
        e_uci.set('mwan3', name, 'max_ttl', default_interface_config['ping_max_ttl'])
        e_uci.set('mwan3', name, 'timeout', default_interface_config['ping_timeout'])
        e_uci.set('mwan3', name, 'interval', default_interface_config['ping_interval'])
        e_uci.set('mwan3', name, 'failure_interval', default_interface_config['ping_failure_interval'])
        e_uci.set('mwan3', name, 'recovery_interval', default_interface_config['ping_recovery_interval'])
        e_uci.set('mwan3', name, 'down', default_interface_config['interface_down_threshold'])
        e_uci.set('mwan3', name, 'up', default_interface_config['interface_up_threshold'])

    added_metric = False
    # avoid adding metric if already present
    if 'metric' not in available_interfaces[name]:
        added_metric = True
        # generate metric
        metric = __generate_metric(e_uci)
        # configure metric for interface
        e_uci.set('network', name, 'metric', metric)
    return created_interface, added_metric


def __store_member(e_uci: EUci, interface_name: str, metric: int, weight: int) -> tuple[str, bool]:
    """
    Stores member configuration for mwan3, not suited to be used outside store_policy.
    Args:
        e_uci: EUci instance
        interface_name: name of interface to link the member to
        metric: metric of the member
        weight: weight of the member

    Returns:
        tuple of string and boolean, first one is the generated name of the member, second one indicates if the member
        was created
    """
    member_config_name = utils.get_id(f'{interface_name}_M{metric}_W{weight}')
    changed = False
    if member_config_name not in utils.get_all_by_type(e_uci, 'mwan3', 'member').keys():
        changed = True
        e_uci.set('mwan3', member_config_name, 'member')
        e_uci.set('mwan3', member_config_name, 'interface', interface_name)
        e_uci.set('mwan3', member_config_name, 'metric', metric)
        e_uci.set('mwan3', member_config_name, 'weight', weight)
    return f'mwan3.{member_config_name}', changed


def store_policy(e_uci: EUci, name: str, interfaces: list[dict]) -> list[str]:
    """
    Stores a policy for mwan3, takes care of creating interfaces and members.
    Args:
        e_uci: EUci instance
        name: name of policy
        interfaces: list of interfaces to add to policy, must have a name, metric and weight fields

    Returns:
        list of changed configuration

    Raises:
        ValueError: if name is not unique
    """
    changed_config = []
    # generate policy name
    policy_config_name = utils.get_id(name)
    # make sure name is not something that already exists
    if policy_config_name in e_uci.get('mwan3').keys():
        raise ValueError(name, 'unique')
    # generate policy config with corresponding name
    e_uci.set('mwan3', policy_config_name, 'policy')
    e_uci.set('mwan3', policy_config_name, 'name', name)
    changed_config.append(f'mwan3.{policy_config_name}')

    member_names: list[str] = []
    for interface in interfaces:
        added_mwan_interface, updated_interface = __store_interface(e_uci, interface['name'])
        if added_mwan_interface:
            changed_config.append(f'mwan3.{interface["name"]}')
        if updated_interface:
            changed_config.append(f'network.{interface["name"]}')

        member_config_name, member_created = __store_member(e_uci,
                                                            interface['name'],
                                                            interface['metric'],
                                                            interface['weight'])
        member_names.append(member_config_name)
        if member_created:
            changed_config.append(member_config_name)

    e_uci.set('mwan3', policy_config_name, 'use_member', member_names)

    e_uci.save('mwan3')
    e_uci.save('network')
    return changed_config
