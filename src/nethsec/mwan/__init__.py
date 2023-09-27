#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

import json
import subprocess

from euci import EUci

from nethsec import utils
from nethsec.utils import ValidationError


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
        ValidationError: if interface name is not defined in /etc/config/network
    """
    # checking if interface is configured
    available_interfaces = utils.get_all_by_type(e_uci, 'network', 'interface')
    if name not in available_interfaces.keys():
        raise ValidationError('name', 'invalid', name)

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
    return member_config_name, changed


def store_rule(e_uci: EUci, name: str, policy: str, protocol: str = None,
               source_addresses: str = None, source_ports: str = None,
               destination_addresses: str = None, destination_ports: str = None) -> str:
    """
    Stores a rule for mwan3
    Args:
        e_uci: EUci instance
        name: name of the rule, must be unique
        policy: policy to use for the rule, must be already set
        protocol: must be one of tcp, udp, icmp or all, defaults to 'all'
        source_addresses: source addresses to match
        source_ports: source ports to match or range
        destination_addresses: destination addresses to match
        destination_ports: destination ports to match or range

    Returns:
        name of the rule created

    Raises:
        ValidationError if name is not unique or policy is not valid
    """
    rule_config_name = utils.get_id(name.lower(), 15)
    if rule_config_name in e_uci.get('mwan3').keys():
        raise ValidationError('name', 'unique', name)
    if policy not in utils.get_all_by_type(e_uci, 'mwan3', 'policy').keys():
        raise ValidationError('policy', 'invalid', policy)
    e_uci.set('mwan3', rule_config_name, 'rule')
    e_uci.set('mwan3', rule_config_name, 'label', name)
    e_uci.set('mwan3', rule_config_name, 'label', name)
    e_uci.set('mwan3', rule_config_name, 'use_policy', policy)
    if protocol is not None:
        e_uci.set('mwan3', rule_config_name, 'proto', protocol)
    if source_addresses is not None:
        e_uci.set('mwan3', rule_config_name, 'src_ip', source_addresses)
    if source_ports is not None:
        e_uci.set('mwan3', rule_config_name, 'src_port', source_ports)
    if destination_addresses is not None:
        e_uci.set('mwan3', rule_config_name, 'dest_ip', destination_addresses)
    if destination_ports is not None:
        e_uci.set('mwan3', rule_config_name, 'dest_port', destination_ports)

    e_uci.save('mwan3')
    return f'mwan3.{rule_config_name}'


def store_policy(e_uci: EUci, name: str, interfaces: list[dict]) -> list[str]:
    """
    Stores a policy for mwan3, takes care of creating interfaces and members.
    Args:
        e_uci: EUci instance
        name: name of policy
        interfaces: list of interfaces to add to policy, must have name, metric and weight fields

    Returns:
        list of changed configuration

    Raises:
        ValidationError: if name is not unique
    """
    changed_config = []
    # generate policy name
    policy_config_name = utils.get_id(name.lower())
    # make sure name is not something that already exists
    if policy_config_name in e_uci.get('mwan3').keys():
        raise ValidationError('name', 'unique', name)
    # generate policy config with corresponding name
    e_uci.set('mwan3', policy_config_name, 'policy')
    e_uci.set('mwan3', policy_config_name, 'label', name)
    changed_config.append(f'mwan3.{policy_config_name}')

    member_names = __add_interfaces(e_uci, interfaces, changed_config)

    e_uci.set('mwan3', policy_config_name, 'use_member', member_names)

    if len(utils.get_all_by_type(e_uci, 'mwan3', 'rule')) == 0:
        changed_config.append(store_rule(e_uci, 'Default Rule', policy_config_name))

    e_uci.save('mwan3')
    e_uci.save('network')
    return changed_config


def __fetch_interface_status(interface_name: str) -> str:
    try:
        output = subprocess.check_output([
            'ubus',
            'call',
            'mwan3',
            'status',
            '{"section": "interfaces"}'
        ]).decode('utf-8')
        decoded_output = json.JSONDecoder().decode(output)
        return decoded_output['interfaces'][interface_name]['status']
    except:
        return 'unknown'


def __parse_member(e_uci: EUci, member_name: str) -> dict:
    """
    Parses a member configuration and returns formatted data.
    Args:
        e_uci: EUci instance
        member_name: member name

    Returns:
        dict with member data
    """
    member_data = e_uci.get_all('mwan3', member_name)
    return {
        'name': member_name,
        'interface': member_data['interface'],
        'metric': member_data['metric'],
        'weight': member_data['weight'],
        'status': __fetch_interface_status(member_data['interface'])
    }


def index_policies(e_uci: EUci) -> list[dict]:
    """
    Returns a list of policies with their members, interfaces and metrics/weights.
    Args:
        e_uci: EUci instance

    Returns:
        list of dicts with policy data
    """
    data = []
    policies = utils.get_all_by_type(e_uci, 'mwan3', 'policy')
    # iterate over policies
    for policy_name in policies.keys():
        policy = policies[policy_name]
        policy_data = {
            'name': policy_name,
        }
        # add label only if present
        if 'label' in policy:
            policy_data['label'] = policy['label']

        # add members
        members = []
        if 'use_member' in policy:
            policy_data['members'] = {}
            for member in policy['use_member']:
                members.append(__parse_member(e_uci, member))

        # infer policy type by metrics
        metrics = [int(member['metric']) for member in members]
        if all(metric == metrics[0] for metric in metrics):
            policy_data['type'] = 'balance'
        elif all(metrics.index(metric) == key for key, metric in enumerate(metrics)):
            policy_data['type'] = 'backup'
        else:
            policy_data['type'] = 'custom'

        unique_metrics = list(set(metrics))
        for unique_metric in unique_metrics:
            policy_data['members'][unique_metric] = list(filter(lambda x: x['metric'] == str(unique_metric), members))

        # append policy to data
        data.append(policy_data)
    return data


def __add_interfaces(e_uci: EUci, interfaces: list[dict], changed_config: list[str] = None) -> list[str]:
    if changed_config is None:
        changed_config = list()
    member_names: list[str] = []
    for interface in interfaces:
        try:
            added_mwan_interface, updated_interface = __store_interface(e_uci, interface['name'])
        except ValidationError:
            raise ValidationError('interfaces', 'invalid', interface['name'])
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
            changed_config.append(f'mwan3.{member_config_name}')

    return member_names


def edit_policy(e_uci: EUci, name: str, label: str, interfaces: list[dict]) -> list[str]:
    if name not in utils.get_all_by_type(e_uci, 'mwan3', 'policy').keys():
        raise ValidationError('name', 'invalid', name)
    changed_config = []
    if label != e_uci.get_all('mwan3', name)['label']:
        e_uci.set('mwan3', name, 'label', label)
        changed_config.append(f'mwan3.{name}')

    member_names = __add_interfaces(e_uci, interfaces, changed_config)

    e_uci.set('mwan3', name, 'use_member', member_names)

    e_uci.save('mwan3')
    e_uci.save('network')
    return changed_config


def delete_policy(e_uci: EUci, name: str) -> list[str]:
    if name not in utils.get_all_by_type(e_uci, 'mwan3', 'policy').keys():
        raise ValidationError('name', 'invalid', name)
    e_uci.delete('mwan3', name)
    e_uci.save('mwan3')
    return [f'mwan3.{name}']


def index_rules(e_uci: EUci) -> list[dict]:
    data = []
    rules = utils.get_all_by_type(e_uci, 'mwan3', 'rule')
    for rule_key in rules.keys():
        rule_data = {}
        rule_value = rules[rule_key]
        rule_data['name'] = rule_key
        rule_data['policy'] = {}
        rule_data['policy']['name'] = rule_value['use_policy']
        if rule_value['use_policy'] in utils.get_all_by_type(e_uci, 'mwan3', 'policy').keys():
            rule_data['policy']['label'] = utils.get_all_by_type(e_uci, 'mwan3', 'policy')[rule_value['use_policy']]['label']
        if 'label' in rule_value:
            rule_data['label'] = rule_value['label']
        if 'proto' in rule_value:
            rule_data['protocol'] = rule_value['proto']
        if 'src_ip' in rule_value:
            rule_data['source_addresses'] = rule_value['src_ip']
        if 'dest_ip' in rule_value:
            rule_data['destination_addresses'] = rule_value['dest_ip']

        data.append(rule_data)
    return data
