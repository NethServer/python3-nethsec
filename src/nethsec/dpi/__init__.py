#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Library that handles the DPI rules.
"""

import json
import subprocess

from euci import EUci

from nethsec import utils, firewall
from nethsec.utils import ValidationError


def __load_applications() -> dict[int, str]:
    """
    Reads the applications from the netify-apps.conf file.

    Returns:
        dict of applications, each dict contains the property "id" and "name"
    """
    applications = dict[int, str]()
    with open('/etc/netify.d/netify-apps.conf', 'r') as file:
        for line in file.readlines():
            if line.startswith('app'):
                line_split = line.strip().removesuffix('\n').removeprefix('app:').split(":")
                applications[int(line_split[0])] = line_split[1]
    return applications


def __load_application_categories() -> dict[int, dict[str]]:
    """
    Reads the application categories from the netify-categories.json file.

    Returns:
        dict of application categories, each dict contains the property "id" and "name"
    """
    categories = dict[int, dict[str]]()
    with open('/etc/netify.d/netify-categories.json', 'r') as file:
        categories_file = json.load(file)

        categories_application_tag_index: dict[str, int] = categories_file['application_tag_index']
        categories_names = dict[int, str]()
        for category_name, category_id in categories_application_tag_index.items():
            categories_names[category_id] = category_name

        categories_application_index: list[int, list[int]] = categories_file['application_index']
        for category_id, applications_id in categories_application_index:
            for application_id in applications_id:
                categories[application_id] = {
                    'id': category_id,
                    'name': categories_names[category_id]
                }

    return categories


def __load_protocols() -> dict[int, str]:
    """
    Reads the protocols from the netifyd --dump-protos command.

    Returns:
        dict of protocols, each dict contains the property "id" and "name"
    """
    result = subprocess.run(['netifyd', '--dump-protos'], check=True, capture_output=True)
    protocols = dict[int, str]()
    for line in result.stdout.decode().splitlines():
        # lines can be empty
        if len(line) < 1:
            continue
        line_split = line.split(":")
        protocols[int(line_split[0].strip())] = line_split[1].strip()

    return protocols


def __load_protocol_categories() -> dict[int, dict[str]]:
    """
    Reads the protocol categories from the netify-categories.json file.

    Returns:
        dict of protocol categories, each dict contains the property "id" and "name"
    """
    categories = dict[int, dict[str]]()
    with open('/etc/netify.d/netify-categories.json', 'r') as file:
        categories_file = json.load(file)

        categories_protocol_tag_index: dict[str, int] = categories_file['protocol_tag_index']
        categories_names = dict[int, str]()
        for category_name, category_id in categories_protocol_tag_index.items():
            categories_names[category_id] = category_name

        categories_protocol_index: list[int, list[int]] = categories_file['protocol_index']
        for category_id, protocol_ids in categories_protocol_index:
            for protocol_id in protocol_ids:
                categories[protocol_id] = {
                    'id': category_id,
                    'name': categories_names[category_id]
                }

    return categories


def __load_blocklist() -> list[dict[str]]:
    """
    Format the applications and protocols into a list of dicts.

    Returns:
        list of dicts, each dict contains the property "id", "name", "type" and "category"
    """
    result = list[dict[str]]()
    applications = __load_applications()
    application_categories = __load_application_categories()

    for application_id, application_name in applications.items():
        result_application = {
            'id': application_id,
            'name': application_name,
            'type': 'application'
        }
        if application_id in application_categories:
            result_application['category'] = application_categories[application_id]
        result.append(result_application)

    protocols = __load_protocols()
    protocol_categories = __load_protocol_categories()

    for protocol_id, protocol_name in protocols.items():
        result_protocol = {
            'id': protocol_id,
            'name': protocol_name,
            'type': 'protocol'
        }
        if protocol_id in protocol_categories:
            result_protocol['category'] = protocol_categories[protocol_id]
        result.append(result_protocol)

    return result


def list_devices(e_uci: EUci):
    """
    List device-interface available for filtering.

    Returns:
        list of dicts, each dict contains the property "interface" and "device"
    """
    zones = firewall.list_zones(e_uci)

    # filter out wan zone
    zones = [zone['name'] for zone in zones.values() if zone['name'] != 'wan']

    # get all devices from zones
    devices = set()
    for zone in zones:
        for device in utils.get_all_devices_by_zone(e_uci, zone):
            devices.add(device)

    filtered_devices = []
    # get all interfaces from network
    for device in devices:
        interface = utils.get_interface_from_device(e_uci, device)
        if interface is not None:
            filtered_devices.append({
                'interface': interface,
                'device': device
            })

    return filtered_devices


def list_applications(search: str = None, limit: int = None, page: int = 1) -> list[dict[str, str]]:
    """
    List applications available for filtering.

    Args:
      - search: search string
      - limit: limit the number of results
      - page: page number

    Returns:
        list of dicts, each dict contains the property "code" and "name"
    """
    result = __load_blocklist()

    if search is not None:
        # lower string so we can do a case-insensitive search
        search = search.lower()
        # I'm aware it's far from a readable code, but list comprehension is the fastest way to filter.
        result = [item for item in result if
                  item.get('name', '').lower().find(search) != -1 or
                  item.get('category', {}).get('name', '').lower().find(search) != -1]

    if limit is not None:
        result = result[limit * (page - 1):limit * page]

    return result


def list_rules(e_uci: EUci) -> list[dict[str]]:
    """
    Index all rules

    Args:
      - e_uci: euci instance

    Returns:
        list of dicts, each dict contains the property "config-name", "description", "enabled", "interface" and "blocks"
    """
    rules = list[dict[str]]()
    fetch_rules = utils.get_all_by_type(e_uci, 'dpi', 'rule')

    if not fetch_rules:
        return rules

    for rule_name in fetch_rules.keys():
        # skipping rules with criteria, must be custom entries
        if e_uci.get('dpi', rule_name, 'criteria', default=None) is None:
            # load blocklist of applications and protocols
            blocklist = __load_blocklist()
            # get content of rule
            rule = fetch_rules[rule_name]
            # prepare the data to append to rules
            data_rule = dict[str]()
            data_rule['config-name'] = rule_name
            data_rule['enabled'] = rule.get('enabled', '1') == '1'
            data_rule['device'] = rule.get('device', '*')
            # from device, get the interface
            interface = utils.get_interface_from_device(e_uci, data_rule['device'])
            if interface is not None:
                data_rule['interface'] = interface
            data_rule['action'] = rule.get('action')
            # get the blocked applications/protocols
            data_rule['criteria'] = list[dict[str]]()

            # filter by application
            application_blocklist = [item for item in blocklist if item['type'] == 'application']
            for application in rule.get('application', []):
                found_app = [item for item in application_blocklist if item['name'] == application]
                # there's a possibility of not finding the application due to manual edit of the config
                if len(found_app) > 0:
                    data_rule['criteria'].append(found_app[0])

            # filter by protocol
            protocol_blocklist = [item for item in blocklist if item['type'] == 'protocol']
            for protocol in rule.get('protocol', []):
                found_protocol = [item for item in protocol_blocklist if item['name'] == protocol]
                # there's a possibility of not finding the protocol due to manual edit of the config
                if len(found_protocol) > 0:
                    data_rule['criteria'].append(found_protocol[0])

            # append rule
            rules.append(data_rule)

    return rules


def __save_rule_data(e_uci: EUci, config_name: str, enabled: bool, device: str, action: str, applications: list[str],
                     protocols: list[str]):
    e_uci.set('dpi', config_name, 'enabled', enabled)
    e_uci.set('dpi', config_name, 'device', device)
    e_uci.set('dpi', config_name, 'action', action)
    e_uci.set('dpi', config_name, 'application', applications)
    e_uci.set('dpi', config_name, 'protocol', protocols)


def add_rule(e_uci: EUci, enabled: bool, device: str, action: str, applications: list[str],
             protocols: list[str]) -> str:
    """
    Store a new rule

    Args:
      - e_uci: euci instance
      - description: description of the rule
      - enabled: enable the rule
      - action: apply specific action to rule, can be 'block', 'bulk', 'best_effort', 'video' or 'voice'
      - device: device to listen and apply the rule on
      - applications: list of applications to block
      - protocols: list of protocols to block

    Returns:
        config name of the rule created
    """
    rule_name = utils.get_random_id()
    e_uci.set('dpi', rule_name, 'rule')
    __save_rule_data(e_uci, rule_name, enabled, device, action, applications, protocols)
    e_uci.save('dpi')
    return rule_name


def delete_rule(e_uci: EUci, config_name: str):
    """
    Delete a rule

    Args:
      - e_uci: euci instance
      - config_name: config name of the rule to delete
    """
    e_uci.delete('dpi', config_name)
    e_uci.save('dpi')


def edit_rule(e_uci: EUci, config_name: str, enabled: bool, device: str, action: str, applications: list[str],
              protocols: list[str]):
    """
    Edit a rule

    Args:
      - e_uci: euci instance
      - config_name: rule to change
      - enabled: enable the rule
      - device: device to listen and apply the rule on
      - action: apply specific action to rule, can be 'block', 'bulk', 'best_effort', 'video' or 'voice'
      - applications: array of applications to block
      - protocols: array of protocols to block

    Raises
        - ValidationError: if the config name is invalid
    """
    if e_uci.get('dpi', config_name, default=None) is None:
        raise ValidationError('config-name', 'invalid', config_name)

    __save_rule_data(e_uci, config_name, enabled, device, action, applications, protocols)

    e_uci.save('dpi')
