#!/usr/bin/python3

#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Library for reading and managing network connections.
"""
import subprocess

from xml.etree import ElementTree
from xml.etree.ElementTree import Element


def __parse_meta_connection_tag(meta: Element) -> dict:
    """
    From a meta tag, extract the connection information.
    Args:
     - meta: ElementTree.Element with the meta tag.

    Returns: dictionary with the connection information.
    """
    result = {}
    layer3 = meta.find('layer3')
    result['src'] = layer3.find('src').text
    result['dest'] = layer3.find('dst').text
    layer4 = meta.find('layer4')
    result['protocol'] = layer4.get('protoname')
    # start port and end port might not be present for some protocols, like ICMP.
    if layer4.find('sport') is not None:
        result['start_port'] = layer4.find('sport').text
    if layer4.find('dport') is not None:
        result['end_port'] = layer4.find('dport').text
    counters = meta.find('counters')
    result['packets'] = counters.find('packets').text
    result['bytes'] = counters.find('bytes').text
    return result


def __parse_connection_info(flow: Element) -> dict:
    result = {}
    # expand meta tags
    for child in flow.findall('meta'):
        # parse the meta tag using __parse_meta_connection_tag function
        if child.get('direction') == 'original' or child.get('direction') == 'reply':
            connection_info = __parse_meta_connection_tag(child)
            if child.get('direction') == 'original':
                result['source'] = connection_info['src']
                result['destination'] = connection_info['dest']
                result['protocol'] = connection_info['protocol']
                if 'start_port' in connection_info:
                    result['source_port'] = connection_info['start_port']
                if 'end_port' in connection_info:
                    result['destination_port'] = connection_info['end_port']
                result['source_stats'] = {
                    'packets': connection_info['packets'],
                    'bytes': connection_info['bytes']
                }
            else:
                result['destination_stats'] = {
                    'packets': connection_info['packets'],
                    'bytes': connection_info['bytes']
                }
        # not easily parsable, just add the values
        else:
            result['timeout'] = child.find('timeout').text
            result['id'] = child.find('id').text
            if child.find('unreplied') is not None:
                result['unreplied'] = True
            if child.find('state') is not None:
                result['state'] = child.find('state').text

    return result


def list_connections():
    """
    List all network connections.
    Returns:
        dict of applications and their connections.
    """
    result = subprocess.run(["conntrack", "-L", "-o", "xml"], capture_output=True, text=True)
    root = ElementTree.fromstring(result.stdout)
    result = []
    for flow in root.findall('flow'):
        # download
        # upload
        # wan
        result.append(__parse_connection_info(flow))

    return result
