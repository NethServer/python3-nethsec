import pytest
import ipaddress
from nethsec import ovpn
from euci import EUci

def test_to_cidr():
    assert ovpn.to_cidr("255.255.255.0") == 24
    
def test_to_netmask():
    assert ovpn.to_netmask(24) == "255.255.255.0"

def test_generate_random_network():
    assert ipaddress.ip_network(ovpn.generate_random_network(EUci())).is_private

def test_opt2cidr():
    assert ovpn.opt2cidr("192.168.1.0 255.255.255.0") == "192.168.1.0/24"
