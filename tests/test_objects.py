from nethsec import utils
from nethsec.utils import ValidationError
import pytest
from euci import EUci, UciExceptionNotFound

from nethsec import firewall, objects

objects_db = """
"""

firewall_db = """
config rule 'r1'
    option name 'r1'
    option ns_dst 'dhcp/ns_8dcab636'

config rule 'r2'
    option name 'r2'
    option ns_dst ''

config rule 'r3'
    option name 'r3'
    option ns_src ''

config rule 'r4'
    option ns_dst ''
    option ns_src ''

config redirect 'redirect1'
    option ns_src ''
    option ipset 'redirect1_ipset'

config ipset 'redirect1_ipset'
    option name 'redirect1_ipset'
    option match 'src_net'
    option enabled '1'
    list entry '6.7.8.9'

config redirect 'redirect2'
    option ns_src ''
"""

dhcp_db = """
config domain 'ns_8bec5896'
	option ip '7.8.9.1'
	option name 'host1'
	option ns_description 'Host 1'

config host 'ns_8dcab636'
	option ip '192.168.100.5'
	option mac 'fe:54:00:6a:50:bf'
	option dns '1'
	option name 'host2'
	option ns_description 'host2'
"""

user_db = """
config user 'ns_user1'
	option name "john"
	option database "main"
	option label "John Doe"
	option openvpn_ipaddr "10.10.10.22"
"""

def _setup_db(tmp_path):
     # setup fake dbs
    with tmp_path.joinpath('objects').open('w') as fp:
        fp.write(objects_db)
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
    with tmp_path.joinpath('dhcp').open('w') as fp:
        fp.write(dhcp_db)
    with tmp_path.joinpath('users').open('w') as fp:
        fp.write(user_db)
    return EUci(confdir=tmp_path.as_posix())

def test_add_doman_set(tmp_path):
    u = _setup_db(tmp_path)
    id1 = objects.add_domain_set(u, "mydomainset", "ipv4", ["test1.com", "test2.com"])
    assert u.get("objects", id1, "name") == "mydomainset"
    assert u.get("objects", id1, "family") == "ipv4"
    assert u.get_all("objects", id1, "domain") == ("test1.com", "test2.com")
    assert u.get("objects", id1, "timeout") == "600"

    linked = firewall.get_all_linked(u, f"objects/{id1}")
    assert linked['firewall'] is not None
    assert u.get('firewall', linked['firewall'][0], 'ns_link') == f"objects/{id1}"
    assert u.get('firewall', linked['firewall'][0], 'name') == "mydomainset"
    assert u.get('firewall', linked['firewall'][0], 'family') == 'ipv4'
    assert u.get('firewall', linked['firewall'][0], 'timeout') == '600'

    assert linked['dhcp'] is not None
    assert u.get('dhcp', linked['dhcp'][0], 'ns_link') == f"objects/{id1}"
    assert u.get_all('dhcp', linked['dhcp'][0], 'name') == ("mydomainset",)
    assert u.get_all('dhcp', linked['dhcp'][0], 'domain') == ("test1.com", "test2.com")

    id2 = objects.add_domain_set(u, "mydomainset2", "ipv6", ["test3.com", "test4.com"], 600)
    assert u.get("objects", id2, "name") == "mydomainset2"
    assert u.get("objects", id2, "family") == "ipv6"
    assert u.get_all("objects", id2, "domain") == ("test3.com", "test4.com")
    assert u.get("objects", id2, "timeout") == "600"
    linked = firewall.get_all_linked(u, f"objects/{id2}")
    assert u.get('firewall', linked['firewall'][0], 'name') == "mydomainset2"
    assert u.get_all('dhcp', linked['dhcp'][0], 'name') == ("mydomainset2",)

def test_edit_domain_set(tmp_path):
    u = _setup_db(tmp_path)
    id = objects.add_domain_set(u, "mydomainset3", "ipv4", ["test1.com", "test2.com"])
    objects.edit_domain_set(u, id, "mydomainset3b", "ipv6", ["test3.com", "test4.com"], 600)
    assert u.get("objects", id, "name") == "mydomainset3b"
    assert u.get("objects", id, "family") == "ipv6"
    assert u.get_all("objects", id, "domain") == ("test3.com", "test4.com")
    assert u.get("objects", id, "timeout") == "600"
    
def test_delete_domain_set(tmp_path):
    u = _setup_db(tmp_path)
    with pytest.raises(ValidationError):
        objects.delete_domain_set(u, "notpresent")
    id = objects.add_domain_set(u, "mydomainset4", "ipv4", ["test1.com", "test2.com"])
    assert objects.delete_domain_set(u, id) == id
    linked = firewall.get_all_linked(u, f"objects/{id}")
    assert linked['firewall'] == []
    assert linked['dhcp'] == []

def test_is_used_domain_set(tmp_path):
    u = _setup_db(tmp_path)
    id = objects.add_domain_set(u, "used1", "ipv4", ["test1.com", "test2.com"])
    u.set('firewall', 'r1', 'ns_dst', f"objects/{id}")
    used, matches = objects.is_used_domain_set(u, id)
    assert used
    assert matches == ["firewall/r1"]

def test_list_domain_sets(tmp_path):
    u = _setup_db(tmp_path)
    sets = objects.list_domain_sets(u)
    assert len(sets) == 4

def test_add_host_set(tmp_path):
    u = _setup_db(tmp_path)
    with pytest.raises(ValidationError):
        objects.add_host_set(u, "myhostset", "ipv4", ["a.b.c.d", "e.f.g.h"])
    id1 = objects.add_host_set(u, "myhostset", "ipv4", ["1.2.3.4", "4.5.6.0/24", "192.168.1.3-192.168.1.10"])
    assert u.get("objects", id1, "name") == "myhostset"
    assert u.get_all("objects", id1, "ipaddr") == ("1.2.3.4", "4.5.6.0/24", "192.168.1.3-192.168.1.10")
    assert u.get("objects", id1, "family") == "ipv4"
    id2 = objects.add_host_set(u, "myhostset2", "ipv6", ["2001:db8:3333:4444:5555:6666:7777:8888", "2001:db8::/95", "2001:db8:3333:4444:5555:6666:7777:8888-2001:db8:3333:4444:5555:6666:7777:8890"])
    assert u.get("objects", id2, "name") == "myhostset2"
    assert u.get("objects", id2, "family") == "ipv6"
    assert u.get_all("objects", id2, "ipaddr") == ("2001:db8:3333:4444:5555:6666:7777:8888", "2001:db8::/95", "2001:db8:3333:4444:5555:6666:7777:8888-2001:db8:3333:4444:5555:6666:7777:8890")

def test_edit_host_set(tmp_path):
    u = _setup_db(tmp_path)
    id = objects.add_host_set(u, "myhostset3", "ipv4", ["6.7.8.9"])
    objects.edit_host_set(u, id, "myhostset3b", "ipv4", ["1.1.1.1", "2.2.2.2"])
    assert u.get("objects", id, "name") == "myhostset3b"
    assert u.get_all("objects", id, "ipaddr") == ("1.1.1.1", "2.2.2.2")

def test_delete_host_set(tmp_path):
    u = _setup_db(tmp_path)
    with pytest.raises(ValidationError):
        objects.delete_host_set(u, "notpresent")
    id = objects.add_host_set(u, "myhostset4", "ipv4", ["6.7.8.9"])
    assert objects.delete_host_set(u, id) == id

def test_is_used_host_set(tmp_path):
    u = _setup_db(tmp_path)
    id = objects.add_host_set(u, "myhostset", "ipv4", ["1.1.1.1"])
    u.set('firewall', 'r3', 'ns_src', f"objects/{id}")
    used, matches = objects.is_used_host_set(u, id)
    assert used
    assert matches == ["firewall/r3"]

def test_list_host_sets(tmp_path):
    u = _setup_db(tmp_path)
    sets = objects.list_host_sets(u)
    assert len(sets) == 4

def test_is_used_object(tmp_path):
    u = _setup_db(tmp_path)
    used, matches = objects.is_used_object(u, "dhcp/ns_8dcab636")
    assert used
    assert matches == ["firewall/r1"]
    assert objects.is_used_object(u, "dhcp/ns_8bec5896")[0] == False

def test_get_object(tmp_path):
    u = _setup_db(tmp_path)
    id = objects.add_host_set(u, "myhostset", "ipv4", ["1.2.3.4"])
    obj = objects.get_object(u, id)

def test_get_object_ips(tmp_path):
    u = _setup_db(tmp_path)
    id0 = objects.add_host_set(u, "myhostset0", "ipv4", ["4.5.6.7"])
    id = objects.add_host_set(u, "myhostset", "ipv4", ["1.2.3.4", "dhcp/ns_8bec5896", "users/ns_user1", f"objects/{id0}"])
    ips = objects.get_object_ips(u, f"objects/{id}")
    assert set(ips) == set(["1.2.3.4", "7.8.9.1", "10.10.10.22", "4.5.6.7"]) # check with set to ignore order

def test_update_redirect_rules(tmp_path):
    u = _setup_db(tmp_path)
    domain1 = objects.add_domain_set(u, "d1", "ipv4", ["test1.com", "test2.com"])
    ipsets = objects.get_domain_set_ipsets(u, domain1)
    host1 = objects.add_host_set(u, "h1", "ipv4", ["192.168.168.1", "users/ns_user1"])
    u.set("firewall", "redirect1", "ns_src", f"objects/{domain1}") # domain can be used only as source
    u.set('firewall', 'redirect1', 'ns_dst', f"dhcp/ns_8bec5896")
    objects.update_redirect_rules(u)
    assert u.get("firewall", "redirect1", "dest_ip") == "7.8.9.1" 
    assert u.get("firewall", "redirect1", "ipset") == f"{ipsets['firewall']} src_net"
    u.set("firewall", "redirect2", "ns_src", f"objects/{host1}")
    u.set('firewall', 'redirect2', 'ns_dst', f"users/ns_user1")
    objects.update_redirect_rules(u)
    assert u.get("firewall", "redirect2", "dest_ip") == "10.10.10.22"
    assert u.get("firewall", "redirect2", "ipset") == f"{host1}_ipset"
    assert u.get("firewall", "redirect2_ipset")

def test_update_firewall_rules(tmp_path):
    u = _setup_db(tmp_path)
    domain1 = objects.add_domain_set(u, "d1", "ipv4", ["test1.com", "test2.com"])
    ipsets = objects.get_domain_set_ipsets(u, domain1)
    host1 = objects.add_host_set(u, "h1", "ipv4", ["192.168.168.1", "users/ns_user1"])
    u.set("firewall", "r1", "ns_dst", f"objects/{domain1}")
    u.set("firewall", "r1", "ns_src", f"objects/{host1}")
    objects.update_firewall_rules(u)
    assert set(u.get_all("firewall", "r1", "src_ip")) == set(objects.get_object_ips(u, f"objects/{host1}"))
    assert u.get("firewall", "r1", "ipset") == f"{ipsets['firewall']} dst"
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", "r1", "dest_ip")

    u.set("firewall", "r2", "ns_dst", f"objects/{host1}")
    u.set("firewall", "r2", "ns_src", f"objects/{domain1}")
    objects.update_firewall_rules(u)

    assert u.get("firewall", "r2", "ipset") == f"{ipsets['firewall']} src"
    assert set(u.get_all("firewall", "r2", "dest_ip")) == set(objects.get_object_ips(u, f"objects/{host1}"))
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", "r2", "src_ip")

    u.set("firewall", "r3", "ns_src", "dhcp/ns_8bec5896")
    u.set("firewall", "r3", "ns_dst", "users/ns_user1")
    objects.update_firewall_rules(u)
    assert u.get_all("firewall", "r3", "src_ip") == ("7.8.9.1",)
    assert u.get_all("firewall", "r3", "dest_ip") == ("10.10.10.22",)

    u.set("firewall", "r4", "ns_src", f"objects/{domain1}")
    u.set("firewall", "r4", "dest_ip", "1.2.3.4")
    objects.update_firewall_rules(u)
    with pytest.raises(UciExceptionNotFound):
        u.get("firewall", "r4", "ns_dst")