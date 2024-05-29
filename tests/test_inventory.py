import pytest
from nethsec import inventory
from euci import EUci
from unittest.mock import MagicMock, patch


firewall_db = """
config zone wan1
	option name 'wan'
	list network 'wan'
	list network 'wan6'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'
	list device 'eth2.1'

config zone
	option name 'lan'
	list network 'lan'
	list network 'br-lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	list device 'tunrw1'
	list device 'ipsec2'
"""

network_db = """
config interface lan
	option device 'vnet3'
	option proto 'static'
            
config interface 'wan'
	option device 'eth1'
	option proto 'dhcp'

config interface 'wan6'
	option device 'eth1'
	option proto 'dhcpv6'

config interface 'bond1'
	option proto 'bonding'
	option ipaddr '10.0.0.22'
	option netmask '255.255.255.0'
	list slaves 'eth3'
	option bonding_policy 'balance-rr'
	option packets_per_slave '1'
	option all_slaves_active '0'
	option link_monitoring 'off'

config interface 'bond2'
	option proto 'bonding'
	option ipaddr '10.11.11.22'
	option netmask '255.255.255.0'
	option bonding_policy 'balance-rr'
	option packets_per_slave '1'
	list slaves 'eth3.2'
"""

dedalo_db = """
config dedalo 'config'
	option aaa_url 'https://my.nethspot.com/wax/aaa'
	option api_url 'https://my.nethspot.com/api'
	option network '192.168.82.0/24'
	option disabled '0'
	option splash_page 'http://my.nethspot.com/wings'
	option max_clients '253'
	option dhcp_end '250'
	option dhcp_start '2'
	option hotspot_id '51'
	option unit_name 'fw1.nethsecurity.org'
	option unit_description 'fw1 sede'
	option interface 'eth2.10'
	option secret 'xxxxxx'
	option unit_uuid 'yyyyy'
"""

flashstart_db = """
config main 'global'
	option enabled '0'
	option password 'xxx'
	option username 'xxx@nethsecurity.org'
	list zones 'lan'
	list bypass '192.168.1.252'
	list bypass '192.168.1.211'
 """

openvpn_db = """
config openvpn 'sample_client'
	option client '1'
	option dev 'tun'
	option proto 'udp'
	list remote 'my_server_1 1194'
	option resolv_retry 'infinite'
	option nobind '1'
	option persist_key '1'
	option persist_tun '1'
	option user 'nobody'
	option ca '/etc/openvpn/ca.crt'
	option cert '/etc/openvpn/client.crt'
	option key '/etc/openvpn/client.key'
	option verb '3'

config openvpn 'ns_roadwarrior1'
	option proto 'udp'
	option port '1194'
	option dev 'tunrw1'
	option dev_type 'tun'
	option topology 'subnet'
	option float '1'
	option passtos '1'
	option multihome '1'
	option verb '3'
	option enabled '1'
	option keepalive '20 120'
	option server '10.9.9.0 255.255.255.0'
	option client_connect '"/usr/libexec/ns-openvpn/openvpn-connect ns_roadwarrior1"'
	option client_disconnect '"/usr/libexec/ns-openvpn/openvpn-disconnect ns_roadwarrior1"'
	option dh '/etc/openvpn/ns_roadwarrior1/pki/dh.pem'
	option ca '/etc/openvpn/ns_roadwarrior1/pki/ca.crt'
	option cert '/etc/openvpn/ns_roadwarrior1/pki/issued/server.crt'
	option crl_verify '/etc/openvpn/ns_roadwarrior1/pki/crl.pem'
	option key '/etc/openvpn/ns_roadwarrior1/pki/private/server.key'
	option management '/var/run/openvpn_ns_roadwarrior1.socket unix'
	option client_to_client '0'
	option auth 'SHA256'
	option cipher 'AES-256-GCM'
	option tls_version_min '1.2'
	option ns_auth_mode 'username_password_certificate'
	list ns_tag 'automated'
	option ns_user_db 'NethService'
	option ns_description 'srv1'
	option auth_user_pass_verify '/usr/libexec/ns-openvpn/openvpn-remote-auth via-env'
	option script_security '3'
	list push 'redirect-gateway'
	list push 'route 192.168.1.0 255.255.255.0'
	list push 'route 172.2.2.0 255.255.254.0'
	list ns_public_ip 'vpn.test.org'

config user 'user1'
	option instance 'ns_roadwarrior1'
	option ipaddr '10.9.9.50'
	option enabled '1'
"""

ns_plug_db = """
config main 'config'
	option tls_verify '1'
	option backup_url 'https://backupd.nethsecurity.org/backup'
	option type 'enterprise'
	option alerts_url 'https://my.nethsecurity.org/isa/'
	option api_url 'https://my.nethsecurity.org/api/'
	option inventory_url 'https://my.nethsecurity.org/isa/inventory/store/'
	option system_id 'xxx'
	option secret 'yyy'
    option server ''
    option unit_id ''
    option token ''
"""

ban_ip_db = """
config banip 'global'
	option ban_enabled '1'
	option ban_debug '1'
	option ban_autodetect '0'
	list ban_logterm 'Exit before auth from'
	option ban_fetchcmd 'curl'
	option ban_protov4 '1'
	list ban_ifv4 'FIBER100M'
	list ban_ifv4 'FTTC_BCK'
	list ban_dev 'eth0'
	list ban_dev 'eth5'
    list ban_allowurl ''
	option ban_loginput '1'
	option ban_logforwardwan '1'
	option ban_logforwardlan '1'
	option ban_autoallowlist '1'
	option ban_autoblocklist '1'
	option ban_allowlistonly '0'
	option ban_nftexpiry '1d'
	option ban_logcount '3'
	list ban_feed 'nethesislvl3'
    list ban_feed 'test1'
"""

ns_ui_db = """
config main 'config'
	option luci_enable '0'
	option nsui_enable '1'
	option nsui_extra_port '9090'
	option nsui_extra_enable '1'
"""

fstab_db = """
config global
	option anon_swap '0'
	option anon_mount '0'
	option auto_swap '1'
	option auto_mount '1'
	option delay_root '5'
	option check_fs '0'

config mount
	option target '/rom'
	option uuid '520aae54-7d368ea4-c0a96e03-92927a0f'
	option enabled '0'

config mount 'ns_data'
	option target '/mnt/data'
	option uuid '523ba406-b2b6-4a3c-b071-ac1bf6acf4c6'
	option enabled '1'
"""

nginx_db = """
config main 'global'
	option uci_enable 'true'

config server '_lan'
	list listen '443 ssl default_server'
	list listen '[::]:443 ssl default_server'
	option server_name '_lan'
	list include 'conf.d/*.locations'
	option uci_manage_ssl 'custom'
	option ssl_certificate '/etc/ssl/acme/test.nethsecurity.org.fullchain.crt'
	option ssl_certificate_key '/etc/ssl/acme/test.nethsecurity.org.key'
	option ssl_session_cache 'shared:SSL:32k'
	option ssl_session_timeout '64m'
	option error_log 'syslog:server=unix:/dev/log'
	option access_log 'syslog:server=unix:/dev/log'

config location 'ns_server2_location1'
	option uci_server 'ns_server2'
	option location '/'
	option proxy_pass 'https://172.4.5.4'

config server 'ns_server1'
	option uci_description 'Test 1'
	option ssl_session_timeout '64m'
	list proxy_set_header 'Host $http_host'
	list listen '443 ssl'
	list listen '[::]:443 ssl'
	option ssl_session_cache 'shared:SSL:32k'
	option server_name 'metrics.nethsecurity.org'
	list include 'conf.d/ns_server1.proxy'
	option uci_manage_ssl 'acme'
	option ssl_certificate '/etc/ssl/acme/test.nethsecurity.org.fullchain.crt'
	option ssl_certificate_key '/etc/ssl/acme/test.nethsecurity.org.key'

config location 'ns_server1_location1'
	option uci_server 'ns_server1'
	option location '/'
	option proxy_pass 'https://172.3.3.3'
"""

ipsec_db = """
config ipsec 'ns_ipsec_global'
	option debug '1'
	option zone 'ipsec'

config crypto_proposal 'ns_6fd94f07_ike'
	option encryption_algorithm 'aes256'
	option hash_algorithm 'sha256'
	option dh_group 'modp2048'
	option ns_link 'ipsec/ns_6fd94f07'

config crypto_proposal 'ns_6fd94f07_esp'
	option encryption_algorithm 'aes256'
	option hash_algorithm 'sha256'
	option dh_group 'modp2048'
	option ns_link 'ipsec/ns_6fd94f07'

config tunnel 'ns_6fd94f07_tunnel_1'
	option ipcomp 'false'
	option dpdaction 'none'
	list local_subnet '192.168.1.0/24'
	list remote_subnet '192.168.3.0/24'
	option rekeytime '3600'
	list crypto_proposal 'ns_6fd94f07_esp'
	option closeaction 'none'
	option startaction 'start'
	option if_id '1'
	option ns_link 'ipsec/ns_6fd94f07'

config tunnel 'ns_6fd94f07_tunnel_2'
	option ipcomp 'false'
	option dpdaction 'none'
	list local_subnet '172.4.4.0/24'
	list remote_subnet '192.168.3.0/24'
	option rekeytime '3600'
	list crypto_proposal 'ns_6fd94f07_esp'
	option closeaction 'none'
	option startaction 'start'
	option if_id '1'
	option ns_link 'ipsec/ns_6fd94f07'

config remote 'ns_6fd94f07'
	option ns_name 't1'
	option authentication_method 'psk'
	option gateway '1.2.3.4'
	option keyexchange 'ikev1'
	option local_identifier '@l1'
	option local_ip '5.6.7.8'
	option enabled '1'
	option remote_identifier '@r1'
	option pre_shared_key 'xxx'
	list crypto_proposal 'ns_6fd94f07_ike'
	option rekeytime '3600'
	list tunnel 'ns_6fd94f07_tunnel_1'
	list tunnel 'ns_6fd94f07_tunnel_2'
"""

dpi_db = """
config main 'config'
	option log_blocked '0'
	option enabled '1'
	option firewall_exemption '0'

config rule 'ns_2b170d05'
	option enabled '1'
	option device 'br-lan'
	option action 'block'
	list application 'netify.facebook'
"""

dhcp_db = """
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'nethesis.it'
	option expandhosts '1'
	option nonegcache '0'
	option cachesize '1000'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	option localservice '1'
	option ednspacket_max '1232'
	option filter_aaaa '0'
	option filter_a '0'
	option logqueries '0'
	list server '8.8.8.8'
	list server '8.8.4.4'
	list rebind_domain 'nethsecurity.org'

config dhcp 'lan'
	option interface 'lan'
	option start '100'
	option limit '150'
	option leasetime '12h'
	option dhcpv4 'server'
	option dhcpv6 'server'
	option ra 'server'
	option ra_slaac '1'
	list ra_flags 'managed-config'
	list ra_flags 'other-config'
"""

mwan3_db = """
config globals 'globals'
	option mmx_mask '0x3F00'

config policy 'ns_default'
	option label 'Default'
	list use_member 'ns_FIBER100M_M10_W100'
	list use_member 'ns_FTTC_BCK_M20_W100'

config interface 'FIBER100M'
	option enabled '1'
	option initial_state 'online'
	option family 'ipv4'
	list track_ip '8.8.8.8'
	list track_ip '208.67.222.222'
	option track_method 'ping'
	option reliability '1'
	option count '1'
	option size '56'
	option max_ttl '60'
	option timeout '4'
	option interval '10'
	option failure_interval '5'
	option recovery_interval '5'
	option down '5'
	option up '5'

config member 'ns_FIBER100M_M10_W100'
	option interface 'FIBER100M'
	option metric '10'
	option weight '100'

config interface 'FTTC_BCK'
	option enabled '1'
	option initial_state 'online'
	option family 'ipv4'
	list track_ip '8.8.8.8'
	list track_ip '208.67.222.222'
	option track_method 'ping'
	option reliability '1'
	option count '1'
	option size '56'
	option max_ttl '60'
	option timeout '4'
	option interval '10'
	option failure_interval '5'
	option recovery_interval '5'
	option down '5'
	option up '5'

config member 'ns_FTTC_BCK_M20_W100'
	option interface 'FTTC_BCK'
	option metric '20'
	option weight '100'

config rule 'ns_default_rule'
	option label 'Default Rule'
	option use_policy 'ns_default'
	option sticky '1'
"""

qosify_db = """
config interface 'wan'
	option name 'wan'
	option disabled '1'
	option bandwidth_up '100mbit'
	option bandwidth_down '100mbit'
	option overhead_type 'none'
	option ingress '1'
	option egress '1'
	option mode 'diffserv4'
	option nat '1'
	option host_isolate '1'
	option autorate_ingress '0'

config device 'wandev'
	option disabled '1'
	option name 'wan'
	option bandwidth '100mbit'

config interface 'FIBER100M'
	option name 'FIBER100M'
	option disabled '0'
	option bandwidth_up '85mbit'
	option bandwidth_down '85mbit'

config interface 'FTTC_BCK'
	option name 'FTTC_BCK'
	option disabled '0'
	option bandwidth_up '20mbit'
	option bandwidth_down '40mbit'
"""

def _setup_db(tmp_path):
     # setup fake db
    with tmp_path.joinpath('network').open('w') as fp:
        fp.write(network_db)
    with tmp_path.joinpath('firewall').open('w') as fp:
        fp.write(firewall_db)
    with tmp_path.joinpath('dedalo').open('w') as fp:
        fp.write(dedalo_db)
    with tmp_path.joinpath('flashstart').open('w') as fp:
        fp.write(flashstart_db)
    with tmp_path.joinpath('openvpn').open('w') as fp:
        fp.write(openvpn_db)
    with tmp_path.joinpath('ns-plug').open('w') as fp:
        fp.write(ns_plug_db)
    with tmp_path.joinpath('banip').open('w') as fp:
        fp.write(ban_ip_db)
    with tmp_path.joinpath('ns-ui').open('w') as fp:
        fp.write(ns_ui_db)
    with tmp_path.joinpath('fstab').open('w') as fp:
        fp.write(fstab_db)
    with tmp_path.joinpath('nginx').open('w') as fp:
        fp.write(nginx_db)
    with tmp_path.joinpath('ipsec').open('w') as fp:
        fp.write(ipsec_db)
    with tmp_path.joinpath('dpi').open('w') as fp:
        fp.write(dpi_db)
    with tmp_path.joinpath('dhcp').open('w') as fp:
        fp.write(dhcp_db)
    with tmp_path.joinpath('mwan3').open('w') as fp:
        fp.write(mwan3_db)
    with tmp_path.joinpath('qosify').open('w') as fp:
        fp.write(qosify_db)
    return EUci(confdir=tmp_path.as_posix())

def test_fact_hotspot(tmp_path):
    u = _setup_db(tmp_path)
    assert inventory.fact_hotspot(u) == {"enabled": True, "server": "https://my.nethspot.com/api"}

def test_fact_flashstart(tmp_path):
    u = _setup_db(tmp_path)
    assert inventory.fact_flashstart(u) == {"enabled": False, "bypass": 2}
    
def test_fact_openvpn_rw(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_openvpn_rw(u) == {"enabled": 1, "server": 1}
    
def test_fact_openvpn_tun(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_openvpn_tun(u) == {"server": 0, "client": 0}
     
def test_fact_subscription_status(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_subscription_status(u) == {"status": "enterprise"}
     
def test_fact_controller(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_controller(u) == {"enabled": False}
     
def test_fact_threat_shield(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_threat_shield(u) == {"enabled": True, "community": 1, "enterprise": 1}
     
def test_fact_ui(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_ui(u) == {"luci": False, "port443": True, "port9090": True}
     
def test_fact_storage(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_storage(u) == {"enabled": True}
     
def test_fact_network(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_network(u) == {"ipv6": 1, "ipv4": 6} # 2 more ipv4 interfaces from previous tests
      
def test_fact_proxy_pass(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_proxy_pass(u) == {"count": 2}
      
def test_fact_ipsec(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_ipsec(u) == {"count": 1}
      
def test_fact_dpi(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_dpi(u) == {"enabled": True, "rules": 1}
      
def test_fact_dhcp_server(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_dhcp_server(u) == {"count": 1}
      
def test_fact_multiwan(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_multiwan(u) == {"wans": 2, "type": "backup"}
      
def test_fact_qos(tmp_path):
	u = _setup_db(tmp_path)
	assert inventory.fact_qos(u) == {"count": 2}