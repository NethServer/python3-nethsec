#!/usr/bin/python3

#
# Copyright (C) 2023 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

"""
Library that handles users and groups
"""

import base64
import hashlib
import ipaddress
import os
import subprocess
import secrets
from nethsec import utils
from urllib.parse import urlparse
from passlib import hash

def get_database_type(uci, database):
    '''
    Retrieve database type

    Arguments:
      - uci -- EUci pointer
      - database -- Database identifier

    Returns:
      - Database type (local or ldap)
    '''
    return uci.get('users', database, default='')

def get_user_by_name(uci, name, database="main"):
    '''
    Retrieve a user by name

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - database -- Local database identifier (default: main)

    Returns:
      - A user object or None if not found
    '''
    user = {"local": get_database_type(uci, database) == "local"}
    for u in uci.get_all('users'):
        if uci.get('users', u, 'database', default='') != database:
            continue
        if uci.get('users', u, default='') == "user":
            if uci.get('users', u, 'name', default='') == name:
                for opt in uci.get_all("users", u):
                    user[opt] = uci.get_all('users', u, opt)
                    # convert tuple to list
                    if type(user[opt]) is tuple:
                        user[opt] = list(user[opt])
                if user["local"]:
                  user["admin"] = is_admin(uci, name)
                else:
                  user["admin"] = False
                user['id'] = u
                return user
    return None

def get_group_by_name(uci, name, database="main"):
    '''
    Retrieve a group by name

    Arguments:
      - uci -- EUci pointer
      - name -- Group name
      - database -- Local database identifier (default: main)


    Returns:
      - A group object or None if not found
    '''
    group = {"local": get_database_type(uci, database) == "local"}
    for g in uci.get_all('users'):
        if uci.get('users', g, 'database', default='') != database:
            continue
        if uci.get('users', g, default='') == "group":
            if uci.get('users', g, 'name', default='') == name:
                for opt in uci.get_all("users", g):
                    group[opt] = uci.get_all('users', g, opt)
                    # convert tuple to list
                    if type(group[opt]) is tuple:
                        group[opt] = list(group[opt])
                group['id'] = g
                return group
    return None

def get_user_addresses(uci, user):
    '''
    Retrieve all IP addresses associated to given user

    Arguments:
      - uci -- EUci pointer
      - user -- User object id (UCI section)

    Returns a tuple of lists:
      - first element is a list of IPv4 addresses
      - second element is a list of IPv6 addresses
    '''
    ipv4 = []
    ipv6 = []
    user_obj = get_user_by_name(uci, user)
    # get addresses from plain ipaddr option
    for ip in uci.get('users', user_obj['id'], 'ipaddr', list=True, default=[]):
        if ':' in ip:
            ipv6.append(ip)
        else:
            ipv4.append(ip)
    # get vpn reservation
    ovpn_ipaddr = uci.get('users', user_obj['id'], 'openvpn_ipaddr', default="")
    if ovpn_ipaddr:
        if ':' in ovpn_ipaddr:
            ipv6.append(ovpn_ipaddr)
        else:
            ipv4.append(ovpn_ipaddr)
    # get address from DNS record and DHCP reservation
    for st in ['host', 'domain']:
        for h in uci.get('objects', user_obj['id'], st, list=True, default=[]): # dhcp reservation
            ip = uci.get('dhcp', h, 'ip', default='')
            if not ip:
                continue
            if ':' in ip:
                ipv6.append(ip)
            else:
                ipv4.append(ip)

    return (ipv4, ipv6)

def get_user_macs(uci, user):
    '''
    Retrieve all MAC addresses associated to given user

    Arguments:
      - uci -- EUci pointer
      - user -- User object id (UCI section)

    Returns:
      - A list of MAC addresses
    '''
    user_obj = get_user_by_name(uci, user)
    return list(uci.get('users', user_obj['id'], 'macaddr', list=True, default=[]))

def get_group_addresses(uci, group):
    '''
    Retrieve all IP addresses associated to given group

    Arguments:
      - uci -- EUci pointer
      - user -- Group object id (UCI section)

    Returns:
      - A tuple of lists:
        - first element is a list of IPv4 addresses
        - second element is a list of IPv6 addresses
    '''
    ipv4 = []
    ipv6 = []
    group_obj = get_group_by_name(uci, group)
    for u in uci.get('users', group_obj['id'], 'user', list=True, default=[]):
        (uipv4, uipv6) = get_user_addresses(uci, u)
        ipv4 = ipv4 + uipv4
        ipv6 = ipv6 + uipv6
    return (ipv4, ipv6)

def get_group_macs(uci, group):
    '''
    Retrieve all MAC addresses associated to given group

    Arguments:
      - uci -- EUci pointer
      - group -- Group object id (UCI section)

    Returns:
      - A list of MAC addresses
    '''
    macs = []
    group_obj = get_group_by_name(uci, group)
    for u in uci.get('users', group_obj['id'], 'user', list=True, default=[]):
        macs = macs + get_user_macs(uci, u)
    return macs

def list_users(uci, database='main'):
    '''
    Retrieve all users

    Arguments:
      - database -- Database identifier (default: main)

    Returns:
      - A list of user objects
    '''
    users = []
    try:
        dbconf = uci.get_all('users', database)
    except:
        raise utils.ValidationError('database', 'db_not_found', database)
    dbtype = get_database_type(uci, database)
    if dbtype == "local":
        for u in utils.get_all_by_type(uci, 'users', 'user'):
            if uci.get('users', u, 'database', default='') != database:
                continue
            if uci.get('users', u, default='') == "user":
                username = uci.get('users', u, 'name', default='')
                user = get_user_by_name(uci, username, database)
                users.append(user)
    elif dbtype == "ldap":
        users = list_remote_users(dbconf.get('uri'), dbconf.get('user_dn'), dbconf.get('user_attr'), dbconf.get('user_cn'), dbconf.get('start_tls') == '1', dbconf.get('tls_reqcert'), dbconf.get('bind_dn'), dbconf.get('bind_password'), dbconf.get('schema'))
        for u in users:
            user = get_user_by_name(uci, u['name'], database)
            if user:
                u.update(user)
            else:
                u['id'] = None
            u['local'] = False
            u['admin'] = False
            u['database'] = database
        pass

    return users

def add_ldap_database(uci, name, uri, schema, base_dn, user_dn, user_attr, user_cn, start_tls=False, tls_reqcert='never', description="", bind_dn=None, bind_password=None):
  '''
  Add a new LDAP database

  Arguments:
    - uci -- EUci pointer
    - name -- Database identifier
    - uri -- LDAP URI
    - schema -- LDAP schema
    - base_dn -- LDAP base DN
    - user_dn -- LDAP user DN
    - user_attr -- LDAP user attribute
    - user_cn -- LDAP user common name
    - start_tls -- Use TLS (default: False)
    - tls_reqcert -- TLS certificate validation (default: never)
    - description -- Database description (default: "")
    - bind_dn -- LDAP bind DN
    - bind_password -- LDAP bind password

  Returns:
    - The database identifier
  '''
  if uci.get('users', name, default=None):
      raise utils.ValidationError('name', 'db_already_exists', name)
  ldap = uci.set('users', name, 'ldap')
  uci.set('users', name, 'uri', uri)
  uci.set('users', name, 'schema', schema)
  uci.set('users', name, 'base_dn', base_dn)
  uci.set('users', name, 'user_dn', user_dn)
  uci.set('users', name, 'user_attr', user_attr)
  uci.set('users', name, 'user_cn', user_cn)
  uci.set('users', name, 'start_tls', '1' if start_tls else '0')
  uci.set('users', name, 'tls_reqcert', tls_reqcert)
  uci.set('users', name, 'description', description)
  if bind_dn and bind_password:
      uci.set('users', name, 'bind_dn', bind_dn)
      uci.set('users', name, 'bind_password', bind_password)
  uci.save("users")
  return ldap

def edit_ldap_database(uci, name, uri, schema, base_dn, user_dn, user_attr, user_cn, start_tls=False, tls_reqcert='never', description="", bind_dn=None, bind_password=None):
  '''
  Edit an existing LDAP database

  Arguments:
    - uci -- EUci pointer
    - name -- Database identifier
    - uri -- LDAP URI
    - schema -- LDAP schema
    - base_dn -- LDAP base DN
    - user_dn -- LDAP user DN
    - user_attr -- LDAP user attribute
    - user_cn -- LDAP user common name
    - start_tls -- Use TLS (default: False)
    - tls_reqcert -- TLS certificate validation (default: never)
    - description -- Database description (default: "")
    - bind_dn -- LDAP bind DN
    - bind_password -- LDAP bind password

  Returns:
    - The database identifier
  '''
  if not uci.get('users', name, default=None):
      raise utils.ValidationError('name', 'db_not_found', name)
  if uci.get('users', name, default='') != "ldap":
      raise utils.ValidationError('name', 'db_not_ldap', name)
  uci.set('users', name, 'uri', uri)
  uci.set('users', name, 'schema', schema)
  uci.set('users', name, 'base_dn', base_dn)
  uci.set('users', name, 'user_dn', user_dn)
  uci.set('users', name, 'user_attr', user_attr)
  uci.set('users', name, 'user_cn', user_cn)
  uci.set('users', name, 'start_tls', '1' if start_tls else '0')
  uci.set('users', name, 'tls_reqcert', tls_reqcert)
  uci.set('users', name, 'description', description)
  if bind_dn and bind_password:
    uci.set('users', name, 'bind_dn', bind_dn)
    uci.set('users', name, 'bind_password', bind_password)
  else:
      try:
          uci.delete('users', name, 'bind_dn')
          uci.delete('users', name, 'bind_password')
      except:
          pass
  uci.save("users")
  return True

def delete_ldap_database(uci, name):
  '''
  Delete an existing LDAP database

  Arguments:
    - uci -- EUci pointer
    - name -- Database identifier

  Returns:
    - True if successful
  '''
  if not uci.get('users', name, default=None):
      raise utils.ValidationError('name', 'db_not_found', name)
  if uci.get('users', name, default='') != "ldap":
      raise utils.ValidationError('name', 'db_not_ldap', name)
  for u in uci.get_all('users'):
      if uci.get('users', u, 'database', default='') == name:
          uci.delete('users', u)
  uci.delete('users', name)
  uci.save("users")
  return True

def add_local_database(uci, name, description=""):
  '''
  Add a new local database

  Arguments:
    - uci -- EUci pointer
    - name -- Database identifier
    - description -- Database description (default: "")

  Returns:
    - The database identifier  
  '''
  if uci.get('users', name, default=None):
      raise utils.ValidationError('name', 'db_already_exists', name)
  local = uci.set('users', name, 'local')
  uci.set('users', name, 'description', description)
  uci.save("users")
  return True

def edit_local_database(uci, name, description=""):
  '''
  Edit an existing local database

  Arguments:
    - uci -- EUci pointer
    - name -- Database identifier
    - description -- Database description (default: "")

  Returns:
    - The database identifier  
  '''
  if not uci.get('users', name, default=None):
      raise utils.ValidationError('name', 'db_not_found', name)
  if uci.get('users', name, default='') != "local":
      raise utils.ValidationError('name', 'db_not_local', name)
  uci.set('users', name, 'description', description)
  uci.save("users")
  return True

def delete_local_database(uci, name):
  '''
  Delete an existing local database

  Arguments:
    - uci -- EUci pointer
    - name -- Database identifier

  Returns:
    - True if successful
  '''
  if not uci.get('users', name, default=None):
      raise utils.ValidationError('name', 'db_not_found', name)
  if uci.get('users', name, default='') != "local":
      raise utils.ValidationError('name', 'db_not_local', name)
  uci.delete('users', name)
  for u in uci.get_all('users'):
      if uci.get('users', u, 'database', default='') == name:
          uci.delete('users', u)
  uci.save("users")
  return True

def list_databases(uci):
    '''
    Retrieve all databases

    Arguments:
      - uci -- EUci pointer

    Returns:
      - A list of database objects, each one containing:
        - name: database identifier
        - type: database type (local or ldap)
        - description: database description
    '''
    ret = []
    for db in uci.get_all('users'):
        if uci.get('users', db, default='') == "local":
            ret.append({"name": db, "type": "local", "description": uci.get('users', db, 'description', default='')})
        elif uci.get('users', db, default='') == "ldap":
            ret.append({"name": db, "type": "ldap", "description": uci.get('users', db, 'description', default=''),
                        "schema": uci.get('users', db, 'schema', default=''),
                        "uri": uci.get('users', db, 'uri', default='')})
    return ret

def get_database(uci, name):
    '''
    Retrieve a database by name

    Arguments:
      - uci -- EUci pointer
      - name -- Database identifier

    Returns:
      - A database object or None if not found
    '''
    try:
        db = uci.get_all('users', name)
    except:
        return None
    db["name"] = name
    db["type"] = get_database_type(uci, name)
    return db

def add_local_user(uci, name, password="", description="", database="main", extra_fields={}):
    '''
    Add a new local user

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - password -- User password
      - description -- User description (default: "")
      - database -- Local database identifier (default: main)
      - extra_fields -- Extra fields to add to the user (default: {})

    Returns:
      - The user identifier
    '''
    if get_user_by_name(uci, name, database):
        raise utils.ValidationError('name', 'user_already_exists', name)
    if get_database_type(uci, database) != "local":
        raise utils.ValidationError('database', 'db_not_local', database)
    id = utils.get_random_id()
    user = uci.set('users', id, 'user')
    uci.set('users', id, 'database', database)
    uci.set('users', id, 'name', name)
    if password:
      uci.set('users', id, 'password', shadow_password(password))
    uci.set('users', id, 'description', description)
    for key in extra_fields:
        uci.set('users', id, key, extra_fields[key])
    uci.save("users")
    return id

def edit_local_user(uci, name, password="", description="", database="main", extra_fields={}):
    '''
    Edit an existing local user

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - password -- User password
      - description -- User description (default: "")
      - database -- Local database identifier (default: main)
      - extra_fields -- Extra fields to add to the user (default: {})

    Returns:
      - The user identifier
    '''
    user = get_user_by_name(uci, name, database)
    if not user:
        raise utils.ValidationError('name', 'user_not_found', name)
    if get_database_type(uci, database) != "local":
        raise utils.ValidationError('database', 'db_not_local', database)
    if password:
      shadow = shadow_password(password)
      uci.set('users', user["id"], 'password', shadow)
      # update password inside the rpcd configuration database
      if is_admin(uci, name):
          for l in utils.get_all_by_type(uci, 'rpcd', 'login'):
              if uci.get('rpcd', l, 'username', default='') == name:
                  uci.set('rpcd', l, 'password', shadow)
                  uci.save("rpcd")
    uci.set('users', user["id"], 'description', description)
    for key in uci.get_all('users', user["id"]):
        if not key in ["name", "description", "password", "database"]:
            uci.delete('users', user["id"], key)
    for key in extra_fields:
        uci.set('users', user["id"], key, extra_fields[key])
    uci.save("users")
    return user["id"]

def delete_local_user(uci, name, database="main"):
    '''
    Delete an existing local user

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - database -- Local database identifier (default: main)

    Returns:
      - True if successful
    '''
    user = get_user_by_name(uci, name, database)
    if not user:
        raise utils.ValidationError('name', 'user_not_found', name)
    if get_database_type(uci, database) != "local":
        raise utils.ValidationError('database', 'db_not_local', database)
    # remove user from all groups
    for g in uci.get_all('users'):
        if uci.get('users', g, 'database', default='') != database:
            continue
        if uci.get('users', g, default='') == "group":
            gusers = list(uci.get('users', g, 'user', list=True, default=[]))
            if name in gusers:
                gusers.remove(name)
                uci.set('users', g, 'user', gusers) # the user field may be deleted by uci if the list is empty
    uci.delete('users', user["id"])
    uci.save("users")
    if is_admin(uci, name):
        remove_admin(uci, name)
    return True

def add_local_group(uci, name, users=[], description="", database="main"):
    '''
    Add a new local group

    Arguments:
      - uci -- EUci pointer
      - name -- Group name
      - users -- List of users (default: [])
      - description -- Group description (default: "")
      - database -- Local database identifier (default: main)

    Returns:
      - The group identifier
    '''
    if get_group_by_name(uci, name, database):
        raise utils.ValidationError('name', 'group_already_exists', name)
    if get_database_type(uci, database) != "local":
        raise utils.ValidationError('database', 'db_not_local', database)

    id = utils.get_random_id()
    group = uci.set('users', id, 'group')
    uci.set('users', id, 'database', database)
    uci.set('users', id, 'name', name)
    uci.set('users', id, 'description', description)
    uci.set('users', id, 'user', users)
    uci.save("users")
    return id

def edit_local_group(uci, name, users=[], description="", database="main"):
    '''
    Edit an existing local group

    Arguments:
      - uci -- EUci pointer
      - name -- Group name
      - users -- List of users (default: [])
      - description -- Group description (default: "")
      - database -- Local database identifier (default: main)

    Returns:
      - The group identifier
    '''
    group = get_group_by_name(uci, name, database)
    if not group:
        raise utils.ValidationError('name', 'group_not_found', name)
    if get_database_type(uci, database) != "local":
        raise utils.ValidationError('database', 'db_not_local', database)
    uci.set('users', group["id"], 'user', users)
    uci.set('users', group["id"], 'description', description)
    uci.save("users")
    return group["id"]

def delete_local_group(uci, name, database="main"):
    '''
    Delete an existing local group

    Arguments:
      - uci -- EUci pointer
      - name -- Group name
      - database -- Local database identifier (default: main)

    Returns:
      - True if successful
    '''
    group = get_group_by_name(uci, name, database)
    if not group:
        raise utils.ValidationError('name', 'group_not_found', name)
    if get_database_type(uci, database) != "local":
        raise utils.ValidationError('database', 'db_not_local', database)
    uci.delete('users', group["id"])
    uci.save("users")
    return True

def add_remote_user(uci, name, database, extra_fields={}):
    '''
    Add a new remote user

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - database -- Database identifier
      - extra_fields -- Extra fields to add to the user (default: {})

    Returns:
      - The user identifier
    '''
    if get_user_by_name(uci, name, database):
        raise utils.ValidationError('name', 'user_already_exists', name)
    if get_database_type(uci, database) != "ldap":

        raise utils.ValidationError('database', 'db_not_ldap', database)
    id = utils.get_random_id()
    user = uci.set('users', id, 'user')
    uci.set('users', id, 'database', database)
    uci.set('users', id, 'name', name)
    for key in extra_fields:
        uci.set('users', id, key, extra_fields[key])
    uci.save("users")
    return id

def edit_remote_user(uci, name, database, extra_fields={}):
    '''
    Edit an existing remote user

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - database -- Database identifier
      - extra_fields -- Extra fields to add to the user (default: {})

    Returns:
      - The user identifier
    '''
    user = get_user_by_name(uci, name, database)
    if not user:
        raise utils.ValidationError('name', 'user_not_found', name)
    if get_database_type(uci, database) != "ldap":
        raise utils.ValidationError('database', 'db_not_ldap', database)
    for key in uci.get_all('users', user["id"]):
        if not key in ["name", "database"]:
            uci.delete('users', user["id"], key)
    for key in extra_fields:
        uci.set('users', user["id"], key, extra_fields[key])
    uci.save("users")
    return user["id"]

def delete_remote_user(uci, name, database):
    '''
    Delete an existing remote user

    Arguments:
      - uci -- EUci pointer
      - name -- User name
      - database -- Database identifier

    Returns:
      - True if successful
    '''
    user = get_user_by_name(uci, name, database)
    if not user:
        raise utils.ValidationError('name', 'user_not_found', name)
    if get_database_type(uci, database) != "ldap":
        raise utils.ValidationError('database', 'db_not_ldap', database)
    uci.delete('users', user["id"])
    uci.save("users")
    return True

def get_ldap_defaults(uri, schema):
    '''
    Retrieve default LDAP settings from given URI

    Arguments:
      - uri -- LDAP URI

    Returns:
      - A dictionary containing:
        - base_dn: LDAP base DN
        - user_dn: LDAP user DN
        - user_attr: LDAP user attribute
        - user_cn: LDAP user common name
    '''
    parsed = urlparse(uri)
    try:
        ipaddress.ip_address(parsed.hostname)
        # it's an IP address, just suggest example defaults
        if schema == "rfc2307":
            return {"base_dn": "dc=directory,dc=nh", "user_dn": "ou=People,dc=directory,dc=nh", "user_attr": "uid", "user_cn": "cn"}
        elif schema == "ad":
            return {"base_dn": "dc=directory,dc=nh", "user_dn": "cn=Users,dc=directory,dc=nh", "user_attr": "cn", "user_cn": "cn"}
    except:
        # it's a hostname, suggest defaults based on domain
        parts = parsed.hostname.split(".")[1:]
        base_dn = ','.join(['dc=' + part for part in parts])
        if schema == "rfc2307":
            return {"base_dn": base_dn, "user_dn": "ou=People," + base_dn, "user_attr": "uid", "user_cn": "cn"}
        elif schema == "ad":
            return {"base_dn": base_dn, "user_dn": "cn=Users," + base_dn, "user_attr": "cn", "user_cn": "cn"}

def shadow_password(password):
    '''
    Generate a shadow password

    Arguments:
      - password -- Clear text password

    Returns:
      - A shadow password in crypt(3) format, as generate by mkpasswd. Format: $6$salt$hash
    '''
    return hash.sha512_crypt.using(salt=secrets.token_hex(8), rounds=5000).hash(password)

def check_password(password, shadow):
    '''
    Check a shadow password

    Arguments:
      - password -- Clear text password
      - shadow -- Shadow password in crypt(3) format

    Returns:
      - True if password matches, False otherwise
    '''
    return hash.sha512_crypt.verify(password, shadow)

def ldif2users(ldif_data, user_attr="uid", user_cn="cn"):
    '''
    Parse an LDIF file and return a list of users

    Arguments:
      - ldif_data -- LDIF data
      - user_attr -- User attribute (default: uid)

    Returns:
      - A list of users
    '''
    users = []
    user = None
    dn = None
    # Parse only the dn lines. Example: dn: uid=user1,ou=People,dc=example,dc=com
    for line in ldif_data.split('\n'):
        if line.startswith('#'):
            if user:
                users.append(user)
            user = {}
            dn = None
            continue
        if line.startswith('dn:'):
            dn = line[3:].strip()
            if dn.lower().startswith(f'{user_attr.lower()}='):
                user["name"] = dn.split(",")[0].removeprefix(f'{user_attr}=').removeprefix(f'{user_attr.upper()}=')
        if line.lower().startswith(f'{user_cn.lower()}:') and dn:
            user["description"] = line[len(user_cn)+1:].strip()
    return users

def list_remote_users(uri, user_dn, user_attr, user_cn, start_tls=False, tls_reqcert="never", bind_dn=None, bind_password=None, schema='ldap'):
    '''
    Test LDAP connection

    Arguments:
      - uri -- LDAP URI
      - user_dn -- LDAP user DN
      - user_attr -- LDAP user attribute
      - user_cn -- LDAP user common name
      - start_tls -- Use TLS (default: False)
      - tls_reqcert -- TLS certificate validation (default: never)
      - bind_dn -- LDAP bind DN
      - bind_password -- LDAP bind password
      - schema -- LDAP schema, 'ad' or 'ldap'

    Returns:
      - A list of users, each one containing:
        - name: user name
        - description: user description
    '''
    env = os.environ.copy()
    env['LDAPTLS_REQCERT'] = tls_reqcert
    try:
        cmd = ["ldapsearch", "-x", "-H", uri, "-b", user_dn]
        if start_tls:
            cmd.append("-ZZ")
        if bind_dn and bind_password:
            cmd.extend(["-D", bind_dn, "-w", bind_password])
        if schema == "ad":
            cmd.append("(objectClass=person)")
        else:
            cmd.append("(objectClass=posixAccount)")
        cmd.append(user_cn)
        p = subprocess.run(cmd, env=env, capture_output=True, text=True)
        return ldif2users(p.stdout, user_attr, user_cn)
    except subprocess.CalledProcessError as e:
        return []
    
def set_admin(uci, username, database):
    '''
    Set a user as admin by creating a login record in rpcd configuration database

    Arguments:
      - uci -- EUci pointer
      - username -- User name
      - database -- Database identifier

    Returns:
      - The user identifier inside the rpcd configuration database
    '''
    user = get_user_by_name(uci, username, database)
    if not user:
        raise utils.ValidationError('name', 'user_not_found', username)
    logins = utils.get_all_by_type(uci, 'rpcd', 'login')
    for l in logins:
        if logins[l].get("username") == username:
            raise utils.ValidationError('name', 'admin_user_already_exists', username)
    id = utils.get_random_id()
    uci.set('rpcd', id, 'login')
    uci.set('rpcd', id, 'username', username)
    uci.set('rpcd', id, 'password', user["password"])
    uci.set('rpcd', id, 'read', '*')
    uci.set('rpcd', id, 'write', '*')
    uci.save("rpcd")
    return id

def remove_admin(uci, username):
    '''
    Remove a user from rpcd configuration database

    Arguments:
      - uci -- EUci pointer
      - username -- User name

    Returns:
      - True if successful
    '''
    logins = utils.get_all_by_type(uci, 'rpcd', 'login')
    for l in logins:
        if logins[l].get("username") == username:
            uci.delete('rpcd', l)
            uci.save("rpcd")
            return True
    raise utils.ValidationError('name', 'admin_user_not_found', username)

def is_admin(uci, username):
    '''
    Check if a user is admin

    Arguments:
      - uci -- EUci pointer
      - username -- User name

    Returns:
      - True if user is admin, False otherwise
    '''
    logins = utils.get_all_by_type(uci, 'rpcd', 'login')
    if logins is None:
        return False
    for l in logins:
        if logins[l].get("username") == username:
            return True
    return False
