#!/usr/bin/python3

#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
Notification utilities
'''

import os
import json
import uuid
import time
import glob
import syslog
import subprocess

def execute_hook(directory, notification):
    if not os.path.exists(directory):
        return []
    script_files = glob.glob(os.path.join(directory, '*'))
    errors = []
    for script in script_files:
        if os.access(script, os.X_OK):
            try:
                # directly execute python scripts to speedup the run
                if script.endswith('.py'):
                    exec(open(script).read())
                else:
                    subprocess.run([script], input=json.dumps(notification), check=True, capture_output=True, text=True)
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR, f"{e}")
                errors.append(script)
                continue
    return errors

def setup():
    '''
    Create the directory structure for notifications.
    '''
    if not os.path.exists('/var/spool/notify'):
        os.makedirs('/var/spool/notify/active', exist_ok=True)
        os.makedirs('/var/spool/notify/archived', exist_ok=True)

def list_notifications():
    '''
    Retrieve a list of all existing notifications, including their "active" or "read" state.

    :return: A list of all existing notifications.
    :rtype: list
    '''
    notifications = {"active": [], "archived": []}

    if not os.path.exists('/var/spool/notify'):
        return notifications
    
    for root, dirs, files in os.walk('/var/spool/notify/active'):
        for file in files:
            with open(os.path.join(root, file), 'r') as f:
                notifications['active'].append(json.load(f))
    for root, dirs, files in os.walk('/var/spool/notify/archived'):
        for file in files:
            with open(os.path.join(root, file), 'r') as f:
                notifications['archived'].append(json.load(f))

    return notifications

def add_notification(priority, title, message=None, payload=None):
    '''
    Create a new notification with specified content.
    After the notification is created, the add hook (/usr/libexec/notify/add) will be executed;
    the whole notification will be passed as an argument to the hook in the standard input.

    Args:
        priority (int): The importance level of the notification. 1 represents low, 2 medium, and 3 high.
        title (str): The main title of the notification displayed to the user.
        message (str, optional): Additional details or explanations about the notification. Defaults to None.
        payload (dict, optional): Contains optional data specific to the notification. Defaults to None.
    
    Returns:
        dict: A dictionary containing the UUID of the notification and any errors that occurred.
            * uuid (str): A unique identifier for the notification.
            * errors (list): A list of any errors that occurred.
    '''
    if priority not in [1, 2, 3]:
        raise ValueError("Invalid priority")
    notification = {
        "priority": priority,
        "title": title,
        "uuid": str(uuid.uuid4()),
        "timestamp": int(time.time())
    }
    if message:
        notification["message"] = message
    if payload:
        notification["payload"] = payload

    setup()
    with open(f'/var/spool/notify/active/{notification["uuid"]}.json', 'w') as f:
        json.dump(notification, f)

    errors = execute_hook("/usr/libexec/notify/add", notification)

    return { "uuid": notification["uuid"], "errors": errors }

def delete_notification(uuid):
    '''
    Remove a notification from the system.
    If the notification is not found in the active directory, it will be searched in the archived directory.
    If the notification is not found in the archived directory, a FileNotFoundError will be raised.
    If the notification has been correctly removed, the delete hook (/usr/libexec/notify/delete) will be executed;
    the UUID of the deleted notification will be passed as an argument to the hook in the standard input.

    Args:
        uuid (str): The unique identifier of the notification to delete.

    Returns:
        list: A list of any errors that occurred during the hook execution.

    '''
    if os.path.exists(f'/var/spool/notify/active/{uuid}.json'):
        os.remove(f'/var/spool/notify/active/{uuid}.json')
    elif os.path.exists(f'/var/spool/notify/archived/{uuid}.json'):
        os.remove(f'/var/spool/notify/archived/{uuid}.json')
    else:
        raise FileNotFoundError(f'Notification with UUID {uuid} not found')
    
    return execute_hook("/usr/libexec/notify/delete", { "uuid": uuid })

def mark_as_read(uuid):
    '''
    Set the state of a notification to "read".
    If the notification is not found in the active directory, a FileNotFoundError will be raised.
    If the notification has been correctly archived, the read hook (/usr/libexec/notify/read) will be executed;
    the UUID of the read notification will be passed as an argument to the hook in the standard input.

    Args:
        uuid (str): The unique identifier of the notification to mark as read.

    Returns:
        list: A list of any errors that occurred during the hook execution.
    '''
    if os.path.exists(f'/var/spool/notify/active/{uuid}.json'):
        os.rename(f'/var/spool/notify/active/{uuid}.json', f'/var/spool/notify/archived/{uuid}.json')
    else:
        raise FileNotFoundError(f'Notification with UUID {uuid} not found in active notifications')
    
    return execute_hook("/usr/libexec/notify/read", { "uuid": uuid })

def mark_as_unread(uuid):
    '''
    Set the state of a notification to "active".
    If the notification is not found in the archived directory, a FileNotFoundError will be raised.
    If the notification has been correctly restored, the unread hook (/usr/libexec/notify/unread) will be executed;
    the UUID of the unread notification will be passed as an argument to the hook in the standard input.

    Args:
        uuid (str): The unique identifier of the notification to mark as unread.

    Returns:
        list: A list of any errors that occurred during the hook execution.
    '''
    if os.path.exists(f'/var/spool/notify/archived/{uuid}.json'):
        os.rename(f'/var/spool/notify/archived/{uuid}.json', f'/var/spool/notify/active/{uuid}.json')
    else:
        raise FileNotFoundError(f'Notification with UUID {uuid} not found in archived notifications')
    
    return execute_hook("/usr/libexec/notify/unread", { "uuid": uuid })