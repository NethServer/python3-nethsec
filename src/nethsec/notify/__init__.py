#!/usr/bin/python3

#
# Copyright (C) 2024 Nethesis S.r.l.
# SPDX-License-Identifier: GPL-2.0-only
#

'''
Notification utilities
'''

import os
import sqlite3
import json
import syslog
import glob
import subprocess

BASE_DIR = '/var/spool/notify'
DB_FILE = os.path.join(BASE_DIR, 'notifications.db')
NO_PRIO = 0
LOW = 1
MEDIUM = 2
HIGH = 3
PRIORITIES = {NO_PRIO: "no_prio", LOW: "low", MEDIUM: "medium", HIGH: "high"}

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
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR)

    if not os.path.exists(DB_FILE):
        # Create SQLite database if it doesn't exist
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY,
                priority INTEGER default 1,
                title TEXT NOT NULL,
                payload TEXT default '',
                timestamp INTEGER default (strftime('%s', 'now')),
                active INTEGER default 1
            )
        ''')
        conn.commit()
        conn.close()

def decorate_notification(row):
    '''
    Decorate a notification with additional information.

    Args:
        row (tuple): A tuple representing a notification from the SQLite database.

    Returns:
        dict: A dictionary representing the notification.
    '''
    priority = PRIORITIES.get(row[1], NO_PRIO)
    try:
        payload = json.loads(row[3])
    except json.JSONDecodeError:
        payload = {}
    return {
        'id': int(row[0]),
        'priority': priority,
        'title': row[2],
        'payload': payload,
        'timestamp': int(row[4]),
        'active': bool(row[5])
    }

def get_notification(id):
    '''
    Retrieve a notification by its unique identifier.

    Args:
        id (int): The unique identifier of the notification to retrieve.

    Returns:
        dict: A dictionary representing the notification.
    '''
    setup()

    # Retrieve notification from SQLite database
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM notifications WHERE id = ?', (id,))
    row = c.fetchone()
    if row is None:
        conn.close()
        raise ValueError(f"Notification with id {id} not found.")
    conn.close()
    return decorate_notification(row)

def list_notifications():
    '''
    Retrieve a list of all existing notifications, including their "active" or "not active" state.

    Returns:
        list: A list of dictionaries representing all existing notifications.
    '''
    setup()

    notifications = []
    # Retrieve notifications from SQLite database
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM notifications')
    for row in c.fetchall():
        notifications.append(decorate_notification(row))

    return notifications

def add_notification(title, priority="low", payload={}):
    '''
    Create a new notification with specified content.

    Args:
        title (str): The main title of the notification.
        priority (str): The importance level of the notification. Valid values are 'low', 'medium', and 'high'.
        payload (dict, optional): Contains optional data specific to the notification. Defaults to empty dict.
    
    Returns:
        dict: A dictionary containing the UUID of the notification and any errors that occurred.
            * id (str): A unique identifier for the notification.
            * errors (list): A list of any errors that occurred.

    Raises:
        ValueError: If an invalid priority is provided.
    '''
    if priority not in PRIORITIES.values():
        raise ValueError("Invalid priority")
    else:
        rev_prios = {v: k for k, v in PRIORITIES.items()}
        priority = rev_prios[priority]

    setup()

    # Insert notification into SQLite database
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO notifications (priority, title, payload)
        VALUES (?, ?, ?)
    ''', (priority, title, json.dumps(payload)))
    id = c.lastrowid
    conn.commit()
    conn.close()

    errors = execute_hook("/usr/libexec/notify/add", { "id": id })

    return { "id": id, "errors": errors }

def delete_notification(id):
    '''
    Remove a notification from the system.
    If the notification has been correctly removed, the delete hook (/usr/libexec/notify/delete) will be executed;
    the id of the deleted notification will be passed as an argument to the hook in the standard input.

    Args:
        id (str): The unique identifier of the notification to delete.

    Returns:
        list: A list of any errors that occurred during the hook execution.

    Raises:
        ValueError: If the notification is not found in the active directory.
    '''
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('DELETE FROM notifications WHERE id = ?', (id,))
    
    if c.rowcount == 0:
        conn.close()
        raise ValueError(f"Notification with id {id} not found.")

    conn.commit()
    conn.close()

    return execute_hook("/usr/libexec/notify/delete", { "id": id })

def mark_as_read(id):
    '''
    Set the state of a notification to "not active".
    If the notification has been correctly archived, the read hook (/usr/libexec/notify/read) will be executed;
    the id of the read notification will be passed as an argument to the hook in the standard input.

    Args:
        uuid (str): The unique identifier of the notification to mark as read.

    Returns:
        list: A list of any errors that occurred during the hook execution.

    Raises:
        ValueError: If the notification is not found in the active directory.
    '''
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('UPDATE notifications SET active = ? WHERE id = ?', (0, id))
    if c.rowcount == 0:
        conn.close()
        raise ValueError(f"Notification with id {id} not found.")
    conn.commit()
    conn.close()
    
    return execute_hook("/usr/libexec/notify/read", { "id": id })

def mark_as_unread(id):
    '''
    Set the state of a notification to "active".
    If the notification has been correctly restored, the unread hook (/usr/libexec/notify/unread) will be executed;
    the id of the unread notification will be passed as an argument to the hook in the standard input.

    Args:
        uuid (str): The unique identifier of the notification to mark as unread.

    Returns:
        list: A list of any errors that occurred during the hook execution.

    Raises:
        ValueError: If the notification is not found in the active directory.
    '''
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE notifications SET active = ? WHERE id = ?', (1, id))
    if c.rowcount == 0:
        conn.close()
        raise ValueError(f"Notification with id {id} not found.")
    conn.commit()
    conn.close()
    
    return execute_hook("/usr/libexec/notify/unread", { "id": id })