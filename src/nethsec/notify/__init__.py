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
LEVEL_DEBUG = 0
LEVEL_INFO = 1
LEVEL_NOTICE = 2
LEVEL_WARNING = 3
LEVEL_ERR = 4
LEVEL_CRIT = 5
LEVEL_ALERT = 6
LEVEL_EMERG = 7

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
                level INTEGER default 1,
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

    try:
        payload = json.loads(row[3])
    except json.JSONDecodeError:
        payload = {}
    return {
        'id': int(row[0]),
        'level': row[1],
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

def list_notifications(filter={}, order_by=None, descendent=False, limit=None):
    '''
    Retrieve a list of all existing notifications, including their "active" or "not active" state.

    Args:
        filter (dict, optional): A dictionary containing key-value pairs to filter notifications by. Defaults to empty dict.
        order_by (str, optional): The field to order the notifications by. Defaults to None.
        descendent (bool, optional): Whether to order the notifications in descending order. Defaults to False.
        limit (int, optional): The maximum number of notifications to return. Defaults to None (no limit).

    Returns:
        list: A list of dictionaries representing all existing notifications.
    '''
    setup()

    notifications = []
    # Retrieve notifications from SQLite database
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    query = 'SELECT * FROM notifications'
    if filter:
        query += ' WHERE'
        for key, value in filter.items():
            query += f' {key} = {value}'
            if key != list(filter.keys())[-1]:
                query += ' AND'
    if order_by and order_by not in ['id', 'level', 'title', 'timestamp']:
        raise ValueError("Invalid order_by value")
    if order_by:
        query += f' ORDER BY {order_by}'
        if descendent:
            query += ' DESC'
    if limit:
        query += f' LIMIT {limit}'
    c.execute(query)

    for row in c.fetchall():
        notifications.append(decorate_notification(row))

    return notifications

def add_notification(title, level=2, payload={}):
    '''
    Create a new notification with specified content.

    Args:
        title (str): The main title of the notification.
        level (int): The importance level of the notification. Valid values are LEVEL_DEBUG (0), LEVEL_INFO (1), LEVEL_NOTICE (2), LEVEL_WARNING (3), LEVEL_ERR (4), LEVEL_CRIT (5), LEVEL_ALERT (6), and LEVEL_EMERG (7). Defaults to LEVEL_NOTICE.
        payload (dict, optional): Contains optional data specific to the notification. Defaults to empty dict.
    
    Returns:
        dict: A dictionary containing the UUID of the notification and any errors that occurred.
            * id (str): A unique identifier for the notification.
            * errors (list): A list of any errors that occurred.

    Raises:
        ValueError: If an invalid level is provided.
    '''
    if level < LEVEL_DEBUG or level > LEVEL_EMERG:
        raise ValueError("Invalid level")

    setup()

    # Insert notification into SQLite database
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO notifications (level, title, payload)
        VALUES (?, ?, ?)
    ''', (level, title, json.dumps(payload)))
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