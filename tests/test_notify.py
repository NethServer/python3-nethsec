import os
import pytest
from nethsec.notify import add_notification, list_notifications, mark_as_read, mark_as_unread, delete_notification

@pytest.fixture
def fake_spool():
    # Create the fixture for the filesystem
    active_dir = '/var/spool/notify/active'
    archived_dir = '/var/spool/notify/archived'
    os.makedirs(active_dir, exist_ok=True)
    os.makedirs(archived_dir, exist_ok=True)
    active_file1 = os.path.join(active_dir, 'notification1.json')
    active_file2 = os.path.join(active_dir, 'notification2.json')
    archived_file1 = os.path.join(archived_dir, 'notification3.json')
    archived_file2 = os.path.join(archived_dir, 'notification4.json')
    with open(active_file1, 'w') as f:
        f.write('{"id": 1, "message": "Notification 1"}')
    with open(active_file2, 'w') as f:
        f.write('{"id": 2, "message": "Notification 2"}')
    with open(archived_file1, 'w') as f:
        f.write('{"id": 3, "message": "Notification 3"}')
    with open(archived_file2, 'w') as f:
        f.write('{"id": 4, "message": "Notification 4"}')

def test_list_notifications_with_no_existing_notifications():
    result = list_notifications()
    assert isinstance(result, dict)
    assert "active" in result
    assert "archived" in result
    assert isinstance(result["active"], list)
    assert isinstance(result["archived"], list)
    assert len(result["active"]) == 0
    assert len(result["archived"]) == 0

def test_list_notifications_with_existing_notifications(fake_spool):
    result = list_notifications()
    assert isinstance(result, dict)
    assert "active" in result
    assert "archived" in result
    assert isinstance(result["active"], list)
    assert isinstance(result["archived"], list)
    assert len(result["active"]) == 2
    assert len(result["archived"]) == 2

def test_add_notification_with_message_and_payload(fake_spool):
    priority = 2
    title = "Test Notification"
    message = "This is a test notification"
    payload = {"key": "value"}
    result = add_notification(priority, title, message, payload)
    assert isinstance(result, dict)
    assert "uuid" in result
    assert "errors" in result
    assert isinstance(result["uuid"], str)
    assert isinstance(result["errors"], list)
    assert len(result["errors"]) == 0

def test_add_notification_without_message_and_payload(fake_spool):
    priority = 1
    title = "Test Notification"
    result = add_notification(priority, title)
    assert isinstance(result, dict)
    assert "uuid" in result
    assert "errors" in result
    assert isinstance(result["uuid"], str)
    assert isinstance(result["errors"], list)
    assert len(result["errors"]) == 0

def test_add_notification_with_invalid_priority(fake_spool):
    priority = 4
    title = "Test Notification"
    with pytest.raises(ValueError) as e:
     add_notification(priority, title)

def test_mark_as_read(fake_spool):
    uuid = "notification1"
    result = mark_as_read(uuid)
    assert isinstance(result, list)
    assert len(result) == 0

def test_mark_as_read_with_invalid_uuid(fake_spool):
    uuid = "invalid"
    with pytest.raises(FileNotFoundError) as e:
        mark_as_read(uuid)

def test_mark_as_unread(fake_spool):
    uuid = "notification3"
    result = mark_as_unread(uuid)
    assert isinstance(result, list)
    assert len(result) == 0


def test_mark_as_unread_with_invalid_uuid(fake_spool):
    uuid = "invalid"
    with pytest.raises(FileNotFoundError) as e:
        mark_as_unread(uuid)

def test_delete_notification(fake_spool):
    uuid = "notification1"
    result = delete_notification(uuid)
    assert isinstance(result, list)
    assert len(result) == 0 

def test_delete_notification_with_invalid_uuid(fake_spool):
    uuid = "invalid"
    with pytest.raises(FileNotFoundError) as e:
        delete_notification(uuid)