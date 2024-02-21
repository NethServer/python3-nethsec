import os
import pytest
from nethsec.notify import add_notification, get_notification, list_notifications, mark_as_read, mark_as_unread, delete_notification

def test_list_notifications_with_no_existing_notifications():
    result = list_notifications()
    assert not result

def test_add_notification_with_message_and_payload():
    priority = "low"
    title = "test_notify"
    payload = {"key": "value"}
    result = add_notification(title, priority, payload)
    assert isinstance(result, dict)
    assert "id" in result
    assert "errors" in result
    assert isinstance(result["id"], int)
    assert isinstance(result["errors"], list)
    assert len(result["errors"]) == 0
    assert result["id"] > 0

def test_get_notification():
    id = 1
    result = get_notification(id)
    assert isinstance(result, dict)
    assert result["id"] == 1
    assert result["priority"] == "low"
    assert result["title"] == "test_notify"
    assert result["payload"] == {"key": "value"}
    assert result["active"] == True
    assert result["timestamp"] > 0

def test_list_notifications_with_existing_notifications():
    result = list_notifications()
    assert isinstance(result, list)
    assert result[0]["id"] == 1
    assert result[0]["priority"] == "low"
    assert result[0]["title"] == "test_notify"
    assert result[0]["payload"] == {"key": "value"}
    assert result[0]["active"] == True
    assert result[0]["timestamp"] > 0

def test_add_notification_without_payload():
    title = "test_notify"
    result = add_notification(title, "high")
    notification = get_notification(result["id"])
    assert notification['id'] == result['id']
    assert notification['payload'] == {}

    print(result)
    assert notification['priority'] == "high"

def test_add_notification_with_invalid_priority():
    title = "test_notify"
    with pytest.raises(ValueError) as e:
      add_notification("badprio", title)

def test_mark_as_read():
    result = mark_as_read(1)
    notification = get_notification(1)
    assert notification['active'] == False

def test_mark_as_read_with_invalid_id():
    with pytest.raises(ValueError) as e:
        mark_as_read(4567890)

def test_mark_as_unread():
    result = mark_as_unread(1)
    notification = get_notification(1)
    assert notification['active'] == True

def test_mark_as_unread_with_invalid_id():
    with pytest.raises(ValueError) as e:
        mark_as_unread(56789)

def test_delete_notification():
    delete_notification(1)
    with pytest.raises(ValueError) as e:
        get_notification(1)

def test_delete_notification_with_invalid_id():
    with pytest.raises(ValueError) as e:
        delete_notification(6789)