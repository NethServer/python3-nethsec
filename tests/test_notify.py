import os
import pytest
from nethsec import notify
from nethsec.notify import add_notification, get_notification, list_notifications, mark_as_read, mark_as_unread, delete_notification

def test_list_notifications_with_no_existing_notifications():
    result = list_notifications()
    assert not result

def test_add_notification_with_message_and_payload():
    level = notify.LEVEL_NOTICE
    title = "test_notify"
    payload = {"key": "value"}
    result = add_notification(title, level, payload)
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
    assert result["level"] == notify.LEVEL_NOTICE
    assert result["title"] == "test_notify"
    assert result["payload"] == {"key": "value"}
    assert result["active"] == True
    assert result["timestamp"] > 0

def test_list_notifications_with_existing_notifications():
    result = list_notifications()
    assert isinstance(result, list)
    assert result[0]["id"] == 1
    assert result[0]["level"] == notify.LEVEL_NOTICE
    assert result[0]["title"] == "test_notify"
    assert result[0]["payload"] == {"key": "value"}
    assert result[0]["active"] == True
    assert result[0]["timestamp"] > 0

def test_add_notification_without_payload():
    title = "test_notify"
    result = add_notification(title, notify.LEVEL_WARNING)
    notification = get_notification(result["id"])
    assert notification['id'] == result['id']
    assert notification['payload'] == {}
    assert notification['level'] == notify.LEVEL_WARNING

def test_add_notification_with_invalid_level():
    with pytest.raises(ValueError) as e:
      add_notification("test_notify", level=10)

def test_mark_as_read():
    result = mark_as_read(1)
    notification = get_notification(1)
    assert notification['active'] == False

def list_notifications_with_filter():
    result = list_notifications({"level": notify.LEVEL_ALERT})
    assert len(result) == 1
    assert result[0]["id"] == 2
    assert result[0]["level"] == notify.LEVEL_ALERT
    assert result[0]["title"] == "test_notify"
    assert result[0]["payload"] == {}
    assert result[0]["active"] == True
    assert result[0]["timestamp"] > 0

def list_notifications_with_order_by():
    result = list_notifications(order_by="timestamp")
    assert len(result) == 2
    assert result[0]["id"] == 2
    assert result[1]["id"] == 1

def list_notifications_with_descendent():
    result = list_notifications(descendent=True, order_by="timestamp")
    assert len(result) == 2
    assert result[0]["id"] == 2
    assert result[1]["id"] == 1

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