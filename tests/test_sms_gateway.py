import pytest
from unittest.mock import patch, Mock

from core.plugins.builtin.sms_gateway.sms_gateway import (
    _parse_host_port,
    SMSGateway,
    CLOUD_URL,
    LOCAL_PORT,
)


def test_parse_host_port_with_port():
    assert _parse_host_port("192.168.1.5:8081", 8080) == ("192.168.1.5", 8081)


def test_parse_host_port_without_port():
    assert _parse_host_port("example.com", 1234) == ("example.com", 1234)


def test_sm_gateway_init_cloud():
    gw = SMSGateway(username="u", password="p", host=None, use_cloud=True)
    assert gw.base_url == CLOUD_URL


def test_sm_gateway_init_local_host_and_port():
    gw = SMSGateway(username="u", password="p", host="192.168.1.5", use_cloud=False)
    assert gw.base_url == f"http://192.168.1.5:{LOCAL_PORT}"


def test_sm_gateway_init_local_host_with_embedded_port():
    gw = SMSGateway(username="u", password="p", host="192.168.1.5:9000", use_cloud=False)
    assert gw.base_url == "http://192.168.1.5:9000"


def test_sm_gateway_init_requires_host_for_local():
    with pytest.raises(ValueError):
        SMSGateway(username="u", password="p", host=None, use_cloud=False)


@patch("core.plugins.builtin.sms_gateway.sms_gateway.requests")
def test_send_and_get_status_and_webhook_and_delete(mock_requests):
    # Mock post for send
    mock_post = Mock()
    mock_post.raise_for_status = Mock()
    mock_post.json.return_value = {"id": "msg-1"}
    mock_requests.post.return_value = mock_post

    # Mock get for get_status
    mock_get = Mock()
    mock_get.raise_for_status = Mock()
    mock_get.json.return_value = {"state": "delivered"}
    mock_requests.get.return_value = mock_get

    # Mock post for register_webhook
    mock_post2 = Mock()
    mock_post2.raise_for_status = Mock()
    mock_post2.json.return_value = {"ok": True}
    mock_requests.post.return_value = mock_post2

    # Mock delete for delete_webhook
    mock_delete = Mock()
    mock_delete.status_code = 200
    mock_requests.delete.return_value = mock_delete

    gw = SMSGateway(username="u", password="p", host="127.0.0.1", use_cloud=False)

    res = gw.send("+12345", "hello")
    assert res == {"id": "msg-1"}
    mock_requests.post.assert_called()

    status = gw.get_status("msg-1")
    assert status == {"state": "delivered"}
    mock_requests.get.assert_called()

    webhook = gw.register_webhook("w1", "https://example.com/hook", "sms:received")
    assert webhook == {"ok": True}
    mock_requests.post.assert_called()

    deleted = gw.delete_webhook("w1")
    assert deleted is True
    mock_requests.delete.assert_called()
