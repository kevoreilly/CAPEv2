import asyncio
import logging
from importlib import import_module
from types import SimpleNamespace

import pytest
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator

consumers = import_module("guac.consumers")
guac_routing = import_module("guac.routing")

TEST_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEST_VNC_PORT = 5901


class FakeTask:
    def __init__(self, task_id, status="running"):
        self.id = task_id
        self.status = status


class FakeDatabase:
    """Minimal stand-in for Database with guac session and task helpers."""

    def __init__(self, *, session_data=None, task=None):
        self._session_data = session_data or {
            "task_id": 123,
            "vm_label": "win10_1",
            "guest_ip": "192.168.56.10",
        }
        self._task = task or FakeTask(123, "running")
        self.deleted_sessions = []

    def get_guac_session(self, token):
        if str(token) == TEST_TOKEN:
            return dict(self._session_data)
        return None

    def view_task(self, task_id):
        if int(task_id) == self._task.id:
            return self._task
        return None

    def delete_guac_session(self, token):
        self.deleted_sessions.append(str(token))


class FakeGuacamoleClient:
    instances = []

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connected = False
        self.handshake_kwargs = None
        self.sent_messages = []
        self.closed = False
        self.__class__.instances.append(self)

    def handshake(self, **kwargs):
        self.handshake_kwargs = kwargs
        self.connected = True

    def send(self, message):
        self.sent_messages.append(message)

    def close(self):
        self.closed = True


class FakeTimeoutManager:
    instances = []

    def __init__(self, vm_ip, user, session_id="unknown", task_id=None):
        self.vm_ip = vm_ip
        self.user = user
        self.session_id = session_id
        self.task_id = task_id
        self.activity_updates = 0
        self.activity_check_interval = 60
        self.idle_timeout_seconds = 120
        self.is_active = True
        self.__class__.instances.append(self)

    def update_activity(self):
        self.activity_updates += 1

    def set_inactive(self):
        self.is_active = False

    def is_timed_out(self):
        return False

    def get_idle_time_ms(self):
        return 0

    async def complete_analysis(self):
        return True


class ExpiringFakeTimeoutManager(FakeTimeoutManager):
    instances = []

    def __init__(self, vm_ip, user, session_id="unknown", task_id=None):
        super().__init__(vm_ip, user, session_id=session_id, task_id=task_id)
        self.activity_check_interval = 0.01
        self.idle_timeout_seconds = 120
        self.complete_analysis_calls = 0

    def is_timed_out(self):
        return True

    def get_idle_time_ms(self):
        return self.idle_timeout_seconds * 1000 + 1

    async def complete_analysis(self):
        self.complete_analysis_calls += 1
        return True


class DisabledTimeoutManager:
    instances = []

    def __init__(self, vm_ip, user, session_id="unknown", task_id=None):
        self.vm_ip = vm_ip
        self.user = user
        self.session_id = session_id
        self.task_id = task_id
        self.activity_updates = 0
        self.activity_check_interval = None
        self.idle_timeout_seconds = 0
        self.is_active = True
        self.__class__.instances.append(self)

    def update_activity(self):
        self.activity_updates += 1

    def set_inactive(self):
        self.is_active = False

    def is_timed_out(self):
        return False

    def get_idle_time_ms(self):
        return 0

    async def complete_analysis(self):
        return True


async def _background_task_stub(self):
    await asyncio.Event().wait()


async def _read_guacd_tracking_stub(self):
    await asyncio.Event().wait()


async def _cancel_then_close_read_guacd(self):
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await self._close_websocket()


def _make_communicator(app, session_id, recording_name, token=TEST_TOKEN):
    """Create a WebsocketCommunicator with the guac_session cookie injected."""
    url = f"/guac/websocket-tunnel/{session_id}/?recording_name={recording_name}"
    communicator = WebsocketCommunicator(app, url, subprotocols=["guacamole"])
    communicator.scope["cookies"] = {"guac_session": token}
    return communicator


@pytest.fixture
def guac_consumer_app_factory(monkeypatch):
    def _build(*, timeout_manager_cls=None, stub_monitor_timeout=True,
               read_guacd_impl=_background_task_stub, fake_db=None):
        FakeGuacamoleClient.instances.clear()
        FakeTimeoutManager.instances.clear()
        ExpiringFakeTimeoutManager.instances.clear()
        DisabledTimeoutManager.instances.clear()

        timeout_manager_cls = timeout_manager_cls or FakeTimeoutManager
        db = fake_db or FakeDatabase()

        monkeypatch.setattr(consumers, "GuacamoleClient", FakeGuacamoleClient)
        monkeypatch.setattr(consumers, "SessionTimeoutManager", timeout_manager_cls)
        monkeypatch.setattr(consumers, "Database", lambda: db)
        monkeypatch.setattr(consumers, "_get_vnc_port", lambda vm_label: TEST_VNC_PORT)
        monkeypatch.setattr(consumers.GuacamoleWebSocketConsumer, "read_guacd", read_guacd_impl)
        monkeypatch.setattr(consumers.GuacamoleWebSocketConsumer, "monitor_task_status", _background_task_stub)
        if stub_monitor_timeout:
            monkeypatch.setattr(consumers.GuacamoleWebSocketConsumer, "monitor_timeout", _background_task_stub)
        monkeypatch.setattr(
            consumers,
            "web_cfg",
            SimpleNamespace(
                guacamole=SimpleNamespace(
                    guacd_host="localhost",
                    guacd_port=4822,
                    guacd_recording_path="/tmp/guacrecordings",
                    guest_protocol="vnc",
                    guest_width=1280,
                    guest_height=1024,
                    username="",
                    password="",
                    vnc_host="localhost",
                    vnc_color_depth=16,
                    vnc_cursor="local",
                )
            ),
        )

        return URLRouter(guac_routing.websocket_urlpatterns), db

    return _build


@pytest.mark.asyncio
class TestGuacConsumers:
    """Integration-style tests for the Guacamole websocket consumer."""

    async def test_consumer_updates_idle_activity_for_real_guacamole_input(self, guac_consumer_app_factory):
        guac_consumer_app, fake_db = guac_consumer_app_factory()
        communicator = _make_communicator(
            guac_consumer_app, "session123", "123_session123",
        )
        timeout_manager = None
        client = None

        try:
            connected, subprotocol = await communicator.connect()
            assert connected is True
            assert subprotocol == "guacamole"

            assert len(FakeGuacamoleClient.instances) == 1
            client = FakeGuacamoleClient.instances[0]
            assert client.handshake_kwargs["hostname"] == "localhost"
            assert client.handshake_kwargs["port"] == TEST_VNC_PORT
            assert client.handshake_kwargs["recording_name"] == "123_session123"

            assert len(FakeTimeoutManager.instances) == 1
            timeout_manager = FakeTimeoutManager.instances[0]
            assert timeout_manager.vm_ip == "192.168.56.10"
            assert timeout_manager.session_id == TEST_TOKEN
            assert timeout_manager.task_id == "123"

            await communicator.send_to(text_data="4.size,4.1280,4.1024;")
            await communicator.send_to(text_data="5.mouse,3.100,3.200,1.0;")
            await communicator.send_to(text_data="3.key,2.65,1.1;")
            await asyncio.sleep(0.05)

            assert timeout_manager.activity_updates == 2
            assert client.sent_messages == [
                "4.size,4.1280,4.1024;",
                "5.mouse,3.100,3.200,1.0;",
                "3.key,2.65,1.1;",
            ]
        finally:
            await communicator.disconnect()

        assert timeout_manager.is_active is False
        assert client.closed is True

    async def test_consumer_accepts_pending_task(self, guac_consumer_app_factory):
        fake_db = FakeDatabase(task=FakeTask(123, "pending"))
        guac_consumer_app, fake_db = guac_consumer_app_factory(fake_db=fake_db)
        communicator = _make_communicator(
            guac_consumer_app, "session_pending", "123_session_pending",
        )

        try:
            connected, subprotocol = await communicator.connect()
            assert connected is True
            assert subprotocol == "guacamole"
            assert len(FakeGuacamoleClient.instances) == 1
            assert fake_db.deleted_sessions == []
        finally:
            await communicator.disconnect()

    async def test_consumer_timeout_completes_analysis_and_closes_session(self, guac_consumer_app_factory, caplog):
        guac_consumer_app, fake_db = guac_consumer_app_factory(
            timeout_manager_cls=ExpiringFakeTimeoutManager,
            stub_monitor_timeout=False,
        )
        caplog.set_level(logging.INFO, logger="guac-session")
        communicator = _make_communicator(
            guac_consumer_app, "session_timeout", "124_session_timeout",
        )

        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol == "guacamole"

        assert len(FakeGuacamoleClient.instances) == 1
        client = FakeGuacamoleClient.instances[0]

        assert len(ExpiringFakeTimeoutManager.instances) == 1
        timeout_manager = ExpiringFakeTimeoutManager.instances[0]
        assert timeout_manager.task_id == "123"

        timeout_message = await asyncio.wait_for(communicator.receive_from(), timeout=1)
        assert timeout_message == "5.error,35.Session timed out due to inactivity,3.522;"

        close_event = await asyncio.wait_for(communicator.receive_output(), timeout=1)
        assert close_event["type"] == "websocket.close"

        await communicator.disconnect()
        await asyncio.wait_for(communicator.wait(), timeout=1)

        assert timeout_manager.complete_analysis_calls == 1
        assert timeout_manager.is_active is False
        assert client.closed is True
        assert "idle for 120001ms (threshold: 120s)" in caplog.text

    async def test_consumer_disconnect_cancels_reader_without_double_close(self, guac_consumer_app_factory):
        guac_consumer_app, fake_db = guac_consumer_app_factory(read_guacd_impl=_cancel_then_close_read_guacd)
        communicator = _make_communicator(
            guac_consumer_app, "session_disconnect", "125_session_disconnect",
        )

        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol == "guacamole"

        assert len(FakeGuacamoleClient.instances) == 1
        client = FakeGuacamoleClient.instances[0]

        assert len(FakeTimeoutManager.instances) == 1
        timeout_manager = FakeTimeoutManager.instances[0]
        assert timeout_manager.task_id == "123"

        await communicator.disconnect()
        await asyncio.wait_for(communicator.wait(), timeout=1)

        assert timeout_manager.is_active is False
        assert client.closed is True

    async def test_consumer_skips_timeout_monitor_when_idle_timeout_disabled(self, guac_consumer_app_factory, monkeypatch):
        scheduled_coroutines = []
        real_create_task = asyncio.create_task

        def tracking_create_task(coro):
            scheduled_coroutines.append(coro.cr_code.co_name)
            return real_create_task(coro)

        monkeypatch.setattr(consumers.asyncio, "create_task", tracking_create_task)

        guac_consumer_app, fake_db = guac_consumer_app_factory(
            timeout_manager_cls=DisabledTimeoutManager,
            stub_monitor_timeout=False,
            read_guacd_impl=_read_guacd_tracking_stub,
        )
        communicator = _make_communicator(
            guac_consumer_app, "session_no_timeout", "126_session_no_timeout",
        )

        connected, subprotocol = await communicator.connect()
        assert connected is True
        assert subprotocol == "guacamole"

        await communicator.send_to(text_data="5.mouse,3.100,3.200,1.0;")
        await asyncio.sleep(0.05)

        assert len(DisabledTimeoutManager.instances) == 1
        assert DisabledTimeoutManager.instances[0].task_id == "123"
        assert DisabledTimeoutManager.instances[0].idle_timeout_seconds == 0
        assert DisabledTimeoutManager.instances[0].activity_check_interval is None
        assert "_read_guacd_tracking_stub" in scheduled_coroutines
        assert "monitor_timeout" not in scheduled_coroutines

        client = FakeGuacamoleClient.instances[0]
        assert client.sent_messages == ["5.mouse,3.100,3.200,1.0;"]

        await communicator.disconnect()
        await asyncio.wait_for(communicator.wait(), timeout=1)

    async def test_consumer_rejects_connection_without_cookie(self, guac_consumer_app_factory):
        guac_consumer_app, fake_db = guac_consumer_app_factory()
        url = "/guac/websocket-tunnel/session_nocookie/?recording_name=test"
        communicator = WebsocketCommunicator(guac_consumer_app, url, subprotocols=["guacamole"])

        connected, _ = await communicator.connect()
        assert connected is False

    async def test_consumer_rejects_connection_with_unknown_token(self, guac_consumer_app_factory):
        guac_consumer_app, fake_db = guac_consumer_app_factory()
        communicator = _make_communicator(
            guac_consumer_app, "unk_session", "test",
            token="00000000-0000-0000-0000-000000000000",
        )

        connected, _ = await communicator.connect()
        assert connected is False
