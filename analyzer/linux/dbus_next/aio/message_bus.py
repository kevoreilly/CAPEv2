from ..message_bus import BaseMessageBus
from .._private.unmarshaller import Unmarshaller
from ..message import Message
from ..constants import BusType, NameFlag, RequestNameReply, ReleaseNameReply, MessageType, MessageFlag
from ..service import ServiceInterface
from ..errors import AuthError
from .proxy_object import ProxyObject
from .. import introspection as intr
from ..auth import Authenticator, AuthExternal

import logging
import array
import asyncio
from asyncio import Queue
import socket
from copy import copy
from typing import Optional


def _future_set_exception(fut, exc):
    if fut is not None and not fut.done():
        fut.set_exception(exc)


def _future_set_result(fut, result):
    if fut is not None and not fut.done():
        fut.set_result(result)


class _MessageWriter:
    def __init__(self, bus):
        self.messages = Queue()
        self.negotiate_unix_fd = bus._negotiate_unix_fd
        self.bus = bus
        self.sock = bus._sock
        self.loop = bus._loop
        self.buf = None
        self.fd = bus._fd
        self.offset = 0
        self.unix_fds = None
        self.fut = None

    def write_callback(self):
        try:
            while True:
                if self.buf is None:
                    if self.messages.qsize() == 0:
                        # nothing more to write
                        self.loop.remove_writer(self.fd)
                        return
                    buf, unix_fds, fut = self.messages.get_nowait()
                    self.unix_fds = unix_fds
                    self.buf = memoryview(buf)
                    self.offset = 0
                    self.fut = fut

                if self.unix_fds and self.negotiate_unix_fd:
                    ancdata = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                array.array("i", self.unix_fds))]
                    self.offset += self.sock.sendmsg([self.buf[self.offset:]], ancdata)
                    self.unix_fds = None
                else:
                    self.offset += self.sock.send(self.buf[self.offset:])

                if self.offset >= len(self.buf):
                    # finished writing
                    self.buf = None
                    _future_set_result(self.fut, None)
                else:
                    # wait for writable
                    return
        except Exception as e:
            _future_set_exception(self.fut, e)
            self.bus._finalize(e)

    def buffer_message(self, msg: Message, future=None):
        self.messages.put_nowait(
            (msg._marshall(negotiate_unix_fd=self.negotiate_unix_fd), copy(msg.unix_fds), future))

    def schedule_write(self, msg: Message = None, future=None):
        if msg is not None:
            self.buffer_message(msg, future)
        if self.bus.unique_name:
            # don't run the writer until the bus is ready to send messages
            self.loop.add_writer(self.fd, self.write_callback)


class MessageBus(BaseMessageBus):
    """The message bus implementation for use with asyncio.

    The message bus class is the entry point into all the features of the
    library. It sets up a connection to the DBus daemon and exposes an
    interface to send and receive messages and expose services.

    You must call :func:`connect() <dbus_next.aio.MessageBus.connect>` before
    using this message bus.

    :param bus_type: The type of bus to connect to. Affects the search path for
        the bus address.
    :type bus_type: :class:`BusType <dbus_next.BusType>`
    :param bus_address: A specific bus address to connect to. Should not be
        used under normal circumstances.
    :param auth: The authenticator to use, defaults to an instance of
        :class:`AuthExternal <dbus_next.auth.AuthExternal>`.
    :type auth: :class:`Authenticator <dbus_next.auth.Authenticator>`
    :param negotiate_unix_fd: Allow the bus to send and receive Unix file
        descriptors (DBus type 'h'). This must be supported by the transport.
    :type negotiate_unix_fd: bool

    :ivar unique_name: The unique name of the message bus connection. It will
        be :class:`None` until the message bus connects.
    :vartype unique_name: str
    :ivar connected: True if this message bus is expected to be able to send
        and receive messages.
    :vartype connected: bool
    """
    def __init__(self,
                 bus_address: str = None,
                 bus_type: BusType = BusType.SESSION,
                 auth: Authenticator = None,
                 negotiate_unix_fd=False):
        super().__init__(bus_address, bus_type, ProxyObject)
        self._negotiate_unix_fd = negotiate_unix_fd
        self._loop = asyncio.get_event_loop()
        self._unmarshaller = self._create_unmarshaller()

        self._writer = _MessageWriter(self)

        if auth is None:
            self._auth = AuthExternal()
        else:
            self._auth = auth

        self._disconnect_future = self._loop.create_future()

    async def connect(self) -> 'MessageBus':
        """Connect this message bus to the DBus daemon.

        This method must be called before the message bus can be used.

        :returns: This message bus for convenience.
        :rtype: :class:`MessageBus <dbus_next.aio.MessageBus>`

        :raises:
            - :class:`AuthError <dbus_next.AuthError>` - If authorization to \
              the DBus daemon failed.
            - :class:`Exception` - If there was a connection error.
        """
        await self._authenticate()

        future = self._loop.create_future()

        self._loop.add_reader(self._fd, self._message_reader)

        def on_hello(reply, err):
            try:
                if err:
                    raise err
                self.unique_name = reply.body[0]
                self._writer.schedule_write()
                _future_set_result(future, self)
            except Exception as e:
                _future_set_exception(future, e)
                self.disconnect()
                self._finalize(err)

        hello_msg = Message(destination='org.freedesktop.DBus',
                            path='/org/freedesktop/DBus',
                            interface='org.freedesktop.DBus',
                            member='Hello',
                            serial=self.next_serial())

        self._method_return_handlers[hello_msg.serial] = on_hello
        self._stream.write(hello_msg._marshall())
        self._stream.flush()

        return await future

    async def introspect(self, bus_name: str, path: str, timeout: float = 30.0) -> intr.Node:
        """Get introspection data for the node at the given path from the given
        bus name.

        Calls the standard ``org.freedesktop.DBus.Introspectable.Introspect``
        on the bus for the path.

        :param bus_name: The name to introspect.
        :type bus_name: str
        :param path: The path to introspect.
        :type path: str
        :param timeout: The timeout to introspect.
        :type timeout: float

        :returns: The introspection data for the name at the path.
        :rtype: :class:`Node <dbus_next.introspection.Node>`

        :raises:
            - :class:`InvalidObjectPathError <dbus_next.InvalidObjectPathError>` \
                    - If the given object path is not valid.
            - :class:`InvalidBusNameError <dbus_next.InvalidBusNameError>` - If \
                  the given bus name is not valid.
            - :class:`DBusError <dbus_next.DBusError>` - If the service threw \
                  an error for the method call or returned an invalid result.
            - :class:`Exception` - If a connection error occurred.
            - :class:`asyncio.TimeoutError` - Waited for future but time run out.
        """
        future = self._loop.create_future()

        def reply_handler(reply, err):
            if err:
                _future_set_exception(future, err)
            else:
                _future_set_result(future, reply)

        super().introspect(bus_name, path, reply_handler)

        return await asyncio.wait_for(future, timeout=timeout)

    async def request_name(self, name: str, flags: NameFlag = NameFlag.NONE) -> RequestNameReply:
        """Request that this message bus owns the given name.

        :param name: The name to request.
        :type name: str
        :param flags: Name flags that affect the behavior of the name request.
        :type flags: :class:`NameFlag <dbus_next.NameFlag>`

        :returns: The reply to the name request.
        :rtype: :class:`RequestNameReply <dbus_next.RequestNameReply>`

        :raises:
            - :class:`InvalidBusNameError <dbus_next.InvalidBusNameError>` - If \
                  the given bus name is not valid.
            - :class:`DBusError <dbus_next.DBusError>` - If the service threw \
                  an error for the method call or returned an invalid result.
            - :class:`Exception` - If a connection error occurred.
        """
        future = self._loop.create_future()

        def reply_handler(reply, err):
            if err:
                _future_set_exception(future, err)
            else:
                _future_set_result(future, reply)

        super().request_name(name, flags, reply_handler)

        return await future

    async def release_name(self, name: str) -> ReleaseNameReply:
        """Request that this message bus release the given name.

        :param name: The name to release.
        :type name: str

        :returns: The reply to the release request.
        :rtype: :class:`ReleaseNameReply <dbus_next.ReleaseNameReply>`

        :raises:
            - :class:`InvalidBusNameError <dbus_next.InvalidBusNameError>` - If \
                  the given bus name is not valid.
            - :class:`DBusError <dbus_next.DBusError>` - If the service threw \
                  an error for the method call or returned an invalid result.
            - :class:`Exception` - If a connection error occurred.
        """
        future = self._loop.create_future()

        def reply_handler(reply, err):
            if err:
                _future_set_exception(future, err)
            else:
                _future_set_result(future, reply)

        super().release_name(name, reply_handler)

        return await future

    async def call(self, msg: Message) -> Optional[Message]:
        """Send a method call and wait for a reply from the DBus daemon.

        :param msg: The method call message to send.
        :type msg: :class:`Message <dbus_next.Message>`

        :returns: A message in reply to the message sent. If the message does
            not expect a reply based on the message flags or type, returns
            ``None`` after the message is sent.
        :rtype: :class:`Message <dbus_next.Message>` or :class:`None` if no reply is expected.

        :raises:
            - :class:`Exception` - If a connection error occurred.
        """
        if msg.flags & MessageFlag.NO_REPLY_EXPECTED or msg.message_type is not MessageType.METHOD_CALL:
            await self.send(msg)
            return None

        future = self._loop.create_future()

        def reply_handler(reply, err):
            if not future.done():
                if err:
                    _future_set_exception(future, err)
                else:
                    _future_set_result(future, reply)

        self._call(msg, reply_handler)

        await future

        return future.result()

    def send(self, msg: Message):
        """Asynchronously send a message on the message bus.

        .. note:: This method may change to a couroutine function in the 1.0
            release of the library.

        :param msg: The message to send.
        :type msg: :class:`Message <dbus_next.Message>`

        :returns: A future that resolves when the message is sent or a
            connection error occurs.
        :rtype: :class:`Future <asyncio.Future>`
        """
        if not msg.serial:
            msg.serial = self.next_serial()

        future = self._loop.create_future()
        self._writer.schedule_write(msg, future)
        return future

    def get_proxy_object(self, bus_name: str, path: str, introspection: intr.Node) -> ProxyObject:
        return super().get_proxy_object(bus_name, path, introspection)

    async def wait_for_disconnect(self):
        """Wait for the message bus to disconnect.

        :returns: :class:`None` when the message bus has disconnected.
        :rtype: :class:`None`

        :raises:
            - :class:`Exception` - If connection was terminated unexpectedly or \
              an internal error occurred in the library.
        """
        return await self._disconnect_future

    def _make_method_handler(self, interface, method):
        if not asyncio.iscoroutinefunction(method.fn):
            return super()._make_method_handler(interface, method)

        def handler(msg, send_reply):
            def done(fut):
                with send_reply:
                    result = fut.result()
                    body, unix_fds = ServiceInterface._fn_result_to_body(
                        result, method.out_signature_tree)
                    send_reply(Message.new_method_return(msg, method.out_signature, body, unix_fds))

            args = ServiceInterface._msg_body_to_args(msg)
            fut = asyncio.ensure_future(method.fn(interface, *args))
            fut.add_done_callback(done)

        return handler

    def _message_reader(self):
        try:
            while True:
                if self._unmarshaller.unmarshall():
                    self._on_message(self._unmarshaller.message)
                    self._unmarshaller = self._create_unmarshaller()
                else:
                    break
        except Exception as e:
            self._finalize(e)

    async def _auth_readline(self):
        buf = b''
        while buf[-2:] != b'\r\n':
            buf += await self._loop.sock_recv(self._sock, 2)
        return buf[:-2].decode()

    async def _authenticate(self):
        await self._loop.sock_sendall(self._sock, b'\0')

        first_line = self._auth._authentication_start(negotiate_unix_fd=self._negotiate_unix_fd)

        if first_line is not None:
            if type(first_line) is not str:
                raise AuthError('authenticator gave response not type str')
            await self._loop.sock_sendall(self._sock, Authenticator._format_line(first_line))

        while True:
            response = self._auth._receive_line(await self._auth_readline())
            if response is not None:
                await self._loop.sock_sendall(self._sock, Authenticator._format_line(response))
                self._stream.flush()
            if response == 'BEGIN':
                break

    def _create_unmarshaller(self):
        sock = None
        if self._negotiate_unix_fd:
            sock = self._sock
        return Unmarshaller(self._stream, sock)

    def _finalize(self, err=None):
        try:
            self._loop.remove_reader(self._fd)
        except Exception:
            logging.warning('could not remove message reader', exc_info=True)
        try:
            self._loop.remove_writer(self._fd)
        except Exception:
            logging.warning('could not remove message writer', exc_info=True)

        super()._finalize(err)

        if self._disconnect_future.done():
            return

        if err and not self._user_disconnect:
            _future_set_exception(self._disconnect_future, err)
        else:
            _future_set_result(self._disconnect_future, None)
