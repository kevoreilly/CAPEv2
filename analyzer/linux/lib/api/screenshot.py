# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import asyncio
import logging
import math
import secrets
import urllib.parse

log = logging.getLogger(__name__)

try:
    log.debug("Importing 'PIL.ImageChops'")
    # from PIL import ImageChops
    from PIL.ImageChops import difference

    log.debug("Importing 'PIL.ImageDraw'")
    from PIL import ImageDraw

    try:
        from PIL import __version__
    except ImportError:
        from PIL import PILLOW_VERSION as __version__
    HAVE_PIL = True
    if int(__version__[0]) < 5:
        log.info("Please upgrade Pillow to >= 5.4.1 for best performance")

except Exception as e:
    HAVE_PIL = False
    log.error(e)

try:
    from dbus_next import DBusError, RequestNameReply, Variant
    from dbus_next.aio import MessageBus
except ImportError as err:
    log.error(err)
    HAVE_DBUS_NEXT = False
else:
    HAVE_DBUS_NEXT = True


class ScreenshotsUnsupported(Exception):
    pass


if HAVE_PIL:

    class Screenshot:
        """Get screenshots."""

        @staticmethod
        def _draw_rectangle(img, xy):
            """Draw a black rectangle.
            @param img: PIL Image object
            @param xy: Coordinates as refined in PIL rectangle() doc
            @return: Image with black rectangle
            """
            dr = ImageDraw.Draw(img)
            dr.rectangle(xy, fill="black", outline="black")
            return img

        @classmethod
        def equal(cls, img1, img2, skip_area=None):
            """Compares two screenshots using Root-Mean-Square Difference (RMS).
            @param img1: screenshot to compare.
            @param img2: screenshot to compare.
            @return: equal status.
            """
            # Trick to avoid getting a lot of screen shots only because the time in the windows
            # clock is changed.
            # We draw a black rectangle on the coordinates where the clock is locates, and then
            # run the comparison.
            # NOTE: the coordinates are changing with VM screen resolution.
            if skip_area:
                # Copying objects to draw in another object.
                img1 = img1.copy()
                img2 = img2.copy()
                # Draw a rectangle to cover windows clock.
                for img in (img1, img2):
                    cls._draw_rectangle(img, skip_area)

            # To get a measure of how similar two images are, we use
            # root-mean-square (RMS). If the images are exactly identical,
            # this value is zero.
            # diff = ImageChops.difference(img1, img2)
            diff = difference(img1, img2)
            h = diff.histogram()
            sq = (value * ((idx % 256) ** 2) for idx, value in enumerate(h))
            sum_of_squares = sum(sq)
            rms = math.sqrt(sum_of_squares / (img1.size[0] * img1.size[1]))

            # Might need to tweak the threshold.
            return rms < 8


if HAVE_DBUS_NEXT:

    class ScreenshotGrabber:
        def __init__(self):
            self.bus = MessageBus(negotiate_unix_fd=True)
            self._is_gnome = None

        async def __aenter__(self):
            await self.bus.connect()
            if not await self.is_gnome():
                await self.grant_permission()
            return self

        async def __aexit__(self, exc_type, exc, tb):
            self.bus.disconnect()

        async def is_gnome(self):
            """
            In this method, we check if Gnome is being used. If it is, then
            `take_screenshot_gnome()` will be used to take screenshots.
            Otherwise, `take_screenshot_nongnome()` will be used. See the documentation
            for those methods for details.
            """
            if self._is_gnome is None:
                bus_name = "org.gnome.Shell"
                path = "/org/gnome/Shell"
                interface_name = "org.gnome.Shell"
                introspection = """
                    <!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
                    "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
                    <node>
                        <interface name="org.gnome.Shell">
                            <property name="ShellVersion" type="s" access="read" />
                        </interface>
                    </node>
                """
                proxy = self.bus.get_proxy_object(bus_name, path, introspection)
                interface = proxy.get_interface(interface_name)
                try:
                    version = await interface.get_shell_version()
                except DBusError:
                    self._is_gnome = False
                    log.info("Detected non-Gnome desktop environment.")
                else:
                    self._is_gnome = True
                    log.info(f"Detected Gnome version {version}")
                    name = "org.gnome.Screenshot"
                    resp = await self.bus.request_name(name)
                    if resp not in (
                        RequestNameReply.PRIMARY_OWNER,
                        RequestNameReply.ALREADY_OWNER,
                    ):
                        raise ScreenshotsUnsupported("Unable to acquire the name {name} on d-bus. Disabling screenshot capturing.")

            return self._is_gnome

        async def grant_permission(self):
            bus_name = "org.freedesktop.impl.portal.PermissionStore"
            path = "/org/freedesktop/impl/portal/PermissionStore"
            interface_name = "org.freedesktop.impl.portal.PermissionStore"
            introspection = """
                <!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
                "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
                <node>
                    <interface name="org.freedesktop.impl.portal.PermissionStore">
                        <method name="Set">
                            <arg name="table" direction="in" type="s" />
                                <arg name="create" direction="in" type="b" />
                                <arg name="id" direction="in" type="s" />
                                <arg name="app_permissions" direction="in" type="a{sas}" />
                                <arg name="data" direction="in" type="v" />
                        </method>
                    </interface>
                </node>
                """
            proxy = self.bus.get_proxy_object(bus_name, path, introspection)
            interface = proxy.get_interface(interface_name)
            await interface.call_set("screenshot", True, "screenshot", {"": ["yes"]}, Variant("y", 0))

        async def take_screenshot(self):
            if await self.is_gnome():
                return await self.take_screenshot_gnome()
            return await self.take_screenshot_nongnome()

        async def take_screenshot_gnome(self):
            """
            Gnome has gone through various iterations of supporting applications taking
            screenshots. It used to not use the Portal interface, such as in Ubuntu
            20.04. Then it used the portal interface but would require the user to grant
            access for the application to use it, such as in Ubuntu 22.04. This was
            before version 2 of the backend (i.e.  org.freedesktop.impl.portal.gnome)
            was introduced. Then Gnome introduced version 2 of the backend interface.
            This is seen in Ubuntu 22.10. It permits use of the PermissionStore to grant
            that access, eliminating the need for user interaction. In all cases, though
            the desktop flashes and makes a snapshot sound when taking the screenshot,
            which is very annoying.
            The method used here works for all (tested) versions of Gnome by using a
            different interface...the one that gnome-screenshot uses. Ordinarily, using
            this interface will not work because it limits who is the sender of the
            message to certain Gnome applications. Because of this, in `is_gnome()`,
            we impersonate being gnome-screenshot so that we can use this interface.
            Another advantage of this is that we don't have the annoying screen
            flash and sound when taking screenshots.
            """
            bus_name = "org.gnome.Shell.Screenshot"
            base_path = "/org/gnome/Shell/Screenshot"
            introspection = """
                <!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
                "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
                <node>
                    <interface name="org.gnome.Shell.Screenshot">
                      <method name="Screenshot">
                          <arg name="include_cursor" direction="in" type="b" />
                            <arg name="flash" direction="in" type="b" />
                            <arg name="filename" direction="in" type="s" />
                            <arg name="success" direction="out" type="b" />
                            <arg name="filename_used" direction="out" type="s" />
                        </method>
                    </interface>
                </node>
            """
            proxy = self.bus.get_proxy_object(bus_name, base_path, introspection)
            interface = proxy.get_interface("org.gnome.Shell.Screenshot")
            success, screenshot_path = await interface.call_screenshot(False, False, "Screenshot.png")
            if not success:
                log.error("Failed to take screenshot.")
                return None
            return screenshot_path

        async def take_screenshot_nongnome(self):
            """
            Take a screenshot in non-Gnome environments using the freedesktop portal
            interface. Calling the `screenshot` interface returns a Request object,
            which a signal is sent for when the screenshot is finished being written.
            To avoid a race condition, we set up a signal handler before calling that
            interface and then return the result from that handler.
            """
            bus_name = "org.freedesktop.portal.Desktop"
            base_path = "/org/freedesktop/portal/desktop"
            introspection = """
                <!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
                "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
                <node>
                    <interface name="org.freedesktop.portal.Screenshot">
                        <method name="Screenshot">
                            <arg name="parent_window" direction="in" type="s" />
                                <arg name="options" direction="in" type="a{sv}" />
                                <arg name="handle" direction="out" type="o" />
                        </method>
                        <property name="version" type="u" access="read" />
                    </interface>
                    <interface name="org.freedesktop.portal.Request">
                        <signal name="Response">
                            <arg name="response" direction="out" type="u" />
                            <arg name="results" direction="out" type="a{sv}" />
                        </signal>
                    </interface>
                </node>
                """

            queue = asyncio.Queue(1)

            async def handler(response, results):
                if response == 0:
                    await queue.put(urllib.parse.urlparse(results["uri"].value).path)
                else:
                    log.warning(f"Received non-zero response when taking screenshot: {response}")
                    await queue.put(None)

            # Set up the signal handler
            sender = self.bus.unique_name.lstrip(":").replace(".", "_")
            token = secrets.token_hex(16)
            signal_path = f"{base_path}/request/{sender}/{token}"
            proxy = self.bus.get_proxy_object(bus_name, signal_path, introspection)
            interface = proxy.get_interface("org.freedesktop.portal.Request")
            interface.on_response(handler)

            # Call the screenshot interface. When the screenshot is ready, the handler
            # will get called and put its path in the queue.
            proxy = self.bus.get_proxy_object(bus_name, base_path, introspection)
            interface = proxy.get_interface("org.freedesktop.portal.Screenshot")
            options = {"handle_token": Variant("s", token)}
            await interface.call_screenshot("", options)

            # Do we need a timeout mechanism here?
            screenshot_path = await queue.get()

            return screenshot_path
