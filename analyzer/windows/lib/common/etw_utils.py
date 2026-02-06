import json
import logging
import pprint
from collections.abc import Iterable, Mapping

from lib.common.abstracts import Auxiliary
from lib.core.config import Config

log = logging.getLogger(__name__)

ETW = False
HAVE_ETW = False
try:
    from etw import ETW, ProviderInfo  # noqa: F401
    from etw import evntrace as et  # noqa: F401
    from etw.GUID import GUID  # noqa: F401

    HAVE_ETW = True
except ImportError as e:
    ETW_IMPORT_ERROR = str(e)
else:
    ETW_IMPORT_ERROR = None


def encode(data, encoding="utf-8"):
    if isinstance(data, str):
        return data.encode(encoding, "ignore")
    elif isinstance(data, Mapping):
        return dict(map(lambda x: encode(x, encoding=encoding), data.items()))
    elif isinstance(data, Iterable):
        return type(data)(map(lambda x: encode(x, encoding=encoding), data))
    else:
        return data


class ETWProviderWrapper(ETW if HAVE_ETW else object):
    def __init__(
        self,
        session_name,
        providers,
        event_id_filters=None,
        ring_buf_size=1024,
        max_str_len=1024,
        min_buffers=0,
        max_buffers=0,
        filters=None,
        event_callback=None,
        logfile=None,
        no_conout=False,
    ):
        if not HAVE_ETW:
            return

        self.logfile = logfile
        self.no_conout = no_conout
        self.event_callback = event_callback or self.on_event
        self.event_id_filters = event_id_filters or []

        super().__init__(
            session_name=session_name,
            ring_buf_size=ring_buf_size,
            max_str_len=max_str_len,
            min_buffers=min_buffers,
            max_buffers=max_buffers,
            event_callback=self.event_callback,
            task_name_filters=filters,
            providers=providers,
            event_id_filters=self.event_id_filters,
        )

    def on_event(self, event_tufo):
        event_id, event = event_tufo

        if self.event_id_filters and event_id not in self.event_id_filters:
            return

        if not self.no_conout:
            log.info("%d (%s)\n%s\n", event_id, event.get("Task Name", ""), pprint.pformat(encode(event)))

        if self.logfile:
            self.write_to_log(self.logfile, event_id, event)

    def write_to_log(self, file_handle, event_id, event):
        json.dump({"event_id": event_id, "event": event}, file_handle)
        file_handle.write("\n")

    def start(self):
        if HAVE_ETW:
            self.do_capture_setup()
            super().start()

    def stop(self):
        if HAVE_ETW:
            super().stop()
            self.do_capture_teardown()

    def do_capture_setup(self):
        pass

    def do_capture_teardown(self):
        pass


class ETWAuxiliaryWrapper(Auxiliary):
    def __init__(self, options, config, enabled_attr):
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = getattr(self.config, enabled_attr, False)
        self.do_run = self.enabled
        self.capture = None

        if not HAVE_ETW:
            log.debug(
                "Could not load auxiliary module %s due to '%s'\n"
                "In order to use ETW functionality, it is required to have pywintrace setup in python",
                self.__class__.__name__,
                ETW_IMPORT_ERROR,
            )

    def start(self):
        if not self.enabled or not HAVE_ETW:
            return False
        try:
            log.debug("Starting %s", self.__class__.__name__)
            if self.capture:
                self.capture.start()
        except Exception as e:
            log.exception("Error starting %s: %s", self.__class__.__name__, e)
        return True

    def stop(self):
        if not HAVE_ETW or not self.capture:
            return
        log.debug("Stopping %s...", self.__class__.__name__)
        self.capture.stop()
        self.upload_results()

    def upload_results(self):
        pass
