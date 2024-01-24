#!/usr/bin/env python

# This has been adapted from https://github.com/fireeye/pywintrace, consolidated in to
# 1 file, with unnecessary parts left out. Some changes have been made to limit the
# amount of code needed at the expense of some flexibility that is unnecessary for
# our purposes.

########################################################################
# Modifications Copyright 2024 Secureworks, Inc.
#
# Copyright 2017 FireEye Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
########################################################################

import ctypes as ct
import ctypes.wintypes as wt
import functools
import json
import logging
import sys
import threading
import traceback
import uuid

logger = logging.getLogger(__name__)

# common.py

MAX_UINT = (2**32) - 1


def convert_bool_str(input_string):
    """
    Helper to convert a string representation of a boolean to a real bool(tm).
    """
    if input_string.lower() in ("1", "true"):
        return True
    return False


def rel_ptr_to_str(base, offset):
    """
    Helper function to convert a relative offset to a string to the actual string.
    """
    return ct.cast(rel_ptr_to_ptr(base, offset), ct.c_wchar_p).value


def rel_ptr_to_ptr(base, offset):
    """
    Helper function to convert a relative offset to a void pointer.
    """
    return ct.cast((ct.cast(base, ct.c_voidp).value + offset), ct.c_voidp)


class SYSTEMTIME(ct.Structure):
    _fields_ = [
        ("wYear", wt.WORD),
        ("wMonth", wt.WORD),
        ("wDayOfWeek", wt.WORD),
        ("wDay", wt.WORD),
        ("wHour", wt.WORD),
        ("wMinute", wt.WORD),
        ("wSecond", wt.WORD),
        ("wMilliseconds", wt.WORD),
    ]


class TIME_ZONE_INFORMATION(ct.Structure):
    _fields_ = [
        ("Bias", ct.c_long),
        ("StandardName", ct.c_wchar * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", ct.c_long),
        ("DaylightName", ct.c_wchar * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", ct.c_long),
    ]


# in6addr.py


class in6_addr(ct.Structure):
    _fields_ = [("Byte", ct.c_byte * 16)]


IN6_ADDR = in6_addr

# GUID.py


class GUID(ct.Structure):
    _fields_ = [
        ("Data1", ct.c_ulong),
        ("Data2", ct.c_ushort),
        ("Data3", ct.c_ushort),
        ("Data4", ct.c_byte * 8),
    ]

    def __init__(self, name):
        ct.oledll.ole32.CLSIDFromString(name, ct.byref(self))

    def __str__(self):
        p = ct.c_wchar_p()
        ct.oledll.ole32.StringFromCLSID(ct.byref(self), ct.byref(p))
        result = p.value
        ct.windll.ole32.CoTaskMemFree(p)
        return result


# wmistr.py

WNODE_FLAG_TRACED_GUID = 0x00020000


class WNODE_HEADER(ct.Structure):
    _fields_ = [
        ("BufferSize", ct.c_ulong),
        ("ProviderId", ct.c_ulong),
        ("HistoricalContext", ct.c_uint64),
        ("TimeStamp", wt.LARGE_INTEGER),
        ("Guid", GUID),
        ("ClientContext", ct.c_ulong),
        ("Flags", ct.c_ulong),
    ]


# evntprov.py


class EVENT_DESCRIPTOR(ct.Structure):
    _fields_ = [
        ("Id", ct.c_ushort),
        ("Version", ct.c_ubyte),
        ("Channel", ct.c_ubyte),
        ("Level", ct.c_ubyte),
        ("Opcode", ct.c_ubyte),
        ("Task", ct.c_ushort),
        ("Keyword", ct.c_ulonglong),
    ]


class EVENT_FILTER_DESCRIPTOR(ct.Structure):
    _fields_ = [("Ptr", ct.c_ulonglong), ("Size", ct.c_ulong), ("Type", ct.c_ulong)]


# evntcons.py

EVENT_HEADER_FLAG_EXTENDED_INFO = 0x01
EVENT_HEADER_FLAG_32_BIT_HEADER = 0x20
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000


class ETW_BUFFER_CONTEXT(ct.Structure):
    _fields_ = [
        ("ProcessorNumber", ct.c_ubyte),
        ("Alignment", ct.c_ubyte),
        ("LoggerId", ct.c_ushort),
    ]


class EVENT_HEADER(ct.Structure):
    _fields_ = [
        ("Size", ct.c_ushort),
        ("HeaderType", ct.c_ushort),
        ("Flags", ct.c_ushort),
        ("EventProperty", ct.c_ushort),
        ("ThreadId", ct.c_ulong),
        ("ProcessId", ct.c_ulong),
        ("TimeStamp", wt.LARGE_INTEGER),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("KernelTime", ct.c_ulong),
        ("UserTime", ct.c_ulong),
        ("ActivityId", GUID),
    ]


class EVENT_HEADER_EXTENDED_DATA_ITEM(ct.Structure):
    _fields_ = [
        ("Reserved1", ct.c_ushort),
        ("ExtType", ct.c_ushort),
        ("Linkage", ct.c_ushort),  # struct{USHORT :1, USHORT :15}
        ("DataSize", ct.c_ushort),
        ("DataPtr", ct.c_ulonglong),
    ]


class EVENT_RECORD(ct.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", ct.c_ushort),
        ("UserDataLength", ct.c_ushort),
        ("ExtendedData", ct.POINTER(EVENT_HEADER_EXTENDED_DATA_ITEM)),
        ("UserData", ct.c_void_p),
        ("UserContext", ct.c_void_p),
    ]


# evntrace.py

EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_REAL_TIME_MODE = 0x00000100  # Real time mode on
TRACEHANDLE = ct.c_ulonglong
INVALID_PROCESSTRACE_HANDLE = TRACEHANDLE(-1)
TRACE_LEVEL_INFORMATION = 4


class ENABLE_TRACE_PARAMETERS(ct.Structure):
    _fields_ = [
        ("Version", ct.c_ulong),
        ("EnableProperty", ct.c_ulong),
        ("ControlFlags", ct.c_ulong),
        ("SourceId", GUID),
        ("EnableFilterDesc", ct.POINTER(EVENT_FILTER_DESCRIPTOR)),
        ("FilterDescCount", ct.c_ulong),
    ]


class EVENT_TRACE_HEADER_CLASS(ct.Structure):
    _fields_ = [("Type", ct.c_ubyte), ("Level", ct.c_ubyte), ("Version", ct.c_uint16)]


class EVENT_TRACE_HEADER(ct.Structure):
    _fields_ = [
        ("Size", ct.c_ushort),
        ("HeaderType", ct.c_ubyte),
        ("MarkerFlags", ct.c_ubyte),
        ("Class", EVENT_TRACE_HEADER_CLASS),
        ("ThreadId", ct.c_ulong),
        ("ProcessId", ct.c_ulong),
        ("TimeStamp", wt.LARGE_INTEGER),
        ("Guid", GUID),
        ("ClientContext", ct.c_ulong),
        ("Flags", ct.c_ulong),
    ]


class EVENT_TRACE(ct.Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", ct.c_ulong),
        ("ParentInstanceId", ct.c_ulong),
        ("ParentGuid", GUID),
        ("MofData", ct.c_void_p),
        ("MofLength", ct.c_ulong),
        ("ClientContext", ct.c_ulong),
    ]


class TRACE_LOGFILE_HEADER(ct.Structure):
    _fields_ = [
        ("BufferSize", ct.c_ulong),
        ("MajorVersion", ct.c_byte),
        ("MinorVersion", ct.c_byte),
        ("SubVersion", ct.c_byte),
        ("SubMinorVersion", ct.c_byte),
        ("ProviderVersion", ct.c_ulong),
        ("NumberOfProcessors", ct.c_ulong),
        ("EndTime", wt.LARGE_INTEGER),
        ("TimerResolution", ct.c_ulong),
        ("MaximumFileSize", ct.c_ulong),
        ("LogFileMode", ct.c_ulong),
        ("BuffersWritten", ct.c_ulong),
        ("StartBuffers", ct.c_ulong),
        ("PointerSize", ct.c_ulong),
        ("EventsLost", ct.c_ulong),
        ("CpuSpeedInMHz", ct.c_ulong),
        ("LoggerName", ct.c_wchar_p),
        ("LogFileName", ct.c_wchar_p),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", wt.LARGE_INTEGER),
        ("PerfFreq", wt.LARGE_INTEGER),
        ("StartTime", wt.LARGE_INTEGER),
        ("ReservedFlags", ct.c_ulong),
        ("BuffersLost", ct.c_ulong),
    ]


# This must be "forward declared", because of the callback type below,
# which is contained in the ct.Structure.
class EVENT_TRACE_LOGFILE(ct.Structure):
    pass


# The type for event trace callbacks.
EVENT_RECORD_CALLBACK = ct.WINFUNCTYPE(None, ct.POINTER(EVENT_RECORD))
EVENT_TRACE_BUFFER_CALLBACK = ct.WINFUNCTYPE(ct.c_ulong, ct.POINTER(EVENT_TRACE_LOGFILE))

EVENT_TRACE_LOGFILE._fields_ = [
    ("LogFileName", ct.c_wchar_p),
    ("LoggerName", ct.c_wchar_p),
    ("CurrentTime", ct.c_longlong),
    ("BuffersRead", ct.c_ulong),
    ("ProcessTraceMode", ct.c_ulong),
    ("CurrentEvent", EVENT_TRACE),
    ("LogfileHeader", TRACE_LOGFILE_HEADER),
    ("BufferCallback", EVENT_TRACE_BUFFER_CALLBACK),
    ("BufferSize", ct.c_ulong),
    ("Filled", ct.c_ulong),
    ("EventsLost", ct.c_ulong),
    ("EventRecordCallback", EVENT_RECORD_CALLBACK),
    ("IsKernelTrace", ct.c_ulong),
    ("Context", ct.c_void_p),
]


class EVENT_TRACE_PROPERTIES(ct.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ct.c_ulong),
        ("MinimumBuffers", ct.c_ulong),
        ("MaximumBuffers", ct.c_ulong),
        ("MaximumFileSize", ct.c_ulong),
        ("LogFileMode", ct.c_ulong),
        ("FlushTimer", ct.c_ulong),
        ("EnableFlags", ct.c_ulong),
        ("AgeLimit", ct.c_ulong),
        ("NumberOfBuffers", ct.c_ulong),
        ("FreeBuffers", ct.c_ulong),
        ("EventsLost", ct.c_ulong),
        ("BuffersWritten", ct.c_ulong),
        ("LogBuffersLost", ct.c_ulong),
        ("RealTimeBuffersLost", ct.c_ulong),
        ("LoggerThreadId", wt.HANDLE),
        ("LogFileNameOffset", ct.c_ulong),
        ("LoggerNameOffset", ct.c_ulong),
    ]


StartTraceW = ct.windll.advapi32.StartTraceW
StartTraceW.argtypes = [
    ct.POINTER(TRACEHANDLE),
    ct.c_wchar_p,
    ct.POINTER(EVENT_TRACE_PROPERTIES),
]
StartTraceW.restype = ct.c_ulong

EnableTraceEx2 = ct.windll.advapi32.EnableTraceEx2
EnableTraceEx2.argtypes = [
    TRACEHANDLE,
    ct.POINTER(GUID),
    ct.c_ulong,
    ct.c_char,
    ct.c_ulonglong,
    ct.c_ulonglong,
    ct.c_ulong,
    ct.POINTER(ENABLE_TRACE_PARAMETERS),
]
EnableTraceEx2.restype = ct.c_ulong

OpenTraceW = ct.windll.advapi32.OpenTraceW
OpenTraceW.argtypes = [ct.POINTER(EVENT_TRACE_LOGFILE)]
OpenTraceW.restype = TRACEHANDLE

ControlTraceW = ct.windll.advapi32.ControlTraceW
ControlTraceW.argtypes = [
    TRACEHANDLE,
    ct.c_wchar_p,
    ct.POINTER(EVENT_TRACE_PROPERTIES),
    ct.c_ulong,
]
ControlTraceW.restype = ct.c_ulong

ProcessTrace = ct.windll.advapi32.ProcessTrace
ProcessTrace.argtypes = [
    ct.POINTER(TRACEHANDLE),
    ct.c_ulong,
    ct.POINTER(wt.FILETIME),
    ct.POINTER(wt.FILETIME),
]
ProcessTrace.restype = ct.c_ulong

CloseTrace = ct.windll.advapi32.CloseTrace
CloseTrace.argtypes = [TRACEHANDLE]
CloseTrace.restype = ct.c_ulong

# tdh.py

DECODING_SOURCE = ct.c_uint
ERROR_SUCCESS = 0x0
ERROR_ALREADY_EXISTS = 0xB7
ERROR_INSUFFICIENT_BUFFER = 0x7A
ERROR_NOT_FOUND = 0x490
MAP_FLAGS = ct.c_uint
PROPERTY_FLAGS = ct.c_uint
TDH_CONTEXT_TYPE = ct.c_uint

TDH_INTYPE_NULL = 0
TDH_INTYPE_UNICODESTRING = 1
TDH_INTYPE_ANSISTRING = 2
TDH_INTYPE_INT8 = 3
TDH_INTYPE_UINT8 = 4
TDH_INTYPE_INT16 = 5
TDH_INTYPE_UINT16 = 6
TDH_INTYPE_INT32 = 7
TDH_INTYPE_UINT32 = 8
TDH_INTYPE_INT64 = 9
TDH_INTYPE_UINT64 = 10
TDH_INTYPE_FLOAT = 11
TDH_INTYPE_DOUBLE = 12
TDH_INTYPE_BOOLEAN = 13
TDH_INTYPE_BINARY = 14
TDH_INTYPE_GUID = 15
TDH_INTYPE_POINTER = 16
TDH_INTYPE_FILETIME = 17
TDH_INTYPE_SYSTEMTIME = 18
TDH_INTYPE_SID = 19
TDH_INTYPE_HEXINT32 = 20
TDH_INTYPE_HEXINT64 = 21
TDH_INTYPE_COUNTEDSTRING = 300
TDH_INTYPE_COUNTEDANSISTRING = 301
TDH_INTYPE_REVERSEDCOUNTEDSTRING = 302
TDH_INTYPE_REVERSEDCOUNTEDANSISTRING = 303
TDH_INTYPE_NONNULLTERMINATEDSTRING = 304
TDH_INTYPE_NONNULLTERMINATEDANSISTRING = 305
TDH_INTYPE_UNICODECHAR = 306
TDH_INTYPE_ANSICHAR = 307
TDH_INTYPE_SIZET = 308
TDH_INTYPE_HEXDUMP = 309
TDH_INTYPE_WBEMSID = 310

TDH_OUTTYPE_NULL = 0
TDH_OUTTYPE_STRING = 1
TDH_OUTTYPE_DATETIME = 2
TDH_OUTTYPE_BYTE = 3
TDH_OUTTYPE_UNSIGNEDBYTE = 4
TDH_OUTTYPE_SHORT = 5
TDH_OUTTYPE_UNSIGNEDSHORT = 6
TDH_OUTTYPE_INT = 7
TDH_OUTTYPE_UNSIGNEDINT = 8
TDH_OUTTYPE_LONG = 9
TDH_OUTTYPE_UNSIGNEDLONG = 10
TDH_OUTTYPE_FLOAT = 11
TDH_OUTTYPE_DOUBLE = 12
TDH_OUTTYPE_BOOLEAN = 13
TDH_OUTTYPE_GUID = 14
TDH_OUTTYPE_HEXBINARY = 15
TDH_OUTTYPE_HEXINT8 = 16
TDH_OUTTYPE_HEXINT16 = 17
TDH_OUTTYPE_HEXINT32 = 18
TDH_OUTTYPE_HEXINT64 = 19
TDH_OUTTYPE_PID = 20
TDH_OUTTYPE_TID = 21
TDH_OUTTYPE_PORT = 22
TDH_OUTTYPE_IPV4 = 23
TDH_OUTTYPE_IPV6 = 24
TDH_OUTTYPE_SOCKETADDRESS = 25
TDH_OUTTYPE_CIMDATETIME = 26
TDH_OUTTYPE_ETWTIME = 27
TDH_OUTTYPE_XML = 28
TDH_OUTTYPE_ERRORCODE = 29
TDH_OUTTYPE_WIN32ERROR = 30
TDH_OUTTYPE_NTSTATUS = 31
TDH_OUTTYPE_HRESULT = 32
TDH_OUTTYPE_CULTURE_INSENSITIVE_DATETIME = 33
TDH_OUTTYPE_JSON = 34
TDH_OUTTYPE_REDUCEDSTRING = 300
TDH_OUTTYPE_NOPRIN = 301

PropertyStruct = 0x1
PropertyParamLength = 0x2

TDH_CONVERTER_LOOKUP = {
    TDH_OUTTYPE_UNSIGNEDBYTE: int,
    TDH_OUTTYPE_INT: int,
    TDH_OUTTYPE_UNSIGNEDINT: int,
    TDH_OUTTYPE_LONG: int,
    TDH_OUTTYPE_UNSIGNEDLONG: int,
    TDH_OUTTYPE_FLOAT: float,
    TDH_OUTTYPE_DOUBLE: float,
    TDH_OUTTYPE_BOOLEAN: convert_bool_str,
}


class EVENT_MAP_ENTRY(ct.Structure):
    _fields_ = [("OutputOffset", ct.c_ulong), ("InputOffset", ct.c_ulong)]


class EVENT_MAP_INFO(ct.Structure):
    _fields_ = [
        ("NameOffset", ct.c_ulong),
        ("Flag", MAP_FLAGS),
        ("EntryCount", ct.c_ulong),
        ("FormatStringOffset", ct.c_ulong),
        ("MapEntryArray", EVENT_MAP_ENTRY * 0),
    ]


class PROPERTY_DATA_DESCRIPTOR(ct.Structure):
    _fields_ = [
        ("PropertyName", ct.c_ulonglong),
        ("ArrayIndex", ct.c_ulong),
        ("Reserved", ct.c_ulong),
    ]


class nonStructType(ct.Structure):
    _fields_ = [
        ("InType", ct.c_ushort),
        ("OutType", ct.c_ushort),
        ("MapNameOffset", ct.c_ulong),
    ]


class structType(ct.Structure):
    _fields_ = [
        ("StructStartIndex", wt.USHORT),
        ("NumOfStructMembers", wt.USHORT),
        ("padding", wt.ULONG),
    ]


class epi_u1(ct.Union):
    _fields_ = [("nonStructType", nonStructType), ("structType", structType)]


class epi_u2(ct.Union):
    _fields_ = [("count", wt.USHORT), ("countPropertyIndex", wt.USHORT)]


class epi_u3(ct.Union):
    _fields_ = [("length", wt.USHORT), ("lengthPropertyIndex", wt.USHORT)]


class epi_u4(ct.Union):
    _fields_ = [("Reserved", wt.ULONG), ("Tags", wt.ULONG)]


class EVENT_PROPERTY_INFO(ct.Structure):
    _fields_ = [
        ("Flags", PROPERTY_FLAGS),
        ("NameOffset", ct.c_ulong),
        ("epi_u1", epi_u1),
        ("epi_u2", epi_u2),
        ("epi_u3", epi_u3),
        ("epi_u4", epi_u4),
    ]


class TDH_CONTEXT(ct.Structure):
    _fields_ = [
        ("ParameterValue", ct.c_ulonglong),
        ("ParameterType", TDH_CONTEXT_TYPE),
        ("ParameterSize", ct.c_ulong),
    ]


class TRACE_EVENT_INFO(ct.Structure):
    _fields_ = [
        ("ProviderGuid", GUID),
        ("EventGuid", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("DecodingSource", DECODING_SOURCE),
        ("ProviderNameOffset", ct.c_ulong),
        ("LevelNameOffset", ct.c_ulong),
        ("ChannelNameOffset", ct.c_ulong),
        ("KeywordsNameOffset", ct.c_ulong),
        ("TaskNameOffset", ct.c_ulong),
        ("OpcodeNameOffset", ct.c_ulong),
        ("EventMessageOffset", ct.c_ulong),
        ("ProviderMessageOffset", ct.c_ulong),
        ("BinaryXMLOffset", ct.c_ulong),
        ("BinaryXMLSize", ct.c_ulong),
        ("ActivityIDNameOffset", ct.c_ulong),
        ("RelatedActivityIDNameOffset", ct.c_ulong),
        ("PropertyCount", ct.c_ulong),
        ("TopLevelPropertyCount", ct.c_ulong),
        ("Flags", ct.c_ulong),
        ("EventPropertyInfoArray", EVENT_PROPERTY_INFO * 0),
    ]


TdhFormatProperty = ct.windll.Tdh.TdhFormatProperty
TdhFormatProperty.argtypes = [
    ct.POINTER(TRACE_EVENT_INFO),
    ct.POINTER(EVENT_MAP_INFO),
    ct.c_ulong,
    ct.c_ushort,
    ct.c_ushort,
    ct.c_ushort,
    ct.c_ushort,
    ct.POINTER(ct.c_byte),
    ct.POINTER(ct.c_ulong),
    ct.c_wchar_p,
    ct.POINTER(ct.c_ushort),
]
TdhFormatProperty.restype = ct.c_ulong

TdhGetEventInformation = ct.windll.Tdh.TdhGetEventInformation
TdhGetEventInformation.argtypes = [
    ct.POINTER(EVENT_RECORD),
    ct.c_ulong,
    ct.POINTER(TDH_CONTEXT),
    ct.POINTER(TRACE_EVENT_INFO),
    ct.POINTER(ct.c_ulong),
]
TdhGetEventInformation.restype = ct.c_ulong

TdhGetEventMapInformation = ct.windll.Tdh.TdhGetEventMapInformation
TdhGetEventMapInformation.argtypes = [
    ct.POINTER(EVENT_RECORD),
    wt.LPWSTR,
    ct.POINTER(EVENT_MAP_INFO),
    ct.POINTER(ct.c_ulong),
]
TdhGetEventMapInformation.restype = ct.c_ulong

TdhGetPropertySize = ct.windll.Tdh.TdhGetPropertySize
TdhGetPropertySize.argtypes = [
    ct.POINTER(EVENT_RECORD),
    ct.c_ulong,
    ct.POINTER(TDH_CONTEXT),
    ct.c_ulong,
    ct.POINTER(PROPERTY_DATA_DESCRIPTOR),
    ct.POINTER(ct.c_ulong),
]
TdhGetPropertySize.restype = ct.c_ulong

TdhGetProperty = ct.windll.Tdh.TdhGetProperty
TdhGetProperty.argtypes = [
    ct.POINTER(EVENT_RECORD),
    ct.c_ulong,
    ct.POINTER(TDH_CONTEXT),
    ct.c_ulong,
    ct.POINTER(PROPERTY_DATA_DESCRIPTOR),
    ct.c_ulong,
    ct.POINTER(ct.c_byte),
]
TdhGetProperty.restype = ct.c_ulong

# etw.py


class ProviderInfo:
    def __init__(self, name, guid):
        self.name = name
        self.guid = guid
        self.level = TRACE_LEVEL_INFORMATION
        self.any_bitmask = 0
        self.all_bitmask = 0


class EventProvider:
    def __init__(self, session_name, session_properties, providers):
        self.session_name = session_name
        self.session_properties = session_properties
        self.providers = providers
        self.session_handle = TRACEHANDLE()

    def start(self):
        status = StartTraceW(
            ct.byref(self.session_handle),
            self.session_name,
            self.session_properties.get(),
        )
        if status != ERROR_SUCCESS:
            raise ct.WinError(status)

        for provider in self.providers:
            status = EnableTraceEx2(
                self.session_handle,
                ct.byref(provider.guid),
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                provider.level,
                provider.any_bitmask,
                provider.all_bitmask,
                0,
                None,
            )
            if status != ERROR_SUCCESS:
                raise ct.WinError(status)

    def stop(self):
        """
        Wraps the necessary processes needed for stopping an ETW provider session.

        :return: Does not return anything
        """
        # don't stop if we don't have a handle, or it's the kernel trace and we started it ourself
        if self.session_handle.value == 0:
            return

        for provider in self.providers:
            status = EnableTraceEx2(
                self.session_handle,
                ct.byref(provider.guid),
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                provider.level,
                provider.any_bitmask,
                provider.all_bitmask,
                0,
                None,
            )
            if status != ERROR_SUCCESS:
                raise ct.WinError(status)

        status = ControlTraceW(
            self.session_handle,
            self.session_name,
            self.session_properties.get(),
            EVENT_TRACE_CONTROL_STOP,
        )
        if status != ERROR_SUCCESS:
            raise ct.WinError(status)

        CloseTrace(self.session_handle)


class EventConsumer:
    """
    Wraps all interactions with Event Tracing for Windows (ETW) event consumers. This includes
    starting and stopping the consumer. Additionally, each consumer begins processing events in
    a separate thread and uses a callback to process any events it receives in this thread -- those
    methods are implemented here as well.

    N.B. If using this class, do not call start() and stop() directly. Only use through via ctxmgr
    """

    def __init__(self, logger_name, event_callback=None):
        self.trace_handle = None
        self.process_thread = None
        self.logger_name = logger_name
        self.end_capture = threading.Event()
        self.event_callback = event_callback
        self.vfield_length = None
        self.index = 0

        self.trace_logfile = EVENT_TRACE_LOGFILE()
        self.trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        self.trace_logfile.LoggerName = logger_name
        self.trace_logfile.EventRecordCallback = EVENT_RECORD_CALLBACK(self._processEvent)

    def start(self):
        """
        Starts a trace consumer.

        :return: Returns True on Success or False on Failure
        """
        self.trace_handle = OpenTraceW(ct.byref(self.trace_logfile))
        if self.trace_handle == INVALID_PROCESSTRACE_HANDLE:
            raise ct.WinError()

        # For whatever reason, the restype is ignored
        self.trace_handle = TRACEHANDLE(self.trace_handle)
        self.process_thread = threading.Thread(target=self._run, args=(self.trace_handle, self.end_capture))
        self.process_thread.daemon = True
        self.process_thread.start()

    def stop(self):
        """
        Stops a trace consumer.

        :return: Returns True on Success or False on Failure
        """
        # Signal to the thread that we are reading to stop processing events.
        self.end_capture.set()

        # Call CloseTrace to cause ProcessTrace to return (unblock)
        CloseTrace(self.trace_handle)

        # If ProcessThread is actively parsing an event, we want to give it a chance to finish
        # before pulling the rug out from underneath it.
        self.process_thread.join()

    @staticmethod
    def _run(trace_handle, end_capture):
        """
        Because ProcessTrace() blocks, this function is used to spin off new threads.

        :param trace_handle: The handle for the trace consumer that we want to begin processing.
        :param end_capture: A callback function which determines what should be done with the results.
        :return: Does not return a value.
        """
        while True:
            if ERROR_SUCCESS != ProcessTrace(ct.byref(trace_handle), 1, None, None):
                end_capture.set()

            if end_capture.is_set():
                break

    @staticmethod
    def _getEventInformation(record):
        """
        Initially we are handed an EVENT_RECORD structure. While this structure technically contains
        all of the information necessary, TdhGetEventInformation parses the structure and simplifies it
        so we can more effectively parse and handle the various fields.

        :param record: The EventRecord structure for the event we are parsing
        :return: Returns a pointer to a TRACE_EVENT_INFO structure or None on error.
        """
        info = ct.POINTER(TRACE_EVENT_INFO)()
        buffer_size = wt.DWORD()

        # Call TdhGetEventInformation once to get the required buffer size and again to actually populate the structure.
        status = TdhGetEventInformation(record, 0, None, None, ct.byref(buffer_size))
        if ERROR_INSUFFICIENT_BUFFER == status:
            info = ct.cast((ct.c_byte * buffer_size.value)(), ct.POINTER(TRACE_EVENT_INFO))
            status = TdhGetEventInformation(record, 0, None, info, ct.byref(buffer_size))

        if ERROR_SUCCESS != status:
            raise ct.WinError(status)

        return info

    @staticmethod
    def _getMapInfo(record, info, event_property):
        """
        When parsing a field in the event property structure, there may be a mapping between a given
        name and the structure it represents. If it exists, we retrieve that mapping here.

        Because this may legitimately return a NULL value we return a tuple containing the success or
        failure status as well as either None (NULL) or an EVENT_MAP_INFO pointer.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: A tuple of the map_info structure and boolean indicating whether we succeeded or not
        """
        map_name = rel_ptr_to_str(info, event_property.epi_u1.nonStructType.MapNameOffset)
        map_size = wt.DWORD()
        map_info = ct.POINTER(EVENT_MAP_INFO)()

        status = TdhGetEventMapInformation(record, map_name, None, ct.byref(map_size))
        if ERROR_INSUFFICIENT_BUFFER == status:
            map_info = ct.cast((ct.c_char * map_size.value)(), ct.POINTER(EVENT_MAP_INFO))
            status = TdhGetEventMapInformation(record, map_name, map_info, ct.byref(map_size))

        if ERROR_SUCCESS == status:
            return map_info, True

        # ERROR_NOT_FOUND is actually a perfectly acceptable status
        if ERROR_NOT_FOUND == status:
            return None, True

        # We actually failed.
        raise ct.WinError()

    @staticmethod
    def _getPropertyLength(record, info, event_property):
        """
        Each property encountered when parsing the top level property has an associated length. If the
        length is available, retrieve it here. In some cases, the length is 0. This can signify that
        we are dealing with a variable length field such as a structure, an IPV6 data, or a string.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: Returns the length of the property as a c_ulong() or None on error
        """
        flags = event_property.Flags

        if flags & PropertyParamLength:
            data_descriptor = PROPERTY_DATA_DESCRIPTOR()
            event_property_array = ct.cast(info.contents.EventPropertyInfoArray, ct.POINTER(EVENT_PROPERTY_INFO))
            j = wt.DWORD(event_property.epi_u3.length)
            property_size = ct.c_ulong()
            length = wt.DWORD()

            # Setup the PROPERTY_DATA_DESCRIPTOR structure
            data_descriptor.PropertyName = ct.cast(info, ct.c_voidp).value + event_property_array[j.value].NameOffset
            data_descriptor.ArrayIndex = MAX_UINT

            status = TdhGetPropertySize(record, 0, None, 1, ct.byref(data_descriptor), ct.byref(property_size))
            if ERROR_SUCCESS != status:
                raise ct.WinError(status)

            status = TdhGetProperty(
                record,
                0,
                None,
                1,
                ct.byref(data_descriptor),
                property_size,
                ct.cast(ct.byref(length), ct.POINTER(ct.c_byte)),
            )
            if ERROR_SUCCESS != status:
                raise ct.WinError(status)
            return length.value

        in_type = event_property.epi_u1.nonStructType.InType
        out_type = event_property.epi_u1.nonStructType.OutType

        # This is a special case in which the input and output types dictate the size
        if (in_type == TDH_INTYPE_BINARY) and (out_type == TDH_OUTTYPE_IPV6):
            return ct.sizeof(IN6_ADDR)

        return event_property.epi_u3.length

    def _unpackSimpleType(self, record, info, event_property):
        """
        This method handles dumping all simple types of data (i.e., non-struct types).

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: Returns a key-value pair as a dictionary. If we fail, the dictionary is {}
        """
        # Get the EVENT_MAP_INFO, if it is present.
        map_info, success = self._getMapInfo(record, info, event_property)
        if not success:
            return {}

        # Get the length of the value of the property we are dealing with.
        property_length = self._getPropertyLength(record, info, event_property)
        if property_length is None:
            return {}
        # The version of the Python interpreter may be different than the system architecture.
        if record.contents.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER:
            ptr_size = 4
        else:
            ptr_size = 8

        name_field = rel_ptr_to_str(info, event_property.NameOffset)
        if property_length == 0 and self.vfield_length is not None:
            if self.vfield_length == 0:
                self.vfield_length = None
                return {name_field: None}

            # If vfield_length isn't 0, we should be able to parse the property.
            property_length = self.vfield_length

        # After calling the TdhFormatProperty function, use the UserDataConsumed parameter value to set the new values
        # of the UserData and UserDataLength parameters (Subtract UserDataConsumed from UserDataLength and use
        # UserDataLength to increment the UserData pointer).

        # All of the variables needed to actually use TdhFormatProperty retrieve the value
        user_data = record.contents.UserData + self.index
        user_data_remaining = record.contents.UserDataLength - self.index

        # if there is no data remaining then return
        if user_data_remaining <= 0:
            logger.warning("No more user data left, returning none for field {:s}".format(name_field))
            return {name_field: None}

        in_type = event_property.epi_u1.nonStructType.InType
        out_type = event_property.epi_u1.nonStructType.OutType
        formatted_data_size = wt.DWORD()
        formatted_data = wt.LPWSTR()
        user_data_consumed = ct.c_ushort()

        status = TdhFormatProperty(
            info,
            map_info,
            ptr_size,
            in_type,
            out_type,
            ct.c_ushort(property_length),
            user_data_remaining,
            ct.cast(user_data, ct.POINTER(ct.c_byte)),
            ct.byref(formatted_data_size),
            None,
            ct.byref(user_data_consumed),
        )

        if status == ERROR_INSUFFICIENT_BUFFER:
            formatted_data = ct.cast((ct.c_char * formatted_data_size.value)(), wt.LPWSTR)
            status = TdhFormatProperty(
                info,
                map_info,
                ptr_size,
                in_type,
                out_type,
                ct.c_ushort(property_length),
                user_data_remaining,
                ct.cast(user_data, ct.POINTER(ct.c_byte)),
                ct.byref(formatted_data_size),
                formatted_data,
                ct.byref(user_data_consumed),
            )

        if status != ERROR_SUCCESS:
            # We can handle this error and still capture the data.
            logger.warning("Failed to get data field data for {:s}, incrementing by reported size".format(name_field))
            self.index += property_length
            return {name_field: None}

        # Increment where we are in the user data segment that we are parsing.
        self.index += user_data_consumed.value

        if name_field.lower().endswith("length"):
            try:
                self.vfield_length = int(formatted_data.value, 10)
            except ValueError:
                logger.warning("Setting vfield_length to None")
                self.vfield_length = None

        data = formatted_data.value
        # Convert the formatted data if necessary
        if out_type in TDH_CONVERTER_LOOKUP and type(data) != TDH_CONVERTER_LOOKUP[out_type]:
            data = TDH_CONVERTER_LOOKUP[out_type](data)

        return {name_field: data}

    def _unpackComplexType(self, record, info, event_property):
        """
        A complex type (e.g., a structure with sub-properties) can only contain simple types. Loop over all
        sub-properties and dump the property name and value.

        :param record: The EventRecord structure for the event we are parsing
        :param info: The TraceEventInfo structure for the event we are parsing
        :param event_property: The EVENT_PROPERTY_INFO structure for the TopLevelProperty of the event we are parsing
        :return: A dictionary of the property and value for the event we are parsing
        """
        out = {}

        array_size = self._getArraySize(record, info, event_property)
        if array_size is None:
            return {}

        for _ in range(array_size):
            start_index = event_property.epi_u1.structType.StructStartIndex
            last_member = start_index + event_property.epi_u1.structType.NumOfStructMembers

            for j in range(start_index, last_member):
                # Because we are no longer dealing with the TopLevelProperty, we need to get the event_property_array
                # again so we can get the EVENT_PROPERTY_INFO structure of the sub-property we are currently parsing.
                event_property_array = ct.cast(
                    info.contents.EventPropertyInfoArray,
                    ct.POINTER(EVENT_PROPERTY_INFO),
                )

                key, value = self._unpackSimpleType(record, info, event_property_array[j])
                if key is None and value is None:
                    break

                out[key] = value

        return out

    def _processEvent(self, record):
        """
        This is a callback function that fires whenever an event needs handling. It iterates through the structure to
        parse the properties of each event. If a user defined callback is specified it then passes the parsed data to
        it.


        :param record: The EventRecord structure for the event we are parsing
        :return: Nothing
        """
        parsed_data = {}

        event_id = record.contents.EventHeader.EventDescriptor.Id
        # set task name to provider guid for the time being
        task_name = str(record.contents.EventHeader.ProviderId)

        # add all header fields from EVENT_HEADER structure
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa363759(v=vs.85).aspx
        out = {
            "EventHeader": {
                "Size": record.contents.EventHeader.Size,
                "HeaderType": record.contents.EventHeader.HeaderType,
                "Flags": record.contents.EventHeader.Flags,
                "EventProperty": record.contents.EventHeader.EventProperty,
                "ThreadId": record.contents.EventHeader.ThreadId,
                "ProcessId": record.contents.EventHeader.ProcessId,
                "TimeStamp": record.contents.EventHeader.TimeStamp,
                "ProviderId": task_name,
                "EventDescriptor": {
                    "Id": event_id,
                    "Version": record.contents.EventHeader.EventDescriptor.Version,
                    "Channel": record.contents.EventHeader.EventDescriptor.Channel,
                    "Level": record.contents.EventHeader.EventDescriptor.Level,
                    "Opcode": record.contents.EventHeader.EventDescriptor.Opcode,
                    "Task": record.contents.EventHeader.EventDescriptor.Task,
                    "Keyword": record.contents.EventHeader.EventDescriptor.Keyword,
                },
                "KernelTime": record.contents.EventHeader.KernelTime,
                "UserTime": record.contents.EventHeader.UserTime,
                "ActivityId": str(record.contents.EventHeader.ActivityId),
            },
            "Task Name": task_name,
        }

        try:
            info = self._getEventInformation(record)

            # Some events do not have an associated task_name value. In this case, we should use the provider
            # name instead.
            if info.contents.TaskNameOffset == 0:
                task_name = rel_ptr_to_str(info, info.contents.ProviderNameOffset)
            else:
                task_name = rel_ptr_to_str(info, info.contents.TaskNameOffset)

            task_name = task_name.strip().upper()

            # Add a description for the event, if present
            if info.contents.EventMessageOffset:
                description = rel_ptr_to_str(info, info.contents.EventMessageOffset)
            else:
                description = ""

            user_data = record.contents.UserData
            if user_data is None:
                user_data = 0

            end_of_user_data = user_data + record.contents.UserDataLength
            self.index = 0
            self.vfield_length = None
            property_array = ct.cast(info.contents.EventPropertyInfoArray, ct.POINTER(EVENT_PROPERTY_INFO))

            for i in range(info.contents.TopLevelPropertyCount):
                # If the user_data is the same value as the end_of_user_data, we are ending with a 0-length
                # field. Though not documented, this is completely valid.
                if user_data == end_of_user_data:
                    break

                # Determine whether we are processing a simple type or a complex type and act accordingly
                if property_array[i].Flags & PropertyStruct:
                    field = self._unpackComplexType(record, info, property_array[i])
                else:
                    field = self._unpackSimpleType(record, info, property_array[i])

                parsed_data.update(field)

            # Add the description field in
            parsed_data["Description"] = description
            parsed_data["Task Name"] = task_name
            # Add ExtendedData if any
            if record.contents.EventHeader.Flags & EVENT_HEADER_FLAG_EXTENDED_INFO:
                parsed_data["EventExtendedData"] = self._parseExtendedData(record)
        except Exception as e:
            logger.warning("Unable to parse event: {}".format(e))

        try:
            out.update(parsed_data)
            # Call the user's specified callback function
            if self.event_callback:
                self.event_callback(out)
        except Exception as e:
            logger.error("Exception during callback: {}".format(e))
            logger.error(traceback.format_exc())


class TraceProperties:
    def __init__(self):
        buf_size = ct.sizeof(EVENT_TRACE_PROPERTIES) + 2 * ct.sizeof(ct.c_wchar) * 1024
        self._buf = (ct.c_char * buf_size)()
        self._props = ct.cast(ct.pointer(self._buf), ct.POINTER(EVENT_TRACE_PROPERTIES))
        self._props.contents.BufferSize = 1024
        self._props.contents.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        self._props.contents.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        self._props.contents.Wnode.BufferSize = buf_size
        self._props.contents.LoggerNameOffset = ct.sizeof(EVENT_TRACE_PROPERTIES)

    def get(self):
        return self._props


class AMSI:
    def __init__(self, event_callback=None):
        try:
            self.providers = [ProviderInfo("AMSI", GUID("{2A576B87-09A7-520E-C21A-4942F0271D67}"))]
        except OSError as err:
            raise OSError("AMSI not supported on this platform") from err
        self.provider = None
        self.properties = TraceProperties()
        self.session_name = "{:s}".format(str(uuid.uuid4()))
        self.running = False
        self.event_callback = event_callback
        self.trace_logfile = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc, ex, tb):
        self.stop()

    def start(self):
        if self.provider is None:
            self.provider = EventProvider(self.session_name, self.properties, self.providers)

        if not self.running:
            self.running = True
            try:
                self.provider.start()
            except OSError as err:
                if err.winerror != ERROR_ALREADY_EXISTS:
                    raise err

            # Start the consumer
            self.consumer = EventConsumer(
                self.session_name,
                self.event_callback,
            )
            self.consumer.start()

    def stop(self):
        """
        Stops the current consumer and provider.

        :return: Does not return anything.
        """

        if self.provider:
            self.running = False
            self.provider.stop()
            self.consumer.stop()


def jsonldump(obj, fp):
    """Write each event object on its own line."""
    json.dump(obj, fp)
    fp.write("\n")


def main():
    with AMSI(event_callback=functools.partial(jsonldump, fp=sys.stdout)):
        print("Listening for AMSI events. Press enter to stop...")
        sys.stdin.readline()


if __name__ == "__main__":
    main()
