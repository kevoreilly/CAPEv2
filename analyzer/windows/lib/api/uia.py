# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Pure-ctypes Microsoft UI Automation (UIA) client for Windows guest interaction.

Uses native ``ole32.dll``, ``oleaut32.dll``, and ``UIAutomationCore.dll`` COM
vtables without requiring third-party packages (``comtypes``, ``pywinauto``,
``pywin32``) inside the guest VM.
"""

from __future__ import annotations

import ctypes
import logging
import time
from collections.abc import Callable
from ctypes import POINTER, Structure, byref, c_int32, c_int64, c_ubyte, c_uint16, c_uint32, c_void_p, cast, wstring_at

log = logging.getLogger(__name__)

# COM initialization and activation constants
COINIT_MULTITHREADED = 0x0
CLSCTX_INPROC_SERVER = 0x1
RPC_E_CHANGED_MODE = -2147417850  # 0x80010106 as signed 32-bit HRESULT
RPC_E_TIMEOUT = -2147417825  # 0x8001011F as signed 32-bit HRESULT
UIA_E_TIMEOUT = -2146233083  # 0x80131505 as signed 32-bit HRESULT
_TIMEOUT_HRESULTS = frozenset({UIA_E_TIMEOUT, RPC_E_TIMEOUT})

# VARIANT types (wtypes.h)
VT_I4 = 3
VT_BOOL = 11
# VARIANT_TRUE is int16(-1) = 0xFFFF in low 16 bits of the VARIANT value slot (little-endian).
_VARIANT_TRUE_BITS = 0x0000FFFF
_VARIANT_FALSE_BITS = 0x00000000

# UIA TreeScope
TreeScope_Descendants = 0x4

# UIA Property / ControlType / Pattern IDs (UIAutomationClient.h)
UIA_BoundingRectanglePropertyId = 30001
UIA_ControlTypePropertyId = 30003
UIA_NamePropertyId = 30005
UIA_IsEnabledPropertyId = 30010
UIA_IsOffscreenPropertyId = 30022

UIA_ButtonControlTypeId = 50000
UIA_CheckBoxControlTypeId = 50002
UIA_HyperlinkControlTypeId = 50005
UIA_RadioButtonControlTypeId = 50013

UIA_InvokePatternId = 10000
UIA_SelectionItemPatternId = 10010
UIA_TogglePatternId = 10015

# UIA ToggleState enum
ToggleState_Off = 0
ToggleState_On = 1
ToggleState_Indeterminate = 2

# Default UIA2 timeouts, traversal cap, and cooldowns to keep Human responsive
DEFAULT_CONNECTION_TIMEOUT_MS = 500
DEFAULT_TRANSACTION_TIMEOUT_MS = 1000
DEFAULT_WINDOW_BUDGET_S = 1.5
DEFAULT_TIMEOUT_BACKOFF_S = 10.0
DEFAULT_ACTION_COOLDOWN_S = 3.0
DEFAULT_UNVERIFIED_TOGGLE_COOLDOWN_S = 60.0
MAX_UIA_ELEMENTS = 256
_MAX_TRACKED_STATE_ENTRIES = 256

# COM vtable slot indices (verified against Windows SDK UIAutomationClient.h)
_VTBL_RELEASE = 2

# IUIAutomation / IUIAutomation2
_VTBL_UIA_ELEMENT_FROM_HANDLE = 6
_VTBL_UIA_CREATE_CACHE_REQUEST = 20
_VTBL_UIA_CREATE_PROPERTY_CONDITION = 23
_VTBL_UIA_CREATE_AND_CONDITION_FROM_NATIVE_ARRAY = 27
_VTBL_UIA_CREATE_OR_CONDITION_FROM_NATIVE_ARRAY = 30
_VTBL_UIA_CREATE_NOT_CONDITION = 31
_VTBL_UIA2_PUT_CONNECTION_TIMEOUT = 61
_VTBL_UIA2_PUT_TRANSACTION_TIMEOUT = 63

# IUIAutomationCacheRequest
_VTBL_CACHE_ADD_PROPERTY = 3

# IUIAutomationElement
_VTBL_ELEM_FIND_ALL = 6
_VTBL_ELEM_FIND_ALL_BUILD_CACHE = 8
_VTBL_ELEM_GET_CURRENT_PATTERN_AS = 14
_VTBL_ELEM_GET_CURRENT_CONTROL_TYPE = 21
_VTBL_ELEM_GET_CURRENT_NAME = 23
_VTBL_ELEM_GET_CURRENT_IS_ENABLED = 28
_VTBL_ELEM_GET_CURRENT_IS_OFFSCREEN = 38
_VTBL_ELEM_GET_CURRENT_BOUNDING_RECTANGLE = 43
_VTBL_ELEM_GET_CACHED_CONTROL_TYPE = 53
_VTBL_ELEM_GET_CACHED_NAME = 55
_VTBL_ELEM_GET_CACHED_IS_ENABLED = 60
_VTBL_ELEM_GET_CACHED_IS_OFFSCREEN = 70
_VTBL_ELEM_GET_CACHED_BOUNDING_RECTANGLE = 75
_VTBL_ELEM_GET_CLICKABLE_POINT = 84

# IUIAutomationElementArray
_VTBL_ARRAY_GET_LENGTH = 3
_VTBL_ARRAY_GET_ELEMENT = 4

# Control patterns
_VTBL_INVOKE_INVOKE = 3
_VTBL_TOGGLE_TOGGLE = 3
_VTBL_TOGGLE_GET_CURRENT_STATE = 4
_VTBL_SELECT_SELECT = 3
_VTBL_SELECT_GET_CURRENT_IS_SELECTED = 6


class GUID(Structure):
    """Windows COM GUID (16 bytes across x86 and x64)."""

    _fields_ = [
        ("Data1", c_uint32),
        ("Data2", c_uint16),
        ("Data3", c_uint16),
        ("Data4", c_ubyte * 8),
    ]

    @classmethod
    def from_string(cls, text: str) -> GUID:
        raw = text.strip().strip("{}").replace("-", "")
        if len(raw) != 32:
            raise ValueError(f"Invalid GUID string: {text!r}")
        data1 = int(raw[0:8], 16)
        data2 = int(raw[8:12], 16)
        data3 = int(raw[12:16], 16)
        data4 = (c_ubyte * 8)(*(int(raw[i : i + 2], 16) for i in range(16, 32, 2)))
        return cls(data1, data2, data3, data4)


_VARIANT_FIELDS = [
    ("vt", c_uint16),
    ("wReserved1", c_uint16),
    ("wReserved2", c_uint16),
    ("wReserved3", c_uint16),
    ("lVal", c_int32),
    ("_pad0", c_int32),
]
if ctypes.sizeof(c_void_p) == 8:
    _VARIANT_FIELDS.append(("_pad1", c_int64))


class VARIANT(Structure):
    """Windows OLE VARIANT without an embedded Union (16 bytes on x86, 24 bytes on x64)."""

    _fields_ = _VARIANT_FIELDS

    @classmethod
    def from_i4(cls, value: int) -> VARIANT:
        var = cls()
        var.vt = VT_I4
        var.lVal = value
        return var

    @classmethod
    def from_bool(cls, value: bool) -> VARIANT:
        var = cls()
        var.vt = VT_BOOL
        var.lVal = _VARIANT_TRUE_BITS if value else _VARIANT_FALSE_BITS
        return var


class UIA_RECT(Structure):
    """Fixed-width Win32 RECT (16 bytes on all platforms)."""

    _fields_ = [
        ("left", c_int32),
        ("top", c_int32),
        ("right", c_int32),
        ("bottom", c_int32),
    ]


class UIA_POINT(Structure):
    """Fixed-width Win32 POINT (8 bytes on all platforms)."""

    _fields_ = [
        ("x", c_int32),
        ("y", c_int32),
    ]


CLSID_CUIAutomation = GUID.from_string("{FF48DBA4-60EF-4201-AA87-54103EEF594E}")
CLSID_CUIAutomation8 = GUID.from_string("{E22AD333-B25F-460C-83D0-0581107395C9}")
IID_IUIAutomation = GUID.from_string("{30CBE57D-D9D0-452A-AB13-7AC5AC4825EE}")
IID_IUIAutomation2 = GUID.from_string("{34723AFF-0C9D-49D0-9896-7AB52DF8CD8A}")
IID_IUIAutomationInvokePattern = GUID.from_string("{FB377FBE-8EA6-46D5-9C73-6499642D3059}")
IID_IUIAutomationTogglePattern = GUID.from_string("{94CF8058-9B8D-4AB9-8BFD-4CD0A33C8C70}")
IID_IUIAutomationSelectionItemPattern = GUID.from_string("{A8EFA66A-0FDA-421A-9194-38021F3578EA}")

BUTTON_CONTROL_TYPES = (
    UIA_ButtonControlTypeId,
    UIA_CheckBoxControlTypeId,
    UIA_RadioButtonControlTypeId,
)
INTERACTIVE_CONTROL_TYPES = (
    UIA_ButtonControlTypeId,
    UIA_CheckBoxControlTypeId,
    UIA_RadioButtonControlTypeId,
    UIA_HyperlinkControlTypeId,
)
_CACHED_PROPERTY_IDS = (
    UIA_ControlTypePropertyId,
    UIA_NamePropertyId,
    UIA_IsEnabledPropertyId,
    UIA_IsOffscreenPropertyId,
    UIA_BoundingRectanglePropertyId,
)


def _winfunctype(restype, *argtypes):
    factory = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
    return factory(restype, *argtypes)


def _com_call(ptr: c_void_p | int, slot: int, restype, argtypes: tuple, *args):
    """Invoke a COM interface method through its vtable pointer."""
    raw_ptr = ptr.value if isinstance(ptr, c_void_p) else ptr
    if not raw_ptr:
        raise ValueError("Null COM interface pointer")
    vtbl_ptr = cast(raw_ptr, POINTER(c_void_p))[0]
    if not vtbl_ptr:
        raise ValueError("Null COM vtable pointer")
    fn_addr = cast(vtbl_ptr, POINTER(c_void_p))[slot]
    if not fn_addr:
        raise ValueError(f"Null COM vtable slot {slot}")
    func = _winfunctype(restype, c_void_p, *argtypes)(fn_addr)
    return func(raw_ptr, *args)


def _com_release(ptr: c_void_p | int | None) -> None:
    """Release a COM interface pointer safely."""
    if not ptr:
        return
    raw_ptr = ptr.value if isinstance(ptr, c_void_p) else ptr
    if not raw_ptr:
        return
    try:
        _com_call(raw_ptr, _VTBL_RELEASE, c_uint32, ())
    except Exception:
        log.debug("Failed to release COM pointer", exc_info=True)


def _bstr_to_str(bstr_ptr: c_void_p, oleaut32) -> str:
    """Convert a Win32 BSTR to a Python str and always free it with SysFreeString."""
    raw = bstr_ptr.value if isinstance(bstr_ptr, c_void_p) else bstr_ptr
    if not raw:
        return ""
    try:
        length = oleaut32.SysStringLen(c_void_p(raw))
        if isinstance(length, int) and length > 0:
            return wstring_at(raw, length)
        return ""
    finally:
        try:
            oleaut32.SysFreeString(c_void_p(raw))
        except Exception:
            log.debug("Failed to free BSTR", exc_info=True)


def _load_com_dlls():
    """Lazily load ole32 and oleaut32 and configure WinAPI prototypes."""
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return None, None
    ole32 = windll.ole32
    oleaut32 = windll.oleaut32

    ole32.CoInitializeEx.argtypes = [c_void_p, c_uint32]
    ole32.CoInitializeEx.restype = c_int32
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    ole32.CoCreateInstance.argtypes = [
        POINTER(GUID),
        c_void_p,
        c_uint32,
        POINTER(GUID),
        POINTER(c_void_p),
    ]
    ole32.CoCreateInstance.restype = c_int32

    oleaut32.SysStringLen.argtypes = [c_void_p]
    oleaut32.SysStringLen.restype = c_uint32
    oleaut32.SysFreeString.argtypes = [c_void_p]
    oleaut32.SysFreeString.restype = None

    return ole32, oleaut32


class UIAClient:
    """Thread-affine MTA Microsoft UI Automation client.

    Call ``initialize()`` and ``close()`` on the same worker thread that invokes
    ``interact_with_hwnd()`` (for example, inside ``Human.run()``).
    """

    def __init__(
        self,
        connection_timeout_ms: int = DEFAULT_CONNECTION_TIMEOUT_MS,
        transaction_timeout_ms: int = DEFAULT_TRANSACTION_TIMEOUT_MS,
        max_elements: int = MAX_UIA_ELEMENTS,
        window_budget_s: float = DEFAULT_WINDOW_BUDGET_S,
        timeout_backoff_s: float = DEFAULT_TIMEOUT_BACKOFF_S,
        action_cooldown_s: float = DEFAULT_ACTION_COOLDOWN_S,
        unverified_toggle_cooldown_s: float = DEFAULT_UNVERIFIED_TOGGLE_COOLDOWN_S,
    ):
        self.connection_timeout_ms = connection_timeout_ms
        self.transaction_timeout_ms = transaction_timeout_ms
        self.max_elements = max_elements
        self.window_budget_s = window_budget_s
        self.timeout_backoff_s = timeout_backoff_s
        self.action_cooldown_s = action_cooldown_s
        self.unverified_toggle_cooldown_s = unverified_toggle_cooldown_s
        self._ole32 = None
        self._oleaut32 = None
        self._com_initialized = False
        self._uia: c_void_p | None = None
        self._condition: c_void_p | None = None
        self._condition_no_hyperlinks: c_void_p | None = None
        self._cache_request: c_void_p | None = None
        self._hwnd_backoff_until: dict[int, float] = {}
        self._action_cooldown_until: dict[tuple[int, int, str], float] = {}

    @property
    def available(self) -> bool:
        return bool(self._uia and self._uia.value and self._condition and self._condition.value)

    def initialize(self) -> bool:
        """Initialize COM (MTA), instantiate IUIAutomation2/IUIAutomation, and build conditions/cache."""
        if self.available:
            return True

        try:
            ole32, oleaut32 = _load_com_dlls()
        except Exception as err:
            log.debug("COM DLLs unavailable for UI Automation: %s", err)
            return False

        if ole32 is None or oleaut32 is None:
            return False

        self._ole32 = ole32
        self._oleaut32 = oleaut32

        try:
            hr = ole32.CoInitializeEx(None, COINIT_MULTITHREADED)
        except Exception as err:
            log.debug("CoInitializeEx failed: %s", err)
            return False

        if not isinstance(hr, int):
            return False

        if hr >= 0:
            self._com_initialized = True
        elif hr != RPC_E_CHANGED_MODE:
            log.debug("CoInitializeEx returned HRESULT 0x%08x", hr & 0xFFFFFFFF)
            return False

        uia_ptr = c_void_p()
        is_uia2 = False
        try:
            hr = ole32.CoCreateInstance(
                byref(CLSID_CUIAutomation8),
                None,
                CLSCTX_INPROC_SERVER,
                byref(IID_IUIAutomation2),
                byref(uia_ptr),
            )
            if isinstance(hr, int) and hr >= 0 and uia_ptr.value:
                is_uia2 = True
            else:
                uia_ptr = c_void_p()
                hr = ole32.CoCreateInstance(
                    byref(CLSID_CUIAutomation),
                    None,
                    CLSCTX_INPROC_SERVER,
                    byref(IID_IUIAutomation),
                    byref(uia_ptr),
                )
        except Exception as err:
            log.debug("CoCreateInstance for UI Automation failed: %s", err)
            self.close()
            return False

        if not isinstance(hr, int) or hr < 0 or not uia_ptr.value:
            log.debug("UI Automation unavailable (CoCreateInstance HRESULT=%r)", hr)
            self.close()
            return False

        self._uia = uia_ptr

        if is_uia2:
            try:
                _com_call(
                    self._uia,
                    _VTBL_UIA2_PUT_CONNECTION_TIMEOUT,
                    c_int32,
                    (c_uint32,),
                    self.connection_timeout_ms,
                )
                _com_call(
                    self._uia,
                    _VTBL_UIA2_PUT_TRANSACTION_TIMEOUT,
                    c_int32,
                    (c_uint32,),
                    self.transaction_timeout_ms,
                )
            except Exception as err:
                log.debug("Failed to configure IUIAutomation2 timeouts: %s", err)

        cond_all, cond_buttons = self._build_interactive_conditions()
        if not cond_all or not cond_all.value:
            _com_release(cond_buttons)
            self.close()
            return False

        self._condition = cond_all
        self._condition_no_hyperlinks = cond_buttons
        self._cache_request = self._build_cache_request()
        log.debug(
            "Initialized native Windows UI Automation client (UIA2=%s, cached=%s)",
            is_uia2,
            bool(self._cache_request and self._cache_request.value),
        )
        return True

    def _create_property_condition(self, property_id: int, value: VARIANT) -> c_void_p | None:
        cond_ptr = c_void_p()
        hr = _com_call(
            self._uia,
            _VTBL_UIA_CREATE_PROPERTY_CONDITION,
            c_int32,
            (c_int32, VARIANT, POINTER(c_void_p)),
            property_id,
            value,
            byref(cond_ptr),
        )
        if hr < 0 or not cond_ptr.value:
            return None
        return cond_ptr

    def _create_or_condition(self, conditions: list[c_void_p]) -> c_void_p | None:
        cond_array = (c_void_p * len(conditions))(*(c.value for c in conditions))
        combined = c_void_p()
        hr = _com_call(
            self._uia,
            _VTBL_UIA_CREATE_OR_CONDITION_FROM_NATIVE_ARRAY,
            c_int32,
            (POINTER(c_void_p), c_int32, POINTER(c_void_p)),
            cond_array,
            len(conditions),
            byref(combined),
        )
        if hr < 0 or not combined.value:
            return None
        return combined

    def _create_and_condition(self, conditions: list[c_void_p]) -> c_void_p | None:
        cond_array = (c_void_p * len(conditions))(*(c.value for c in conditions))
        combined = c_void_p()
        hr = _com_call(
            self._uia,
            _VTBL_UIA_CREATE_AND_CONDITION_FROM_NATIVE_ARRAY,
            c_int32,
            (POINTER(c_void_p), c_int32, POINTER(c_void_p)),
            cond_array,
            len(conditions),
            byref(combined),
        )
        if hr < 0 or not combined.value:
            return None
        return combined

    def _create_not_condition(self, condition: c_void_p) -> c_void_p | None:
        negated = c_void_p()
        hr = _com_call(
            self._uia,
            _VTBL_UIA_CREATE_NOT_CONDITION,
            c_int32,
            (c_void_p, POINTER(c_void_p)),
            condition,
            byref(negated),
        )
        if hr < 0 or not negated.value:
            return None
        return negated

    def _build_interactive_conditions(self) -> tuple[c_void_p | None, c_void_p | None]:
        """Build server-side UIA conditions filtering enabled, on-screen interactive controls."""
        if not self._uia or not self._uia.value:
            return None, None

        temps: list[c_void_p] = []
        cond_all: c_void_p | None = None
        cond_buttons: c_void_p | None = None
        try:
            button_type_conds: list[c_void_p] = []
            for ctrl_type in BUTTON_CONTROL_TYPES:
                cond_ptr = self._create_property_condition(UIA_ControlTypePropertyId, VARIANT.from_i4(ctrl_type))
                if cond_ptr is None:
                    return None, None
                temps.append(cond_ptr)
                button_type_conds.append(cond_ptr)

            link_cond = self._create_property_condition(UIA_ControlTypePropertyId, VARIANT.from_i4(UIA_HyperlinkControlTypeId))
            if link_cond is None:
                return None, None
            temps.append(link_cond)

            all_types_or = self._create_or_condition(button_type_conds + [link_cond])
            if all_types_or is None:
                return None, None
            temps.append(all_types_or)

            buttons_or = self._create_or_condition(button_type_conds)
            if buttons_or is None:
                return None, None
            temps.append(buttons_or)

            # Filter IsEnabled=True and NOT(IsOffscreen=True) server-side so hidden/disabled
            # chrome controls never consume MAX_UIA_ELEMENTS before reaching visible prompts.
            # Using NOT(IsOffscreen=True) preserves elements whose providers return NotSupported.
            enabled_cond = self._create_property_condition(UIA_IsEnabledPropertyId, VARIANT.from_bool(True))
            offscreen_cond = self._create_property_condition(UIA_IsOffscreenPropertyId, VARIANT.from_bool(True))
            not_offscreen_cond = None
            if enabled_cond is not None:
                temps.append(enabled_cond)
            if offscreen_cond is not None:
                temps.append(offscreen_cond)
                not_offscreen_cond = self._create_not_condition(offscreen_cond)
                if not_offscreen_cond is not None:
                    temps.append(not_offscreen_cond)

            if enabled_cond is not None and not_offscreen_cond is not None:
                cond_all = self._create_and_condition([all_types_or, enabled_cond, not_offscreen_cond])
                cond_buttons = self._create_and_condition([buttons_or, enabled_cond, not_offscreen_cond])

            # Fall back to the type-OR conditions if And/Not condition creation is unavailable.
            if cond_all is None:
                cond_all = all_types_or
                temps.remove(all_types_or)
            if cond_buttons is None:
                cond_buttons = buttons_or
                temps.remove(buttons_or)

            return cond_all, cond_buttons
        except Exception as err:
            log.debug("Failed to create UIA control-type conditions: %s", err)
            _com_release(cond_all)
            _com_release(cond_buttons)
            return None, None
        finally:
            for cond_ptr in temps:
                _com_release(cond_ptr)

    def _build_cache_request(self) -> c_void_p | None:
        """Build an IUIAutomationCacheRequest to prefetch element metadata in one RPC."""
        if not self._uia or not self._uia.value:
            return None

        cache_req = c_void_p()
        try:
            hr = _com_call(
                self._uia,
                _VTBL_UIA_CREATE_CACHE_REQUEST,
                c_int32,
                (POINTER(c_void_p),),
                byref(cache_req),
            )
            if hr < 0 or not cache_req.value:
                return None

            for prop_id in _CACHED_PROPERTY_IDS:
                hr = _com_call(cache_req, _VTBL_CACHE_ADD_PROPERTY, c_int32, (c_int32,), prop_id)
                if hr < 0:
                    _com_release(cache_req)
                    return None
            return cache_req
        except Exception as err:
            log.debug("Failed to build UIA cache request: %s", err)
            _com_release(cache_req)
            return None

    def close(self) -> None:
        """Release all UIA COM interfaces and uninitialize COM on this thread."""
        if self._cache_request is not None:
            _com_release(self._cache_request)
            self._cache_request = None
        if self._condition_no_hyperlinks is not None:
            _com_release(self._condition_no_hyperlinks)
            self._condition_no_hyperlinks = None
        if self._condition is not None:
            _com_release(self._condition)
            self._condition = None
        if self._uia is not None:
            _com_release(self._uia)
            self._uia = None
        self._hwnd_backoff_until.clear()
        self._action_cooldown_until.clear()
        if self._com_initialized and self._ole32 is not None:
            try:
                self._ole32.CoUninitialize()
            except Exception:
                log.debug("CoUninitialize failed", exc_info=True)
            self._com_initialized = False

    def _prune_expired(self, mapping: dict, now: float) -> None:
        if len(mapping) <= _MAX_TRACKED_STATE_ENTRIES:
            return
        expired = [k for k, until in mapping.items() if now >= until]
        for k in expired:
            mapping.pop(k, None)

    def _record_hwnd_timeout(self, hwnd: int, now: float) -> None:
        if self.timeout_backoff_s <= 0:
            return
        self._prune_expired(self._hwnd_backoff_until, now)
        self._hwnd_backoff_until[hwnd] = now + self.timeout_backoff_s

    def _is_action_cooled_down(self, hwnd: int, ctrl_type: int, name: str, now: float) -> bool:
        key = (hwnd, ctrl_type, name.strip().lower())
        return now < self._action_cooldown_until.get(key, 0.0)

    def _record_action_cooldown(self, hwnd: int, ctrl_type: int, name: str, cooldown_s: float, now: float) -> None:
        if cooldown_s <= 0:
            return
        self._prune_expired(self._action_cooldown_until, now)
        key = (hwnd, ctrl_type, name.strip().lower())
        self._action_cooldown_until[key] = now + cooldown_s

    def interact_with_hwnd(
        self,
        hwnd: int,
        match_fn: Callable[[str], bool],
        click_point_fn: Callable[[int, int], None] | None = None,
        *,
        include_hyperlinks: bool = True,
    ) -> bool:
        """Inspect UIA descendants of ``hwnd`` and trigger the first matching interactive control.

        Returns ``True`` if a control was invoked, toggled, selected, or clicked.
        """
        if not self.available or not hwnd:
            return False

        now = time.monotonic()
        if now < self._hwnd_backoff_until.get(hwnd, 0.0):
            return False

        condition = self._condition if include_hyperlinks or not self._condition_no_hyperlinks else self._condition_no_hyperlinks
        deadline = now + self.window_budget_s if self.window_budget_s > 0 else float("inf")
        use_cache = bool(self._cache_request and self._cache_request.value)

        root_elem = c_void_p()
        elem_array = c_void_p()
        try:
            hr = _com_call(
                self._uia,
                _VTBL_UIA_ELEMENT_FROM_HANDLE,
                c_int32,
                (c_void_p, POINTER(c_void_p)),
                c_void_p(hwnd),
                byref(root_elem),
            )
            if hr in _TIMEOUT_HRESULTS:
                self._record_hwnd_timeout(hwnd, time.monotonic())
                return False
            if hr < 0 or not root_elem.value:
                return False

            if use_cache:
                hr = _com_call(
                    root_elem,
                    _VTBL_ELEM_FIND_ALL_BUILD_CACHE,
                    c_int32,
                    (c_int32, c_void_p, c_void_p, POINTER(c_void_p)),
                    TreeScope_Descendants,
                    condition,
                    self._cache_request,
                    byref(elem_array),
                )
            else:
                hr = _com_call(
                    root_elem,
                    _VTBL_ELEM_FIND_ALL,
                    c_int32,
                    (c_int32, c_void_p, POINTER(c_void_p)),
                    TreeScope_Descendants,
                    condition,
                    byref(elem_array),
                )
            if hr in _TIMEOUT_HRESULTS:
                self._record_hwnd_timeout(hwnd, time.monotonic())
                return False
            if hr < 0 or not elem_array.value:
                return False

            length = c_int32(0)
            hr = _com_call(elem_array, _VTBL_ARRAY_GET_LENGTH, c_int32, (POINTER(c_int32),), byref(length))
            if hr < 0 or length.value <= 0:
                return False

            count = min(length.value, self.max_elements)
            for idx in range(count):
                loop_now = time.monotonic()
                if loop_now >= deadline:
                    self._record_hwnd_timeout(hwnd, loop_now)
                    break

                elem = c_void_p()
                try:
                    hr = _com_call(
                        elem_array,
                        _VTBL_ARRAY_GET_ELEMENT,
                        c_int32,
                        (c_int32, POINTER(c_void_p)),
                        idx,
                        byref(elem),
                    )
                    if hr in _TIMEOUT_HRESULTS:
                        self._record_hwnd_timeout(hwnd, time.monotonic())
                        break
                    if hr < 0 or not elem.value:
                        continue
                    acted, timed_out = self._try_interact_element(
                        hwnd,
                        elem,
                        match_fn,
                        click_point_fn,
                        cached=use_cache,
                        now=loop_now,
                    )
                    if timed_out:
                        self._record_hwnd_timeout(hwnd, time.monotonic())
                        break
                    if acted:
                        return True
                finally:
                    _com_release(elem)
        except Exception as err:
            log.debug("UIA traversal failed for hwnd %s: %s", hwnd, err)
        finally:
            _com_release(elem_array)
            _com_release(root_elem)
        return False

    def _try_interact_element(
        self,
        hwnd: int,
        elem: c_void_p,
        match_fn: Callable[[str], bool],
        click_point_fn: Callable[[int, int], None] | None,
        *,
        cached: bool,
        now: float,
    ) -> tuple[bool, bool]:
        """Return ``(acted, timed_out)`` for a single UIA descendant element."""
        slot_enabled = _VTBL_ELEM_GET_CACHED_IS_ENABLED if cached else _VTBL_ELEM_GET_CURRENT_IS_ENABLED
        slot_offscreen = _VTBL_ELEM_GET_CACHED_IS_OFFSCREEN if cached else _VTBL_ELEM_GET_CURRENT_IS_OFFSCREEN
        slot_name = _VTBL_ELEM_GET_CACHED_NAME if cached else _VTBL_ELEM_GET_CURRENT_NAME
        slot_ctrl_type = _VTBL_ELEM_GET_CACHED_CONTROL_TYPE if cached else _VTBL_ELEM_GET_CURRENT_CONTROL_TYPE

        is_enabled = c_int32(0)
        hr = _com_call(elem, slot_enabled, c_int32, (POINTER(c_int32),), byref(is_enabled))
        if hr in _TIMEOUT_HRESULTS:
            return False, True
        if hr < 0 or not is_enabled.value:
            return False, False

        is_offscreen = c_int32(0)
        hr = _com_call(elem, slot_offscreen, c_int32, (POINTER(c_int32),), byref(is_offscreen))
        if hr in _TIMEOUT_HRESULTS:
            return False, True
        if hr >= 0 and is_offscreen.value:
            return False, False

        bstr_name = c_void_p()
        hr = _com_call(elem, slot_name, c_int32, (POINTER(c_void_p),), byref(bstr_name))
        if hr in _TIMEOUT_HRESULTS:
            return False, True
        if hr < 0:
            return False, False
        name = _bstr_to_str(bstr_name, self._oleaut32)
        if not name or not match_fn(name):
            return False, False

        ctrl_type = c_int32(0)
        hr = _com_call(elem, slot_ctrl_type, c_int32, (POINTER(c_int32),), byref(ctrl_type))
        if hr in _TIMEOUT_HRESULTS:
            return False, True
        if hr < 0:
            return False, False

        if self._is_action_cooled_down(hwnd, ctrl_type.value, name, now):
            return False, False

        is_toggle_control = ctrl_type.value in (UIA_CheckBoxControlTypeId, UIA_RadioButtonControlTypeId)

        if ctrl_type.value == UIA_CheckBoxControlTypeId:
            handled, acted, timed_out = self._try_toggle(elem, name)
            if timed_out:
                return False, True
            if handled:
                if acted:
                    self._record_action_cooldown(hwnd, ctrl_type.value, name, self.action_cooldown_s, time.monotonic())
                return acted, False
        elif ctrl_type.value == UIA_RadioButtonControlTypeId:
            handled, acted, timed_out = self._try_select(elem, name)
            if timed_out:
                return False, True
            if handled:
                if acted:
                    self._record_action_cooldown(hwnd, ctrl_type.value, name, self.action_cooldown_s, time.monotonic())
                return acted, False

        invoked, timed_out = self._try_invoke(elem, name)
        if timed_out:
            return False, True
        if invoked:
            cooldown = self.unverified_toggle_cooldown_s if is_toggle_control else self.action_cooldown_s
            self._record_action_cooldown(hwnd, ctrl_type.value, name, cooldown, time.monotonic())
            return True, False

        if click_point_fn is not None:
            point, timed_out = self._get_clickable_coordinates(elem, cached=cached)
            if timed_out:
                return False, True
            if point is not None:
                log.info('Clicking UIA element "%s" at (%d, %d)', name, point[0], point[1])
                click_point_fn(point[0], point[1])
                cooldown = self.unverified_toggle_cooldown_s if is_toggle_control else self.action_cooldown_s
                self._record_action_cooldown(hwnd, ctrl_type.value, name, cooldown, time.monotonic())
                return True, False

        return False, False

    def _try_toggle(self, elem: c_void_p, name: str) -> tuple[bool, bool, bool]:
        """Return ``(pattern_supported, toggled, timed_out)`` for a CheckBox element."""
        pattern = c_void_p()
        try:
            hr = _com_call(
                elem,
                _VTBL_ELEM_GET_CURRENT_PATTERN_AS,
                c_int32,
                (c_int32, POINTER(GUID), POINTER(c_void_p)),
                UIA_TogglePatternId,
                byref(IID_IUIAutomationTogglePattern),
                byref(pattern),
            )
            if hr in _TIMEOUT_HRESULTS:
                return True, False, True
            if hr < 0 or not pattern.value:
                return False, False, False

            state = c_int32(ToggleState_Off)
            hr = _com_call(pattern, _VTBL_TOGGLE_GET_CURRENT_STATE, c_int32, (POINTER(c_int32),), byref(state))
            if hr in _TIMEOUT_HRESULTS:
                return True, False, True
            if hr < 0 or state.value == ToggleState_On:
                return True, False, False

            log.info('Toggling UIA checkbox "%s"', name)
            hr = _com_call(pattern, _VTBL_TOGGLE_TOGGLE, c_int32, ())
            if hr in _TIMEOUT_HRESULTS:
                return True, False, True
            return True, hr >= 0, False
        finally:
            _com_release(pattern)

    def _try_select(self, elem: c_void_p, name: str) -> tuple[bool, bool, bool]:
        """Return ``(pattern_supported, selected, timed_out)`` for a RadioButton element."""
        pattern = c_void_p()
        try:
            hr = _com_call(
                elem,
                _VTBL_ELEM_GET_CURRENT_PATTERN_AS,
                c_int32,
                (c_int32, POINTER(GUID), POINTER(c_void_p)),
                UIA_SelectionItemPatternId,
                byref(IID_IUIAutomationSelectionItemPattern),
                byref(pattern),
            )
            if hr in _TIMEOUT_HRESULTS:
                return True, False, True
            if hr < 0 or not pattern.value:
                return False, False, False

            selected = c_int32(0)
            hr = _com_call(pattern, _VTBL_SELECT_GET_CURRENT_IS_SELECTED, c_int32, (POINTER(c_int32),), byref(selected))
            if hr in _TIMEOUT_HRESULTS:
                return True, False, True
            if hr < 0 or selected.value:
                return True, False, False

            log.info('Selecting UIA radio button "%s"', name)
            hr = _com_call(pattern, _VTBL_SELECT_SELECT, c_int32, ())
            if hr in _TIMEOUT_HRESULTS:
                return True, False, True
            return True, hr >= 0, False
        finally:
            _com_release(pattern)

    def _try_invoke(self, elem: c_void_p, name: str) -> tuple[bool, bool]:
        """Return ``(invoked, timed_out)`` via IUIAutomationInvokePattern."""
        pattern = c_void_p()
        try:
            hr = _com_call(
                elem,
                _VTBL_ELEM_GET_CURRENT_PATTERN_AS,
                c_int32,
                (c_int32, POINTER(GUID), POINTER(c_void_p)),
                UIA_InvokePatternId,
                byref(IID_IUIAutomationInvokePattern),
                byref(pattern),
            )
            if hr in _TIMEOUT_HRESULTS:
                return False, True
            if hr < 0 or not pattern.value:
                return False, False

            log.info('Invoking UIA control "%s"', name)
            hr = _com_call(pattern, _VTBL_INVOKE_INVOKE, c_int32, ())
            if hr in _TIMEOUT_HRESULTS:
                return False, True
            return hr >= 0, False
        finally:
            _com_release(pattern)

    def _get_clickable_coordinates(self, elem: c_void_p, *, cached: bool) -> tuple[tuple[int, int] | None, bool]:
        """Return ``((x, y) | None, timed_out)`` via GetClickablePoint or BoundingRectangle."""
        pt = UIA_POINT()
        got_clickable = c_int32(0)
        hr = _com_call(
            elem,
            _VTBL_ELEM_GET_CLICKABLE_POINT,
            c_int32,
            (POINTER(UIA_POINT), POINTER(c_int32)),
            byref(pt),
            byref(got_clickable),
        )
        if hr in _TIMEOUT_HRESULTS:
            return None, True
        if hr >= 0 and got_clickable.value and pt.x >= 0 and pt.y >= 0:
            return (pt.x, pt.y), False

        rect = UIA_RECT()
        slot_rect = _VTBL_ELEM_GET_CACHED_BOUNDING_RECTANGLE if cached else _VTBL_ELEM_GET_CURRENT_BOUNDING_RECTANGLE
        hr = _com_call(elem, slot_rect, c_int32, (POINTER(UIA_RECT),), byref(rect))
        if hr in _TIMEOUT_HRESULTS:
            return None, True
        if hr >= 0 and rect.right > rect.left and rect.bottom > rect.top:
            center_x = (rect.left + rect.right) // 2
            center_y = (rect.top + rect.bottom) // 2
            if center_x >= 0 and center_y >= 0:
                return (center_x, center_y), False
        return None, False
