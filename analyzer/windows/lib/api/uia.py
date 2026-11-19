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
from collections.abc import Callable
from ctypes import POINTER, Structure, Union, byref, c_int32, c_int64, c_ubyte, c_uint16, c_uint32, c_void_p, cast, wstring_at

log = logging.getLogger(__name__)

# COM initialization and activation constants
COINIT_MULTITHREADED = 0x0
CLSCTX_INPROC_SERVER = 0x1
RPC_E_CHANGED_MODE = -2147417850  # 0x80010106 as signed 32-bit HRESULT

# VARIANT type
VT_I4 = 3

# UIA TreeScope
TreeScope_Descendants = 0x4

# UIA Property / ControlType / Pattern IDs (UIAutomationClient.h)
UIA_ControlTypePropertyId = 30003
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

# Default UIA2 timeouts (milliseconds) to prevent hung target windows from blocking Human
DEFAULT_CONNECTION_TIMEOUT_MS = 500
DEFAULT_TRANSACTION_TIMEOUT_MS = 1000
MAX_UIA_ELEMENTS = 128

# COM vtable slot indices (verified against Windows SDK UIAutomationClient.h)
_VTBL_RELEASE = 2

# IUIAutomation / IUIAutomation2
_VTBL_UIA_ELEMENT_FROM_HANDLE = 6
_VTBL_UIA_CREATE_PROPERTY_CONDITION = 23
_VTBL_UIA_CREATE_OR_CONDITION_FROM_NATIVE_ARRAY = 30
_VTBL_UIA2_PUT_CONNECTION_TIMEOUT = 61
_VTBL_UIA2_PUT_TRANSACTION_TIMEOUT = 63

# IUIAutomationElement
_VTBL_ELEM_FIND_ALL = 6
_VTBL_ELEM_GET_CURRENT_PATTERN_AS = 14
_VTBL_ELEM_GET_CURRENT_CONTROL_TYPE = 21
_VTBL_ELEM_GET_CURRENT_NAME = 23
_VTBL_ELEM_GET_CURRENT_IS_ENABLED = 28
_VTBL_ELEM_GET_CURRENT_IS_OFFSCREEN = 38
_VTBL_ELEM_GET_CURRENT_BOUNDING_RECTANGLE = 43
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


class _BRECORD(Structure):
    _fields_ = [
        ("pvRecord", c_void_p),
        ("pRecInfo", c_void_p),
    ]


class _VARIANT_DATA(Union):
    _fields_ = [
        ("llVal", c_int64),
        ("lVal", c_int32),
        ("brecord", _BRECORD),
    ]


class VARIANT(Structure):
    """Windows OLE VARIANT (16 bytes on x86, 24 bytes on x64)."""

    _fields_ = [
        ("vt", c_uint16),
        ("wReserved1", c_uint16),
        ("wReserved2", c_uint16),
        ("wReserved3", c_uint16),
        ("data", _VARIANT_DATA),
    ]

    @classmethod
    def from_i4(cls, value: int) -> VARIANT:
        var = cls()
        var.vt = VT_I4
        var.data.lVal = value
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

INTERACTIVE_CONTROL_TYPES = (
    UIA_ButtonControlTypeId,
    UIA_CheckBoxControlTypeId,
    UIA_RadioButtonControlTypeId,
    UIA_HyperlinkControlTypeId,
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
    ):
        self.connection_timeout_ms = connection_timeout_ms
        self.transaction_timeout_ms = transaction_timeout_ms
        self.max_elements = max_elements
        self._ole32 = None
        self._oleaut32 = None
        self._com_initialized = False
        self._uia: c_void_p | None = None
        self._condition: c_void_p | None = None

    @property
    def available(self) -> bool:
        return bool(self._uia and self._uia.value and self._condition and self._condition.value)

    def initialize(self) -> bool:
        """Initialize COM (MTA), instantiate IUIAutomation2/IUIAutomation, and build the search condition."""
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

        cond = self._build_interactive_condition()
        if not cond or not cond.value:
            self.close()
            return False

        self._condition = cond
        log.debug("Initialized native Windows UI Automation client (UIA2=%s)", is_uia2)
        return True

    def _build_interactive_condition(self) -> c_void_p | None:
        """Build an OR condition matching interactive UIA control types."""
        if not self._uia or not self._uia.value:
            return None

        sub_conditions: list[c_void_p] = []
        try:
            for ctrl_type in INTERACTIVE_CONTROL_TYPES:
                cond_ptr = c_void_p()
                hr = _com_call(
                    self._uia,
                    _VTBL_UIA_CREATE_PROPERTY_CONDITION,
                    c_int32,
                    (c_int32, VARIANT, POINTER(c_void_p)),
                    UIA_ControlTypePropertyId,
                    VARIANT.from_i4(ctrl_type),
                    byref(cond_ptr),
                )
                if hr < 0 or not cond_ptr.value:
                    return None
                sub_conditions.append(cond_ptr)

            cond_array = (c_void_p * len(sub_conditions))(*(c.value for c in sub_conditions))
            combined = c_void_p()
            hr = _com_call(
                self._uia,
                _VTBL_UIA_CREATE_OR_CONDITION_FROM_NATIVE_ARRAY,
                c_int32,
                (POINTER(c_void_p), c_int32, POINTER(c_void_p)),
                cond_array,
                len(sub_conditions),
                byref(combined),
            )
            if hr < 0 or not combined.value:
                return None
            return combined
        except Exception as err:
            log.debug("Failed to create UIA control-type condition: %s", err)
            return None
        finally:
            for cond_ptr in sub_conditions:
                _com_release(cond_ptr)

    def close(self) -> None:
        """Release all UIA COM interfaces and uninitialize COM on this thread."""
        if self._condition is not None:
            _com_release(self._condition)
            self._condition = None
        if self._uia is not None:
            _com_release(self._uia)
            self._uia = None
        if self._com_initialized and self._ole32 is not None:
            try:
                self._ole32.CoUninitialize()
            except Exception:
                log.debug("CoUninitialize failed", exc_info=True)
            self._com_initialized = False

    def interact_with_hwnd(
        self,
        hwnd: int,
        match_fn: Callable[[str], bool],
        click_point_fn: Callable[[int, int], None] | None = None,
    ) -> bool:
        """Inspect UIA descendants of ``hwnd`` and trigger the first matching interactive control.

        Returns ``True`` if a control was invoked, toggled, selected, or clicked.
        """
        if not self.available or not hwnd:
            return False

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
            if hr < 0 or not root_elem.value:
                return False

            hr = _com_call(
                root_elem,
                _VTBL_ELEM_FIND_ALL,
                c_int32,
                (c_int32, c_void_p, POINTER(c_void_p)),
                TreeScope_Descendants,
                self._condition,
                byref(elem_array),
            )
            if hr < 0 or not elem_array.value:
                return False

            length = c_int32(0)
            hr = _com_call(elem_array, _VTBL_ARRAY_GET_LENGTH, c_int32, (POINTER(c_int32),), byref(length))
            if hr < 0 or length.value <= 0:
                return False

            count = min(length.value, self.max_elements)
            for idx in range(count):
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
                    if hr < 0 or not elem.value:
                        continue
                    if self._try_interact_element(elem, match_fn, click_point_fn):
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
        elem: c_void_p,
        match_fn: Callable[[str], bool],
        click_point_fn: Callable[[int, int], None] | None,
    ) -> bool:
        is_enabled = c_int32(0)
        hr = _com_call(elem, _VTBL_ELEM_GET_CURRENT_IS_ENABLED, c_int32, (POINTER(c_int32),), byref(is_enabled))
        if hr < 0 or not is_enabled.value:
            return False

        is_offscreen = c_int32(0)
        hr = _com_call(elem, _VTBL_ELEM_GET_CURRENT_IS_OFFSCREEN, c_int32, (POINTER(c_int32),), byref(is_offscreen))
        if hr >= 0 and is_offscreen.value:
            return False

        bstr_name = c_void_p()
        hr = _com_call(elem, _VTBL_ELEM_GET_CURRENT_NAME, c_int32, (POINTER(c_void_p),), byref(bstr_name))
        if hr < 0:
            return False
        name = _bstr_to_str(bstr_name, self._oleaut32)
        if not name or not match_fn(name):
            return False

        ctrl_type = c_int32(0)
        hr = _com_call(elem, _VTBL_ELEM_GET_CURRENT_CONTROL_TYPE, c_int32, (POINTER(c_int32),), byref(ctrl_type))
        if hr < 0:
            return False

        if ctrl_type.value == UIA_CheckBoxControlTypeId:
            handled, acted = self._try_toggle(elem, name)
            if handled:
                return acted
        elif ctrl_type.value == UIA_RadioButtonControlTypeId:
            handled, acted = self._try_select(elem, name)
            if handled:
                return acted

        if self._try_invoke(elem, name):
            return True

        if click_point_fn is not None:
            point = self._get_clickable_coordinates(elem)
            if point is not None:
                log.info('Clicking UIA element "%s" at (%d, %d)', name, point[0], point[1])
                click_point_fn(point[0], point[1])
                return True

        return False

    def _try_toggle(self, elem: c_void_p, name: str) -> tuple[bool, bool]:
        """Return ``(pattern_supported, toggled)`` for a CheckBox element."""
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
            if hr < 0 or not pattern.value:
                return False, False

            state = c_int32(ToggleState_Off)
            hr = _com_call(pattern, _VTBL_TOGGLE_GET_CURRENT_STATE, c_int32, (POINTER(c_int32),), byref(state))
            if hr >= 0 and state.value == ToggleState_On:
                return True, False

            log.info('Toggling UIA checkbox "%s"', name)
            hr = _com_call(pattern, _VTBL_TOGGLE_TOGGLE, c_int32, ())
            return True, hr >= 0
        finally:
            _com_release(pattern)

    def _try_select(self, elem: c_void_p, name: str) -> tuple[bool, bool]:
        """Return ``(pattern_supported, selected)`` for a RadioButton element."""
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
            if hr < 0 or not pattern.value:
                return False, False

            selected = c_int32(0)
            hr = _com_call(pattern, _VTBL_SELECT_GET_CURRENT_IS_SELECTED, c_int32, (POINTER(c_int32),), byref(selected))
            if hr >= 0 and selected.value:
                return True, False

            log.info('Selecting UIA radio button "%s"', name)
            hr = _com_call(pattern, _VTBL_SELECT_SELECT, c_int32, ())
            return True, hr >= 0
        finally:
            _com_release(pattern)

    def _try_invoke(self, elem: c_void_p, name: str) -> bool:
        """Invoke a Button or Hyperlink via IUIAutomationInvokePattern."""
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
            if hr < 0 or not pattern.value:
                return False

            log.info('Invoking UIA control "%s"', name)
            hr = _com_call(pattern, _VTBL_INVOKE_INVOKE, c_int32, ())
            return hr >= 0
        finally:
            _com_release(pattern)

    def _get_clickable_coordinates(self, elem: c_void_p) -> tuple[int, int] | None:
        """Return screen ``(x, y)`` for a UIA element via GetClickablePoint or BoundingRectangle."""
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
        if hr >= 0 and got_clickable.value and pt.x >= 0 and pt.y >= 0:
            return pt.x, pt.y

        rect = UIA_RECT()
        hr = _com_call(elem, _VTBL_ELEM_GET_CURRENT_BOUNDING_RECTANGLE, c_int32, (POINTER(UIA_RECT),), byref(rect))
        if hr >= 0 and rect.right > rect.left and rect.bottom > rect.top:
            center_x = (rect.left + rect.right) // 2
            center_y = (rect.top + rect.bottom) // 2
            if center_x >= 0 and center_y >= 0:
                return center_x, center_y
        return None
