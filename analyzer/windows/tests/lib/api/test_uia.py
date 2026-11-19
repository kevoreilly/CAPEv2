"""Tests for pure-ctypes Microsoft UI Automation client (lib.api.uia)."""

import ctypes
import struct
import sys
import unittest
from ctypes import POINTER, c_int32, c_uint32, c_void_p, create_unicode_buffer
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()

from lib.api import uia as uia_mod

_CB = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)


class FakeCOMObject:
    """In-memory COM object backed by a real ctypes vtable array."""

    def __init__(self, num_slots: int, handlers: dict[int, tuple[object, tuple, object]]):
        self.released = 0
        self._callbacks = []
        self._vtbl = (c_void_p * num_slots)()

        def _release(_this):
            self.released += 1
            return 0

        rel_cb = _CB(c_uint32, c_void_p)(_release)
        self._callbacks.append(rel_cb)
        self._vtbl[2] = ctypes.cast(rel_cb, c_void_p).value

        for slot, (restype, argtypes, fn) in handlers.items():
            cb = _CB(restype, c_void_p, *argtypes)(fn)
            self._callbacks.append(cb)
            self._vtbl[slot] = ctypes.cast(cb, c_void_p).value

        self._this = c_void_p(ctypes.addressof(self._vtbl))

    @property
    def ptr(self) -> int:
        return ctypes.addressof(self._this)


class FakeBSTRHeap:
    """Tracks allocated fake BSTR buffers to verify SysFreeString cleanup."""

    def __init__(self):
        self._buffers: dict[int, tuple[ctypes.Array, int]] = {}
        self.freed: list[int] = []

    def alloc(self, text: str) -> int:
        buf = create_unicode_buffer(text)
        addr = ctypes.addressof(buf)
        self._buffers[addr] = (buf, len(text))
        return addr

    def sys_string_len(self, ptr) -> int:
        raw = ptr.value if isinstance(ptr, c_void_p) else ptr
        entry = self._buffers.get(raw)
        return entry[1] if entry else 0

    def sys_free_string(self, ptr) -> None:
        raw = ptr.value if isinstance(ptr, c_void_p) else ptr
        self.freed.append(raw)


def _make_invoke_pattern(on_invoke, *, invoke_hr: int = 0):
    def _invoke(_this):
        on_invoke()
        return invoke_hr

    return FakeCOMObject(4, {3: (c_int32, (), _invoke)})


def _make_toggle_pattern(state: int, on_toggle, *, state_hr: int = 0, toggle_hr: int = 0):
    def _toggle(_this):
        on_toggle()
        return toggle_hr

    def _get_state(_this, out_state):
        if state_hr < 0:
            return state_hr
        out_state[0] = state
        return 0

    return FakeCOMObject(
        5,
        {
            3: (c_int32, (), _toggle),
            4: (c_int32, (POINTER(c_int32),), _get_state),
        },
    )


def _make_selection_pattern(selected: int, on_select, *, selected_hr: int = 0, select_hr: int = 0):
    def _select(_this):
        on_select()
        return select_hr

    def _get_selected(_this, out_sel):
        if selected_hr < 0:
            return selected_hr
        out_sel[0] = selected
        return 0

    return FakeCOMObject(
        7,
        {
            3: (c_int32, (), _select),
            6: (c_int32, (POINTER(c_int32),), _get_selected),
        },
    )


def _make_element(
    bstrs: FakeBSTRHeap,
    *,
    name: str,
    ctrl_type: int,
    enabled: int = 1,
    offscreen: int = 0,
    patterns: dict[int, FakeCOMObject] | None = None,
    pattern_hr: int | None = None,
    clickable_point: tuple[int, int] | None = None,
    rect: tuple[int, int, int, int] | None = None,
    find_all_array: FakeCOMObject | None = None,
    find_all_hr: int = 0,
    call_log: list[str] | None = None,
    seen_conditions: list[int] | None = None,
):
    patterns = patterns or {}

    def _record(label: str):
        if call_log is not None:
            call_log.append(label)

    def _find_all(_this, _scope, cond, out_arr):
        _record("FindAll")
        if seen_conditions is not None:
            seen_conditions.append(cond)
        if find_all_hr < 0:
            out_arr[0] = 0
            return find_all_hr
        if find_all_array is None:
            out_arr[0] = 0
            return -2147467259  # E_FAIL
        out_arr[0] = find_all_array.ptr
        return 0

    def _find_all_build_cache(_this, _scope, cond, _cache_req, out_arr):
        _record("FindAllBuildCache")
        if seen_conditions is not None:
            seen_conditions.append(cond)
        if find_all_hr < 0:
            out_arr[0] = 0
            return find_all_hr
        if find_all_array is None:
            out_arr[0] = 0
            return -2147467259  # E_FAIL
        out_arr[0] = find_all_array.ptr
        return 0

    def _get_pattern_as(_this, pattern_id, _riid, out_pat):
        _record(f"GetCurrentPatternAs:{pattern_id}")
        if pattern_hr is not None and pattern_hr < 0:
            out_pat[0] = 0
            return pattern_hr
        pat = patterns.get(pattern_id)
        if pat is None:
            out_pat[0] = 0
            return -2147467262  # E_NOINTERFACE
        out_pat[0] = pat.ptr
        return 0

    def _get_ctrl_type(label: str):
        def _fn(_this, out_ct):
            _record(label)
            out_ct[0] = ctrl_type
            return 0

        return _fn

    def _get_name(label: str):
        def _fn(_this, out_bstr):
            _record(label)
            out_bstr[0] = bstrs.alloc(name)
            return 0

        return _fn

    def _get_enabled(label: str):
        def _fn(_this, out_en):
            _record(label)
            out_en[0] = enabled
            return 0

        return _fn

    def _get_offscreen(label: str):
        def _fn(_this, out_off):
            _record(label)
            out_off[0] = offscreen
            return 0

        return _fn

    def _get_rect(label: str):
        def _fn(_this, out_rect):
            _record(label)
            if rect is None:
                return -2147467259
            out_rect[0].left, out_rect[0].top, out_rect[0].right, out_rect[0].bottom = rect
            return 0

        return _fn

    def _get_clickable(_this, out_pt, out_got):
        _record("GetClickablePoint")
        if clickable_point is None:
            out_got[0] = 0
            return 0
        out_pt[0].x, out_pt[0].y = clickable_point
        out_got[0] = 1
        return 0

    return FakeCOMObject(
        85,
        {
            6: (c_int32, (c_int32, c_void_p, POINTER(c_void_p)), _find_all),
            8: (c_int32, (c_int32, c_void_p, c_void_p, POINTER(c_void_p)), _find_all_build_cache),
            14: (c_int32, (c_int32, POINTER(uia_mod.GUID), POINTER(c_void_p)), _get_pattern_as),
            21: (c_int32, (POINTER(c_int32),), _get_ctrl_type("get_CurrentControlType")),
            23: (c_int32, (POINTER(c_void_p),), _get_name("get_CurrentName")),
            28: (c_int32, (POINTER(c_int32),), _get_enabled("get_CurrentIsEnabled")),
            38: (c_int32, (POINTER(c_int32),), _get_offscreen("get_CurrentIsOffscreen")),
            43: (c_int32, (POINTER(uia_mod.UIA_RECT),), _get_rect("get_CurrentBoundingRectangle")),
            53: (c_int32, (POINTER(c_int32),), _get_ctrl_type("get_CachedControlType")),
            55: (c_int32, (POINTER(c_void_p),), _get_name("get_CachedName")),
            60: (c_int32, (POINTER(c_int32),), _get_enabled("get_CachedIsEnabled")),
            70: (c_int32, (POINTER(c_int32),), _get_offscreen("get_CachedIsOffscreen")),
            75: (c_int32, (POINTER(uia_mod.UIA_RECT),), _get_rect("get_CachedBoundingRectangle")),
            84: (c_int32, (POINTER(uia_mod.UIA_POINT), POINTER(c_int32)), _get_clickable),
        },
    )


def _make_element_array(elements: list[FakeCOMObject]) -> FakeCOMObject:
    def _get_len(_this, out_len):
        out_len[0] = len(elements)
        return 0

    def _get_elem(_this, idx, out_elem):
        out_elem[0] = elements[idx].ptr
        return 0

    return FakeCOMObject(
        5,
        {
            3: (c_int32, (POINTER(c_int32),), _get_len),
            4: (c_int32, (c_int32, POINTER(c_void_p)), _get_elem),
        },
    )


def _make_uia_server(root_by_hwnd: dict[int, FakeCOMObject], *, is_uia2: bool = True, enable_cache: bool = True):
    state = {
        "prop_conds": [],
        "or_counts": [],
        "and_counts": [],
        "not_count": 0,
        "cached_props": [],
        "conn_timeout": None,
        "tx_timeout": None,
        "conditions": [],
        "cache_requests": [],
        "elem_from_handle_calls": 0,
    }

    def _elem_from_handle(_this, hwnd, out_elem):
        state["elem_from_handle_calls"] += 1
        root = root_by_hwnd.get(hwnd)
        if root is None:
            out_elem[0] = 0
            return -2147467259
        out_elem[0] = root.ptr
        return 0

    def _create_cache_request(_this, out_req):
        if not enable_cache:
            out_req[0] = 0
            return -2147467263  # E_NOTIMPL

        def _add_prop(_req_this, prop_id):
            state["cached_props"].append(prop_id)
            return 0

        req = FakeCOMObject(4, {3: (c_int32, (c_int32,), _add_prop)})
        state["cache_requests"].append(req)
        out_req[0] = req.ptr
        return 0

    def _create_prop_cond(_this, prop_id, variant, out_cond):
        state["prop_conds"].append((prop_id, variant.vt, variant.lVal))
        cond = FakeCOMObject(3, {})
        state["conditions"].append(cond)
        out_cond[0] = cond.ptr
        return 0

    def _create_and_cond(_this, _conds, count, out_cond):
        state["and_counts"].append(count)
        combined = FakeCOMObject(3, {})
        state["conditions"].append(combined)
        out_cond[0] = combined.ptr
        return 0

    def _create_or_cond(_this, _conds, count, out_cond):
        state["or_counts"].append(count)
        combined = FakeCOMObject(3, {})
        state["conditions"].append(combined)
        out_cond[0] = combined.ptr
        return 0

    def _create_not_cond(_this, _cond, out_cond):
        state["not_count"] += 1
        negated = FakeCOMObject(3, {})
        state["conditions"].append(negated)
        out_cond[0] = negated.ptr
        return 0

    def _put_conn_timeout(_this, timeout):
        state["conn_timeout"] = timeout
        return 0

    def _put_tx_timeout(_this, timeout):
        state["tx_timeout"] = timeout
        return 0

    handlers = {
        6: (c_int32, (c_void_p, POINTER(c_void_p)), _elem_from_handle),
        20: (c_int32, (POINTER(c_void_p),), _create_cache_request),
        23: (c_int32, (c_int32, uia_mod.VARIANT, POINTER(c_void_p)), _create_prop_cond),
        27: (c_int32, (POINTER(c_void_p), c_int32, POINTER(c_void_p)), _create_and_cond),
        30: (c_int32, (POINTER(c_void_p), c_int32, POINTER(c_void_p)), _create_or_cond),
        31: (c_int32, (c_void_p, POINTER(c_void_p)), _create_not_cond),
    }
    slots = 58
    if is_uia2:
        slots = 64
        handlers[61] = (c_int32, (c_uint32,), _put_conn_timeout)
        handlers[63] = (c_int32, (c_uint32,), _put_tx_timeout)

    return FakeCOMObject(slots, handlers), state


class TestUIAStructABI(unittest.TestCase):
    def test_guid_and_variant_and_geometry_sizes(self):
        self.assertEqual(16, ctypes.sizeof(uia_mod.GUID))
        self.assertEqual(16, ctypes.sizeof(uia_mod.UIA_RECT))
        self.assertEqual(8, ctypes.sizeof(uia_mod.UIA_POINT))
        expected_variant_size = 24 if ctypes.sizeof(c_void_p) == 8 else 16
        self.assertEqual(expected_variant_size, ctypes.sizeof(uia_mod.VARIANT))
        self.assertEqual(8, uia_mod.VARIANT.lVal.offset)
        # Ensure VARIANT contains no ctypes.Union fields (avoids union-by-value FFI edge cases).
        for _, field_type in uia_mod.VARIANT._fields_:
            self.assertFalse(issubclass(field_type, ctypes.Union))

        v_i4 = uia_mod.VARIANT.from_i4(uia_mod.UIA_ButtonControlTypeId)
        self.assertEqual(uia_mod.VT_I4, v_i4.vt)
        self.assertEqual(uia_mod.UIA_ButtonControlTypeId, v_i4.lVal)

        v_true = uia_mod.VARIANT.from_bool(True)
        self.assertEqual(uia_mod.VT_BOOL, v_true.vt)
        raw_true = bytes(v_true)
        self.assertEqual(-1, struct.unpack_from("<h", raw_true, 8)[0])
        self.assertEqual(b"\x00\x00", raw_true[10:12])

        v_false = uia_mod.VARIANT.from_bool(False)
        self.assertEqual(uia_mod.VT_BOOL, v_false.vt)
        self.assertEqual(0, struct.unpack_from("<h", bytes(v_false), 8)[0])

    def test_guid_from_string_fields(self):
        guid = uia_mod.CLSID_CUIAutomation
        self.assertEqual(0xFF48DBA4, guid.Data1)
        self.assertEqual(0x60EF, guid.Data2)
        self.assertEqual(0x4201, guid.Data3)
        self.assertEqual([0xAA, 0x87, 0x54, 0x10, 0x3E, 0xEF, 0x59, 0x4E], list(guid.Data4))


class TestUIAClient(unittest.TestCase):
    def _make_mock_dlls(self, bstrs: FakeBSTRHeap, uia_obj: FakeCOMObject, *, uia2_succeeds: bool = True, coinit_hr: int = 0):
        ole32 = MagicMock()
        ole32.CoInitializeEx.return_value = coinit_hr

        def _co_create(clsid_ptr, _outer, _ctx, _iid_ptr, ppv_ptr):
            clsid = ctypes.cast(clsid_ptr, POINTER(uia_mod.GUID)).contents
            out_ppv = ctypes.cast(ppv_ptr, POINTER(c_void_p))
            if clsid.Data1 == uia_mod.CLSID_CUIAutomation8.Data1:
                if uia2_succeeds:
                    out_ppv[0] = uia_obj.ptr
                    return 0
                out_ppv[0] = 0
                return -2147221164  # REGDB_E_CLASSNOTREG
            if clsid.Data1 == uia_mod.CLSID_CUIAutomation.Data1:
                out_ppv[0] = uia_obj.ptr
                return 0
            return -2147467259

        ole32.CoCreateInstance.side_effect = _co_create

        oleaut32 = MagicMock()
        oleaut32.SysStringLen.side_effect = bstrs.sys_string_len
        oleaut32.SysFreeString.side_effect = bstrs.sys_free_string
        return ole32, oleaut32

    def test_uia2_initialize_sets_timeouts_builds_cache_and_releases_on_close(self):
        bstrs = FakeBSTRHeap()
        uia_obj, state = _make_uia_server({}, is_uia2=True)
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj, uia2_succeeds=True)

        client = uia_mod.UIAClient(connection_timeout_ms=400, transaction_timeout_ms=900)
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())

        self.assertTrue(client.available)
        self.assertEqual(400, state["conn_timeout"])
        self.assertEqual(900, state["tx_timeout"])
        self.assertEqual([4, 3], state["or_counts"])
        self.assertEqual([3, 3], state["and_counts"])
        self.assertEqual(1, state["not_count"])
        self.assertEqual(list(uia_mod._CACHED_PROPERTY_IDS), state["cached_props"])
        # All intermediate conditions were released; only the two final AND conditions stay alive until close().
        self.assertEqual([1] * (len(state["conditions"]) - 2) + [0, 0], [c.released for c in state["conditions"]])
        self.assertEqual([0], [r.released for r in state["cache_requests"]])

        client.close()
        self.assertFalse(client.available)
        self.assertTrue(all(c.released == 1 for c in state["conditions"]))
        self.assertEqual([1], [r.released for r in state["cache_requests"]])
        self.assertEqual(1, uia_obj.released)
        ole32.CoUninitialize.assert_called_once()

    def test_win7_fallback_and_rpc_changed_mode_skips_couninitialize(self):
        bstrs = FakeBSTRHeap()
        uia_obj, state = _make_uia_server({}, is_uia2=False)
        ole32, oleaut32 = self._make_mock_dlls(
            bstrs,
            uia_obj,
            uia2_succeeds=False,
            coinit_hr=uia_mod.RPC_E_CHANGED_MODE,
        )

        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())

        self.assertIsNone(state["conn_timeout"])
        client.close()
        ole32.CoUninitialize.assert_not_called()
        self.assertEqual(1, uia_obj.released)

    def test_find_all_build_cache_reads_cached_properties_without_live_rpcs(self):
        bstrs = FakeBSTRHeap()
        root_calls: list[str] = []
        elem_calls: list[str] = []
        events: list[str] = []

        btn = _make_element(
            bstrs,
            name="Enable Editing",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            patterns={uia_mod.UIA_InvokePatternId: _make_invoke_pattern(lambda: events.append("invoked"))},
            call_log=elem_calls,
        )
        arr = _make_element_array([btn])
        root = _make_element(
            bstrs,
            name="Word",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=arr,
            call_log=root_calls,
        )
        uia_obj, _ = _make_uia_server({0x4242: root}, enable_cache=True)
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            acted = client.interact_with_hwnd(0x4242, match_fn=lambda n: "enable" in n.lower())
            client.close()

        self.assertTrue(acted)
        self.assertEqual(["invoked"], events)
        self.assertEqual(["FindAllBuildCache"], root_calls)
        self.assertIn("get_CachedIsEnabled", elem_calls)
        self.assertIn("get_CachedIsOffscreen", elem_calls)
        self.assertIn("get_CachedName", elem_calls)
        self.assertIn("get_CachedControlType", elem_calls)
        self.assertNotIn("get_CurrentIsEnabled", elem_calls)
        self.assertNotIn("get_CurrentIsOffscreen", elem_calls)
        self.assertNotIn("get_CurrentName", elem_calls)
        self.assertNotIn("get_CurrentControlType", elem_calls)

    def test_toggle_skips_checked_checkbox_and_invokes_next_button(self):
        bstrs = FakeBSTRHeap()
        events = []

        checked_box = _make_element(
            bstrs,
            name="I accept the terms",
            ctrl_type=uia_mod.UIA_CheckBoxControlTypeId,
            patterns={uia_mod.UIA_TogglePatternId: _make_toggle_pattern(uia_mod.ToggleState_On, lambda: events.append("toggled"))},
        )
        next_btn = _make_element(
            bstrs,
            name="Enable Content",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            patterns={uia_mod.UIA_InvokePatternId: _make_invoke_pattern(lambda: events.append("invoked"))},
        )
        arr = _make_element_array([checked_box, next_btn])
        root = _make_element(bstrs, name="Word", ctrl_type=uia_mod.UIA_ButtonControlTypeId, find_all_array=arr)
        uia_obj, _ = _make_uia_server({0x4242: root})
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            acted = client.interact_with_hwnd(0x4242, match_fn=lambda name: "accept" in name.lower() or "enable" in name.lower())
            client.close()

        self.assertTrue(acted)
        self.assertEqual(["invoked"], events)
        self.assertEqual(1, checked_box.released)
        self.assertEqual(1, next_btn.released)
        self.assertEqual(1, arr.released)
        self.assertEqual(1, root.released)
        # Every allocated BSTR was freed via SysFreeString.
        self.assertEqual(2, len(bstrs.freed))

    def test_unchecked_checkbox_toggles_once_and_state_error_does_not_blindly_toggle(self):
        bstrs = FakeBSTRHeap()
        events = []

        unchecked_box = _make_element(
            bstrs,
            name="I accept",
            ctrl_type=uia_mod.UIA_CheckBoxControlTypeId,
            patterns={uia_mod.UIA_TogglePatternId: _make_toggle_pattern(uia_mod.ToggleState_Off, lambda: events.append("toggle_box"))},
        )
        broken_box = _make_element(
            bstrs,
            name="I accept broken",
            ctrl_type=uia_mod.UIA_CheckBoxControlTypeId,
            patterns={
                uia_mod.UIA_TogglePatternId: _make_toggle_pattern(
                    uia_mod.ToggleState_Off,
                    lambda: events.append("should_not_toggle"),
                    state_hr=-2147467259,
                )
            },
        )
        selected_radio = _make_element(
            bstrs,
            name="I accept",
            ctrl_type=uia_mod.UIA_RadioButtonControlTypeId,
            patterns={uia_mod.UIA_SelectionItemPatternId: _make_selection_pattern(1, lambda: events.append("select_already"))},
        )
        broken_radio = _make_element(
            bstrs,
            name="I accept broken radio",
            ctrl_type=uia_mod.UIA_RadioButtonControlTypeId,
            patterns={
                uia_mod.UIA_SelectionItemPatternId: _make_selection_pattern(
                    0,
                    lambda: events.append("should_not_select"),
                    selected_hr=-2147467259,
                )
            },
        )
        unselected_radio = _make_element(
            bstrs,
            name="I agree",
            ctrl_type=uia_mod.UIA_RadioButtonControlTypeId,
            patterns={uia_mod.UIA_SelectionItemPatternId: _make_selection_pattern(0, lambda: events.append("select_radio"))},
        )

        root_box = _make_element(
            bstrs,
            name="Dlg1",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=_make_element_array([broken_box, unchecked_box]),
        )
        root_radio = _make_element(
            bstrs,
            name="Dlg2",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=_make_element_array([selected_radio, broken_radio, unselected_radio]),
        )
        uia_obj, _ = _make_uia_server({0x10: root_box, 0x20: root_radio})
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            self.assertTrue(client.interact_with_hwnd(0x10, match_fn=lambda _: True))
            self.assertTrue(client.interact_with_hwnd(0x20, match_fn=lambda _: True))
            client.close()

        self.assertEqual(["toggle_box", "select_radio"], events)

    def test_clickable_point_and_bounding_rect_fallback_and_hyperlink_condition_toggle(self):
        bstrs = FakeBSTRHeap()
        clicks = []
        seen_conditions: list[int] = []

        disabled_btn = _make_element(bstrs, name="Run", ctrl_type=uia_mod.UIA_ButtonControlTypeId, enabled=0)
        offscreen_btn = _make_element(bstrs, name="Run", ctrl_type=uia_mod.UIA_ButtonControlTypeId, enabled=1, offscreen=1)
        rect_btn = _make_element(
            bstrs,
            name="Run anyway",
            ctrl_type=uia_mod.UIA_HyperlinkControlTypeId,
            rect=(100, 200, 200, 240),
        )
        root = _make_element(
            bstrs,
            name="SmartScreen",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=_make_element_array([disabled_btn, offscreen_btn, rect_btn]),
            seen_conditions=seen_conditions,
        )
        uia_obj, _ = _make_uia_server({0x55: root})
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient(action_cooldown_s=0.0)
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            acted = client.interact_with_hwnd(
                0x55,
                match_fn=lambda name: "run" in name.lower(),
                click_point_fn=lambda x, y: clicks.append((x, y)),
                include_hyperlinks=True,
            )
            client.interact_with_hwnd(0x55, match_fn=lambda _: False, include_hyperlinks=False)
            cond_all = client._condition.value
            cond_buttons = client._condition_no_hyperlinks.value
            client.close()

        self.assertTrue(acted)
        self.assertEqual([(150, 220)], clicks)
        self.assertEqual([cond_all, cond_buttons], seen_conditions)
        self.assertNotEqual(cond_all, cond_buttons)

    def test_timeout_aborts_remaining_elements_and_backs_off_hwnd(self):
        bstrs = FakeBSTRHeap()
        second_elem_calls: list[str] = []

        hanging_elem = _make_element(
            bstrs,
            name="Install",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            pattern_hr=uia_mod.UIA_E_TIMEOUT,
        )
        second_elem = _make_element(
            bstrs,
            name="Next",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            call_log=second_elem_calls,
        )
        root = _make_element(
            bstrs,
            name="HungApp",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=_make_element_array([hanging_elem, second_elem]),
        )
        uia_obj, state = _make_uia_server({0x99: root})
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient(timeout_backoff_s=10.0)
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            self.assertFalse(client.interact_with_hwnd(0x99, match_fn=lambda _: True))
            # Second element was never inspected after UIA_E_TIMEOUT.
            self.assertEqual([], second_elem_calls)
            self.assertEqual(1, state["elem_from_handle_calls"])
            # Immediate retry skips the backed-off hwnd without calling ElementFromHandle.
            self.assertFalse(client.interact_with_hwnd(0x99, match_fn=lambda _: True))
            self.assertEqual(1, state["elem_from_handle_calls"])
            client.close()

    def test_patternless_checkbox_clicks_once_within_unverified_cooldown(self):
        bstrs = FakeBSTRHeap()
        clicks: list[tuple[int, int]] = []

        custom_checkbox = _make_element(
            bstrs,
            name="I agree",
            ctrl_type=uia_mod.UIA_CheckBoxControlTypeId,
            rect=(10, 20, 50, 40),
        )
        root = _make_element(
            bstrs,
            name="Installer",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=_make_element_array([custom_checkbox]),
        )
        uia_obj, _ = _make_uia_server({0x77: root})
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient(action_cooldown_s=1.0, unverified_toggle_cooldown_s=60.0)
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            self.assertTrue(client.interact_with_hwnd(0x77, match_fn=lambda _: True, click_point_fn=lambda x, y: clicks.append((x, y))))
            # Consecutive scan does not toggle the patternless checkbox back off.
            self.assertFalse(client.interact_with_hwnd(0x77, match_fn=lambda _: True, click_point_fn=lambda x, y: clicks.append((x, y))))
            client.close()

        self.assertEqual([(30, 30)], clicks)

    def test_initialize_returns_false_when_com_mocked_or_unavailable(self):
        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(MagicMock(), MagicMock())):
            self.assertFalse(client.initialize())
        self.assertFalse(client.available)

    @unittest.skipUnless(sys.platform == "win32", "Requires native Windows UIAutomationCore.dll")
    def test_live_windows_uia_initialize_and_close(self):
        client = uia_mod.UIAClient()
        try:
            self.assertTrue(client.initialize())
            self.assertTrue(client.available)
            self.assertIsNotNone(client._condition_no_hyperlinks)
            self.assertIsNotNone(client._cache_request)
        finally:
            client.close()
        self.assertFalse(client.available)


if __name__ == "__main__":
    unittest.main()
