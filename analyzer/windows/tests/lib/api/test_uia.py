"""Tests for pure-ctypes Microsoft UI Automation client (lib.api.uia)."""

import ctypes
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


def _make_invoke_pattern(on_invoke):
    def _invoke(_this):
        on_invoke()
        return 0

    return FakeCOMObject(4, {3: (c_int32, (), _invoke)})


def _make_toggle_pattern(state: int, on_toggle):
    def _toggle(_this):
        on_toggle()
        return 0

    def _get_state(_this, out_state):
        out_state[0] = state
        return 0

    return FakeCOMObject(
        5,
        {
            3: (c_int32, (), _toggle),
            4: (c_int32, (POINTER(c_int32),), _get_state),
        },
    )


def _make_selection_pattern(selected: int, on_select):
    def _select(_this):
        on_select()
        return 0

    def _get_selected(_this, out_sel):
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
    clickable_point: tuple[int, int] | None = None,
    rect: tuple[int, int, int, int] | None = None,
    find_all_array: FakeCOMObject | None = None,
):
    patterns = patterns or {}

    def _find_all(_this, _scope, _cond, out_arr):
        if find_all_array is None:
            out_arr[0] = 0
            return -2147467259  # E_FAIL
        out_arr[0] = find_all_array.ptr
        return 0

    def _get_pattern_as(_this, pattern_id, _riid, out_pat):
        pat = patterns.get(pattern_id)
        if pat is None:
            out_pat[0] = 0
            return -2147467262  # E_NOINTERFACE
        out_pat[0] = pat.ptr
        return 0

    def _get_ctrl_type(_this, out_ct):
        out_ct[0] = ctrl_type
        return 0

    def _get_name(_this, out_bstr):
        out_bstr[0] = bstrs.alloc(name)
        return 0

    def _get_enabled(_this, out_en):
        out_en[0] = enabled
        return 0

    def _get_offscreen(_this, out_off):
        out_off[0] = offscreen
        return 0

    def _get_rect(_this, out_rect):
        if rect is None:
            return -2147467259
        out_rect[0].left, out_rect[0].top, out_rect[0].right, out_rect[0].bottom = rect
        return 0

    def _get_clickable(_this, out_pt, out_got):
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
            14: (c_int32, (c_int32, POINTER(uia_mod.GUID), POINTER(c_void_p)), _get_pattern_as),
            21: (c_int32, (POINTER(c_int32),), _get_ctrl_type),
            23: (c_int32, (POINTER(c_void_p),), _get_name),
            28: (c_int32, (POINTER(c_int32),), _get_enabled),
            38: (c_int32, (POINTER(c_int32),), _get_offscreen),
            43: (c_int32, (POINTER(uia_mod.UIA_RECT),), _get_rect),
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


def _make_uia_server(root_by_hwnd: dict[int, FakeCOMObject], *, is_uia2: bool = True):
    state = {
        "prop_values": [],
        "or_counts": [],
        "conn_timeout": None,
        "tx_timeout": None,
        "conditions": [],
    }

    def _elem_from_handle(_this, hwnd, out_elem):
        root = root_by_hwnd.get(hwnd)
        if root is None:
            out_elem[0] = 0
            return -2147467259
        out_elem[0] = root.ptr
        return 0

    def _create_prop_cond(_this, prop_id, variant, out_cond):
        assert prop_id == uia_mod.UIA_ControlTypePropertyId
        assert variant.vt == uia_mod.VT_I4
        state["prop_values"].append(variant.data.lVal)
        cond = FakeCOMObject(3, {})
        state["conditions"].append(cond)
        out_cond[0] = cond.ptr
        return 0

    def _create_or_cond(_this, _conds, count, out_cond):
        state["or_counts"].append(count)
        combined = FakeCOMObject(3, {})
        state["conditions"].append(combined)
        out_cond[0] = combined.ptr
        return 0

    def _put_conn_timeout(_this, timeout):
        state["conn_timeout"] = timeout
        return 0

    def _put_tx_timeout(_this, timeout):
        state["tx_timeout"] = timeout
        return 0

    handlers = {
        6: (c_int32, (c_void_p, POINTER(c_void_p)), _elem_from_handle),
        23: (c_int32, (c_int32, uia_mod.VARIANT, POINTER(c_void_p)), _create_prop_cond),
        30: (c_int32, (POINTER(c_void_p), c_int32, POINTER(c_void_p)), _create_or_cond),
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
        self.assertEqual(8, uia_mod.VARIANT.data.offset)

        v = uia_mod.VARIANT.from_i4(uia_mod.UIA_ButtonControlTypeId)
        self.assertEqual(uia_mod.VT_I4, v.vt)
        self.assertEqual(uia_mod.UIA_ButtonControlTypeId, v.data.lVal)

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

    def test_uia2_initialize_sets_timeouts_and_releases_on_close(self):
        bstrs = FakeBSTRHeap()
        uia_obj, state = _make_uia_server({}, is_uia2=True)
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj, uia2_succeeds=True)

        client = uia_mod.UIAClient(connection_timeout_ms=400, transaction_timeout_ms=900)
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())

        self.assertTrue(client.available)
        self.assertEqual(400, state["conn_timeout"])
        self.assertEqual(900, state["tx_timeout"])
        self.assertEqual(list(uia_mod.INTERACTIVE_CONTROL_TYPES), state["prop_values"])
        self.assertEqual([4], state["or_counts"])
        # All 4 temporary sub-conditions were released; the combined condition stays alive until close().
        self.assertEqual([1, 1, 1, 1, 0], [c.released for c in state["conditions"]])

        client.close()
        self.assertFalse(client.available)
        self.assertEqual(1, state["conditions"][-1].released)
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

    def test_unchecked_checkbox_toggles_once_and_unselected_radio_selects(self):
        bstrs = FakeBSTRHeap()
        events = []

        unchecked_box = _make_element(
            bstrs,
            name="I accept",
            ctrl_type=uia_mod.UIA_CheckBoxControlTypeId,
            patterns={uia_mod.UIA_TogglePatternId: _make_toggle_pattern(uia_mod.ToggleState_Off, lambda: events.append("toggle_box"))},
        )
        selected_radio = _make_element(
            bstrs,
            name="I accept",
            ctrl_type=uia_mod.UIA_RadioButtonControlTypeId,
            patterns={uia_mod.UIA_SelectionItemPatternId: _make_selection_pattern(1, lambda: events.append("select_already"))},
        )
        unselected_radio = _make_element(
            bstrs,
            name="I agree",
            ctrl_type=uia_mod.UIA_RadioButtonControlTypeId,
            patterns={uia_mod.UIA_SelectionItemPatternId: _make_selection_pattern(0, lambda: events.append("select_radio"))},
        )

        root_box = _make_element(bstrs, name="Dlg1", ctrl_type=uia_mod.UIA_ButtonControlTypeId, find_all_array=_make_element_array([unchecked_box]))
        root_radio = _make_element(
            bstrs,
            name="Dlg2",
            ctrl_type=uia_mod.UIA_ButtonControlTypeId,
            find_all_array=_make_element_array([selected_radio, unselected_radio]),
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

    def test_clickable_point_and_bounding_rect_fallback_skip_disabled_and_offscreen(self):
        bstrs = FakeBSTRHeap()
        clicks = []

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
        )
        uia_obj, _ = _make_uia_server({0x55: root})
        ole32, oleaut32 = self._make_mock_dlls(bstrs, uia_obj)

        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(ole32, oleaut32)):
            self.assertTrue(client.initialize())
            acted = client.interact_with_hwnd(
                0x55,
                match_fn=lambda name: "run" in name.lower(),
                click_point_fn=lambda x, y: clicks.append((x, y)),
            )
            client.close()

        self.assertTrue(acted)
        self.assertEqual([(150, 220)], clicks)

    def test_initialize_returns_false_when_com_mocked_or_unavailable(self):
        client = uia_mod.UIAClient()
        with patch.object(uia_mod, "_load_com_dlls", return_value=(MagicMock(), MagicMock())):
            self.assertFalse(client.initialize())
        self.assertFalse(client.available)


if __name__ == "__main__":
    unittest.main()
