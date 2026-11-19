.. _CAPE-Human-Interaction:

===========================
Automated Human Interaction
===========================

The Windows ``human`` auxiliary module (``analyzer/windows/modules/auxiliary/human.py``)
runs inside the guest during detonation to simulate cursor movement, dismiss installer
and security prompts, and interact with opened documents.

No extra third-party Python packages (such as ``comtypes``, ``pywinauto``, or ``pywin32``)
are required inside the guest VM.

Supported UI Interfaces
=======================

Classic Win32, NSIS, and MSI Controls
-------------------------------------

``human.py`` enumerates visible top-level and child ``HWND`` controls via Win32 APIs:

* **Push buttons, checkboxes, and radio buttons**: inspects ``GWL_STYLE & BS_TYPEMASK`` on
  standard ``Button`` controls so Win32/NSIS/MSI checkboxes and radio buttons route to
  check-once handling (``check_button()``) rather than toggling repeatedly, while skipping
  ``BS_GROUPBOX`` containers.
* **Hang protection**: Win32 queries and clicks use ``SendMessageTimeoutW``
  (``SMTO_ABORTIFHUNG``, 500ms timeout) with signed ``WM_GETTEXTLENGTH`` clamping so
  unresponsive windows do not block the interaction thread.

Modern UI Frameworks (Windows UI Automation)
--------------------------------------------

When classic Win32 ``HWND`` enumeration does not match a control (or first on Office
``NUIDialog`` / ``bosa_sdm_msword`` dialogs before falling back to a blind ``Enter``
keypress), ``human.py`` invokes ``analyzer/windows/lib/api/uia.py``:

* **Pure-ctypes COM client**: binds directly to native ``ole32.dll``, ``oleaut32.dll``,
  and ``UIAutomationCore.dll`` (``IUIAutomation2`` with 500ms connection / 1000ms
  transaction timeouts on Windows 8+/10/11, falling back to ``IUIAutomation`` on
  Windows 7).
* **Frameworks covered**: windowless and custom-rendered controls in **DirectUI**
  (TaskDialog, SmartScreen, WiX Burn/MSI prompts), **WPF**, **UWP/WinUI**
  (``ApplicationFrameWindow``), and **Microsoft Office** (``NetUIHWND``, ``NUIDialog``,
  ``bosa_sdm_msword``, Protected View and Security Warning bars).
* **Pattern dispatch**: prefetches enabled, onscreen buttons, checkboxes, radio buttons,
  and hyperlinks in a single RPC using server-side ``AndCondition``/``NotCondition`` and
  ``FindAllBuildCache``. Activates controls through native ``TogglePattern``,
  ``SelectionItemPattern``, or ``InvokePattern`` with clickable-point / bounding-box mouse
  click fallback.
* **Budgets and cooldowns**: enforces a per-window time budget (1.5s), temporary backoff
  (10s) on ``UIA_E_TIMEOUT`` / ``RPC_E_TIMEOUT``, and per-control cooldowns to avoid
  repeating actions on the same element.

Window Scoping Safeguards
=========================

To avoid clicking unrelated desktop chrome or causing unintended navigation:

* **Skipped window classes** (``UIA_SKIP_WINDOW_CLASSES``): Chromium/Firefox browsers
  (``Chrome_WidgetWin_1``, ``MozillaWindowClass``), Explorer/taskbar/Start shell windows
  (``CabinetWClass``, ``Shell_TrayWnd``, ``Progman``, ``WorkerW``,
  ``Windows.UI.Core.CoreWindow``, etc.), console/Windows Terminal windows
  (``ConsoleWindowClass``, ``CASCADIA_HOSTING_WINDOW_CLASS``), pre-analysis desktop
  windows, and minimized (``IsIconic``) windows are excluded from UIA traversal.
* **Application main frames** (``APP_MAIN_FRAME_CLASSES``): on Word (``OpusApp``),
  Excel (``XLMAIN``), PowerPoint (``PPTFrameClass``), Outlook (``rctrl_renwnd32``), and
  Adobe Acrobat (``AcrobatSDIWindow``) main frames, UIA disables hyperlink clicking and
  filters permanent Ribbon/toolbar captions (``Save``, ``Open``, ``Next``, etc. via
  ``APP_FRAME_EXCLUDED_UIA_BUTTONS``) while keeping Protected View and Security Warning
  buttons (such as ``Enable Editing`` and ``Enable Content``) clickable.

Localized Windows MUI Dialogs
=============================

At startup, ``human.py`` loads localized standard Windows dialog captions directly from
``user32.dll`` via ``LoadStringW`` so button matching adapts to the guest OS display
language:

* **Clickable MUI IDs**: ``800`` (OK), ``803`` (Retry), ``805`` (Yes), ``809`` (Try Again),
  ``810`` (Continue).
* **Ignored MUI IDs**: ``801`` (Cancel), ``802`` (Abort), ``808`` (Help).
* **Matching rules**: strips Western (``&``) and CJK (``(&X)`` / ``(X)`` / ``（X）``)
  accelerator mnemonics, applies ``DONT_CLICK_BUTTONS`` + ignored MUI captions before
  ``CLICK_BUTTONS`` + clickable MUI captions, and matches using word boundaries for Latin
  scripts and substring matching for CJK text.

Submission Options
==================

Options can be passed via ``--options`` in ``utils/submit.py``, the REST API, or the web UI:

* ``nohuman=1``: disable the Windows ``human`` auxiliary module completely.
* ``nouia=1``: disable native Windows UI Automation while keeping classic Win32 dialog
  interaction active. (``nouia`` is filtered from ``capemon`` configuration via
  ``server_options`` in ``analyzer/windows/lib/api/process.py``.)

Extending Support
=================

To customize button matching or UIA window handling in
``analyzer/windows/modules/auxiliary/human.py``:

* Add localized or application-specific button labels to ``CLICK_BUTTONS`` or
  ``DONT_CLICK_BUTTONS``.
* Add top-level window classes to skip during UIA traversal to
  ``UIA_SKIP_WINDOW_CLASSES``.
* Add document/application main-frame window classes to ``APP_MAIN_FRAME_CLASSES`` and
  excluded toolbar/Ribbon labels to ``APP_FRAME_EXCLUDED_UIA_BUTTONS``.
