============================================
Debugging Stuck Virtual Machines in Cuckoo/CAPE
============================================

This guide outlines a systematic approach to diagnosing and resolving issues where the analysis process hangs ("stucks") indefinitely.

Problem Triage
==============

When a task appears stuck (e.g., Python process running, VM running, but no activity), determine which component is frozen:

1. **Guest OS:** Kernel panic or BSOD inside the VM.
2. **QEMU Process:** Deadlocked hypervisor.
3. **Python Controller:** Waiting on a socket/pipe that will never return data.

Phase 1: Immediate Diagnostics
==============================

Check the CPU state of the processes to identify the bottleneck.

**1. Find Process IDs (PIDs)**

.. code-block:: bash

    ps aux | grep qemu
    ps aux | grep python

**2. Check CPU Usage**

.. code-block:: bash

    top -p <PID>

* **100% CPU:** The process is in a tight loop (livelock).
* **0% CPU (State S - Sleeping):** Waiting for network/socket data. (Most common for Python).
* **0% CPU (State D - Disk Sleep):** Waiting for Hardware I/O.

Phase 2: Debugging the Python Controller
========================================

If Python is sleeping (0% CPU), it is likely blocked on a synchronous call waiting for the Guest.

**Using py-spy (Recommended)**

Dumps the Python stack trace without pausing execution.

.. code-block:: bash

    pip install py-spy
    sudo py-spy dump --pid <PYTHON_PID>

**What to look for:**
* ``wait_for_completion`` (Looping/Waiting for Agent)
* ``select``, ``poll``, ``recv`` (Waiting for Network I/O)

Phase 3: Debugging the QEMU Engine
==================================

If Python is waiting on QEMU, inspect the VM state.

**1. Check System Calls**

See what the process is asking the Linux Kernel to do.

.. code-block:: bash

    sudo strace -p <QEMU_PID>

* **futex:** Threading deadlock.
* **ppoll/select:** Normal idle state (waiting for guest interrupt).

**2. QEMU Monitor (QMP)**

Query the internal state of the hypervisor.

.. code-block:: bash

    echo "info status" | socat - UNIX-CONNECT:/tmp/qemu-monitor.sock

**3. Visual Inspection (Screenshot)**

If using Libvirt, capture a screenshot of the Guest without stopping it to check for BSODs or Popups.

.. code-block:: bash

    virsh list
    virsh screenshot <VM_NAME> /tmp/debug_screenshot.ppm

Phase 4: Root Cause Analysis
============================

Linking the Python trace to the VM state.

Scenario A: "The Zombie Success"
--------------------------------
* **Symptom:** Logs say "Analysis completed successfully", but Python process is still running hours later.
* **Trace:** Python is stuck in ``wait_for_completion`` loop (sleeping).
* **Cause:** The Agent inside the VM died or network was cut *after* sending success, but *before* the Python loop could confirm the shutdown.
* **Fix:** Python enters an infinite retry loop because the error handler just ``continues`` instead of aborting.

Scenario B: "The Blind Wait"
----------------------------
* **Symptom:** Python blocked on ``recv`` or ``read``.
* **Cause:** The Agent crashed without closing the TCP socket. Python waits for EOF that never comes.
* **Fix:** Enforce socket timeouts in code.

Phase 5: Resolution & Code Fixes
================================

To prevent future hangs, apply these fixes to ``lib/cuckoo/core/guest.py``.

**1. Fix the Infinite Loop**
Modify ``wait_for_completion`` to calculate a hard deadline based on configuration.

.. code-block:: python

    # Calculate Hard Limit
    effective_timeout = self.timeout if self.timeout else cfg.timeouts.default
    hard_limit = effective_timeout + cfg.timeouts.critical

    while self.do_run:
        # Check Hard Limit
        if timeit.default_timer() - start > hard_limit:
            log.error("Hard Timeout reached! Killing analysis.")
            return

**2. Fix Database Staleness**
Ensure the loop checks the *actual* database state, not cached RAM values (essential for tasks deleted by user).

.. code-block:: python

    db.session.expire_all()
    if db.guest_get_status(self.task_id) is None:
        return  # Task deleted

**3. Emergency Cleanup**
If a process is already stuck, kill the zombie pair manually.

.. code-block:: bash

    kill -9 <PYTHON_PID>
    kill -9 <QEMU_PID>
