============================
Installing the Android guest
============================

This page is the guest-image path used to validate ``analyzer/android``:
**Android-x86 9.0 on KVM (x86_64)**. It is not Android Studio, not a Linux VM
with an emulator nested inside, and not ARM / AVD. Those can be additional
machine types later; this analyzer does not require them.

The qcow, ISO, and your live ``conf/kvm.conf`` stay on the host. Do not commit
them.

What this PR needs from the guest
=================================

* A libvirt domain whose **label** matches ``conf/kvm.conf``.
* ``platform = android`` so ``GuestManager`` zips ``analyzer/android`` and so
  ``find_machine_to_service_task()`` will not pick a free Windows VM.
* Stock Android has no writable ``/tmp``. The analyzer, sample, and agent
  working files go under ``/data/local/tmp`` (``/`` is tmpfs / read-only).
* ``agent.py`` listening on TCP **8000**, already running in the snapshot so a
  revert is enough to bring it back. See :doc:`agent` and :doc:`saving`.

ISO → KVM
=========

1. Download an **Android-x86 9.0 x86_64** ISO from the
   `Android-x86 project <https://www.android-x86.org/>`_ (this PR was tested on
   ``android_x86_64-userdebug 9``, kernel ``4.19.110-android-x86_64``).
2. Create a libvirt KVM domain with a **qcow2** disk (snapshots require qcow2
   or LVM; see :doc:`saving`). A working size for this path is about 2 vCPU and
   3 GiB RAM, machine type q35, an ``e1000`` NIC on your CAPE analysis bridge
   (often ``virbr0`` / ``virbr1``).
3. Install from the ISO. Use a **userdebug** (or otherwise rooted) image so
   ``su`` works; the agent must run as root (``uid=0``).
4. Enable networking. Give the guest a **stable IPv4** (static config or a
   DHCP reservation) and put that address in ``kvm.conf``. If the IP changes,
   the host cannot reach the agent.

Python and ``agent.py``
=======================

Android-x86 does not ship CPython. The guest used for this PR runs CAPE's
``agent/agent.py`` under **Termux** ``python3`` (sideload Termux, then
``pkg install python``). Copy ``agent.py`` to ``/data/local/tmp/agent.py``.

Bionic often cannot bind ``0.0.0.0`` (``socket.gaierror``). Pass the guest's
own address as the listen host; leave the port at 8000::

    /data/data/com.termux/files/usr/bin/python3 /data/local/tmp/agent.py <guest_ip> 8000 -v

Confirm from the CAPE host *before* you snapshot::

    curl http://<guest_ip>:8000

You should get JSON similar to ``{"message": "CAPE Agent!", "version": "0.22", ...}``.

Taking a snapshot with the agent already running is enough (same as Windows).
You do not need an init script if revert restores that running process. If you
do want boot-start later, keep the same listen-IP invocation; do not switch it
to ``0.0.0.0`` on this image.

Do **not** retarget the analyzer's loopback ``POST /status`` to the CAPE host
IP. Agent pinning would drop it. Loopback may fail on this bind; the host still
completes the task from the ``/execpy`` child exit code.

Snapshot → machines table
=========================

1. With the agent up, create an **internal** libvirt snapshot, for example
   named ``clean``::

       virsh snapshot-create-as --domain android1 --name clean

   Then you can shut the domain down. CAPE will revert to that snapshot per
   task.
2. Add a stanza to ``conf/kvm.conf`` (do not commit this file) and include the
   id in ``machines =``::

       [android1]
       label = android1
       platform = android
       ip = 192.168.122.50
       arch = x64
       snapshot = clean
       interface = virbr0

   ``label`` must be the libvirt domain name. ``arch = x64`` matches the
   x86_64 ISO. ``interface`` is the bridge tcpdump should use, if you override
   the auxiliary default.
3. Restart ``cape.service`` so the machines table picks up ``platform=android``.
   A bare ``.apk`` (or ``--package apk``) should then store ``task.platform=android``
   and select this VM instead of a free Windows machine.

Submit a sample::

    python utils/submit.py /path/to/sample.apk
    python utils/submit.py --package apk /path/to/sample.apk

Architecture follow-ups (not this slice)
========================================

These are real product questions. They are **later machine types or later
PRs**, not a rewrite of install / launch / process lifetime.

ARM APKs and phone-like AVDs
----------------------------

Not tested. This guest is Android-x86 **x86_64** because it sits next to the
Windows KVM domain: libvirt snapshot revert, ``agent.py`` on port 8000, and
``platform=android`` in the machines table.

x86 Android is a poor stand-in for a modern phone. The long-term shape is extra
machine types (ARM64 AVD or a phone-like image), not a second analyzer tree.
``analyzer/android`` can stay; ``kvm.conf`` / qemu machinery grows ``arch`` and
network. Play APKs that ship only ``armeabi-v7a`` / ``arm64-v8a`` native libs
will miss those ``.so`` files on this x86_64 guest (Java still runs).

eBPF and detection bypass
-------------------------

Not in this PR. Linux CAPE already has a first-cut capture path (Tracee →
``results["tracee"]``, no signatures). Android eBPF on a 4.19 Android-x86
kernel is a different stack, and Magisk-style hide / bypass is image hardening,
not the analyzer. Dynamic events on Android are a parallel Frida-capture track,
not eBPF in this slice.

User interaction / VNC
----------------------

This slice launches with ``monkey`` on the LAUNCHER activity. There is no CAPE
web VNC (no Guacamole-style guest desktop). Operators can already attach
``virt-manager`` / spice / VNC to the libvirt domain for debugging. Exposing
that as a user-facing analysis feature is a later product decision.

Root detectors (for example RootBeer)
-------------------------------------

This image is **userdebug with ``su``**; the agent runs as ``uid=0``. Root
detectors are expected to report rooted. That is honest for this guest, not a
failed analysis. A live ``scottyab/rootbeer`` sample run belongs in the PR
thread (report + guest log), not in git. Native-only ARM checks may be a no-op
on x86_64; Java checks (``su`` on ``PATH``, test-keys, dangerous packages)
should still fire.
