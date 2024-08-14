.. _tracee:

========
Tracee eBPF for Linux
========

CAPEv2 now has support for [Aqua Security Tracee](https://www.aquasec.com/products/tracee/), an eBPF-based threat detection engine with built-in signatures, for Linux dynamic analysis to complement the existing `strace` implementation.

To use it, you need to install the [CAPEv2 Community Repo](https://github.com/CAPESandbox/community). Here is a guide: https://capev2.readthedocs.io/en/latest/usage/utilities.html#community-download-utility.

Once you have installed the CAPEv2 Community Repo, you should have `analyzer/linux/modules/auxiliary/tracee.py`.

Tracee has functionality to:

- **capture artifacts** such as loaded kernel modules, suspicious memory regions and eBPF programs in their **run-time state**, allowing their **easy extraction even from packed and encrypted malwares**
- **capture suspicious events** such as:
    - Dynamic Code Loading
    - Fileless Execution
    - Syscall Table Hooking
    - `kallsyms_lookup_name` -  it could be used in some rootkits ([more information](https://github.com/xcellerator/linux_kernel_hacking/issues/3))
    - **Kernel Module Loading** - new kernel module loaded (possible kernel rookits)
    - **Process VM Write** - detect potential code injection attacks using the `process_vm_writev` syscall
    - **Scheduled Task Modification** - like cron
    - **Standard I/O Over Socket** - potential remote shell
    - **Many more...**
- operate at the eBPF level to capture events

The information captured from Tracee will then be displayed in a results UI:

![Screenshot of the Tracee Behaviour UI](https://github.com/user-attachments/assets/039ea42f-36bd-4530-b5d9-48face5f642b)

Configuring Tracee using Policies
===

The CAPEv2 Tracee module provides `analyzer/linux/modules/auxiliary/tracee/policy.yml` to Tracee. This policy.yml file defines how Tracee should behave and what events it should capture. You can modify locally it to fit your needs.

Documentation for the policy file: https://aquasecurity.github.io/tracee/v0.20/docs/policies/

Verifying Functionality
===

After performing the Tracee setup for Linux guests detailed in [Installing the Linux guest](https://capev2.readthedocs.io/en/latest/installation/guest/linux.html), you may want to verify the functionality of your installation and make sure everything is working well.

You can obtain a **live malware sample** for Linux to load into CAPEv2 from https://bazaar.abuse.ch/sample/bd0141e88a0d56b508bc52db4dab68a49b6027a486e4d9514ec0db006fe71eed/. Please be careful with this file as it's actual malware. We do not take responsibility for anything that goes wrong.

Once the task is finished processing, the "Detailed Behaviour (Tracee)" tab ought to be available.