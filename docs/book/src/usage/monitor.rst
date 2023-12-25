===============
CAPE's debugger
===============

CAPE's debugger is one of the most powerful features of the sandbox: a programmable debugger configured at submission by either Yara signature or submission options, allowing breakpoints to be set dynamically. This allows instruction traces of malware execution to be captured, as well as configuring actions to perform such as control flow manipulation for anti-sandbox bypasses, or dumping decrypted config regions or unpacked payloads.

What make CAPE's debugger unique among Windows debuggers is the fact that it has been built with minimal (almost zero) use of Windows debugging interfaces specifically for the purpose of malware analysis. Its goal is to make maximal use of the processor's debugging hardware but to avoid Windows interfaces which are typically targeted by anti-debug techniques.

The debugger is not interactive, its actions are pre-determined upon submission and the results can be found in the debugger log which is presented in a dedicated tab in the UI.

Th following is a quick guide on getting started with the debugger.

Breakpoints: bp0, bp1, bp2, bp3
===============================
The most important feature of the debugger is the ability to set and catch hardware breakpoints using the debug registers of the CPU. There are four breakpoints slots in the Intel CPU to make use of, however it's worth noting that there is no help from the hardware for implemening a debugger feature like stepping over calls, so to achieve this one of the four breakpoints is needed. There are instructions (such as syscalls) which cannot be stepped into, so which must be stepped over. So to allow this as well as stepping over calls via the 'depth' option, at least one breakpoint must be kept free. For more background information on the hardware used here see: https://en.wikipedia.org/wiki/X86_debug_register.

* Breakpoints are set using the options bp0, bp1, bp2 and bp3, supplying an RVA value. For example ``bp0=0x1234``. The image base for the RVAs can be set dynamically in a number of ways, please see the remainder of the documentation.
* In order to break on entry point, the option can be to set to 'ep': ``bp0=ep``.This will instruct the debugger to break on the entry point of the main executable of each process and begin tracing. (In the case of a DLL, this breakpoint will also be set on the entry point of the DLL).

Depth
=====
In single-step mode, the behaviour of a trace can be characterised in terms of whether it steps into a call, or over it. From this comes the concept of depth; the debugger will trace at the same depth in a trace by stepping-over calls to deeper functions. Thus if we set a depth of zero (which is also the default) the behaviour will be to step over all the subsequent calls (at least until a ret is encountered):

* ``depth=0``

If we set a depth of, say, three, then the debugger will step into calls into further levels of depth three times:

* ``depth=3``

Count
=====
Another important characteristic of a trace is its length or count of instructions. This is set with the count option, for example:

* ``count=10000``

The count may also be specified as hexadecimal:

* ``count=0xff00``

The default count is 0x4000.

Break-on-return
===============
Sometimes it might be more convenient or quicker to take advantage of the fact that a certain API call is made from an interesting code region, with its return or 'caller' address to the region in question accompanying the API output in the behavior log. We can tell the debugger to use that return address as a breakpoint with the break-on-return option, for example:

* ``break-on-return=RtlDecompressBuffer``

Base-on-api
===========
Instead of breaking directly on the return address of an API, we may just wish to base our breakpoints on the same base address as a particular API. For this we use the base-on-api option, for example:
* ``base-on-api=NtSetInformationThread``

* This option requires that the breakpoint RVA value be specified by one of the breakpoint options (bp, br).

Base-on-alloc
=============
An obvious restriction using this method is that the API call from which the image base is determined must be made before the code we wish to put a breakpoint on is executed. For this reason, there exists an alternative option, base-on-alloc, which will attempt to set the breakpoint RVA relative to every newly executable region (whether through allocation or protection). The advantage of this method is that the breakpoint will always be set before the code can execute, but the downside is that breakpoints may repeatedly be set needlessly with allocations that are not of interest. This is simply set by the option:
* ``base-on-alloc=1``

Actions
=======
Often we might wish to perform an action when a breakpoint is hit. These actions can be defined by the actions: action0, action1, action2, and action3, each corresponding to a respective breakpoint. The action is specified by a simple string (not case sensitive). The list of actions is constantly growing, so if the need arises for further actions, they can be simply added.

Control flow manipulation:
    * ``Skip`` --> Skip the instruction (equivalent to 'nopping out' the instruction)
    * ``Jmp`` --> Jump a specified distance, or in the case of a conditional jump instruction, always taking the jump
    * ``Goto`` --> Jump to a specified target address
    * ``Ret`` --> Return (jump) to the address on top of the stack (and pop the address off the stack)
    * ``Nop`` --> Overwrite the instruction in memory with a 'nop' (useful for example to avoid repeated breakpoints on a jmp)
    * ``Wret`` --> Overwrite the instruction in memory with a 'ret' (useful for example to avoid repeated breakpoints on a call target)
    * ``Scan`` --> Perform a Yara scan on the memory region containing the specified target address
    * ``SetBP`` --> Set another breakpoint
Dumping (payload capture/unpacking):
    * ``DumpImage`` --> Dump the current executing module (or memory region)
    * ``DumpSize`` --> Set size of dump to be captured with a subsequent 'dump' action
    * ``SetDump`` --> Set both address and (optional) size of dump to be captured with a subsequent 'dump' action
    * ``Dump`` --> Dump memory region specified by previous actions (e.g. DumpSize or SetDump)
To control the CPU zero flag:
    * ``SetZeroFlag, ClearZeroFlag, FlipZeroFlag``
To control the sign flag:
    * ``SetSignFlag, ClearSignFlag, FlipSignFlag``
The carry flag:
    * ``SetCarryFlag, ClearCarryFlag & FlipCarryFlag``
Change Register value:
    * ``SetEax (or SetRax)`` --> Change the register value Eax to the given value
    * ``SetEbx etc..``
Changing the count value:
    * Count --> Change the count value as explained above
Stack manipulation:
    * ``Push`` --> Push a given value onto the stack.
    * ``Pop`` --> Pop a value from the stack.
Probing:
    * ``DumpStack`` --> Display values on the stack (and their module name if possible)
    * ``Print`` --> Print the string buffer at the given address
Hooks:
    * ``Hooks`` --> Enable or disable the hooks (using 1 or 0)
Instruction traces can grow to be huge so often it's important to be able to stop at a chosen point. To stop the trace at a given breakpoint, the action is simply:
    * ``Stop``

The list of actions and their implementation can be found in Trace.c of Capemon(CAPE's monitor), specifically in the ActionDispatcher.
It would be really easy to add additionnal actions and there is a lot of other gadgets which could be added there depending on the needs of the debugger's user.

Type
====
Although the debugger defaults to execution breakpoints, it is also possible to set data breakpoints either for read-only, or both read & write. This is specified with the options: type0, type1, type2, and type3 for the corresponding breakpoint. The type option uses the following values:

* r - read only
* w - write and read
* x - execution
* For example:
    * ``type0=w,type1=r``


br0, br1, br2, br3
==================
 Sometimes it may be convenient to set a breakpoint on the return address of a function, for example when it might be easier to write a YARA signature to detect a function but when you wish to break after it has been executed.
 For this, the br options exist, where br0 will set a breakpoint on the return address of the function at the supplied address.
 The format for the address is the same as the one for breakpoints mentionned above.
 Since the return address (for the breakpoint) is fetched from the top of the stack, the addresses supplied must either be the very first instruction of the function or certainly must come before any instruction that modifies the stack pointer such as push or pop.

Fake-rdtsc
==========
This advanced feature is there for interacting with the TSC register. To learn more on it and what it's used for see: https://en.wikipedia.org/wiki/Time_Stamp_Counter.

* To 'emulate' (skip and fake) the rdtsc instruction, the option fake-rdtsc=1 may be set. This will only have an affect on rdtsc instructions that are traced over by the debugger. If the debugger is not tracing at the time the CPU executes the instruction, it cannot of course fake the return value.
* The effect of this setting is to allow the first traced rdtsc instruction to execute normally, but thereafter to fake the return value with the original return value plus whatever value is specified in the option. For example:

  * 'rdtsc=0x1000'

* This will result in each subsequent rdtsc instruction after the first being faked with a value that has incremented by 0x1000.

Practical examples
==================
For more and the most up-to-date versions of examples please see `<https://github.com/kevoreilly/CAPEv2/tree/master/analyzer/windows/data/yara>`_

.. code-block:: bash

    rule Guloader
    {
        meta:
            author = "kevoreilly"
            description = "Guloader bypass"
            cape_options = "bp0=$trap0,bp0=$trap1+4,action0=skip,bp1=$trap2+11,bp1=$trap3+19,action1=skip,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,"
        strings:
            $trap0 = {0F 85 [2] FF FF 81 BD ?? 00 00 00 [2] 00 00 0F 8F [2] FF FF 39 D2 83 FF 00}
            $trap1 = {49 83 F9 00 75 [1-20] 83 FF 00 [2-6] 81 FF}
            $trap2 = {39 CB 59 01 D7 49 85 C8 83 F9 00 75 B3}
            $trap3 = {61 0F AE E8 0F 31 0F AE E8 C1 E2 20 09 C2 29 F2 83 FA 00 7E CE C3}
            $antihook = {FF 34 08 [0-48] 8F 04 0B [0-80] 83 C1 04 83 F9 18 75 [0-128] FF E3}
        condition:
            2 of them
    }

    rule GuloaderB
    {
        meta:
            author = "kevoreilly"
            description = "Guloader bypass 2021 Edition"
            cape_options = "bp0=$trap0+12,action0=ret,bp1=$trap1,action1=ret2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,"
        strings:
            $trap0 = {81 C6 00 10 00 00 81 FE 00 F0 FF 7F 0F 84 [2] 00 00}
            $trap1 = {31 FF [0-24] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
            $antihook = {FF 34 08 [0-48] 8F 04 0B [0-80] 83 C1 04 83 F9 18 75 [0-128] FF E3}
        condition:
            2 of them
    }

    rule Pafish
    {
        meta:
            author = "kevoreilly"
            description = "Pafish bypass"
            cape_options = "bp0=$rdtsc_vmexit-2,action0=SetZeroFlag,count=1"
        strings:
            $rdtsc_vmexit = {8B 45 E8 80 F4 00 89 C3 8B 45 EC 80 F4 00 89 C6 89 F0 09 D8 85 C0 75 07}
        condition:
            uint16(0) == 0x5A4D and $rdtsc_vmexit
    }

    rule Ursnif3
    {
        meta:
            author = "kevoreilly"
            description = "Ursnif Config Extraction"
            cape_options = "br0=$crypto32-73,instr0=cmp,dumpsize=eax,action0=dumpebx,dumptype0=0x24,count=1"
        strings:
            $golden_ratio = {8B 70 EC 33 70 F8 33 70 08 33 30 83 C0 04 33 F1 81 F6 B9 79 37 9E C1 C6 0B 89 70 08 41 81 F9 84 00 00 00}
            $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
            $crypto32_2 = {8B 45 EC 0F B6 38 FF 45 EC 33 C9 41 8B C7 23 C1 40 40 D1 EF 75 1B 89 4D 08 EB 45}
        condition:
            ($golden_ratio) and any of ($crypto32*)
    }

As shown in the example above, the debugger options are passed in the cape_options section of yar files in the analyzer of CAPE but could be passed to the submission itself like other parameters.
It is important to note that even through it appear that br0 and br1 would have multiple values in the Guloader rule above, it is not the case and it's not possible to assign multiples values to them. This is because the yara is designed with an assumption in mind: the patterns $trap0 and $trap1 should never appear concurrently in the same sample. This particular sig is designed to deal with two variants of the same malware where bp0 and bp1 will only ever be set to either one of those values.

Importing instruction traces into disassembler
==============================================
It is possible to import CAPE's debugger output into a dissassembler.
One example procedure is as follow:
* Highlight CFG in disassembler:

.. code-block:: bash

    1 Install lighthouse plugin from
        pip3 install git+https://github.com/kevoreilly/lighthouse
    2 Load payload into IDA
    3 Check image base matches that from debugger log (if not rebase)
    4 Go to File -> Load File -> Code coverage file and load debugger logfile (ignore any warnings - any address outside image base causes these)

.. image:: ../_images/screenshots/debugger2disassembler.png
    :align: center
