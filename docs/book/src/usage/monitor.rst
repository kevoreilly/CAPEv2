===============
CAPE's debugger
===============

* Is unique among Windows debuggers, and is one of the most powerful features of the sandbox, having been built from scratch with the overriding design principles of minimal (almost zero) use of Windows debugging interfaces, maximal use of the processor's debugging hardware, and to be quick and easy to use.
* Here is a quick guide on getting started with the debugger:
* For starters it's worth emphasising that the debugger is programmable but not interactive; thus you configure it when submitting a sample, allow it to run, then check the results at the end in the form of the debugger log (in the debugger tab).

Breakpoints: bp0, bp1, bp2
==========================
* Perhaps the simplest of the debugger options is bp to set one of three cpu breakpoints. While the hardware does technically provide four breakpoints, one must be reserved for the debugger to maintain the ability to step-over during tracing (this is essential for single-step mode).
* The simplest form of this option is to set it to 'ep': ``bp0=ep``

* This will instruct the debugger to break on the entry point of the main executable of each process and begin tracing. (In the case of a DLL, this breakpoint will also be set on the entrypoint of the DLL). When the breakpoint hits, any corresponding actions will be performed (see later) and the instruction broken upon will be output to the log. As long as the count (see later) hasn't been set to zero, the debugger will then proceed to trace the instruction flow in single-step mode.
* To target specific code regions more accurately, breakpoints on specific addresses can be used. These values are interpreted as RVA values unless they are above a hardcoded value (0x200000) in which case they are interpreted as VA values. This allows both RVAs and VAs to be used interchangeably, in most cases the debugger will recognise due to its size that a value is a VA not an RVA and set the breakpoint appropriately.
* There are four breakpoints in the Intel CPU to make use of, so we could in theory use all four directly. However, the debugger in CAPE exposes only the first three. The fourth (bp3) is kept free so that it can be used in stepping over calls. There is no help from the hardware for a debugger feature like stepping over, so a breakpoint is needed to implement the depth feature but is also required for calls that CAPE debugger *must* step over, such as calls into kernel mode for example.
* We set and use bp0 through bp2 as follows. These breakpoints will be applied to each thread of each process in the analysis:
    * bp0=ep,bp1=0x1234,bp2=0x5678

Depth
=====
* The behaviour of the instruction trace in single-step mode can be characterised in terms of whether it will step into a call, or over it. From this comes the concept of depth - the debugger will trace at the same depth in a trace by stepping over calls to deeper functions. Thus if we set a depth of zero (which is also the default) the behaviour will be to step over all the subsequent calls (at least until a ret is encountered):
    * depth=0
* If we set a depth of, say, three, then the debugger will step into calls into further levels of depth three times:
    * depth=3

Count
=====
* The other obvious characteristic of our trace is its length, or count of instructions. This is set with the count option, for example:
    * count=10000
* The count may also be specified as a hexadecimal:
    * count=0xff00

* In order to limit the size of the output, the debugger starts with some default values for some important parameters which are worth understanding to enable more advanced use. The first two parameters that are really important are count and depth. As mentioned above, the default depth is zero and the default count is 0x4000.

Break-on-return
===============
* Sometimes it might be more convenient or quicker to take advantage of the fact that a certain API call is made from an interesting code region, with its return or 'caller' address to the region in question accompanying the API output in the behavior log. We can tell the debugger to use that return address as a breakpoint with the break-on-return option, for example:
    * break-on-return=RtlDecompressBuffer

Base-on-api
===========
* Instead of breaking directly on the return address of an API, we may just wish to base our breakpoints on the same base address as a particular API. For this we use the base-on-api option, for example:
    * base-on-api=NtSetInformationThread

* This option requires that the breakpoint RVA value be specified by one of the breakpoint options (bp, br).

Base-on-alloc
=============
* An obvious restriction using this method is that the API call from which the image base is determined must be made before the code we wish to put a breakpoint on is executed. For this reason there exists an alternative option, base-on-alloc, which will attempt to set the breakpoint RVA relative to every newly executable region (whether through allocation or protection). The advantage with this method is that the breakpoint will always be set before the code can execute, but the downside is that breakpoints may repeatedly be set needlessly with allocations that are not of interest. This is simply set by the option:
    * base-on-alloc=1

Actions
=======
* Often we might wish to perform an action when a breakpoint is hit. These actions can be defined by the options: action0, action1 and action2, each corresponding to a respective breakpoint. The action is specified by a simple string (not case sensitive). The list of actions is constantly growing, so if need arises for further actions, they can be simply added.
* For example, we might wish to divert the execution flow upon a conditional jump JZ - 'flip' the direction of a branch. Since this is one of the most useful actions, there are a number of actions to choose from.
* For direct control over the instruction pointer:
    * Skip
    * Jmp

* To control the CPU zero flag:
    * SetZeroFlag, ClearZeroFlag, FlipZeroFlag
* To control the sign flag:
    * SetSignFlag, ClearSignFlag, FlipSignFlag

* The carry flag:
    * SetCarryFlag, ClearCarryFlag & FlipCarryFlag

* The 'skip' action is equivalent to 'nopping out' the instruction. The Jmp action results in the jump always being taken, no matter what the state of the flags or the condition. The remaiining options set, clear or flip the relevant flags. For example:
    * bp0=0x1234,action0=skip

* Here upon breaking on the instruction at 0x1234, the instruction will be skipped.

Type
====
* Although the debugger defaults to execution breakpoints, it is also possible to set data breakpoints either for read only, or both read & write. This is specified with the options: type0, type1 and type2 for the corresponding breakpoint. The type option uses the following values:

* r - read only
* w - write and read
* x - execution
* For example:
    * type0=w,type1=r


br1, br2, br3
=============
* Sometimes it may be convenient to set a breakpoint on the return address of a function, for example when it might be easier to write a YARA signature to detect a function but when you wish to break after it has executed.
* For this the br options exist, where br0 will set a breakpoint on the return address of the function at the supplied address.
* For example:
    * br0=0x4567
* Since the return address (for the breakpoint) is fetched from the top of the stack, the addresses supplied must either be the very first instruction of the function, or certainly must come before any instruction that modifies the stack pointer such as push or pop.

Fake-rdtsc
==========
* In order to 'emulate' (skip and fake) the rdtsc instruction, the option fake-rdtsc=1 may be set. This will only have an effect on rdtsc instructions that are traced over by the debugger. If the debugger is not tracing at the time the CPU executes the instruction, it cannot of course fake the return value.
* The effect of this setting is to allow the first traced rdtsc instruction to execute normally, but thereafter to fake the return value with the original return value plus whatever value is specified in the option. For example:
    * rdtsc=0x1000
* This will result in each subsequent rdtsc instruction after the first being faked with a value that has incremented by 0x1000.

Practical examples
==================

* Those examples can be outdated, but to get an idea is more than enough

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
