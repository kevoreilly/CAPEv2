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
