### Yara categories explained

* Server side -> [`data/yara/<CATEGORY>`](https://github.com/kevoreilly/CAPEv2/tree/master/data/yara)

    * This yara is initialized in `lib/cuckoo/core/startup.py`
        * So if your yara doesn't work pay attention to output log of `cape-processor.service` or `process.py` if executed manually, might be autodisabled due to compilation problems

    * CAPE - Will scan EVERYTHING, binaries, memory, payloads, procdumps, procmemory, etc...
    * binaries - only applied to initial sample, that user submit
    * urls -
    * memory - used for Volatility's YaraScan module, if enabled
    * macro - office extracted macros

* VM side -> [`analizer/windows/data/yara`](https://github.com/kevoreilly/CAPEv2/tree/master/analyzer/windows/data/yara)
    * Yaras for byppases or script monitor execution
    * It's not precompiled on server side due to that monitor and server side yara should use the same version
