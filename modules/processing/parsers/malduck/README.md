:duck: Malduck
=========

Malduck is your ducky companion in malware analysis journeys. It is mostly based on [Roach](https://github.com/hatching/roach) project, which derives many concepts from [mlib](https://github.com/mak/mlib) 
library created by [Maciej Kotowicz](https://lokalhost.pl). The purpose of fork was to make Roach independent from [Cuckoo Sandbox](https://cuckoosandbox.org/) project, but still supporting its internal `procmem` format.

Malduck provides many improvements resulting from CERT.pl codebase, making scripts written for malware analysis purposes much shorter and more powerful. 

Improvements
============

* Support for (non)memory-mapped PE images without header fix-up.
* Searching for wildcarded byte sequences
* Support for x64 disassembly
* Fixed-precision integer types
* Many improvements in ProcessMemory

Usage
==========

Installing may be performed by running

```
pip install malduck
```

Usage documentation can be found [on readthedocs](https://malduck.readthedocs.io/en/latest/).

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)