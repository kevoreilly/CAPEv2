===============
What is CAPE?
===============

CAPE is an open source automated malware analysis system.

It's used to automatically run and analyze files and collect comprehensive
analysis results that outline what the malware does while running inside an
isolated Windows operating system.

It can retrieve the following type of results:

    * Traces of win32 API calls performed by all processes spawned by the malware.
    * Files being created, deleted and downloaded by the malware during its execution.
    * Memory dumps of the malware processes.
    * Network traffic trace in PCAP format.
    * Screenshots of Windows desktop taken during the execution of the malware.
    * Full memory dumps of the machines.

Some History
============

Cuckoo Sandbox started as a `Google Summer of Code`_ project in 2010 within
`The Honeynet Project`_.
It was originally designed and developed by *Claudio “nex” Guarnieri*, who is
still the main developer and coordinates all efforts from joined developers and
contributors.

After initial work during the summer 2010, the first beta release was published
on Feb. 5th 2011, when Cuckoo was publicly announced and distributed for the
first time.

In March 2011, Cuckoo has been selected again as a supported project during
Google Summer of Code 2011 with The Honeynet Project, during which
*Dario Fernandes* joined the project and extended its functionality.

On November 2nd 2011 Cuckoo the release of its 0.2 version to the public as the
first real stable release.
On late November 2011 *Alessandro "jekil" Tanasi* joined the team expanding
Cuckoo's processing and reporting functionality.

On December 2011 Cuckoo v0.3 gets released and quickly hits release 0.3.2 in
early February.

In late January 2012 we opened `Malwr.com`_, a free and public running Cuckoo
Sandbox instance provided with a full fledged interface through which people
can submit files to be analysed and get results back.

In March 2012 Cuckoo Sandbox wins the first round of the `Magnificent7`_ program
organized by `Rapid7`_.

During the Summer of 2012 *Jurriaan "skier" Bremer* joined the development team,
refactoring the Windows analysis component sensibly improving the analysis'
quality.

On 24th July 2012, Cuckoo Sandbox 0.4 is released.

On 20th December 2012, Cuckoo Sandbox 0.5 "To The End Of The World" is released.

On 15th April 2013 we released Cuckoo Sandbox 0.6, shortly after having launched
the second version of `Malwr.com`_.

On 1st August 2013 *Claudio “nex” Guarnieri*, *Jurriaan "skier" Bremer* and
*Mark "rep" Schloesser* presented `Mo' Malware Mo' Problems - Cuckoo Sandbox to the rescue`_
at Black Hat Las Vegas.

On 9th January 2014, Cuckoo Sandbox 1.0 is released.

In March 2014 `Cuckoo Foundation`_ born as non-profit organization dedicated to growth of Cuckoo Sandbox and the
surrounding projects and initiatives.

On 7th April 2014, Cuckoo Sandbox 1.1 is released.

.. _`Google Summer of Code`: http://www.google-melange.com
.. _`The Honeynet Project`: http://www.honeynet.org
.. _`Malwr.com`: http://malwr.com
.. _`Magnificent7`: http://community.rapid7.com/community/open_source/magnificent7
.. _`Mo' Malware Mo' Problems - Cuckoo Sandbox to the rescue`: https://media.blackhat.com/us-13/US-13-Bremer-Mo-Malware-Mo-Problems-Cuckoo-Sandbox-Slides.pdf
.. _`Rapid7`: http://www.rapid7.com
.. _`Cuckoo Foundation`: http://cuckoofoundation.org/

On 30th of November 2015 Cuckoo-modified was moved to Brad's repository, that got huge improvements to monitor and other parts of core system
.. _ `Cuckoo-modified`: https://github.com/spender-sandbox/cuckoo-modified

On 16th September 2016 CAPE(Configuration And Payload Extraction) was born
.. _ `CAPE CTXIS`: https://github.com/ctxis/CAPE
.. _ `CAPE upstream`: https://github.com/kevoreilly/CAPE

On 20th October 2019 CAPEv2 Python3
.. _ `CAPEv2 upstream`: https://github.com/kevoreilly/CAPEv2


Use Cases
=========

CAPE is designed to be used both as a standalone application as well as to be
integrated in larger frameworks, thanks to its extremely modular design.

It can be used to analyze:

    * Generic Windows executables
    * DLL files
    * PDF documents
    * Microsoft Office documents
    * URLs and HTML files
    * PHP scripts
    * CPL files
    * Visual Basic (VB) scripts
    * ZIP files
    * Java JAR
    * Python files
    * *Almost anything else*

Thanks to its modularity and powerful scripting capabilities, there's not limit
to what you can achieve with CAPE.

For more information on customizing CAPE, see the :doc:`../customization/index`
chapter.

Architecture
============

CAPE Sandbox consists of a central management software which handles sample
execution and analysis.

Each analysis is launched in a fresh and isolated virtual machine.
CAPE's infrastructure is composed by an Host machine (the management
software) and a number of Guest machines (virtual machines for analysis).

The Host runs the core component of the sandbox that manages the whole
analysis process, while the Guests are the isolated environments
where the malware samples get actually safely executed and analyzed.

The following picture explains CAPE's main architecture:

    .. image:: ../_images/schemas/architecture-main.png
        :align: center

Although the recommended setup is *GNU/Linux* (Ubuntu LTS preferably) as host and
*Windows 7* as guest.

Obtaining CAPE
================

CAPE can be downloaded from the `official git repository`_, where the stable and
packaged releases are distributed, or can be cloned from our `official git
repository`_.

    .. warning::

        Tt most likely lacks updated documentation will happens, for that we try to keep `changelog`_.

.. _`official git repository`: https://github.com/kevoreilly/CAPEv2
.. _`changelog`: https://github.com/kevoreilly/CAPEv2/blob/master/changelog.md

