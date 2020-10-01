===========================================================================
Here are some examples about how to test your extensions of current modules
===========================================================================

Curtain
=======

Curtain is powershell logging/processing and deobfuscating module

To test your improvement of deobfuscation::

.. code-block:: python

    from modules.processing.curtain import deobfuscate
    blob = """here"""
    print(deobfuscate(blob))

Suricata name detection
=======================

.. code-block:: python

    import os, sys
    CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
    sys.path.append(CUCKOO_ROOT)

    from lib.cuckoo.core.plugins import get_suricata_family
    # Signature example: "ET MALWARE Sharik/Smoke CnC Beacon 11"
    print(get_suricata_family(signature_string))
