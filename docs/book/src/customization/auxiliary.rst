=================
Auxiliary Modules
=================

**Auxiliary** modules define some procedures that need to be executed in parallel
to every single analysis process.
All auxiliary modules should be placed under the *modules/auxiliary/* directory.

The skeleton of a module would look something like this:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Auxiliary

        class MyAuxiliary(Auxiliary):

            def start(self):
                # Do something.

            def stop(self):
                # Stop the execution.

The function ``start()`` will be executed before starting the analysis machine and effectively
executing the submitted malicious file, while the ``stop()`` function will be launched at the
very end of the analysis process, before launching the processing and reporting procedures.

For example, an auxiliary module provided by default in CAPE is called *sniffer.py* and
takes care of executing **tcpdump** in order to dump the generated network traffic.

Auxiliary Module Configuration
==============================

Auxiliary modules can be "configured" before being started. This allows data to be added
at runtime, whilst also allowing for the configuration to be stored separately from the
CAPE python code.

Private Auxiliary Module Configuration
--------------------------------------

Private auxiliary module configuration is stored outside the auxiliary class, in a module
under the same name as the auxiliary module. This is useful when managing configuration
of auxiliary modules separately if desired, for privacy reasons or otherwise.

Here is a configuration module example that installs some software prior to the auxiliary
module starting:

    .. code-block:: python
        :linenos:

        # data/auxiliary/example.py
        import subprocess
        import logging
        from pathlib import Path

        log = logging.getLogger(__name__)
        BIN_PATH = Path.cwd() / "bin"


        def configure(aux_instance):
            # here "example" refers to modules.auxiliary.example.Example
            if not aux_instance.enabled:
                return
            msi = aux_instance.options.get("example_msi")
            if not msi:
                return
            msi_path = BIN_PATH / msi
            if not msi_path.exists():
                log.warning("missing MSI %s", msi_path)
                return
            cmd = ["msiexec", "/i", msi_path, "/quiet"]
            try:
                log.info("Executing msi package...")
                subprocess.check_output(cmd)
                log.info("Installation succesful")
            except subprocess.CalledProcessError as exc:
                log.error("Installation failed: %s", exc)
                return
