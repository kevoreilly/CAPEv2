# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package
from lib.common.constants import OPT_CLASS

log = logging.getLogger(__name__)


class Jar(Package):
    """Java analysis package."""

    PATHS = [
        # javaw.exe preferred (no console window)
        ("ProgramFiles", "Java", "jre*", "bin", "javaw.exe"),
        ("ProgramFiles", "Java", "jdk*", "bin", "javaw.exe"),
        ("ProgramFiles", "Java", "jdk-*", "bin", "javaw.exe"),
        ("ProgramFiles", "Microsoft", "jdk-*", "bin", "javaw.exe"),
        ("ProgramFiles", "Eclipse Adoptium", "jdk-*", "bin", "javaw.exe"),
        ("ProgramFiles", "Eclipse Adoptium", "jre-*", "bin", "javaw.exe"),
        ("ProgramFiles", "OpenJDK", "jdk-*", "bin", "javaw.exe"),
        # java.exe fallback
        ("ProgramFiles", "Java", "jre*", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jdk*", "bin", "java.exe"),
        ("ProgramFiles", "Java", "jdk-*", "bin", "java.exe"),
        ("ProgramFiles", "Microsoft", "jdk-*", "bin", "java.exe"),
        ("ProgramFiles", "Eclipse Adoptium", "jdk-*", "bin", "java.exe"),
        ("ProgramFiles", "Eclipse Adoptium", "jre-*", "bin", "java.exe"),
        ("ProgramFiles", "OpenJDK", "jdk-*", "bin", "java.exe"),
    ]
    summary = "Executes a .jar file using javaw.exe (or java.exe)."
    description = f"""Uses 'javaw.exe -jar [path]' to run the given sample.
    Falls back to java.exe if javaw.exe is not available.
    If the '{OPT_CLASS}' option is specified, uses '-cp [path] [class]'
    to run the named java class instead."""
    option_names = (OPT_CLASS,)

    def start(self, path):
        java = self.get_path_glob("Java")
        class_path = self.options.get("class")

        java_opts = []
        # When SSLproxy MITM is active, tell Java to use the Windows
        # certificate store so it trusts the MITM CA without needing
        # to import it into Java's cacerts keystore.
        if self.options.get("sslproxy"):
            java_opts.extend([
                "-Djavax.net.ssl.trustStoreType=Windows-ROOT",
                "-Djavax.net.ssl.trustStore=NUL",
            ])

        if java_opts:
            os.environ["JAVA_TOOL_OPTIONS"] = " ".join(java_opts)
            log.info("Set JAVA_TOOL_OPTIONS=%s", os.environ["JAVA_TOOL_OPTIONS"])

        args = f'-cp "{path}" {class_path}' if class_path else f'-jar "{path}"'
        log.info("Executing: %s %s", java, args)
        return self.execute(java, args, path)
