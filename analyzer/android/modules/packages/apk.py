import logging
import os
import subprocess
import time

from lib.core.packages import Package

log = logging.getLogger(__name__)


class Apk(Package):
    """Android APK analysis package.

    Installs the submitted APK, launches its launcher activity, and reports
    back the resulting app PID for the analyzer's process monitor. No
    dynamic instrumentation (Frida) is wired in yet -- this package covers
    install + launch + process lifecycle only.
    """

    PID_WAIT_TIMEOUT = 30
    PID_POLL_INTERVAL = 0.5

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.package_name = None

    def start(self):
        self.prepare()
        self.package_name = self._install()
        self._launch()

        pid = self._wait_for_pid()
        if pid is None:
            raise Exception(f"App {self.package_name} did not appear in the process list within {self.PID_WAIT_TIMEOUT}s")
        return pid

    def _installed_packages(self):
        out = subprocess.check_output(["pm", "list", "packages"]).decode(errors="replace")
        return {line.strip()[len("package:") :] for line in out.splitlines() if line.strip().startswith("package:")}

    def _install(self):
        before = self._installed_packages()

        # -r: replace an existing install of the same package.
        # -g: grant all runtime permissions at install time, so a permission
        #     dialog can't block the app from ever reaching its payload.
        # Try with -g first (supported on API >= 23). Fall back to omitting -g
        # on older APIs if it fails with an invalid option error.
        result = subprocess.run(
            ["pm", "install", "-r", "-g", self.target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output = result.stdout.decode(errors="replace")
        log.info("pm install output: %s", output.strip())

        # If -g is unrecognized/unsupported by this pm build, retry without it
        if "Success" not in output and any(x in output.lower() for x in ("unknown option", "invalid option", "-g")):
            log.warning("pm install -g failed (likely older Android version). Retrying without -g...")
            result = subprocess.run(
                ["pm", "install", "-r", self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output = result.stdout.decode(errors="replace")
            log.info("pm install (fallback) output: %s", output.strip())

        if "Success" not in output:
            raise Exception(f"Failed to install {self.target}: {output.strip()}")

        new_packages = self._installed_packages() - before
        if len(new_packages) == 1:
            return new_packages.pop()

        # Reinstall of an already-present package (same sample submitted
        # twice, or a pre-seeded system app) won't show up as "new" -- fall
        # back to parsing it straight out of the APK manifest.
        guessed = self._package_name_from_aapt()
        if guessed:
            return guessed

        if new_packages:
            guess = next(iter(new_packages))
            log.warning("Install added multiple new packages %s, guessing %s", new_packages, guess)
            return guess

        raise Exception(
            f"Could not determine package name for {self.target}: "
            "pm list packages showed no new entries and aapt is unavailable"
        )

    def _package_name_from_aapt(self):
        for binary in ("aapt2", "aapt"):
            try:
                out = subprocess.check_output([binary, "dump", "badging", self.target], stderr=subprocess.DEVNULL).decode(
                    errors="replace"
                )
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
            for line in out.splitlines():
                if line.startswith("package:"):
                    for field in line.split():
                        if field.startswith("name="):
                            return field.split("=", 1)[1].strip("'")
        return None

    def _launch(self):
        # /system/bin/monkey ships with no shebang line on this build (just a
        # bare "#" comment), so exec()'ing it directly raises ENOEXEC --
        # interactive shells silently retry through sh on that errno,
        # subprocess does not. Route it through sh explicitly instead, using
        # sh's own positional-parameter substitution so package_name never
        # needs manual shell-quoting.
        subprocess.run(
            ["sh", "-c", 'exec monkey -p "$1" -c android.intent.category.LAUNCHER 1', "sh", self.package_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _wait_for_pid(self):
        deadline = time.time() + self.PID_WAIT_TIMEOUT
        while time.time() < deadline:
            pid = self._pid_for_package()
            if pid is not None:
                return pid
            time.sleep(self.PID_POLL_INTERVAL)
        return None

    def _pid_for_package(self):
        try:
            out = subprocess.check_output(["pidof", self.package_name], stderr=subprocess.DEVNULL)
            pids = out.decode().strip().split()
            if pids:
                return int(pids[0])
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
            pass

        # pidof can miss a process that's still mid-fork from zygote; fall
        # back to scanning /proc directly for an exact cmdline match.
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/cmdline", "rb") as f:
                        cmdline = f.read().split(b"\x00")[0].decode(errors="replace")
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if cmdline == self.package_name:
                    return int(entry)
        except FileNotFoundError:
            pass
        return None

    def finish(self):
        if self.package_name:
            subprocess.run(["am", "force-stop", self.package_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
