import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)

PCAP_HEADER_SIZE = 24


def _get_option(options, key, default=None):
    """Read `key` from `options` whether it's a dict-like or an attribute bag.

    CAPE's processing modules receive `self.options` from different callers
    in slightly different shapes (dict from task options, namespace from
    config parsing). This helper handles both without TypeErrors."""
    if options is None:
        return default
    getter = getattr(options, "get", None)
    if callable(getter):
        try:
            return getter(key, default)
        except TypeError:
            pass
    return getattr(options, key, default)


def _is_usable_pcap(path):
    return bool(path and os.path.exists(path) and os.path.getsize(path) > PCAP_HEADER_SIZE)


def resolve_processing_pcap_path(analysis_path, default_pcap_path, pcapsrc="auto"):
    """Pick the best PCAP for downstream processing modules.

    `pcapsrc` may explicitly request `mixed`, `decrypted`, or `original`.
    Any other value falls back to auto-selection: prefer `dump_mixed.pcap`,
    then `dump_decrypted.pcap`, then the original capture.
    """
    mixed_path = os.path.join(analysis_path, "dump_mixed.pcap")
    decrypted_path = os.path.join(analysis_path, "dump_decrypted.pcap")
    requested = (pcapsrc or "auto").lower()

    explicit = {
        "mixed": mixed_path,
        "decrypted": decrypted_path,
        "original": default_pcap_path,
        "default": default_pcap_path,
        "dump": default_pcap_path,
    }
    if requested in explicit:
        candidate = explicit[requested]
        return candidate if candidate == default_pcap_path or _is_usable_pcap(candidate) else default_pcap_path

    for candidate in (mixed_path, decrypted_path, default_pcap_path):
        if candidate == default_pcap_path or _is_usable_pcap(candidate):
            return candidate

    return default_pcap_path


class DecryptPcap(Processing):
    """Generate decrypted pcaps from TLS traffic using GoGoRoboCap.

    Auto-detects the best decryption method:

    1. If SSLproxy's synthetic PCAP exists (sslproxy/sslproxy.pcap), uses
       --sslproxy-clean to strip the prepended TLS ClientHello so Suricata
       can do proper protocol identification, then merges with the original
       network PCAP for a combined encrypted + decrypted view.

    2. Otherwise, collects TLS master keys from tlsdump, sslkeylogfile, and
       sslproxy master_keys.log, then decrypts dump.pcap via GoGoRoboCap.

    The ``pcapsrc`` config option can override auto-detection:
      - ``auto`` (default): try sslproxy synth first, fall back to keylog
      - ``pcap_with_keylog``: always use keylog decryption
      - ``sslproxy_synth_pcap``: always use sslproxy synthetic PCAP
    """

    key = "decryptpcap"
    order = 0  # Run before network (order=1) and suricata (order=1)

    def run(self):
        self.key = "decryptpcap"

        pcap_path = Path(self.pcap_path)
        analysis_path = Path(self.analysis_path)
        decrypted_path = analysis_path / "dump_decrypted.pcap"
        mixed_path = analysis_path / "dump_mixed.pcap"

        for p in (decrypted_path, mixed_path):
            if p.exists():
                p.unlink()

        if not pcap_path.exists() or pcap_path.stat().st_size == 0:
            return {}

        gogorobocap_bin = self.options.get("gogorobocap", "data/gogorobocap/gogorobocap-linux-amd64")
        if not os.path.isabs(gogorobocap_bin):
            gogorobocap_bin = os.path.join(CUCKOO_ROOT, gogorobocap_bin)

        if not os.path.isfile(gogorobocap_bin) or not os.access(gogorobocap_bin, os.X_OK):
            log.error("GoGoRoboCap binary not found or not executable at %s", gogorobocap_bin)
            return {}

        pcapsrc = self.options.get("pcapsrc", "auto")
        sslproxy_pcap = analysis_path / "sslproxy" / "sslproxy.pcap"
        has_synth = sslproxy_pcap.exists() and sslproxy_pcap.stat().st_size > PCAP_HEADER_SIZE

        if pcapsrc == "sslproxy_synth_pcap" or (pcapsrc == "auto" and has_synth):
            result = self._process_sslproxy_synth(gogorobocap_bin, pcap_path, analysis_path, decrypted_path, mixed_path)
            if result:
                return result
            if pcapsrc == "sslproxy_synth_pcap":
                return {}
            # auto mode: synth failed, fall through to keylog

        return self._process_keylog(gogorobocap_bin, pcap_path, analysis_path, decrypted_path, mixed_path)

    def _process_sslproxy_synth(self, gogorobocap_bin, pcap_path, analysis_path, decrypted_path, mixed_path):
        """Strip TLS ClientHello from SSLproxy synthetic PCAP, merge with original."""
        sslproxy_pcap = analysis_path / "sslproxy" / "sslproxy.pcap"
        if not sslproxy_pcap.exists() or sslproxy_pcap.stat().st_size <= PCAP_HEADER_SIZE:
            log.debug("No sslproxy.pcap found, nothing to process")
            return {}

        sslproxy_clean = analysis_path / "sslproxy" / "sslproxy_clean.pcap"
        if not self._run_sslproxy_clean(gogorobocap_bin, sslproxy_pcap, sslproxy_clean):
            return {}

        if not sslproxy_clean.exists() or sslproxy_clean.stat().st_size <= PCAP_HEADER_SIZE:
            log.debug("sslproxy-clean produced no output")
            return {}

        result = {}

        # The cleaned PCAP is the decrypted output
        try:
            os.link(str(sslproxy_clean), str(decrypted_path))
        except OSError:
            shutil.copy2(str(sslproxy_clean), str(decrypted_path))
        result["decrypted_pcap_sha256"] = File(str(decrypted_path)).get_sha256()

        # Merge original (encrypted) + cleaned (decrypted) into mixed
        if self._mergecap([pcap_path, sslproxy_clean], mixed_path):
            result["mixed_pcap_sha256"] = File(str(mixed_path)).get_sha256()

        return result

    def _process_keylog(self, gogorobocap_bin, pcap_path, analysis_path, decrypted_path, mixed_path):
        """Decrypt dump.pcap using collected TLS master keys."""
        key_sources = [
            analysis_path / "tlsdump" / "tlsdump.log",
            analysis_path / "aux" / "sslkeylogfile" / "sslkeys.log",
            analysis_path / "sslproxy" / "master_keys.log",
        ]
        available_keys = [k for k in key_sources if k.exists() and k.stat().st_size > 0]
        if not available_keys:
            return {}

        tmp_keylog_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", dir=str(analysis_path), suffix=".keylog", delete=False
            ) as tmp_keylog:
                tmp_keylog_path = tmp_keylog.name
                for key_file in available_keys:
                    for line in key_file.read_text().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        # Skip SSLproxy placeholder entries (all-zero secrets)
                        if line.endswith("0" * 96):
                            continue
                        tmp_keylog.write(line + "\n")

            if not self._run_gogorobocap(gogorobocap_bin, pcap_path, tmp_keylog_path, "decrypted", decrypted_path):
                return {}

            if not self._run_gogorobocap(gogorobocap_bin, pcap_path, tmp_keylog_path, "mixed", mixed_path):
                if decrypted_path.exists():
                    decrypted_path.unlink()
                return {}

        finally:
            if tmp_keylog_path and os.path.exists(tmp_keylog_path):
                os.unlink(tmp_keylog_path)

        result = {}
        if decrypted_path.exists() and decrypted_path.stat().st_size > PCAP_HEADER_SIZE:
            result["decrypted_pcap_sha256"] = File(str(decrypted_path)).get_sha256()
        if mixed_path.exists() and mixed_path.stat().st_size > PCAP_HEADER_SIZE:
            result["mixed_pcap_sha256"] = File(str(mixed_path)).get_sha256()

        return result

    def _run_sslproxy_clean(self, binary, input_pcap, output_pcap):
        """Run GoGoRoboCap --sslproxy-clean to strip TLS ClientHello from synthetic PCAPs."""
        cmd = [
            str(binary),
            "-sslproxy-clean",
            "-i", str(input_pcap),
            "-o", str(output_pcap),
        ]
        log.debug("Running GoGoRoboCap sslproxy-clean: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            if result.returncode != 0:
                log.error(
                    "GoGoRoboCap (sslproxy-clean) failed with code %d: %s",
                    result.returncode, result.stderr.decode(errors="replace")
                )
                return False
            log.info("GoGoRoboCap sslproxy-clean: %s", result.stdout.decode(errors="replace").strip())
            return True
        except subprocess.TimeoutExpired:
            log.error("GoGoRoboCap (sslproxy-clean) timed out after 300s")
            return False
        except OSError as e:
            log.error("Failed to execute GoGoRoboCap: %s", e)
            return False

    def _mergecap(self, input_pcaps, output_path):
        """Merge multiple PCAPs into one using mergecap."""
        cmd = ["mergecap", "-w", str(output_path)] + [str(p) for p in input_pcaps]
        log.debug("Running mergecap: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            if result.returncode != 0:
                log.error("mergecap failed with code %d: %s",
                          result.returncode, result.stderr.decode(errors="replace"))
                return False
            return True
        except subprocess.TimeoutExpired:
            log.error("mergecap timed out after 120s")
            return False
        except OSError as e:
            log.error("Failed to execute mergecap: %s", e)
            return False

    def _run_gogorobocap(self, binary, pcap_path, keylog_path, mode, output_path):
        """Run GoGoRoboCap with the given mode. Returns True on success."""
        cmd = [
            str(binary),
            "-i", str(pcap_path),
            "-keylog", str(keylog_path),
            "-tlsmode", mode,
            "-o", str(output_path),
        ]
        log.debug("Running GoGoRoboCap: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            if result.returncode != 0:
                log.error(
                    "GoGoRoboCap (%s mode) failed with code %d: %s",
                    mode, result.returncode, result.stderr.decode(errors="replace")
                )
                return False
            return True
        except subprocess.TimeoutExpired:
            log.error("GoGoRoboCap (%s mode) timed out after 300s", mode)
            return False
        except OSError as e:
            log.error("Failed to execute GoGoRoboCap: %s", e)
            return False
