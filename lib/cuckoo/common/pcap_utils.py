import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from utils.tls import tlslog_to_sslkeylogfile

EDITCAP = "editcap"
EDITCAP_TIMEOUT = 60

log = logging.getLogger(__name__)


def append_file_contents_to_file(file_with_contents: Path, append_to_file: Path):
    """Append the contents of one file to another file.

    Args:
        file_with_contents: Path to the source file to read from
        append_to_file: Path to the destination file to append to
    """
    with file_with_contents.open("r") as src, append_to_file.open("a+") as dst:
        dst.write(src.read())


def file_exists_not_empty(path: Path | None) -> bool:
    """Check if a file exists and is not empty.

    Args:
        path: Path to the file to check, or None

    Returns:
        True if the path is not None, the file exists, and has size > 0, False otherwise
    """
    return bool(path and path.exists() and path.stat().st_size > 0)


def generate_pcapng(sslkeylogfile_path: Path, pcap_path: Path, outfile: Path, timeout: int = EDITCAP_TIMEOUT):
    """Generate a pcapng file from a pcap file and SSL key log file using editcap.

    Args:
        sslkeylogfile_path: Path to the SSL key log file containing TLS decryption keys
        pcap_path: Path to the input pcap file
        outfile: Path where the output pcapng file should be written
        timeout: Maximum time in seconds to wait for editcap to complete (default: EDITCAP_TIMEOUT)

    Raises:
        EmptyPcapError: If the pcap file doesn't exist or is empty
        subprocess.CalledProcessError: If editcap exits with a non-zero status
        subprocess.TimeoutExpired: If editcap execution exceeds the timeout
    """
    if not file_exists_not_empty(pcap_path):
        raise EmptyPcapError(pcap_path)
    cmd = [EDITCAP, "--inject-secrets", f"tls,{sslkeylogfile_path}", pcap_path, outfile]
    log.debug("generating pcapng with command '%s", cmd)
    subprocess.check_call(cmd, timeout=timeout)


def _has_magic(file: str | Path, magic_numbers: tuple[int, ...]) -> bool:
    """Check if a file starts with one of the given magic numbers.

    Args:
        file: Path to the file to check
        magic_numbers: Tuple of magic numbers to check for (as integers in big-endian)

    Returns:
        True if the file starts with one of the magic numbers, False otherwise

    Note:
        Magic numbers are read in big-endian byte order (the natural way to represent
        hex values). If you need to check files with different byte orders, include
        both byte order variations in the magic_numbers tuple.
    """
    if not magic_numbers:
        return False

    max_magic = max(magic_numbers)
    magic_byte_len = (max_magic.bit_length() + 7) // 8

    try:
        with open(file, "rb") as fd:
            magic_bytes = fd.read(magic_byte_len)
            # Return false if the file is too small to contain the magic number
            if len(magic_bytes) < magic_byte_len:
                return False

            magic_number = int.from_bytes(magic_bytes, byteorder="big")
            return magic_number in magic_numbers
    except (OSError, IOError):
        return False


def is_pcap(file: str | Path) -> bool:
    """Check if a file is a PCAP file by checking its magic number.

    PCAP files start with either 0xA1B2C3D4 (big-endian) or 0xD4C3B2A1 (little-endian).
    """
    return _has_magic(file, (0xA1B2C3D4, 0xD4C3B2A1))


def is_pcapng(file: str | Path) -> bool:
    """Check if a file is a PCAPNG file by checking its magic number.

    PCAPNG files start with 0x0A0D0D0A (Section Header Block magic).
    """
    return _has_magic(file, (0x0A0D0D0A,))


class EmptyPcapError(Exception):
    """Exception raised when a pcap file is empty or doesn't exist."""

    def __init__(self, pcap_path: Path):
        """Initialize the EmptyPcapError.

        Args:
            pcap_path: Path to the empty or non-existent pcap file
        """
        self.pcap_path = pcap_path
        super().__init__(f"pcap file is empty: {pcap_path}")


class PcapToNg:
    """Combine a PCAP, TLS key log and SSL key log into a .pcapng file.

    Requires the `editcap` executable."""

    def __init__(self, pcap_path: str | Path, tlsdump_log: Path | str | None = None, sslkeys_log: Path | str | None = None):
        """Initialize the PcapToNg converter.

        Args:
            pcap_path: Path to the source pcap file
            tlsdump_log: Optional path to the CAPEMON TLS dump log file
            sslkeys_log: Optional path to the SSLKEYLOGFILE format key log
        """
        self.pcap_path = Path(pcap_path)
        self.pcapng_path = Path(f"{self.pcap_path}ng")
        self.tlsdump_log = Path(tlsdump_log) if tlsdump_log else None
        self.sslkeys_log = Path(sslkeys_log) if sslkeys_log else None

    def generate(self, outfile: Path | str | None = None):
        """Generate a pcapng file by combining the pcap with TLS/SSL key logs.

        This method will:
        1. Skip generation if the output already exists and is a valid pcapng
        2. Combine TLS dump logs and SSL key logs into a temporary file
        3. Use editcap to inject the TLS secrets into the pcap to create a pcapng

        Args:
            outfile: Optional path where the pcapng should be written.
                    If None, uses the pcap_path with 'ng' suffix.

        Note:
            Errors are logged but not raised. The method returns silently if:
            - The output file already exists
            - The input pcap doesn't exist or is empty
            - editcap is not found in PATH
            - editcap execution fails
        """
        if not outfile:
            outfile = self.pcapng_path
        elif isinstance(outfile, str):
            outfile = Path(outfile)

        if outfile.exists() and is_pcapng(outfile):
            log.debug('pcapng already exists, nothing to do "%s"', outfile)
            return

        if not self.pcap_path.exists():
            log.debug('pcap not found, nothing to do "%s"', self.pcap_path)
            return

        if self.pcap_path.stat().st_size == 0:
            log.debug('pcap is empty, nothing to do "%s"', self.pcap_path)
            return

        if not shutil.which(EDITCAP):
            log.error("%s not in path and is required", EDITCAP)
            return

        failmsg = "failed to generate .pcapng"
        try:
            # Combine all TLS logs into a single file in a format that can be read by editcap
            with tempfile.NamedTemporaryFile("w", dir=self.pcap_path.parent, encoding="utf-8") as tmp_ssl_key_log:
                tmp_ssl_key_log_path = Path(tmp_ssl_key_log.name)
                # Write CAPEMON keys
                if file_exists_not_empty(self.tlsdump_log):
                    log.debug("writing tlsdump.log to temp key log file")
                    tlslog_to_sslkeylogfile(self.tlsdump_log, tmp_ssl_key_log_path)
                # Write SSLKEYLOGFILE keys
                if file_exists_not_empty(self.sslkeys_log):
                    log.debug("writing SSLKEYLOGFILE to temp key log file")
                    append_file_contents_to_file(self.sslkeys_log, tmp_ssl_key_log_path)
                generate_pcapng(tmp_ssl_key_log_path, self.pcap_path, outfile)
        except subprocess.CalledProcessError as exc:
            log.error("%s: editcap exited with code: %d", failmsg, exc.returncode)
        except subprocess.TimeoutExpired:
            log.error("%s: editcap reached timeout", failmsg)
        except (OSError, EmptyPcapError) as exc:
            log.error("%s: %s", failmsg, exc)
