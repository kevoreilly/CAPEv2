import os
import re
from dataclasses import dataclass
from typing import ClassVar


@dataclass()
class TLS12KeyLog:
    """TLS 1.2 key log."""

    # The type of secret that is being conveyed. TLS 1.2 and earlier
    # uses the label "CLIENT_RANDOM" to identify the "master" secret
    # for the connection.
    LOG_LABEL: ClassVar[str] = "CLIENT_RANDOM"
    # The 32-byte value of the Random field from the
    # 'client hello' message sent during the TLS handshake.
    client_random: str
    # The 32-byte value of the Random field from the
    # 'server hello' message sent during the TLS handshake.
    server_random: str
    # The value of the identified secret for the identified
    # connection.
    master_secret: str

    @classmethod
    def from_cape_log(cls, log):
        TLS12_PATTERN = r"client_random:\s*(?P<client_random>[a-f0-9]+)\s*,\s*server_random:\s*(?P<server_random>[a-f0-9]+)\s*,\s*master_secret:\s*(?P<master_secret>[a-f0-9]+)\s*"
        retval = None
        match = re.match(TLS12_PATTERN, log)
        params = match.groupdict() if match else {}
        if len(params) == 3:
            retval = cls(**params)
        return retval

    def __str__(self):
        """Return a string that adheres to the SSLKEYLOGFILE standard
        for TLS 1.2 (and earlier).
        """
        return f"{self.LOG_LABEL} {self.client_random} {self.master_secret}"


def tlslog_to_sslkeylogfile(tls_log_path, sslkeylogfile_path):
    """Convert Cape's TLS log file (tlsdump.log) into a format that is
    readable by WireShark (SSLKEYLOGFILE).

    The SSLKEYLOGFILE format is defined by the IETF TLS working group.
    The draft standard is published here:
    https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/
    """
    if not os.path.exists(tls_log_path):
        return

    # SSLKEYLOGFILE should be encoded using utf-8, even though the
    # content only includes ASCII characters. Though Unicode is
    # permitted in comments, the file MUST NOT contain a Unicode byte
    # order mark.
    with open(tls_log_path, "r") as ifile, open(sslkeylogfile_path, "w+", encoding="utf-8") as ofile:
        for line in ifile:
            tlslog = TLS12KeyLog.from_cape_log(line)
            if tlslog:
                ofile.write(f"{tlslog}\n")
