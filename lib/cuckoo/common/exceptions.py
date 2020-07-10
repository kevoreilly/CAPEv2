# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


class CuckooCriticalError(Exception):
    """Cuckoo struggle in a critical error."""

    pass


class CuckooStartupError(CuckooCriticalError):
    """Error starting up Cuckoo."""

    pass


class CuckooDatabaseError(CuckooCriticalError):
    """Cuckoo database error."""

    pass


class CuckooDependencyError(CuckooCriticalError):
    """Missing dependency error."""

    pass


class CuckooOperationalError(Exception):
    """Cuckoo operation error."""

    pass


class CuckooMachineError(CuckooOperationalError):
    """Error managing analysis machine."""

    pass


class CuckooMachineSnapshotError(CuckooMachineError):
    """Error restoring snapshot from machine."""

    pass


class CuckooAnalysisError(CuckooOperationalError):
    """Error during analysis."""

    pass


class CuckooProcessingError(CuckooOperationalError):
    """Error in processor module."""

    pass


class CuckooReportError(CuckooOperationalError):
    """Error in reporting module."""

    pass


class CuckooGuestError(CuckooOperationalError):
    """Cuckoo guest agent error."""

    pass


class CuckooGuestCriticalTimeout(CuckooGuestError):
    """The Host was unable to connect to the Guest."""

    pass


class CuckooResultError(CuckooOperationalError):
    """Cuckoo result server error."""

    pass


class CuckooDisableModule(CuckooOperationalError):
    """Exception for disabling a module dynamically."""

    pass


class CuckooFeedbackError(CuckooOperationalError):
    """Error in feedback module."""


class CuckooApiError(CuckooOperationalError):
    """Error during API usage."""

    pass


class CuckooDemuxError(CuckooOperationalError):
    """Error in demux module."""

    pass
