# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


def DispositionDict():
    return {1: "REG_CREATED_NEW_KEY", 2: "REG_OPENED_EXISTING_KEY"}


def ClsContextDict():
    return {
        "CLSCTX_INPROC_SERVER": 0x1,
        "CLSCTX_INPROC_HANDLER": 0x2,
        "CLSCTX_LOCAL_SERVER": 0x4,
        "CLSCTX_INPROC_SERVER16": 0x8,
        "CLSCTX_REMOTE_SERVER": 0x10,
        "CLSCTX_INPROC_HANDLER16": 0x20,
        "CLSCTX_NO_CODE_DOWNLOAD": 0x400,
        "CLSCTX_NO_CUSTOM_MARSHAL": 0x1000,
        "CLSCTX_ENABLE_CODE_DOWNLOAD": 0x2000,
        "CLSCTX_NO_FAILURE_LOG": 0x4000,
        "CLSCTX_DISABLE_AAA": 0x8000,
        "CLSCTX_ENABLE_AAA": 0x10000,
        "CLSCTX_FROM_DEFAULT_CONTEXT": 0x20000,
        "CLSCTX_ACTIVATE_32_BIT_SERVER": 0x40000,
        "CLSCTX_ACTIVATE_64_BIT_SERVER": 0x80000,
        "CLSCTX_ENABLE_CLOAKING": 0x100000,
        "CLSCTX_APPCONTAINER": 0x400000,
        "CLSCTX_ACTIVATE_AAA_AS_IU": 0x800000,
        "CLSCTX_PS_DLL": 0x80000000,
    }


def BlobTypeDict():
    return {
        0x0001: "SIMPLEBLOB",
        0x0006: "PUBLICKEYBLOB",
        0x0007: "PRIVATEKEYBLOB",
        0x0008: "PLAINTEXTKEYBLOB",
        0x0009: "OPAQUEKEYBLOB",
        0x000A: "PUBLICKEYBLOBEX",
        0x000B: "SYMMETRICWRAPKEYBLOB",
        0x000C: "KEYSTATEBLOB",
    }


def AlgidDict():
    return {
        0x0001: "AT_KEYEXCHANGE",
        0x0002: "AT_SIGNATURE",
        0x8001: "MD2",
        0x8002: "MD4",
        0x8003: "MD5",
        0x8004: "SHA1",
        0x800C: "SHA_256",
        0x800D: "SHA_384",
        0x800E: "SHA_512",
        0x8005: "MAC",
        0x8009: "HMAC",
        0x2400: "RSA Public Key Signature",
        0x2200: "DSA Public Key Signature",
        0xA400: "RSA Public Key Exchange",
        0x6602: "RC2",
        0x6801: "RC4",
        0x660D: "RC5",
        0x6601: "DES",
        0x6603: "3DES",
        0x6604: "DESX",
        0x6609: "Two-key 3DES",
        0x6611: "AES",
        0x660E: "AES_128",
        0x660F: "AES_192",
        0x6610: "AES_256",
        0xAA03: "AGREEDKEY_ANY",
        0x660C: "CYLINK_MEK",
        0xAA02: "DH_EPHEM",
        0xAA01: "DH_SF",
        0xAA05: "ECDH",
        0x2203: "ECDSA",
        0xA001: "ECMQV",
        0x800B: "HASH_REPLACE_OWF",
        0xA003: "HUGHES_MD5",
        0x2000: "NO_SIGN",
    }


def FolderDict():
    return {
        0: "CSIDL_DESKTOP",
        1: "CSIDL_INTERNET",
        2: "CSIDL_PROGRAMS",
        3: "CSIDL_CONTROLS",
        4: "CSIDL_PRINTERS",
        5: "CSIDL_MYDOCUMENTS",
        6: "CSIDL_FAVORITES",
        7: "CSIDL_STARTUP",
        8: "CSIDL_RECENT",
        9: "CSIDL_SENDTO",
        10: "CSIDL_BITBUCKET",
        11: "CSIDL_STARTMENU",
        13: "CSIDL_MYMUSIC",
        14: "CSIDL_MYVIDEO",
        16: "CSIDL_DESKTOPDIRECTORY",
        17: "CSIDL_DRIVES",
        18: "CSIDL_NETWORK",
        19: "CSIDL_NETHOOD",
        20: "CSIDL_FONTS",
        21: "CSIDL_TEMPLATES",
        22: "CSIDL_COMMON_STARTMENU",
        23: "CSIDL_COMMON_PROGRAMS",
        24: "CSIDL_COMMON_STARTUP",
        25: "CSIDL_COMMON_DESKTOPDIRECTORY",
        26: "CSIDL_APPDATA",
        27: "CSIDL_PRINTHOOD",
        28: "CSIDL_LOCAL_APPDATA",
        29: "CSIDL_ALTSTARTUP",
        30: "CSIDL_COMMON_ALTSTARTUP",
        31: "CSIDL_COMMON_FAVORITES",
        32: "CSIDL_INTERNET_CACHE",
        33: "CSIDL_COOKIES",
        34: "CSIDL_HISTORY",
        35: "CSIDL_COMMON_APPDATA",
        36: "CSIDL_WINDOWS",
        37: "CSIDL_SYSTEM",
        38: "CSIDL_PROGRAM_FILES",
        39: "CSIDL_MYPICTURES",
        40: "CSIDL_PROFILE",
        41: "CSIDL_SYSTEMX86",
        42: "CSIDL_PROGRAM_FILESX86",
        43: "CSIDL_PROGRAM_FILES_COMMON",
        44: "CSIDL_PROGRAM_FILES_COMMONX86",
        45: "CSIDL_COMMON_TEMPLATES",
        46: "CSIDL_COMMON_DOCUMENTS",
        47: "CSIDL_COMMON_ADMINTOOLS",
        48: "CSIDL_ADMINTOOLS",
        49: "CSIDL_CONNECTIONS",
        53: "CSIDL_COMMON_MUSIC",
        54: "CSIDL_COMMON_PICTURES",
        55: "CSIDL_COMMON_VIDEO",
        56: "CSIDL_RESOURCES",
        57: "CSIDL_RESOURCES_LOCALIZED",
        58: "CSIDL_COMMON_OEM_LINKS",
        59: "CSIDL_CDBURN_AREA",
        61: "CSIDL_COMPUTERSNEARME",
    }


def HookIdentifierDict():
    return {
        # cuckoo chooses not to represent this value properly as a -1
        4294967295: "WH_MSGFILTER",
        0: "WH_JOURNALRECORD",
        1: "WH_JOURNALPLAYBACK",
        2: "WH_KEYBOARD",
        3: "WH_GETMESSAGE",
        4: "WH_CALLWNDPROC",
        5: "WH_CBT",
        6: "WH_SYSMSGFILTER",
        7: "WH_MOUSE",
        8: "WH_HARDWARE",
        9: "WH_DEBUG",
        10: "WH_SHELL",
        11: "WH_FOREGROUNDIDLE",
        12: "WH_CALLWNDPROCRET",
        13: "WH_KEYBOARD_LL",
        14: "WH_MOUSE_LL",
    }


def InfoLevelDict():
    return {
        1: "HTTP_QUERY_CONTENT_TYPE",
        5: "HTTP_QUERY_CONTENT_LENGTH",
        6: "HTTP_QUERY_CONTENT_LANGUAGE",
        9: "HTTP_QUERY_DATE",
        10: "HTTP_QUERY_EXPIRES",
        18: "HTTP_QUERY_VERSION",
        21: "HTTP_QUERY_RAW_HEADERS",
    }


def CreateDispositionDict():
    return {
        0: "FILE_SUPERSEDE",
        1: "FILE_OPEN",
        2: "FILE_CREATE",
        3: "FILE_OPEN_IF",
        4: "FILE_OVERWRITE",
        5: "FILE_OVERWRITE_IF",
    }


def SystemInformationClassDict():
    return {
        0: "FILE_SUPERSEDE",
        1: "FILE_OPEN",
        2: "FILE_CREATE",
        3: "FILE_OPEN_IF",
        4: "FILE_OVERWRITE",
        5: "FILE_OVERWRITE_IF",
    }


def RegistryTypeDict():
    return {
        0: "REG_NONE",
        1: "REG_SZ",
        2: "REG_EXPAND_SZ",
        3: "REG_BINARY",
        4: "REG_DWORD",
        5: "REG_DWORD_BIG_ENDIAN",
        6: "REG_LINK",
        7: "REG_MULTI_SZ",
        8: "REG_RESOURCE_LIST",
        9: "REG_FULL_RESOURCE_DESCRIPTOR",
        10: "REG_RESOURCE_REQUIREMENTS_LIST",
        11: "REG_QWORD",
    }


def ServicesControlCodeDict():
    return {
        1: "SERVICE_CONTROL_STOP",
        2: "SERVICE_CONTROL_PAUSE",
        3: "SERVICE_CONTROL_CONTINUE",
        4: "SERVICE_CONTROL_INTERROGATE",
        6: "SERVICE_CONTROL_PARAMCHANGE",
        7: "SERVICE_CONTROL_NETBINDADD",
        8: "SERVICE_CONTROL_NETBINDREMOVE",
        9: "SERVICE_CONTROL_NETBINDENABLE",
        10: "SERVICE_CONTROL_NETBINDDISABLE",
    }


def ServicesErrorControlDict():
    return {0: "SERVICE_ERROR_IGNORE", 1: "SERVICE_ERROR_NORMAL", 2: "SERVICE_ERROR_SEVERE", 3: "SERVICE_ERROR_CRITICAL"}


def ServicesStartTypeDict():
    return {
        0: "SERVICE_BOOT_START",
        1: "SERVICE_SYSTEM_START",
        2: "SERVICE_AUTO_START",
        3: "SERVICE_DEMAND_START",
        4: "SERVICE_DISABLED",
    }


def ServicesServiceTypeDict():
    return {
        1: "SERVICE_KERNEL_DRIVER",
        2: "SERVICE_FILE_SYSTEM_DRIVER",
        4: "SERVICE_ADAPTER",
        8: "SERVICE_RECOGNIZED_DRIVER",
        16: "SERVICE_WIN32_OWN_PROCESS",
        32: "SERVICE_WIN32_SHARE_PROCESS",
    }


def IoControlCodeDict():
    return {
        0x1200B: "IOCTL_AFD_START_LISTEN",
        0x12010: "IOCTL_AFD_ACCEPT",
        0x1201B: "IOCTL_AFD_RECV_DATAGRAM",
        0x12024: "IOCTL_AFD_SELECT",
        0x12023: "IOCTL_AFD_SEND_DATAGRAM",
        0x1207B: "IOCTL_AFD_GET_INFO",
        0x1203B: "IOCTL_AFD_SET_INFO",
        0x12047: "IOCTL_AFD_SET_CONTEXT",
        0x12003: "IOCTL_AFD_BIND",
        0x12007: "IOCTL_AFD_CONNECT",
        0x1202B: "IOCTL_AFD_DISCONNECT",
        0x120BF: "IOCTL_AFD_DEFER_ACCEPT",
        0x12017: "IOCTL_AFD_RECV",
        0x1201F: "IOCTL_AFD_SEND",
        0x1202F: "IOCTL_AFD_GET_SOCK_NAME",
        0x12087: "IOCTL_AFD_EVENT_SELECT",
        0x1208B: "IOCTL_AFD_ENUM_NETWORK_EVENTS",
        0x4D008: "IOCTL_SCSI_MINIPORT",
        0x4D014: "IOCTL_SCSI_PASS_THROUGH_DIRECT",
        0x70000: "IOCTL_DISK_GET_DRIVE_GEOMETRY",
        0x700A0: "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
        0x7405C: "IOCTL_DISK_GET_LENGTH_INFO",
        0x90018: "FSCTL_LOCK_VOLUME",
        0x9001C: "FSCTL_UNLOCK_VOLUME",
        0x900A8: "FSCTL_GET_REPARSE_POINT",
        0x2D0C10: "IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER",
        0x2D1080: "IOCTL_STORAGE_GET_DEVICE_NUMBER",
        0x2D1400: "IOCTL_STORAGE_QUERY_PROPERTY",
        0x398000: "IOCTL_KSEC_REGISTER_LSA_PROCESS",
        0x390004: "IOCTL_KSEC_1",
        0x390008: "IOCTL_KSEC_RANDOM_FILL_BUFFER",
        0x39000E: "IOCTL_KSEC_ENCRYPT_PROCESS",
        0x390012: "IOCTL_KSEC_DECRYPT_PROCESS",
        0x390016: "IOCTL_KSEC_ENCRYPT_CROSS_PROCESS",
        0x39001A: "IOCTL_KSEC_DECRYPT_CROSS_PROCESS",
        0x39001E: "IOCTL_KSEC_ENCRYPT_SAME_LOGON",
        0x390022: "IOCTL_KSEC_DECRYPT_SAME_LOGON",
        0x390038: "IOCTL_KSEC_REGISTER_EXTENSION",
        0x4D0008: "IOCTL_MOUNTDEV_QUERY_DEVICE_NAME",
        0x560000: "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
        0x6D0008: "IOCTL_MOUNTMGR_QUERY_POINTS",
        0x6D0030: "IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATH",
        0x6D0034: "IOCTL_MOUNTMGR_QUERY_DOS_VOLUME_PATHS",
    }


def CoInternetSetFeatureEnabledDict():
    return {
        0: "FEATURE_OBJECT_CACHING",
        1: "FEATURE_ZONE_ELEVATION",
        2: "FEATURE_MIME_HANDLING",
        3: "FEATURE_MIME_SNIFFING",
        4: "FEATURE_WINDOW_RESTRICTIONS",
        5: "FEATURE_WEBOC_POPUPMANAGEMENT",
        6: "FEATURE_BEHAVIORS",
        7: "FEATURE_DISABLE_MK_PROTOCOL",
        8: "FEATURE_LOCALMACHINE_LOCKDOWN",
        9: "FEATURE_SECURITYBAND",
        10: "FEATURE_RESTRICT_ACTIVEXINSTALL",
        11: "FEATURE_VALIDATE_NAVIGATE_URL",
        12: "FEATURE_RESTRICT_FILEDOWNLOAD",
        13: "FEATURE_ADDON_MANAGEMENT",
        14: "FEATURE_PROTOCOL_LOCKDOWN",
        15: "FEATURE_HTTP_USERNAME_PASSWORD_DISABLE",
        16: "FEATURE_SAFE_BINDTOOBJECT",
        17: "FEATURE_UNC_SAVEDFILECHECK",
        18: "FEATURE_GET_URL_DOM_FILEPATH_UNENCODED",
        19: "FEATURE_TABBED_BROWSING",
        20: "FEATURE_SSLUX",
        21: "FEATURE_DISABLE_NAVIGATION_SOUNDS",
        22: "FEATURE_DISABLE_LEGACY_COMPRESSION",
        23: "FEATURE_FORCE_ADDR_AND_STATUS",
        24: "FEATURE_XMLHTTP",
        25: "FEATURE_DISABLE_TELNET_PROTOCOL",
        26: "FEATURE_FEEDS",
        27: "FEATURE_BLOCK_INPUT_PROMPTS",
    }


def InternetSetOptionADict():
    return {
        1: "INTERNET_OPTION_CALLBACK",
        2: "INTERNET_OPTION_CONNECT_TIMEOUT",
        3: "INTERNET_OPTION_CONNECT_RETRIES",
        4: "INTERNET_OPTION_CONNECT_BACKOFF",
        5: "INTERNET_OPTION_SEND_TIMEOUT",
        6: "INTERNET_OPTION_RECEIVE_TIMEOUT",
        7: "INTERNET_OPTION_DATA_SEND_TIMEOUT",
        8: "INTERNET_OPTION_DATA_RECEIVE_TIMEOUT",
        9: "INTERNET_OPTION_HANDLE_TYPE",
        11: "INTERNET_OPTION_LISTEN_TIMEOUT",
        12: "INTERNET_OPTION_READ_BUFFER_SIZE",
        13: "INTERNET_OPTION_WRITE_BUFFER_SIZE",
        15: "INTERNET_OPTION_ASYNC_ID",
        16: "INTERNET_OPTION_ASYNC_PRIORITY",
        21: "INTERNET_OPTION_PARENT_HANDLE",
        22: "INTERNET_OPTION_KEEP_CONNECTION",
        23: "INTERNET_OPTION_REQUEST_FLAGS",
        24: "INTERNET_OPTION_EXTENDED_ERROR",
        26: "INTERNET_OPTION_OFFLINE_MODE",
        27: "INTERNET_OPTION_CACHE_STREAM_HANDLE",
        28: "INTERNET_OPTION_USERNAME",
        29: "INTERNET_OPTION_PASSWORD",
        30: "INTERNET_OPTION_ASYNC",
        31: "INTERNET_OPTION_SECURITY_FLAGS",
        32: "INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT",
        33: "INTERNET_OPTION_DATAFILE_NAME",
        34: "INTERNET_OPTION_URL",
        35: "INTERNET_OPTION_SECURITY_CERTIFICATE",
        36: "INTERNET_OPTION_SECURITY_KEY_BITNESS",
        37: "INTERNET_OPTION_REFRESH",
        38: "INTERNET_OPTION_PROXY",
        39: "INTERNET_OPTION_SETTINGS_CHANGED",
        40: "INTERNET_OPTION_VERSION",
        41: "INTERNET_OPTION_USER_AGENT",
        42: "INTERNET_OPTION_END_BROWSER_SESSION",
        43: "INTERNET_OPTION_PROXY_USERNAME",
        44: "INTERNET_OPTION_PROXY_PASSWORD",
        45: "INTERNET_OPTION_CONTEXT_VALUE",
        46: "INTERNET_OPTION_CONNECT_LIMIT",
        47: "INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT",
        48: "INTERNET_OPTION_POLICY",
        49: "INTERNET_OPTION_DISCONNECTED_TIMEOUT",
        50: "INTERNET_OPTION_CONNECTED_STATE",
        51: "INTERNET_OPTION_IDLE_STATE",
        52: "INTERNET_OPTION_OFFLINE_SEMANTICS",
        53: "INTERNET_OPTION_SECONDARY_CACHE_KEY",
        54: "INTERNET_OPTION_CALLBACK_FILTER",
        55: "INTERNET_OPTION_CONNECT_TIME",
        56: "INTERNET_OPTION_SEND_THROUGHPUT",
        57: "INTERNET_OPTION_RECEIVE_THROUGHPUT",
        58: "INTERNET_OPTION_REQUEST_PRIORITY",
        59: "INTERNET_OPTION_HTTP_VERSION",
        60: "INTERNET_OPTION_RESET_URLCACHE_SESSION",
        62: "INTERNET_OPTION_ERROR_MASK",
        63: "INTERNET_OPTION_FROM_CACHE_TIMEOUT",
        64: "INTERNET_OPTION_BYPASS_EDITED_ENTRY",
        65: "INTERNET_OPTION_HTTP_DECODING",
        67: "INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO",
        68: "INTERNET_OPTION_CODEPAGE",
        69: "INTERNET_OPTION_CACHE_TIMESTAMPS",
        70: "INTERNET_OPTION_DISABLE_AUTODIAL",
        73: "INTERNET_OPTION_MAX_CONNS_PER_SERVER",
        74: "INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER",
        75: "INTERNET_OPTION_PER_CONNECTION_OPTION",
        76: "INTERNET_OPTION_DIGEST_AUTH_UNLOAD",
        77: "INTERNET_OPTION_IGNORE_OFFLINE",
        78: "INTERNET_OPTION_IDENTITY",
        79: "INTERNET_OPTION_REMOVE_IDENTITY",
        80: "INTERNET_OPTION_ALTER_IDENTITY",
        81: "INTERNET_OPTION_SUPPRESS_BEHAVIOR",
        82: "INTERNET_OPTION_AUTODIAL_MODE",
        83: "INTERNET_OPTION_AUTODIAL_CONNECTION",
        84: "INTERNET_OPTION_CLIENT_CERT_CONTEXT",
        85: "INTERNET_OPTION_AUTH_FLAGS",
        86: "INTERNET_OPTION_COOKIES_3RD_PARTY",
        87: "INTERNET_OPTION_DISABLE_PASSPORT_AUTH",
        88: "INTERNET_OPTION_SEND_UTF8_SERVERNAME_TO_PROXY",
        89: "INTERNET_OPTION_EXEMPT_CONNECTION_LIMIT",
        90: "INTERNET_OPTION_ENABLE_PASSPORT_AUTH",
        91: "INTERNET_OPTION_HIBERNATE_INACTIVE_WORKER_THREADS",
        92: "INTERNET_OPTION_ACTIVATE_WORKER_THREADS",
        93: "INTERNET_OPTION_RESTORE_WORKER_THREAD_DEFAULTS",
        94: "INTERNET_OPTION_SOCKET_SEND_BUFFER_LENGTH",
        95: "INTERNET_OPTION_PROXY_SETTINGS_CHANGED",
        96: "INTERNET_OPTION_DATAFILE_EXT",
        100: "INTERNET_OPTION_CODEPAGE_PATH",
        101: "INTERNET_OPTION_CODEPAGE_EXTRA",
        102: "INTERNET_OPTION_IDN",
        103: "INTERNET_OPTION_MAX_CONNS_PER_PROXY",
        104: "INTERNET_OPTION_SUPPRESS_SERVER_AUTH",
        105: "INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT",
    }


def afWSASocketDict():
    return {
        0: "AF_UNSPEC",
        2: "AF_INET",
        6: "AF_IPX",
        16: "AF_APPLETALK",
        17: "AF_NETBIOS",
        23: "AF_INET6",
        26: "AF_IRDA",
        32: "AF_BTH",
    }


def protocolWSASocketDict():
    return {
        1: "IPPROTO_ICMP",
        2: "IPPROTO_IGMP",
        3: "BTHPROTO_RFCOMM",
        6: "IPPROTO_TCP",
        17: "IPPROTO_UDP",
        58: "IPPROTO_ICMPV6",
        113: "IPPROTO_RM",
    }


def FileInformationClassDict():
    return {
        1: "FileDirectoryInformation",
        2: "FileFullDirectoryInformation",
        3: "FileBothDirectoryInformation",
        4: "FileBasicInformation",
        5: "FileStandardInformation",
        6: "FileInternalInformation",
        7: "FileEaInformation",
        8: "FileAccessInformation",
        9: "FileNameInformation",
        10: "FileRenameInformation",
        11: "FileLinkInformation",
        12: "FileNamesInformation",
        13: "FileDispositionInformation",
        14: "FilePositionInformation",
        15: "FileFullEaInformation",
        16: "FileModeInformation",
        17: "FileAlignmentInformation",
        18: "FileAllInformation",
        19: "FileAllocationInformation",
        20: "FileEndOfFileInformation",
        21: "FileAlternativeNameInformation",
        22: "FileStreamInformation",
        23: "FilePipeInformation",
        24: "FilePipeLocalInformation",
        25: "FilePipeRemoteInformation",
        26: "FileMailslotQueryInformation",
        27: "FileMailslotSetInformation",
        28: "FileCompressionInformation",
        29: "FileObjectIdInformation",
        30: "FileCompletionInformation",
        31: "FileMoveClusterInformation",
        32: "FileQuotaInformation",
        33: "FileReparsePointInformation",
        34: "FileNetworkOpenInformation",
        35: "FileAttributeTagInformation",
        36: "FileTrackingInformation",
        37: "FileIdBothDirectoryInformation",
        38: "FileIdFullDirectoryInformation",
        39: "FileShortNameInformation",
        40: "FileIoCompletionNotificationInformation",
        41: "FileIoStatusBlockRangeInformation",
        42: "FileIoPriorityHintInformation",
        43: "FileSfioReserveInformation",
        44: "FileSfioVolumeInformation",
        45: "FileHardLinkInformation",
        46: "FileProcessIdsUsingFileInformation",
        47: "FileNormalizedNameInformation",
        48: "FileNetworkPhysicalNameInformation",
        49: "FileIdGlobalTxDirectoryInformation",
        50: "FileIsRemoteDeviceInformation",
        51: "FileAttributeCacheInformation",
        52: "FileNumaNodeInformation",
        53: "FileStandardLinkInformation",
        54: "FileRemoteProtocolInformation",
        55: "FileReplaceCompletionInformation",
        56: "FileMaximumInformation",
    }


def ProcessInformationClassDict():
    return {
        0: "ProcessBasicInformation",
        7: "ProcessDebugPort",
        29: "ProcessBreakOnTermination",
        30: "ProcessDebugObjectHandle",
        31: "ProcessDebugFlags",
        34: "ProcessExecuteFlags",
    }


def ThreadInformationClassDict():
    return {
        0: "ThreadBasicInformation",
        17: "ThreadHideFromDebugger",
    }


def MemTypeDict():
    return {
        0x20000: "MEM_PRIVATE",
        0x40000: "MEM_MAPPED",
        0x1000000: "MEM_IMAGE",
    }


def ShowDict():
    return {
        0: "SW_HIDE",
        1: "SW_SHOWNORMAL",
        2: "SW_SHOWMINIMIZED",
        3: "SW_SHOWMAXIMIZED",
        4: "SW_SHOWNOACTIVATE",
        5: "SW_SHOW",
        6: "SW_MINIMIZE",
        7: "SW_SHOWMINNOACTIVE",
        8: "SW_SHOWNA",
        9: "SW_RESTORE",
        10: "SW_SHOWDEFAULT",
        11: "SW_FORCEMINIMIZE",
    }


def RegistryDict():
    return {
        0x80000000: "HKEY_CLASSES_ROOT",
        0x80000001: "HKEY_CURRENT_USER",
        0x80000002: "HKEY_LOCAL_MACHINE",
        0x80000003: "HKEY_USERS",
        0x80000004: "HKEY_PERFORMANCE_DATA",
        0x80000005: "HKEY_CURRENT_CONFIG",
        0x80000006: "HKEY_DYN_DATA",
    }


def afWSASocketTypeDict():
    return {
        1: "SOCK_STREAM",
        2: "SOCK_DGRAM",
        3: "SOCK_RAW",
        4: "SOCK_RDM",
        5: "SOCK_SEQPACKET",
    }
