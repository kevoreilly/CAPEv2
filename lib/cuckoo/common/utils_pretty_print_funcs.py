# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import lib.cuckoo.common.utils_dicts as utils_dicts


def api_name_ntcreatesection_arg_name_desiredaccess(arg_val):
    val = int(arg_val, 16)
    res = []
    if val == 0xF001F:
        return "SECTION_ALL_ACCESS"
    if val & 0xF0000:
        res.append("STANDARD_RIGHTS_REQUIRED")
        val &= ~0xF0000
    if val & 1:
        res.append("SECTION_QUERY")
        val &= ~1
    if val & 4:
        res.append("SECTION_MAP_READ")
        val &= ~4
    if val & 2:
        res.append("SECTION_MAP_WRITE")
        val &= ~2
    if val & 8:
        res.append("SECTION_MAP_EXECUTE")
        val &= ~8
    if val & 0x10:
        res.append("SECTION_EXTEND_SIZE")
        val &= ~0x10
    if val & 0x20:
        res.append("SECTION_MAP_EXECUTE_EXPLICIT")
        val &= ~0x20
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_shgetfolderpathw_arg_name_folder(arg_val):
    val = int(arg_val, 16)
    res = []
    if val & 0x800:
        res.append("CSIDL_FLAG_PER_USER_INIT")
        val &= ~0x800
    if val & 0x1000:
        res.append("CSIDL_FLAG_NO_ALIAS")
        val &= ~0x1000
    if val & 0x2000:
        res.append("CSIDL_FLAG_DONT_UNEXPAND")
        val &= ~0x2000
    if val & 0x4000:
        res.append("CSIDL_FLAG_DONT_VERIFY")
        val &= ~0x4000
    if val & 0x8000:
        res.append("CSIDL_FLAG_CREATE")
        val &= ~0x8000
    folder = utils_dicts.FolderDict().get(val)
    if folder:
        res.append(folder)
    else:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_createtoolhelp32snapshot_arg_name_flags(arg_val):
    val = int(arg_val, 16)
    res = []
    if val == 0xF:
        return "TH32CS_SNAPALL"
    if val & 1:
        res.append("TH32CS_SNAPHEAPLIST")
        val &= ~1
    if val & 2:
        res.append("TH32CS_SNAPPROCESS")
        val &= ~2
    if val & 4:
        res.append("TH32CS_SNAPTHREAD")
        val &= ~4
    if val & 8:
        res.append("TH32CS_SNAPMODULE")
        val &= ~8
    if val & 0x10:
        res.append("TH32CS_SNAPMODULE32")
        val &= ~0x10
    if val & 0x80000000:
        res.append("TH32CS_INHERIT")
        val &= ~0x80000000
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def blobtype(arg_val):
    val = int(arg_val)
    return utils_dicts.BlobTypeDict().get(val)


def algid(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.AlgidDict().get(val)


def hookidentifer(arg_val):
    val = int(arg_val)
    return utils_dicts.HookIdentifierDict().get(val)


def infolevel(arg_val):
    try:
        val = int(arg_val, 16)
    except Exception:
        val = int(arg_val)
    return utils_dicts.InfoLevelDict().get(val)


def disposition(arg_val):
    val = int(arg_val)
    return utils_dicts.DispositionDict().get(val)


def createdisposition(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.CreateDispositionDict().get(val)


def shareaccess(arg_val):
    val = int(arg_val)
    res = []
    if val & 1:
        res.append("FILE_SHARE_READ")
        val &= ~1
    if val & 2:
        res.append("FILE_SHARE_WRITE")
        val &= ~2
    if val & 4:
        res.append("FILE_SHARE_DELETE")
        val &= ~4
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def systeminformationclass(arg_val):
    val = int(arg_val)
    return utils_dicts.SystemInformationClassDict().get(val)


def category_registry_arg_name_type(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.RegistryTypeDict().get(val)


def api_name_opensc_arg_name_desiredaccess(arg_val):
    val = int(arg_val, 16)
    res = []
    if val == 0x02000000:
        return "MAXIMUM_ALLOWED"
    if val == 0xF003F:
        return "SC_MANAGER_ALL_ACCESS"
    if val & 0x0001:
        res.append("SC_MANAGER_CONNECT")
        val &= ~0x0001
    if val & 0x0002:
        res.append("SC_MANAGER_CREATE_SERVICE")
        val &= ~0x0002
    if val & 0x0004:
        res.append("SC_MANAGER_ENUMERATE_SERVICE")
        val &= ~0x0004
    if val & 0x0008:
        res.append("SC_MANAGER_LOCK")
        val &= ~0x0008
    if val & 0x0010:
        res.append("SC_MANAGER_QUERY_LOCK_STATUS")
        val &= ~0x0010
    if val & 0x0020:
        res.append("SC_MANAGER_MODIFY_BOOT_CONFIG")
        val &= ~0x0020
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def category_services_arg_name_controlcode(arg_val):
    val = int(arg_val)
    return utils_dicts.ServicesControlCodeDict().get(val)


def category_services_arg_name_errorcontrol(arg_val):
    val = int(arg_val)
    return utils_dicts.ServicesErrorControlDict().get(val)


def category_services_arg_name_starttype(arg_val):
    val = int(arg_val)
    return utils_dicts.ServicesStartTypeDict().get(val)


def category_services_arg_name_servicetype(arg_val):
    val = int(arg_val)
    retstr = utils_dicts.ServicesServiceTypeDict().get(val & 0x3F)
    if val & 0x130:
        retstr += "|SERVICE_INTERACTIVE_PROCESS"
    return retstr


def category_services_arg_name_desiredaccess(arg_val):
    val = int(arg_val, 16)
    res = []
    if val == 0x02000000:
        return "MAXIMUM_ALLOWED"
    if val == 0xF01FF:
        return "SERVICE_ALL_ACCESS"
    if val & 0x0001:
        res.append("SERVICE_QUERY_CONFIG")
        val &= ~0x0001
    if val & 0x0002:
        res.append("SERVICE_CHANGE_CONFIG")
        val &= ~0x0002
    if val & 0x0004:
        res.append("SERVICE_QUERY_STATUS")
        val &= ~0x0004
    if val & 0x0008:
        res.append("SERVICE_ENUMERATE_DEPENDENTS")
        val &= ~0x0008
    if val & 0x0010:
        res.append("SERVICE_START")
        val &= ~0x0010
    if val & 0x0020:
        res.append("SERVICE_STOP")
        val &= ~0x0020
    if val & 0x0040:
        res.append("SERVICE_PAUSE_CONTINUE")
        val &= ~0x0040
    if val & 0x0080:
        res.append("SERVICE_INTERROGATE")
        val &= ~0x0080
    if val & 0x0100:
        res.append("SERVICE_USER_DEFINED_CONTROL")
        val &= ~0x0100
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def category_registry_arg_name_access_desired_access(arg_val):
    val = int(arg_val, 16)
    res = []
    if val == 0x02000000:
        return "MAXIMUM_ALLOWED"
    if val == 0xF003F:
        return "KEY_ALL_ACCESS"
    elif val == 0x20019:
        return "KEY_READ"
    elif val == 0x20006:
        return "KEY_WRITE"
    elif val == 0x2001F:
        return "KEY_READ|KEY_WRITE"

    if val & 0x0001:
        res.append("KEY_QUERY_VALUE")
        val &= ~0x0001
    if val & 0x0002:
        res.append("KEY_SET_VALUE")
        val &= ~0x0002
    if val & 0x0004:
        res.append("KEY_CREATE_SUB_KEY")
        val &= ~0x0004
    if val & 0x0008:
        res.append("KEY_ENUMERATE_SUB_KEYS")
        val &= ~0x0008
    if val & 0x0010:
        res.append("KEY_NOTIFY")
        val &= ~0x0010
    if val & 0x0020:
        res.append("KEY_CREATE_LINK")
        val &= ~0x0020
    if val & 0x0100:
        res.append("KEY_WOW64_64KEY")
        val &= ~0x0100
    if val & 0x0F0000:
        res.append("STANDARD_RIGHTS_REQUIRED")
        val &= ~0x0F0000
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def arg_name_protection_and_others(arg_val):
    val = int(arg_val, 16)
    res = []
    if val & 0x00000001:
        res.append("PAGE_NOACCESS")
        val &= ~0x00000001
    if val & 0x00000002:
        res.append("PAGE_READONLY")
        val &= ~0x00000002
    if val & 0x00000004:
        res.append("PAGE_READWRITE")
        val &= ~0x00000004
    if val & 0x00000008:
        res.append("PAGE_WRITECOPY")
        val &= ~0x00000008
    if val & 0x00000010:
        res.append("PAGE_EXECUTE")
        val &= ~0x00000010
    if val & 0x00000020:
        res.append("PAGE_EXECUTE_READ")
        val &= ~0x00000020
    if val & 0x00000040:
        res.append("PAGE_EXECUTE_READWRITE")
        val &= ~0x00000040
    if val & 0x00000080:
        res.append("PAGE_EXECUTE_WRITECOPY")
        val &= ~0x00000080
    if val & 0x00000100:
        res.append("PAGE_GUARD")
        val &= ~0x00000100
    if val & 0x00000200:
        res.append("PAGE_NOCACHE")
        val &= ~0x00000200
    if val & 0x00000400:
        res.append("PAGE_WRITECOMBINE")
        val &= ~0x00000400
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def arg_name_iocontrolcode(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.IoControlCodeDict().get(val)


def api_name_in_creation(arg_val):
    val = int(arg_val, 16)
    res = []
    if val & 0x00000001:
        res.append("DEBUG_PROCESS")
        val &= ~0x00000001
    if val & 0x00000002:
        res.append("DEBUG_ONLY_THIS_PROCESS")
        val &= ~0x00000002
    if val & 0x00000004:
        res.append("CREATE_SUSPENDED")
        val &= ~0x00000004
    if val & 0x00000008:
        res.append("DETACHED_PROCESS")
        val &= ~0x00000008
    if val & 0x00000010:
        res.append("CREATE_NEW_CONSOLE")
        val &= ~0x00000010
    if val & 0x00000020:
        res.append("NORMAL_PRIORITY_CLASS")
        val &= ~0x00000020
    if val & 0x00000040:
        res.append("IDLE_PRIORITY_CLASS")
        val &= ~0x00000040
    if val & 0x00000080:
        res.append("HIGH_PRIORITY_CLASS")
        val &= ~0x00000080
    if val & 0x00000400:
        res.append("CREATE_UNICODE_ENVIRONMENT")
        val &= ~0x00000400
    if val & 0x00040000:
        res.append("CREATE_PROTECTED_PROCESS")
        val &= ~0x00040000
    if val & 0x00080000:
        res.append("EXTENDED_STARTUPINFO_PRESENT")
        val &= ~0x00080000
    if val & 0x01000000:
        res.append("CREATE_BREAKAWAY_FROM_JOB")
        val &= ~0x01000000
    if val & 0x02000000:
        res.append("CREATE_PRESERVE_CODE_AUTHZ_LEVEL")
        val &= ~0x02000000
    if val & 0x04000000:
        res.append("CREATE_DEFAULT_ERROR_MODE")
        val &= ~0x04000000
    if val & 0x08000000:
        res.append("CREATE_NO_WINDOW")
        val &= ~0x08000000
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_move_arg_name_flags(arg_val):
    val = int(arg_val, 16)
    res = []
    if val & 0x00000001:
        res.append("MOVEFILE_REPLACE_EXISTING")
        val &= ~0x00000001
    if val & 0x00000002:
        res.append("MOVEFILE_COPY_ALLOWED")
        val &= ~0x00000002
    if val & 0x00000004:
        res.append("MOVEFILE_DELAY_UNTIL_REBOOT")
        val &= ~0x00000004
    if val & 0x00000008:
        res.append("MOVEFILE_WRITE_THROUGH")
        val &= ~0x00000008
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def arg_name_fileattributes(arg_val):
    val = int(arg_val, 16)
    res = []
    if val == 0x00000080:
        return "FILE_ATTRIBUTE_NORMAL"
    if val & 0x00000001:
        res.append("FILE_ATTRIBUTE_READONLY")
        val &= ~0x00000001
    if val & 0x00000002:
        res.append("FILE_ATTRIBUTE_HIDDEN")
        val &= ~0x00000002
    if val & 0x00000004:
        res.append("FILE_ATTRIBUTE_SYSTEM")
        val &= ~0x00000004
    if val & 0x00000010:
        res.append("FILE_ATTRIBUTE_DIRECTORY")
        val &= ~0x00000010
    if val & 0x00000020:
        res.append("FILE_ATTRIBUTE_ARCHIVE")
        val &= ~0x00000020
    if val & 0x00000040:
        res.append("FILE_ATTRIBUTE_DEVICE")
        val &= ~0x00000040
    if val & 0x00000100:
        res.append("FILE_ATTRIBUTE_TEMPORARY")
        val &= ~0x00000100
    if val & 0x00000200:
        res.append("FILE_ATTRIBUTE_SPARSE_FILE")
        val &= ~0x00000200
    if val & 0x00000400:
        res.append("FILE_ATTRIBUTE_REPARSE_POINT")
        val &= ~0x00000400
    if val & 0x00000800:
        res.append("FILE_ATTRIBUTE_COMPRESSED")
        val &= ~0x00000800
    if val & 0x00001000:
        res.append("FILE_ATTRIBUTE_OFFLINE")
        val &= ~0x00001000
    if val & 0x00002000:
        res.append("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED")
        val &= ~0x00002000
    if val & 0x00004000:
        res.append("FILE_ATTRIBUTE_ENCRYPTED")
        val &= ~0x00004000
    if val & 0x00008000:
        res.append("FILE_ATTRIBUTE_VIRTUAL")
        val &= ~0x00008000
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_nt_arg_name_desiredaccess(arg_val):
    val = int(arg_val, 16)
    remove = 0
    res = []
    if val & 0x80000000:
        res.append("GENERIC_READ")
        remove |= 0x80000000
    if val & 0x40000000:
        res.append("GENERIC_WRITE")
        remove |= 0x40000000
    if val & 0x20000000:
        res.append("GENERIC_EXECUTE")
        remove |= 0x20000000
    if val & 0x10000000:
        res.append("GENERIC_ALL")
        remove |= 0x10000000
    if val & 0x02000000:
        res.append("MAXIMUM_ALLOWED")
        remove |= 0x02000000
    if (val & 0x1F01FF) == 0x1F01FF:
        res.append("FILE_ALL_ACCESS")
        val &= ~0x1F01FF
    if (val & 0x120089) == 0x120089:
        res.append("FILE_GENERIC_READ")
        remove |= 0x120089
    if (val & 0x120116) == 0x120116:
        res.append("FILE_GENERIC_WRITE")
        remove |= 0x120116
    if (val & 0x1200A0) == 0x1200A0:
        res.append("FILE_GENERIC_EXECUTE")
        remove |= 0x1200A0
    val &= ~remove
    # for values 1 -> 0x20, these can have different meanings depending on whether
    # it's a file or a directory operated on -- choose file by default since
    # we don't have enough information to make an accurate determination
    if val & 0x00000001:
        res.append("FILE_READ_ACCESS")
        remove |= 0x00000001
    if val & 0x00000002:
        res.append("FILE_WRITE_ACCESS")
        remove |= 0x00000002
    if val & 0x00000004:
        res.append("FILE_APPEND_DATA")
        remove |= 0x00000004
    if val & 0x00000008:
        res.append("FILE_READ_EA")
        remove |= 0x00000008
    if val & 0x00000010:
        res.append("FILE_WRITE_EA")
        remove |= 0x00000010
    if val & 0x00000020:
        res.append("FILE_EXECUTE")
        remove |= 0x00000020
    if val & 0x00000040:
        res.append("FILE_DELETE_CHILD")
        remove |= 0x00000040
    if val & 0x00000080:
        res.append("FILE_READ_ATTRIBUTES")
        remove |= 0x00000080
    if val & 0x00000100:
        res.append("FILE_WRITE_ATTRIBUTES")
        remove |= 0x00000100
    if val & 0x00010000:
        res.append("DELETE")
        remove |= 0x00010000
    if val & 0x00020000:
        res.append("READ_CONTROL")
        remove |= 0x00020000
    if val & 0x00040000:
        res.append("WRITE_DAC")
        remove |= 0x00040000
    if val & 0x00080000:
        res.append("WRITE_OWNER")
        remove |= 0x00080000
    if val & 0x00100000:
        res.append("SYNCHRONIZE")
        remove |= 0x00100000
    if val & 0x01000000:
        res.append("ACCESS_SYSTEM_SECURITY")
        remove |= 0x01000000
    val &= ~remove
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_ntopenprocess_arg_name_desiredaccess(arg_val):
    val = int(arg_val, 16)
    remove = 0
    res = []
    if val & 0x80000000:
        res.append("GENERIC_READ")
        remove |= 0x80000000
    if val & 0x40000000:
        res.append("GENERIC_WRITE")
        remove |= 0x40000000
    if val & 0x20000000:
        res.append("GENERIC_EXECUTE")
        remove |= 0x20000000
    if val & 0x10000000:
        res.append("GENERIC_ALL")
        remove |= 0x10000000
    if val & 0x02000000:
        res.append("MAXIMUM_ALLOWED")
        remove |= 0x02000000
    # for >= vista
    if (val & 0x1FFFFF) == 0x1FFFFF:
        res.append("PROCESS_ALL_ACCESS")
        val &= ~0x1FFFFF
    # for < vista
    if (val & 0x1F0FFF) == 0x1F0FFF:
        res.append("PROCESS_ALL_ACCESS")
        val &= ~0x1F0FFF
    val &= ~remove
    if val & 0x0001:
        res.append("PROCESS_TERMINATE")
        remove |= 0x0001
    if val & 0x0002:
        res.append("PROCESS_CREATE_THREAD")
        remove |= 0x0002
    if val & 0x0004:
        res.append("PROCESS_SET_SESSIONID")
        remove |= 0x0004
    if val & 0x0008:
        res.append("PROCESS_VM_OPERATION")
        remove |= 0x0008
    if val & 0x0010:
        res.append("PROCESS_VM_READ")
        remove |= 0x0010
    if val & 0x0020:
        res.append("PROCESS_VM_WRITE")
        remove |= 0x0020
    if val & 0x0040:
        res.append("PROCESS_DUP_HANDLE")
        remove |= 0x0040
    if val & 0x0080:
        res.append("PROCESS_CREATE_PROCESS")
        remove |= 0x0080
    if val & 0x0100:
        res.append("PROCESS_SET_QUOTA")
        remove |= 0x0100
    if val & 0x0200:
        res.append("PROCESS_SET_INFORMATION")
        remove |= 0x0200
    if val & 0x0400:
        res.append("PROCESS_QUERY_INFORMATION")
        remove |= 0x0400
    if val & 0x0800:
        res.append("PROCESS_SUSPEND_RESUME")
        remove |= 0x0800
    if val & 0x1000:
        res.append("PROCESS_QUERY_LIMITED_INFORMATION")
        remove |= 0x1000
    if val & 0x100000:
        res.append("SYNCHRONIZE")
        remove |= 0x100000
    val &= ~remove
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_ntopenthread_arg_name_desiredaccess(arg_val):
    val = int(arg_val, 16)
    remove = 0
    res = []
    if val & 0x80000000:
        res.append("GENERIC_READ")
        remove |= 0x80000000
    if val & 0x40000000:
        res.append("GENERIC_WRITE")
        remove |= 0x40000000
    if val & 0x20000000:
        res.append("GENERIC_EXECUTE")
        remove |= 0x20000000
    if val & 0x10000000:
        res.append("GENERIC_ALL")
        remove |= 0x10000000
    if val & 0x02000000:
        res.append("MAXIMUM_ALLOWED")
        remove |= 0x02000000
    # for >= vista
    if (val & 0x1FFFFF) == 0x1FFFFF:
        res.append("THREAD_ALL_ACCESS")
        val &= ~0x1FFFFF
    # for < vista
    if (val & 0x1F03FF) == 0x1F03FF:
        res.append("THREAD_ALL_ACCESS")
        val &= ~0x1F03FF
    val &= ~remove
    if val & 0x0001:
        res.append("THREAD_TERMINATE")
        remove |= 0x0001
    if val & 0x0002:
        res.append("THREAD_SUSPEND_RESUME")
        remove |= 0x0002
    if val & 0x0008:
        res.append("THREAD_GET_CONTEXT")
        remove |= 0x0008
    if val & 0x0010:
        res.append("THREAD_SET_CONTEXT")
        remove |= 0x0010
    if val & 0x0020:
        res.append("THREAD_SET_INFORMATION")
        remove |= 0x0020
    if val & 0x0040:
        res.append("THREAD_QUERY_INFORMATION")
        remove |= 0x0040
    if val & 0x0080:
        res.append("THREAD_SET_THREAD_TOKEN")
        remove |= 0x0080
    if val & 0x0100:
        res.append("THREAD_IMPERSONATE")
        remove |= 0x0100
    if val & 0x0200:
        res.append("THREAD_DIRECT_IMPERSONATION")
        remove |= 0x0200
    if val & 0x0400:
        res.append("THREAD_SET_LIMITED_INFORMATION")
        remove |= 0x0400
    if val & 0x0800:
        res.append("THREAD_QUERY_LIMITED_INFORMATION")
        remove |= 0x0800
    val &= ~remove
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_cointernet_arg_name_featureentry(arg_val):
    val = int(arg_val)
    return utils_dicts.CoInternetSetFeatureEnabledDict().get(val)


def api_name_cointernet_arg_name_flags(arg_val):
    val = int(arg_val, 16)
    res = []
    if val & 0x00000001:
        res.append("SET_FEATURE_ON_THREAD")
        val &= ~0x00000001
    if val & 0x00000002:
        res.append("SET_FEATURE_ON_PROCESS")
        val &= ~0x00000002
    if val & 0x00000004:
        res.append("SET_FEATURE_IN_REGISTRY")
        val &= ~0x00000004
    if val & 0x00000008:
        res.append("SET_FEATURE_ON_THREAD_LOCALMACHINE")
        val &= ~0x00000008
    if val & 0x00000010:
        res.append("SET_FEATURE_ON_THREAD_INTRANET")
        val &= ~0x00000010
    if val & 0x00000020:
        res.append("SET_FEATURE_ON_THREAD_TRUSTED")
        val &= ~0x00000020
    if val & 0x00000040:
        res.append("SET_FEATURE_ON_THREAD_INTERNET")
        val &= ~0x00000040
    if val & 0x00000080:
        res.append("SET_FEATURE_ON_THREAD_RESTRICTED")
        val &= ~0x00000080
    if val:
        res.append(f"0x{val:08x}")
    return "|".join(res)


def api_name_socket(arg_val, arg_name):
    if arg_name == "af":
        val = int(arg_val)
        return utils_dicts.afWSASocketDict().get(val)
    elif arg_name == "type":
        val = int(arg_val)
        return utils_dicts.afWSASocketTypeDict().get(val)
    elif arg_name == "protocol":
        val = int(arg_val)
        return utils_dicts.protocolWSASocketDict().get(val)


def api_name_internetsetoptiona_arg_name_option(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.InternetSetOptionADict().get(val)


def arg_name_fileinformationclass(arg_val):
    val = int(arg_val)
    return utils_dicts.FileInformationClassDict().get(val)


def arg_name_processinformationclass(arg_val):
    val = int(arg_val)
    return utils_dicts.ProcessInformationClassDict().get(val)


def arg_name_threadinformationclass(arg_val):
    val = int(arg_val)
    return utils_dicts.ThreadInformationClassDict().get(val)


def arg_name_memtype(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.MemTypeDict().get(val)


def arg_name_show(arg_val):
    val = int(arg_val)
    return utils_dicts.ShowDict().get(val)


def arg_name_registry(arg_val):
    val = int(arg_val, 16)
    return utils_dicts.RegistryDict().get(val)
