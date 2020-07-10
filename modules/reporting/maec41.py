# Copyright (c) 2013, The MITRE Corporation
# Copyright (c) 2010-2015, Cuckoo Developers
# All rights reserved.

# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from __future__ import absolute_import
import os
import hashlib
import re
from collections import defaultdict

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from lib.cuckoo.common.utils import datetime_to_iso
from modules.processing.behavior import fix_key

try:
    import cybox
    import cybox.utils.nsparser
    from cybox.utils import Namespace
    from cybox.core import Object
    from cybox.common import ToolInformation
    from cybox.common import StructuredText

    HAVE_CYBOX = True
except ImportError as e:
    HAVE_CYBOX = False

try:
    from maec.bundle import Bundle, MalwareAction, BundleReference, ProcessTree, AVClassification
    from maec.package import MalwareSubject, Package, Analysis
    import maec.utils
    import mixbox

    HAVE_MAEC = True
except ImportError as e:
    HAVE_MAEC = False


api_call_mappings = {
    "NtCreateFile": {
        "action_name": "create file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "File"},
            },
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "output"},
        },
    },
    "NtOpenFile": {
        "action_name": "open file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "File"},
            },
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"},
        },
    },
    "NtReadFile": {
        "action_name": "read from file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            }
        },
    },
    "NtWriteFile": {
        "action_name": "write to file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            }
        },
    },
    "NtDeleteFile": {
        "action_name": "delete file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "NtDeviceIoControlFile": {
        "action_name": "send control code to file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            }
        },
    },
    "NtQueryDirectoryFile": {
        "action_name": "find file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            },
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"},
        },
    },
    "NtQueryInformationFile": {
        "action_name": "get file attributes",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            }
        },
    },
    "NtSetInformationFile": {
        "action_name": "set file attributes",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            }
        },
    },
    "NtCreateDirectoryObject": {
        "action_name": "create directory",
        "action_vocab": "maecVocabs:DirectoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "DirectoryHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "File"},
            }
        },
    },
    "CreateDirectoryW": {
        "action_name": "create directory",
        "action_vocab": "maecVocabs:DirectoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "DirectoryName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "output",
            }
        },
    },
    "CreateDirectoryExW": {
        "action_name": "create directory",
        "action_vocab": "maecVocabs:DirectoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "DirectoryName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "output",
            }
        },
    },
    "RemoveDirectoryA": {
        "action_name": "delete directory",
        "action_vocab": "maecVocabs:DirectoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "DirectoryName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "RemoveDirectoryW": {
        "action_name": "delete directory",
        "action_vocab": "maecVocabs:DirectoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "DirectoryName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "MoveFileWithProgressW": {
        "action_name": "move file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ExistingFileName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
            },
            "NewFileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "output"},
        },
    },
    "FindFirstFileExA": {
        "action_name": "find file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "FindFirstFileExW": {
        "action_name": "find file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "CopyFileA": {
        "action_name": "copy file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ExistingFileName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
            },
            "NewFileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "output"},
        },
    },
    "CopyFileW": {
        "action_name": "copy file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ExistingFileName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
            },
            "NewFileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "output"},
        },
    },
    "CopyFileExW": {
        "action_name": "copy file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ExistingFileName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
            },
            "NewFileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "output"},
        },
    },
    "DeleteFileA": {
        "action_name": "delete file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "DeleteFileW": {
        "action_name": "delete file",
        "action_vocab": "maecVocabs:FileActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "RegOpenKeyExA": {
        "action_name": "open registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Registry": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Hive",
                "association_type": "input",
                "post_processing": "hiveHexToString",
            },
            "SubKey": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together": ["Registry", "SubKey"],
        },
    },
    "RegOpenKeyExW": {
        "action_name": "open registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Registry": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Hive",
                "association_type": "input",
                "post_processing": "hiveHexToString",
            },
            "SubKey": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together": ["Registry", "SubKey"],
        },
    },
    "RegCreateKeyExA": {
        "action_name": "create registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Registry": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Hive",
                "association_type": "output",
                "post_processing": "hiveHexToString",
            },
            "SubKey": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "output",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together": ["Registry", "SubKey"],
        },
    },
    "RegCreateKeyExW": {
        "action_name": "create registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Registry": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Hive",
                "association_type": "output",
                "post_processing": "hiveHexToString",
            },
            "SubKey": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "output",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together": ["Registry", "SubKey"],
        },
    },
    "RegDeleteKeyA": {
        "action_name": "delete registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "SubKey": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegDeleteKeyW": {
        "action_name": "delete registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "SubKey": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegEnumKeyW": {
        "action_name": "enumerate registry key subkeys",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Name": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "output",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegEnumKeyExA": {
        "action_name": "enumerate registry key subkeys",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Name": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "output",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegEnumKeyExW": {
        "action_name": "enumerate registry key subkeys",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Name": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Key",
                "association_type": "output",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegEnumValueA": {
        "action_name": "enumerate registry key values",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ValueName", "element_name": "Name"},
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Data", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "RegEnumValueW": {
        "action_name": "enumerate registry key values",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ValueName", "element_name": "Name"},
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Data", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "RegSetValueExA": {
        "action_name": "modify registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ValueName", "element_name": "Name"},
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Buffer", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "RegSetValueExW": {
        "action_name": "modify registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ValueName", "element_name": "Name"},
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Buffer", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "RegQueryValueExA": {
        "action_name": "read registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Data", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "RegQueryValueExW": {
        "action_name": "read registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Data", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "RegDeleteValueA": {
        "action_name": "delete registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegDeleteValueW": {
        "action_name": "delete registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "RegQueryInfoKeyA": {
        "action_name": "get registry key attributes",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "RegQueryInfoKeyW": {
        "action_name": "get registry key attributes",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "RegCloseKey": {
        "action_name": "close registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "NtCreateKey": {
        "action_name": "create registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ObjectAttributes", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "ObjectAttributes", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "output",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtOpenKey": {
        "action_name": "open registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ObjectAttributes", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "ObjectAttributes", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "input",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtOpenKeyEx": {
        "action_name": "open registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ObjectAttributes", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "ObjectAttributes", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "input",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtRenameKey": {
        "action_name": "rename registry key",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "NewName", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "NewName", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "input",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtReplaceKey": {
        "action_name": "save hive key to file",
        "parameter_associated_objects": {
            "NewHiveFileName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "output",
            },
            "OldHiveFileName": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtEnumerateKey": {
        "action_name": "enumerate registry key subkeys",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "NtEnumerateValueKey": {
        "action_name": "enumerate registry key values",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "NtSetValueKey": {
        "action_name": "modify registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ValueName", "element_name": "Name"},
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Buffer", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "NtQueryValueKey": {
        "action_name": "read registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "Type", "element_name": "Datatype", "post_processing": "regDatatypeToString"},
                    {"parameter_name": "Information", "element_name": "Data"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__",
                "association_type": "output",
            },
        },
    },
    "NtQueryMultipleValueKey": {
        "action_name": "read registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "ValueBuffer": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Data",
                "association_type": "output",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtDeleteKey": {
        "action_name": "delete registry key",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "NtDeleteValueKey": {
        "action_name": "delete registry key value",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ValueName": {
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "associated_object_element": "Values/list__Name",
                "association_type": "input",
            },
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtLoadKey": {
        "action_name": "load registry keys from file",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "TargetKey", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "TargetKey", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "input",
            },
            "SourceFile": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtLoadKey2": {
        "action_name": "load registry keys from file",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "TargetKey", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "TargetKey", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "input",
            },
            "SourceFile": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtLoadKeyEx": {
        "action_name": "load registry keys from file",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "TargetKey", "element_name": "Hive", "post_processing": "regStringToHive"},
                    {"parameter_name": "TargetKey", "element_name": "Key", "post_processing": "regStringToKey"},
                ],
                "associated_object_type": "WindowsRegistryKeyObjectType",
                "association_type": "input",
            },
            "SourceFile": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "File_Path",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtQueryKey": {
        "action_name": "get registry key attributes",
        "action_vocab": "maecVocabs:RegistryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "KeyHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            }
        },
    },
    "NtSaveKey": {
        "action_name": "save registry key subtree to file",
        "parameter_associated_objects": {
            "KeyHandle": {"associated_object_type": "WindowsHandleObjectType", "associated_object_element": "ID", "association_type": "input"},
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "RegistryKey"},
            },
        },
    },
    "NtSaveKeyEx": {
        "action_name": "save registry key subtree to file",
        "parameter_associated_objects": {
            "KeyHandle": {"associated_object_type": "WindowsHandleObjectType", "associated_object_element": "ID", "association_type": "input"},
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
        },
    },
    "NtCreateProcess": {
        "action_name": "create process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"},
        },
    },
    "NtCreateProcessEx": {
        "action_name": "create process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"},
        },
    },
    "NtCreateUserProcess": {
        "action_name": "create process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            },
            "ThreadName": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "output",
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ProcessFileName", "element_name": "File_Name",},
                    {"parameter_name": "ImagePathName", "element_name": "Path"},
                ],
                "associated_object_type": "ProcessObjectType",
                "associated_object_element": "Image_Info",
                "association_type": "output",
            },
        },
    },
    "RtlCreateUserProcess": {
        "action_name": "create process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ParentProcess": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
            "ImagePath": {
                "associated_object_type": "ProcessObjectType",
                "associated_object_element": "Image_Info/Path",
                "association_type": "input",
            },
        },
    },
    "NtOpenProcess": {
        "action_name": "open process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
            "ProcessIdentifier": {
                "associated_object_type": "ProcessObjectType",
                "associated_object_element": "PID",
                "association_type": "input",
            },
        },
    },
    "NtTerminateProcess": {
        "action_name": "kill process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "NtCreateSection": {
        "action_name": "create section",
        "parameter_associated_objects": {
            "SectionHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Section"},
            },
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            },
        },
    },
    "NtOpenSection": {
        "action_name": "open section",
        "parameter_associated_objects": {
            "SectionHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Section"},
            },
            "ObjectAttributes": {
                "associated_object_type": "MemoryObjectType",
                "associated_object_element": "Name",
                "association_type": "input",
            },
        },
    },
    "CreateProcessInternalW": {
        "action_name": "create process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessId": {
                "associated_object_type": "WindowsProcessObjectType",
                "associated_object_element": "PID",
                "association_type": "output",
            },
            "ThreadId": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "output",
            },
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            },
        },
        "parameter_associated_arguments": {"ApplicationName": {"associated_argument_name": "Application Name"}},
    },
    "ExitProcess": {
        "action_name": "kill process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_arguments": {"ExitCode": {"associated_argument_name": "Exit Code"}},
    },
    "ShellExecuteExW": {
        "action_name": "create process",
        "action_vocab": "maecVocabs:ProcessActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FilePath": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "input"}
        },
    },
    "NtUnmapViewOfSection": {
        "action_name": "unmap view of section",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "NtAllocateVirtualMemory": {
        "action_name": "allocate process virtual memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "NtReadVirtualMemory": {
        "action_name": "read from process memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "ReadProcessMemory": {
        "action_name": "read from process memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "NtWriteVirtualMemory": {
        "action_name": "write to process memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "WriteProcessMemory": {
        "action_name": "write to process memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "NtProtectVirtualMemory": {
        "action_name": "modify process virtual memory protection",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "VirtualProtectEx": {
        "action_name": "modify process virtual memory protection",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "NtFreeVirtualMemory": {
        "action_name": "free process virtual memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "VirtualFreeEx": {
        "action_name": "free process virtual memory",
        "action_vocab": "maecVocabs:ProcessMemoryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            }
        },
    },
    "FindWindowA": {
        "action_name": "find window",
        "action_vocab": "maecVocabs:GUIActionNameVocab-1.0",
        "parameter_associated_objects": {
            "WindowName": {
                "associated_object_type": "GUIWindowObjectType",
                "associated_object_element": "Window_Display_Name",
                "association_type": "input",
            }
        },
    },
    "FindWindowW": {
        "action_name": "find window",
        "action_vocab": "maecVocabs:GUIActionNameVocab-1.0",
        "parameter_associated_objects": {
            "WindowName": {
                "associated_object_type": "GUIWindowObjectType",
                "associated_object_element": "Window_Display_Name",
                "association_type": "input",
            }
        },
    },
    "FindWindowExA": {
        "action_name": "find window",
        "action_vocab": "maecVocabs:GUIActionNameVocab-1.0",
        "parameter_associated_objects": {
            "WindowName": {
                "associated_object_type": "GUIWindowObjectType",
                "associated_object_element": "Window_Display_Name",
                "association_type": "input",
            }
        },
    },
    "FindWindowExW": {
        "action_name": "find window",
        "action_vocab": "maecVocabs:GUIActionNameVocab-1.0",
        "parameter_associated_objects": {
            "WindowName": {
                "associated_object_type": "GUIWindowObjectType",
                "associated_object_element": "Window_Display_Name",
                "association_type": "input",
            }
        },
    },
    "SetWindowsHookExA": {
        "action_name": "add windows hook",
        "action_vocab": "maecVocabs:HookingActionNameVocab-1.0",
        "parameter_associated_objects": {
            "HookIdentifier": {
                "associated_object_type": "WindowsKernelHookObjectType",
                "associated_object_element": "Type",
                "association_type": "input",
            },
            "ProcedureAddress": {
                "associated_object_type": "WindowsKernelHookObjectType",
                "associated_object_element": "Hooking_Address",
                "association_type": "input",
            },
            "ThreadId": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "input",
            },
            "group_together": ["HookIdentifier", "ProcedureAddress"],
        },
    },
    "SetWindowsHookExW": {
        "action_name": "add windows hook",
        "action_vocab": "maecVocabs:HookingActionNameVocab-1.0",
        "parameter_associated_objects": {
            "HookIdentifier": {
                "associated_object_type": "WindowsKernelHookObjectType",
                "associated_object_element": "Type",
                "association_type": "input",
            },
            "ProcedureAddress": {
                "associated_object_type": "WindowsKernelHookObjectType",
                "associated_object_element": "Hooking_Address",
                "association_type": "input",
            },
            "ThreadId": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "input",
            },
            "group_together": ["HookIdentifier", "ProcedureAddress"],
        },
    },
    "UnhookWindowsHookEx": {
        "action_name": "remove windows hook",
        "parameter_associated_objects": {
            "HookHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Hook"},
            }
        },
    },
    "LdrLoadDll": {
        "action_name": "load library",
        "action_vocab": "maecVocabs:LibraryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "LibraryObjectType", "associated_object_element": "Name", "association_type": "input"},
            "BaseAddress": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Module"},
            },
        },
    },
    "LdrGetDllHandle": {
        "action_name": "get dll handle",
        "parameter_associated_objects": {
            "FileName": {"associated_object_type": "LibraryObjectType", "associated_object_element": "Name", "association_type": "input"},
            "ModuleHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Module"},
            },
        },
    },
    "LdrGetProcedureAddress": {
        "action_name": "get function address",
        "action_vocab": "maecVocabs:LibraryActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ModuleHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Module"},
            },
            "FunctionAddress": {
                "associated_object_type": "APIObjectType",
                "associated_object_element": "Address",
                "association_type": "output",
                "post_processing": "intToHex",
            },
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "FunctionName", "element_name": "Function_Name"},
                    {"parameter_name": "Ordinal", "element_name": "Ordinal"},
                ],
                "associated_object_type": "WindowsExecutableFileObjectType",
                "associated_object_element": "Exports/Exported_Functions/list__",
                "association_type": "input",
            },
        },
    },
    "DeviceIoControl": {
        "action_name": "send control code to driver",
        "parameter_associated_objects": {
            "DeviceHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Device"},
            }
        },
        "parameter_associated_arguments": {
            "IoControlCode": {
                "associated_argument_name": "Control Code",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            }
        },
    },
    "ExitWindowsEx": {
        "action_name": "shutdown system",
        "action_vocab": "maecVocabs:SystemActionNameVocab-1.0",
        "parameter_associated_arguments": {"Flags": {"associated_argument_name": "Flags"}, "Reason": {"associated_argument_name": "Reason"}},
    },
    "IsDebuggerPresent": {"action_name": "check for remote debugger", "action_vocab": "maecVocabs:DebuggingActionNameVocab-1.0"},
    "LookupPrivilegeValueW": {
        "action_name": "find privilege value",
        "parameter_associated_objects": {
            "SystemName": {"associated_object_type": "SystemObjectType", "associated_object_element": "Hostname", "association_type": "input"}
        },
        "parameter_associated_arguments": {"PrivilegeName": {"associated_argument_name": "Privilege Name"}},
    },
    "NtClose": {
        "action_name": "close handle",
        "parameter_associated_objects": {
            "Handle": {"associated_object_type": "WindowsHandleObjectType", "associated_object_element": "ID", "association_type": "input"}
        },
    },
    "WriteConsoleA": {
        "action_name": "write to console",
        "parameter_associated_objects": {
            "ConsoleHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Console"},
            }
        },
    },
    "WriteConsoleW": {
        "action_name": "write to console",
        "parameter_associated_objects": {
            "ConsoleHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Console"},
            }
        },
    },
    "ZwMapViewOfSection": {
        "action_name": "map view of section",
        "parameter_associated_objects": {
            "SectionHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Section"},
            },
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
        },
        "parameter_associated_arguments": {
            "BaseAddress": {"associated_argument_name": "Base Address", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
            "SectionOffset": {"associated_argument_name": "Section Offset"},
        },
    },
    "GetSystemMetrics": {
        "action_name": "get system metrics",
        "parameter_associated_arguments": {"SystemMetricIndex": {"associated_argument_name": "System Metric Index"}},
    },
    "NtDelayExecution": {
        "action_name": "delay execution",
        "parameter_associated_arguments": {"Milliseconds": {"associated_argument_name": "Milliseconds"}},
    },
    "GetLocalTime": {"action_name": "get system local time", "action_vocab": "maecVocabs:SystemActionNameVocab-1.0"},
    "GetSystemTime": {"action_name": "get system time", "action_vocab": "maecVocabs:SystemActionNameVocab-1.0"},
    "GetTickCount": {"action_name": "get tick count"},
    "NtQuerySystemTime": {"action_name": "get system time", "action_vocab": "maecVocabs:SystemActionNameVocab-1.0"},
    "WSAStartup": {
        "action_name": "initialize winsock",
        "parameter_associated_arguments": {"VersionRequested": {"associated_argument_name": "Version Requested"}},
    },
    "gethostbyname": {
        "action_name": "get host by name",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {
            "Name": {"associated_argument_name": "Hostname", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"}
        },
    },
    "socket": {
        "action_name": "create socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_objects": {
            "type": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Type",
                "association_type": "output",
                "post_processing": "socketTypeToString",
            },
            "af": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Address_Family",
                "association_type": "output",
                "post_processing": "socketAFToString",
            },
            "protocol": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Protocol",
                "association_type": "output",
                "post_processing": "socketProtoToString",
            },
            "group_together": ["type", "protocol", "af"],
        },
    },
    "connect": {
        "action_name": "connect to socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "send": {
        "action_name": "send data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {
            "socket": {"associated_argument_name": "Socket Descriptor"},
            "buffer": {"associated_argument_name": "Data Buffer"},
        },
    },
    "sendto": {
        "action_name": "send data to address on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {
            "socket": {"associated_argument_name": "Socket Descriptor"},
            "buffer": {"associated_argument_name": "Data Buffer"},
        },
    },
    "recv": {
        "action_name": "receive data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {
            "socket": {"associated_argument_name": "Socket Descriptor"},
            "buffer": {"associated_argument_name": "Data Buffer"},
        },
    },
    "recvfrom": {
        "action_name": "receive data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {
            "socket": {"associated_argument_name": "Socket Descriptor"},
            "buffer": {"associated_argument_name": "Data Buffer"},
        },
    },
    "accept": {
        "action_name": "accept socket connection",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "bind": {
        "action_name": "bind address to socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "ip", "element_name": "IP_Address/Address_Value"},
                    {"parameter_name": "port", "element_name": "Port/Port_Value"},
                ],
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Local_Address",
                "association_type": "input",
            }
        },
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "listen": {
        "action_name": "listen on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "select": {
        "action_name": "check for ready sockets",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "setsockopt": {
        "action_name": "set socket option",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "ioctlsocket": {
        "action_name": "send command to socket",
        "parameter_associated_arguments": {
            "socket": {"associated_argument_name": "Socket Descriptor"},
            "command": {"associated_argument_name": "Command"},
        },
    },
    "closesocket": {
        "action_name": "close socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "shutdown": {
        "action_name": "disable socket operation",
        "parameter_associated_arguments": {
            "socket": {"associated_argument_name": "Socket Descriptor"},
            "how": {"associated_argument_name": "Operation"},
        },
    },
    "WSARecv": {
        "action_name": "receive data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "WSARecvFrom": {
        "action_name": "receive data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "WSASend": {
        "action_name": "send data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "WSASendTo": {
        "action_name": "send data on socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "WSASocketA": {
        "action_name": "create socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_objects": {
            "type": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Type",
                "association_type": "output",
                "post_processing": "socketTypeToString",
            },
            "af": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Address_Family",
                "association_type": "output",
                "post_processing": "socketAFToString",
            },
            "protocol": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Protocol",
                "association_type": "output",
                "post_processing": "socketProtoToString",
            },
            "group_together": ["type", "protocol", "af"],
        },
    },
    "WSASocketW": {
        "action_name": "create socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_objects": {
            "type": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Type",
                "association_type": "output",
                "post_processing": "socketTypeToString",
            },
            "af": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Address_Family",
                "association_type": "output",
                "post_processing": "socketAFToString",
            },
            "protocol": {
                "associated_object_type": "NetworkSocketObjectType",
                "associated_object_element": "Protocol",
                "association_type": "output",
                "post_processing": "socketProtoToString",
            },
            "group_together": ["type", "protocol", "af"],
        },
    },
    "ConnectEx": {
        "action_name": "connect to socket",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_arguments": {"socket": {"associated_argument_name": "Socket Descriptor"}},
    },
    "TransmitFile": {
        "action_name": "send file over socket",
        "parameter_associated_objects": {
            "socket": {"associated_object_type": "WindowsHandleObjectType", "associated_object_element": "ID", "association_type": "input"},
            "FileHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "File"},
            },
            "NumberOfBytesToWrite": {
                "associated_object_type": "FileObjectType",
                "associated_object_element": "Size_In_Bytes",
                "association_type": "output",
            },
        },
        "parameter_associated_arguments": {"NumberOfBytesPerSend": {"associated_argument_name": "Send Data Block Size"}},
    },
    "NtCreateMutant": {
        "action_name": "create mutex",
        "action_vocab": "maecVocabs:SynchronizationActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Mutex"},
            },
            "MutexName": {
                "associated_object_type": "WindowsMutexObjectType",
                "associated_object_element": "Name",
                "association_type": "output",
            },
        },
        "parameter_associated_arguments": {"InitialOwner": {"associated_argument_name": "Initial Owner"}},
    },
    "NtOpenMutant": {
        "action_name": "open mutex",
        "action_vocab": "maecVocabs:SynchronizationActionNameVocab-1.0",
        "parameter_associated_objects": {
            "Handle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Mutex"},
            },
            "MutexName": {"associated_object_type": "WindowsMutexObjectType", "associated_object_element": "Name", "association_type": "input"},
        },
    },
    "NtCreateNamedPipeFile": {
        "action_name": "create named pipe",
        "action_vocab": "maecVocabs:IPCActionNameVocab-1.0",
        "parameter_associated_objects": {
            "NamedPipeHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "NamedPipe"},
            },
            "PipeName": {"associated_object_type": "WindowsPipeObjectType", "associated_object_element": "Name", "association_type": "output"},
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {
                "associated_argument_name": "Access Mode",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "ShareAccess": {"associated_argument_name": "Share Access Mode"},
        },
    },
    "OpenSCManagerA": {
        "action_name": "open service control manager",
        "parameter_associated_objects": {
            "MachineName": {"associated_object_type": "SystemObjectType", "associated_object_element": "Hostname", "association_type": "input"}
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {
                "associated_argument_name": "Access Mode",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "DatabaseName": {"associated_argument_name": "Database Name"},
        },
    },
    "OpenSCManagerW": {
        "action_name": "open service control manager",
        "parameter_associated_objects": {
            "MachineName": {"associated_object_type": "SystemObjectType", "associated_object_element": "Hostname", "association_type": "input"}
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {
                "associated_argument_name": "Access Mode",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "DatabaseName": {"associated_argument_name": "Database Name"},
        },
    },
    "CreateServiceA": {
        "action_name": "create service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceControlHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "ServiceControlManager"},
            },
            "ServiceName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Service_Name",
                "association_type": "output",
            },
            "DisplayName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Display_Name",
                "association_type": "output",
            },
            "ServiceType": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Service_Type",
                "association_type": "output",
            },
            "StartType": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Startup_Type",
                "association_type": "output",
            },
            "ServiceStartName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Started_As",
                "association_type": "output",
            },
            "BinaryPathName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Image_Info/Path",
                "association_type": "output",
            },
            "group_together": ["ServiceName", "DisplayName", "ServiceType", "StartType", "ServiceStartName", "BinaryPathName"],
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {
                "associated_argument_name": "Access Mode",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "ErrorControl": {"associated_argument_name": "Error Control"},
        },
    },
    "CreateServiceW": {
        "action_name": "create service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceControlHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "ServiceControlManager"},
            },
            "ServiceName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Service_Name",
                "association_type": "output",
            },
            "DisplayName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Display_Name",
                "association_type": "output",
            },
            "ServiceType": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Service_Type",
                "association_type": "output",
            },
            "StartType": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Startup_Type",
                "association_type": "output",
            },
            "ServiceStartName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Started_As",
                "association_type": "output",
            },
            "BinaryPathName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Image_Info/Path",
                "association_type": "output",
            },
            "group_together": ["ServiceName", "DisplayName", "ServiceType", "StartType", "ServiceStartName", "BinaryPathName"],
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {
                "associated_argument_name": "Access Mode",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "ErrorControl": {"associated_argument_name": "Error Control"},
        },
    },
    "OpenServiceA": {
        "action_name": "open service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceControlManager": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "ServiceControlManager"},
            },
            "ServiceName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Service_Name",
                "association_type": "input",
            },
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {"associated_argument_name": "Access Mode", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"}
        },
    },
    "OpenServiceW": {
        "action_name": "open service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceControlManager": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "ServiceControlManager"},
            },
            "ServiceName": {
                "associated_object_type": "WindowsServiceObjectType",
                "associated_object_element": "Service_Name",
                "association_type": "input",
            },
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {"associated_argument_name": "Access Mode", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"}
        },
    },
    "StartServiceA": {
        "action_name": "start service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Service"},
            }
        },
        "parameter_associated_arguments": {"Arguments": {"associated_argument_name": "Access Mode"}},
    },
    "StartServiceW": {
        "action_name": "start service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Service"},
            }
        },
        "parameter_associated_arguments": {"Arguments": {"associated_argument_name": "Access Mode"}},
    },
    "ControlService": {
        "action_name": "send control code to service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Service"},
            }
        },
        "parameter_associated_arguments": {
            "ControlCode": {"associated_argument_name": "Control Code", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"}
        },
    },
    "DeleteService": {
        "action_name": "delete service",
        "action_vocab": "maecVocabs:ServiceActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ServiceHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Service"},
            }
        },
    },
    "NtCreateThread": {
        "action_name": "create thread",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            },
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Process"},
            },
        },
        "parameter_associated_arguments": {
            "ObjectAttributes": {"associated_argument_name": "Options", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"}
        },
    },
    "NtOpenThread": {
        "action_name": "open thread",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            }
        },
        "parameter_associated_arguments": {
            "DesiredAccess": {
                "associated_argument_name": "Access Mode",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "ObjectAttributes": {"associated_argument_name": "Options", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
        },
    },
    "NtGetContextThread": {
        "action_name": "get thread context",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            }
        },
    },
    "NtSetContextThread": {
        "action_name": "set thread context",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            }
        },
    },
    "NtSuspendThread": {
        "action_name": "suspend thread",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            }
        },
    },
    "NtResumeThread": {
        "action_name": "resume thread",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            }
        },
    },
    "NtTerminateThread": {
        "action_name": "kill thread",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            }
        },
    },
    "CreateThread": {
        "action_name": "create thread",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ThreadId": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "output",
            }
        },
        "parameter_associated_arguments": {
            "StartRoutine": {
                "associated_argument_name": "Code Address",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "Parameter": {"associated_argument_name": "Options", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
            "CreationFlags": {
                "associated_argument_name": "Creation Flags",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
        },
    },
    "CreateRemoteThread": {
        "action_name": "create remote thread in process",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
            },
            "ThreadId": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "output",
            },
        },
        "parameter_associated_arguments": {
            "StartRoutine": {
                "associated_argument_name": "Code Address",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "Parameter": {"associated_argument_name": "Options", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
            "CreationFlags": {
                "associated_argument_name": "Creation Flags",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
        },
    },
    "ExitThread": {"action_name": "exit thread"},
    "RtlCreateUserThread": {
        "action_name": "create thread",
        "action_vocab": "maecVocabs:ProcessThreadActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ProcessHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
            },
            "ThreadHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "output",
                "forced": {"associated_object_element": "Type", "value": "Thread"},
            },
            "ThreadId": {
                "associated_object_type": "WindowsThreadObjectType",
                "associated_object_element": "Thread_ID",
                "association_type": "output",
            },
        },
        "parameter_associated_arguments": {
            "CreatedSuspended": {
                "associated_argument_name": "Control Parameter",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "StartAddress": {
                "associated_argument_name": "Code Address",
                "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0",
            },
            "StartParameter": {"associated_argument_name": "Options", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
        },
    },
    "URLDownloadToFileW": {
        "action_name": "download file",
        "action_vocab": "maecVocabs:NetworkActionNameVocab-1.0",
        "parameter_associated_objects": {
            "URL": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
            "FileName": {"associated_object_type": "FileObjectType", "associated_object_element": "File_Path", "association_type": "output"},
        },
    },
    "InternetOpenA": {
        "action_name": "initialize wininet",
        "parameter_associated_objects": {
            "Agent": {
                "associated_object_type": "HTTPSessionObjectType",
                "associated_object_element": "list__HTTP_Request_Response/HTTP_Client_Request/HTTP_Request_Header/Parsed_Header/User_Agent",
                "association_type": "input",
            }
        },
        "parameter_associated_arguments": {
            "AccessType": {"associated_argument_name": "Access Mode", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
            "ProxyName": {"associated_argument_name": "Proxy Name"},
            "ProxyBypass": {"associated_argument_name": "Proxy Bypass"},
            "Flags": {"associated_argument_name": "Flags"},
        },
    },
    "InternetOpenW": {
        "action_name": "initialize wininet",
        "parameter_associated_objects": {
            "Agent": {
                "associated_object_type": "HTTPSessionObjectType",
                "associated_object_element": "list__HTTP_Request_Response/HTTP_Client_Request/HTTP_Request_Header/Parsed_Header/User_Agent",
                "association_type": "input",
            }
        },
        "parameter_associated_arguments": {
            "AccessType": {"associated_argument_name": "Access Mode", "associated_argument_vocab": "cyboxVocabs:ActionArgumentNameVocab-1.0"},
            "ProxyName": {"associated_argument_name": "Proxy Name"},
            "ProxyBypass": {"associated_argument_name": "Proxy Bypass"},
            "Flags": {"associated_argument_name": "Flags"},
        },
    },
    "InternetConnectA": {
        "action_name": "connect to server",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            },
            "ServerName": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
            "ServerPort": {"associated_object_type": "PortObjectType", "associated_object_element": "Port_Value", "association_type": "input"},
        },
        "parameter_associated_arguments": {
            "Username": {"associated_argument_name": "Username"},
            "Password": {"associated_argument_name": "Password"},
            "Service": {"associated_argument_name": "Service Type"},
            "Flags": {"associated_argument_name": "Flags"},
        },
    },
    "InternetConnectW": {
        "action_name": "connect to server",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            },
            "ServerName": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
            "ServerPort": {"associated_object_type": "PortObjectType", "associated_object_element": "Port_Value", "association_type": "input"},
        },
        "parameter_associated_arguments": {
            "Username": {"associated_argument_name": "Username"},
            "Password": {"associated_argument_name": "Password"},
            "Service": {"associated_argument_name": "Service Type"},
            "Flags": {"associated_argument_name": "Flags"},
        },
    },
    "InternetOpenURLA": {
        "action_name": "connect to url",
        "action_vocab": "maecVocabs:NetworkActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ConnectionHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Connection"},
            },
            "URL": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
            "Headers": {
                "associated_object_type": "HTTPSessionObjectType",
                "associated_object_element": "list__HTTP_Request_Response/HTTP_Client_Request/HTTP_Request_Header/Parsed_Header/Raw_Header",
                "association_type": "input",
            },
        },
        "parameter_associated_arguments": {"Flags": {"associated_argument_name": "Flags"}},
    },
    "InternetOpenURLW": {
        "action_name": "connect to url",
        "action_vocab": "maecVocabs:NetworkActionNameVocab-1.0",
        "parameter_associated_objects": {
            "ConnectionHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Connection"},
            },
            "URL": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
            "Headers": {
                "associated_object_type": "HTTPSessionObjectType",
                "associated_object_element": "list__HTTP_Request_Response/HTTP_Client_Request/HTTP_Request_Header/Parsed_Header/Raw_Header",
                "association_type": "input",
            },
        },
        "parameter_associated_arguments": {"Flags": {"associated_argument_name": "Flags"}},
    },
    "HttpOpenRequestA": {
        "action_name": "open http request",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            },
            "Path": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
        },
        "parameter_associated_arguments": {"Flags": {"associated_argument_name": "Flags"}},
    },
    "HttpOpenRequestW": {
        "action_name": "open http request",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            },
            "Path": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"},
        },
        "parameter_associated_arguments": {"Flags": {"associated_argument_name": "Flags"}},
    },
    "InternetReadFile": {
        "action_name": "read from internet resource",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            }
        },
    },
    "InternetWriteFile": {
        "action_name": "write to internet resource",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            }
        },
    },
    "InternetCloseHandle": {
        "action_name": "close internet resource handle",
        "parameter_associated_objects": {
            "InternetHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "Internet Resource"},
            }
        },
    },
    "HttpSendRequestA": {
        "action_name": "send http request",
        "parameter_associated_objects": {
            "RequestHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "HTTPRequest"},
            },
            "Headers": {
                "associated_object_type": "HTTPSessionObjectType",
                "associated_object_element": "list__HTTP_Request_Response/HTTP_Client_Request/HTTP_Request_Header/Raw_Header",
                "association_type": "input",
            },
        },
        "parameter_associated_arguments": {"PostData": {"associated_argument_name": "Post Data"}},
    },
    "HttpSendRequestW": {
        "action_name": "send http request",
        "parameter_associated_objects": {
            "RequestHandle": {
                "associated_object_type": "WindowsHandleObjectType",
                "associated_object_element": "ID",
                "association_type": "input",
                "forced": {"associated_object_element": "Type", "value": "HTTPRequest"},
            },
            "Headers": {
                "associated_object_type": "HTTPSessionObjectType",
                "associated_object_element": "list__HTTP_Request_Response/HTTP_Client_Request/HTTP_Request_Header/Raw_Header",
                "association_type": "input",
            },
        },
        "parameter_associated_arguments": {"PostData": {"associated_argument_name": "Post Data"}},
    },
    "DnsQuery_A": {
        "action_name": "send dns query",
        "action_vocab": "maecVocabs:DNSActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "Name", "element_name": "QName/Value"},
                    {"parameter_name": "Type", "element_name": "QType"},
                ],
                "associated_object_type": "DNSQueryObjectType",
                "associated_object_element": "Question",
                "association_type": "input",
            }
        },
        "parameter_associated_arguments": {"Options": {"associated_argument_name": "Options"}},
    },
    "DnsQuery_UTF8": {
        "action_name": "send dns query",
        "action_vocab": "maecVocabs:DNSActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "Name", "element_name": "QName/Value"},
                    {"parameter_name": "Type", "element_name": "QType"},
                ],
                "associated_object_type": "DNSQueryObjectType",
                "associated_object_element": "Question",
                "association_type": "input",
            }
        },
        "parameter_associated_arguments": {"Options": {"associated_argument_name": "Options"}},
    },
    "DnsQuery_W": {
        "action_name": "send dns query",
        "action_vocab": "maecVocabs:DNSActionNameVocab-1.0",
        "parameter_associated_objects": {
            "group_together_nested": {
                "parameter_mappings": [
                    {"parameter_name": "Name", "element_name": "QName/Value"},
                    {"parameter_name": "Type", "element_name": "QType"},
                ],
                "associated_object_type": "DNSQueryObjectType",
                "associated_object_element": "Question",
                "association_type": "input",
            }
        },
        "parameter_associated_arguments": {"Options": {"associated_argument_name": "Options"}},
    },
    "getaddrinfo": {
        "action_name": "get host by name",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_objects": {
            "NodeName": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"}
        },
        "parameter_associated_arguments": {"ServiceName": {"associated_argument_name": "Service Name"}},
    },
    "GetAddrInfoW": {
        "action_name": "get host by name",
        "action_vocab": "maecVocabs:SocketActionNameVocab-1.0",
        "parameter_associated_objects": {
            "NodeName": {"associated_object_type": "URIObjectType", "associated_object_element": "Value", "association_type": "input"}
        },
        "parameter_associated_arguments": {"ServiceName": {"associated_argument_name": "Service Name"}},
    },
}


def hiveHexToString(hive_hex_value):
    """Maps a Registry Hive hex input to its String (name) equivalent"""
    str_val = str(hive_hex_value)
    if str_val == "0x80000000" or str_val == "-2147483648" or str_val == "2147483648":
        return "HKEY_CLASSES_ROOT"
    elif str_val == "0x80000001" or str_val == "-2147483647" or str_val == "2147483649":
        return "HKEY_CURRENT_USER"
    elif str_val == "0x80000002" or str_val == "-2147483646" or str_val == "2147483650":
        return "HKEY_LOCAL_MACHINE"
    elif str_val == "0x80000003" or str_val == "-2147483645" or str_val == "2147483651":
        return "HKEY_USERS"
    elif str_val == "0x80000004":
        return "HKEY_PERFORMANCE_DATA"
    elif str_val == "0x80000005" or str_val == "2147483653":
        return "HKEY_CURRENT_CONFIG"
    elif str_val == "0x80000006":
        return "HKEY_DYN_DATA"
    else:
        return hive_hex_value


def regDatatypeToString(datatype_int_value):
    """Maps a Registry Datatype integer input to its String (name) equivalent"""
    if str(datatype_int_value) == "1":
        return "REG_SZ"
    elif str(datatype_int_value) == "2":
        return "REG_EXPAND_SZ"
    elif str(datatype_int_value) == "3":
        return "REG_BINARY"
    elif str(datatype_int_value) == "4":
        return "REG_DWORD"
    elif str(datatype_int_value) == "5":
        return "REG_DWORD_BIG_ENDIAN"
    elif str(datatype_int_value) == "6":
        return "REG_LINK"
    elif str(datatype_int_value) == "7":
        return "REG_MULTI_SZ"
    elif str(datatype_int_value) == "8":
        return "REG_RESOURCE_LIST"
    elif str(datatype_int_value) == "9":
        return "REG_FULL_RESOURCE_DESCRIPTOR"
    elif str(datatype_int_value) == "10":
        return "REG_RESOURCE_REQUIREMENTS_LIST"
    elif str(datatype_int_value) == "11":
        return "REG_QWORD"
    else:
        return datatype_int_value


def socketProtoToString(proto_int_value):
    """Maps a Socket Protocol integer input to its String (name) equivalent"""
    if str(proto_int_value) == "1":
        return "IPPROTO_ICMP"
    elif str(proto_int_value) == "2":
        return "IPPROTO_IGMP"
    elif str(proto_int_value) == "3":
        return "BTHPROTO_RFCOMM"
    elif str(proto_int_value) == "6":
        return "IPPROTO_TCP"
    elif str(proto_int_value) == "17":
        return "IPPROTO_UDP"
    elif str(proto_int_value) == "58":
        return "IPPROTO_ICMPV6"
    elif str(proto_int_value) == "113":
        return "IPPROTO_RM"
    else:
        return proto_int_value


def socketAFToString(af_int_value):
    """Maps a Socket Address Family integer input to its String (name) equivalent"""
    if str(af_int_value) == "0":
        return "AF_UNSPEC"
    elif str(af_int_value) == "2":
        return "AF_INET"
    elif str(af_int_value) == "6":
        return "AF_IPX"
    elif str(af_int_value) == "16":
        return "AF_APPLETALK"
    elif str(af_int_value) == "17":
        return "AF_NETBIOS"
    elif str(af_int_value) == "23":
        return "AF_INET6"
    elif str(af_int_value) == "26":
        return "AF_IRDA"
    elif str(af_int_value) == "32":
        return "AF_BTH"
    else:
        return af_int_value


def socketTypeToString(type_int_value):
    """Maps a Socket Type integer input to its String (name) equivalent"""
    if str(type_int_value) == "1":
        return "SOCK_STREAM"
    elif str(type_int_value) == "2":
        return "SOCK_DGRAM"
    elif str(type_int_value) == "3":
        return "SOCK_RAW"
    elif str(type_int_value) == "4":
        return "SOCK_RDM"
    elif str(type_int_value) == "5":
        return "SOCK_SEQPACKET"
    else:
        return type_int_value


def intToHex(value):
    """Convert an integer to a hex string"""
    if isinstance(value, int):
        value = "0x{0:08x}".format(value)

    return value


def regStringToHive(reg_string):
    """Maps a string representing a Registry Key from a NT* API call input to its normalized hive"""
    normalized_key = fix_key(reg_string)
    return normalized_key.split("\\")[0]


def regStringToKey(reg_string):
    """Maps a string representing a Registry Key from a NT* API call input to its normalized key portion"""
    normalized_key = fix_key(reg_string)
    return "\\".join(normalized_key.split("\\")[1:])


class MAEC41Report(Report):
    """Generates a MAEC 4.1 report.
       --Output modes (set in reporting.conf):
           mode = "full": Output fully mapped Actions (see maec41), including Windows Handle mapped/substituted objects,
                          along with API call/parameter capture via Action Implementations.
           mode = "overview": Output only fully mapped Actions, without any Action Implementations. Default mode.
           mode = "api": Output only Actions with Action Implementations, but no mapped components.
       --Other configuration parameters:
           processtree = "true" | "false". Output captured ProcessTree as part of dynamic analysis MAEC Bundle. Default = "true".
           output_handles = "true" | "false". Output the Windows Handles used to  construct the Object-Handle mappings as a
                                              separate Object Collection in the dynamic analysis MAEC Bundle. Only applicable
                                              for mode = "full" or mode = "overview". Default = "false".
           static = "true" | "false". Output Cuckoo static analysis (PEfile) output as a separate MAEC Bundle in the document.
                                      Default = "true".
           strings = "true" | "false". Output Cuckoo strings output as a separate MAEC Bundle in the document. Default = "true".
           virustotal = "true" | "false". Output VirusTotal output as a separate MAEC Bundle in the document. Default = "true".
           deduplicate = "true" | "false". Deduplicate the CybOX Objects in the generated dynamic analysis MAEC Bundle. Default = "true".
    """

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_CYBOX:
            raise CuckooDependencyError("Unable to import cybox (install with `pip3 install cybox`)")
        if not HAVE_MAEC:
            raise CuckooDependencyError("Unable to import maec (install with `pip3 install maec`)")
        self._illegal_xml_chars_RE = re.compile(u"[\x00-\x08\x0b\x0c\x0e-\x1F\uD800-\uDFFF\uFFFE\uFFFF]")
        # Map of PIDs to the Actions that they spawned.
        self.pidActionMap = {}
        # Windows Handle map.
        self.handleMap = {}
        # Save results.
        self.results = results
        # Setup MAEC document structure.
        self.setupMAEC()
        # Build MAEC doc.
        self.addSubjectAttributes()
        self.addDroppedFiles()
        self.addAnalyses()
        self.addActions()
        self.addProcessTree()
        # Write XML report.
        self.output()

    def setupMAEC(self):
        """Generates MAEC Package, Malware Subject, and Bundle structure"""
        # Instantiate the Namespace class for automatic ID generation.
        NS = Namespace("http://www.cuckoosandbox.org", "Cuckoosandbox")
        mixbox.idgen.set_id_namespace(NS)
        # Setup the MAEC components
        if "target" in self.results and self.results["target"]["category"] == "file":
            self.tool_id = mixbox.idgen.create_id(prefix=self.results["target"]["file"]["md5"])
        elif "target" in self.results and self.results["target"]["category"] == "url":
            self.tool_id = mixbox.idgen.create_id(prefix=hashlib.md5(self.results["target"]["file"]).hexdigest())
        else:
            raise CuckooReportError("Unknown target type or targetinfo module disabled")

        # Generate Package.
        self.package = Package()
        # Generate Malware Subject.
        self.subject = MalwareSubject()
        # Add the Subject to the Package.
        self.package.add_malware_subject(self.subject)
        # Generate dynamic analysis bundle.
        self.dynamic_bundle = Bundle(None, False, "4.1", "dynamic analysis tool output")
        # Add the Bundle to the Subject.
        self.subject.add_findings_bundle(self.dynamic_bundle)
        # Generate Static Analysis Bundles, if static results exist.
        if self.options["static"] and "static" in self.results and self.results["static"]:
            self.static_bundle = Bundle(None, False, "4.1", "static analysis tool output")
            self.subject.add_findings_bundle(self.static_bundle)
        if self.options["strings"] and "strings" in self.results and self.results["strings"]:
            self.strings_bundle = Bundle(None, False, "4.1", "static analysis tool output")
            self.subject.add_findings_bundle(self.strings_bundle)
        if self.options["virustotal"] and "virustotal" in self.results and self.results["virustotal"]:
            self.virustotal_bundle = Bundle(None, False, "4.1", "static analysis tool output")
            self.subject.add_findings_bundle(self.virustotal_bundle)

    def addActions(self):
        """Add Actions section."""
        # Process-initiated Actions.
        if "behavior" in self.results and "processes" in self.results["behavior"]:
            for process in self.results["behavior"]["processes"]:
                self.createProcessActions(process)
        # Network actions.
        if "network" in self.results and isinstance(self.results["network"], dict) and len(self.results["network"]) > 0:
            if (
                "udp" in self.results["network"]
                and isinstance(self.results["network"]["udp"], list)
                and len(self.results["network"]["udp"]) > 0
            ):
                self.dynamic_bundle.add_named_action_collection("Network Actions")
                for network_data in self.results["network"]["udp"]:
                    self.createActionNet(
                        network_data, {"value": "connect to socket address", "xsi:type": "maecVocabs:NetworkActionNameVocab-1.0"}, "UDP"
                    )
            if (
                "dns" in self.results["network"]
                and isinstance(self.results["network"]["dns"], list)
                and len(self.results["network"]["dns"]) > 0
            ):
                self.dynamic_bundle.add_named_action_collection("Network Actions")
                for network_data in self.results["network"]["dns"]:
                    self.createActionNet(
                        network_data, {"value": "send dns query", "xsi:type": "maecVocabs:DNSActionNameVocab-1.0"}, "UDP", "DNS"
                    )
            if (
                "tcp" in self.results["network"]
                and isinstance(self.results["network"]["tcp"], list)
                and len(self.results["network"]["tcp"]) > 0
            ):
                self.dynamic_bundle.add_named_action_collection("Network Actions")
                for network_data in self.results["network"]["tcp"]:
                    self.createActionNet(
                        network_data, {"value": "connect to socket address", "xsi:type": "maecVocabs:NetworkActionNameVocab-1.0"}, "TCP"
                    )
            if (
                "http" in self.results["network"]
                and isinstance(self.results["network"]["http"], list)
                and len(self.results["network"]["http"]) > 0
            ):
                self.dynamic_bundle.add_named_action_collection("Network Actions")
                for network_data in self.results["network"]["http"]:
                    self.createActionNet(
                        network_data,
                        {
                            "value": "send http " + str(network_data["method"]).lower() + " request",
                            "xsi:type": "maecVocabs:HTTPActionNameVocab-1.0",
                        },
                        "TCP",
                        "HTTP",
                    )
        # Deduplicate the Bundle.
        if self.options["deduplicate"]:
            self.dynamic_bundle.deduplicate()

    def createActionNet(self, network_data, action_name, layer4_protocol=None, layer7_protocol=None):
        """Create a network Action.
        @return: action.
        """
        src_category = "ipv4-addr"
        dst_category = "ipv4-addr"
        if ":" in network_data.get("src", ""):
            src_category = "ipv6-addr"
        if ":" in network_data.get("dst", ""):
            dst_category = "ipv6-addr"
        # Construct the various dictionaries.
        if layer7_protocol is not None:
            object_properties = {
                "xsi:type": "NetworkConnectionObjectType",
                "layer4_protocol": {"value": layer4_protocol, "force_datatype": True},
                "layer7_protocol": {"value": layer7_protocol, "force_datatype": True},
            }
        else:
            object_properties = {
                "xsi:type": "NetworkConnectionObjectType",
                "layer4_protocol": {"value": layer4_protocol, "force_datatype": True},
            }
        associated_object = {"id": mixbox.idgen.create_id(prefix="object"), "properties": object_properties}
        # General network connection properties.
        if layer7_protocol is None:
            object_properties["source_socket_address"] = {
                "ip_address": {"category": src_category, "address_value": network_data["src"]},
                "port": {"port_value": network_data["sport"]},
            }
            object_properties["destination_socket_address"] = {
                "ip_address": {"category": dst_category, "address_value": network_data["dst"]},
                "port": {"port_value": network_data["dport"]},
            }
        # Layer 7-specific object properties.
        if layer7_protocol == "DNS":
            answer_resource_records = []
            for answer_record in network_data["answers"]:
                answer_resource_records.append({"entity_type": answer_record["type"], "record_data": answer_record["data"]})
            object_properties["layer7_connections"] = {
                "dns_queries": [
                    {
                        "question": {"qname": {"value": network_data["request"]}, "qtype": network_data["type"]},
                        "answer_resource_records": answer_resource_records,
                    }
                ]
            }
        elif layer7_protocol == "HTTP":
            object_properties["layer7_connections"] = {
                "http_session": {
                    "http_request_response": [
                        {
                            "http_client_request": {
                                "http_request_line": {
                                    "http_method": {"value": network_data["method"], "force_datatype": True},
                                    "value": network_data["path"],
                                    "version": network_data["version"],
                                },
                                "http_request_header": {
                                    "parsed_header": {
                                        "user_agent": network_data["user-agent"],
                                        "host": {"domain_name": {"value": network_data["host"]}, "port": {"port_value": network_data["port"]}},
                                    }
                                },
                                "http_message_body": {"message_body": network_data["body"]},
                            }
                        }
                    ]
                }
            }
        action_dict = {"id": mixbox.idgen.create_id(prefix="action"), "name": action_name, "associated_objects": [associated_object]}
        # Add the Action to the dynamic analysis bundle.
        self.dynamic_bundle.add_action(MalwareAction.from_dict(action_dict), "Network Actions")

    def addProcessTree(self):
        """Creates the ProcessTree corresponding to that observed by Cuckoo."""
        if (
            self.options["processtree"]
            and "behavior" in self.results
            and "processtree" in self.results["behavior"]
            and self.results["behavior"]["processtree"]
        ):
            # Process Tree TypedField Fix.
            NS_LIST = cybox.utils.nsparser.NS_LIST + [
                (
                    "http://maec.mitre.org/language/schema.html#bundle",
                    "maecBundle",
                    "http://maec.mitre.org/language/version4.1/maec_bundle_schema.xsd",
                ),
            ]
            OBJ_LIST = cybox.utils.nsparser.OBJ_LIST + [
                (
                    "ProcessTreeNodeType",
                    "maec.bundle.process_tree.ProcessTreeNode",
                    "",
                    "http://cybox.mitre.org/objects#ProcessObject-2",
                    ["ProcessObjectType"],
                ),
            ]
            cybox.META = cybox.utils.nsparser.Metadata(NS_LIST, OBJ_LIST)

            root_node = self.results["behavior"]["processtree"][0]

            if root_node:
                root_node_dict = {
                    "id": mixbox.idgen.create_id(prefix="process_tree_node"),
                    "pid": root_node["pid"],
                    "name": root_node["name"],
                    "initiated_actions": self.pidActionMap[root_node["pid"]],
                    "spawned_processes": [self.createProcessTreeNode(child_process) for child_process in root_node["children"]],
                }

                self.dynamic_bundle.set_process_tree(ProcessTree.from_dict({"root_process": root_node_dict}))

    def createProcessTreeNode(self, process):
        """Creates a single ProcessTreeNode corresponding to a single node in the tree observed cuckoo.
        @param process: process from cuckoo dict.
        """
        process_node_dict = {
            "id": mixbox.idgen.create_id(prefix="process_tree_node"),
            "pid": process["pid"],
            "name": process["name"],
            "initiated_actions": self.pidActionMap[process["pid"]],
            "spawned_processes": [self.createProcessTreeNode(child_process) for child_process in process["children"]],
        }
        return process_node_dict

    def apiCallToAction(self, call, pos):
        """Create and return a dictionary representing a MAEC Malware Action.
        @param call: the input API call.
        @param pos: position of the Action with respect to the execution of the malware.
        """
        # Setup the action/action implementation dictionaries and lists.
        action_dict = {}
        parameter_list = []
        # Add the action parameter arguments.
        apos = 1
        for arg in call["arguments"]:
            parameter_list.append({"ordinal_position": apos, "name": arg["name"], "value": self._illegal_xml_chars_RE.sub("?", arg["value"])})
            apos = apos + 1
        # Try to add the mapped Action Name.
        if call["api"] in api_call_mappings:
            mapping_dict = api_call_mappings[call["api"]]
            # Handle the Action Name.
            if "action_vocab" in mapping_dict:
                action_dict["name"] = {"value": mapping_dict["action_name"], "xsi:type": mapping_dict["action_vocab"]}
            else:
                action_dict["name"] = {"value": mapping_dict["action_name"], "xsi:type": None}
        # Try to add the mapped Action Arguments and Associated Objects.
        # Only output in "overview" or "full" modes.
        if self.options["mode"].lower() == "overview" or self.options["mode"].lower() == "full":
            # Check to make sure we have a mapping for this API call.
            if call["api"] in api_call_mappings:
                mapping_dict = api_call_mappings[call["api"]]
                # Handle the Action Name.
                if "action_vocab" in mapping_dict:
                    action_dict["name"] = {"value": mapping_dict["action_name"], "xsi:type": mapping_dict["action_vocab"]}
                else:
                    action_dict["name"] = {"value": mapping_dict["action_name"], "xsi:type": None}
                # Handle any Parameters.
                if "parameter_associated_arguments" in mapping_dict:
                    action_dict["action_arguments"] = self.processActionArguments(
                        mapping_dict["parameter_associated_arguments"], parameter_list
                    )
                # Handle any Associated Objects.
                if "parameter_associated_objects" in mapping_dict:
                    action_dict["associated_objects"] = self.processActionAssociatedObjects(
                        mapping_dict["parameter_associated_objects"], parameter_list
                    )

        # Only output Implementation in "api" or "full" modes.
        if self.options["mode"].lower() == "api" or self.options["mode"].lower() == "full":
            action_dict["implementation"] = self.processActionImplementation(call, parameter_list)

        # Add the common Action properties.
        action_dict["id"] = mixbox.idgen.create_id(prefix="action")
        action_dict["ordinal_position"] = pos
        action_dict["action_status"] = self.mapActionStatus(call["status"])
        action_dict["timestamp"] = str(call["timestamp"]).replace(" ", "T").replace(",", ".")

        return action_dict

    def processActionImplementation(self, call, parameter_list):
        """Creates a MAEC Action Implementation based on API call input.
        @param parameter_list: the input parameter list (from the API call).
        """
        # Generate the API Call dictionary.
        if len(parameter_list) > 0:
            api_call_dict = {"function_name": call["api"], "return_value": call["return"], "parameters": parameter_list}
        else:
            api_call_dict = {"function_name": call["api"], "return_value": call["return"]}
        # Generate the action implementation dictionary.
        action_implementation_dict = {"id": mixbox.idgen.create_id(prefix="action"), "type": "api call", "api_call": api_call_dict}
        return action_implementation_dict

    def processActionArguments(self, parameter_mappings_dict, parameter_list):
        """Processes a dictionary of parameters that should be mapped to Action Arguments in the Malware Action.
        @param parameter_mappings_dict: the input parameter to Arguments mappings.
        @param parameter_list: the input parameter list (from the API call).
        """
        arguments_list = []
        for call_parameter in parameter_list:
            parameter_name = call_parameter["name"]
            argument_value = call_parameter["value"]
            # Make sure the argument value is set, otherwise skip this parameter.
            if not argument_value:
                continue
            if parameter_name in parameter_mappings_dict and "associated_argument_vocab" in parameter_mappings_dict[parameter_name]:
                arguments_list.append(
                    {
                        "argument_value": argument_value,
                        "argument_name": {
                            "value": parameter_mappings_dict[parameter_name]["associated_argument_name"],
                            "xsi:type": parameter_mappings_dict[parameter_name]["associated_argument_vocab"],
                        },
                    }
                )
            elif parameter_name in parameter_mappings_dict and "associated_argument_vocab" not in parameter_mappings_dict[parameter_name]:
                arguments_list.append(
                    {
                        "argument_value": argument_value,
                        "argument_name": {"value": parameter_mappings_dict[parameter_name]["associated_argument_name"], "xsi:type": None},
                    }
                )
        if arguments_list:
            return arguments_list

    def processActionAssociatedObjects(self, associated_objects_dict, parameter_list):
        """Processes a dictionary of parameters that should be mapped to Associated Objects in the Action
        @param associated_objects_dict: the input parameter to Associated_Objects mappings.
        @param parameter_list: the input parameter list (from the API call).
        """
        associated_objects_list = []
        processed_parameters = []
        # First, handle any parameters that need to be grouped together into a single Object.
        if "group_together" in associated_objects_dict:
            grouped_list = associated_objects_dict["group_together"]
            associated_object_dict = {}
            associated_object_dict["id"] = mixbox.idgen.create_id(prefix="object")
            associated_object_dict["properties"] = {}
            for parameter_name in grouped_list:
                parameter_value = self.getParameterValue(parameter_list, parameter_name)
                # Make sure the parameter value is set.
                if parameter_value:
                    self.processAssociatedObject(associated_objects_dict[parameter_name], parameter_value, associated_object_dict)
                # Add the parameter to the list of those that have already been processed.
                processed_parameters.append(parameter_name)
            associated_objects_list.append(associated_object_dict)
        # Handle grouped nested parameters (corner case).
        if "group_together_nested" in associated_objects_dict:
            nested_group_dict = associated_objects_dict["group_together_nested"]
            # Construct the values dictionary.
            values_dict = {}
            for parameter_mapping in nested_group_dict["parameter_mappings"]:
                parameter_value = self.getParameterValue(parameter_list, parameter_mapping["parameter_name"])
                # Handle any values that require post-processing (via external functions).
                if "post_processing" in parameter_mapping:
                    parameter_value = globals()[parameter_mapping["post_processing"]](parameter_value)
                # Make sure the parameter value is set.
                if parameter_value and "/" not in parameter_mapping["element_name"]:
                    values_dict[parameter_mapping["element_name"].lower()] = parameter_value
                elif parameter_value and "/" in parameter_mapping["element_name"]:
                    split_element_name = parameter_mapping["element_name"].split("/")
                    values_dict[split_element_name[0].lower()] = self.createNestedDict(split_element_name[1:], parameter_value)
            # Make sure we have data in the values dictionary.
            if values_dict:
                associated_objects_list.append(self.processAssociatedObject(nested_group_dict, values_dict))
        # Handle non-grouped, normal parameters.
        for call_parameter in parameter_list:
            if call_parameter["name"] not in processed_parameters and call_parameter["name"] in associated_objects_dict:
                parameter_value = self.getParameterValue(parameter_list, call_parameter["name"])
                # Make sure the parameter value is set.
                if parameter_value:
                    associated_objects_list.append(
                        self.processAssociatedObject(associated_objects_dict[call_parameter["name"]], parameter_value)
                    )
        if associated_objects_list:
            # Process any RegKeys to account for the Hive == Handle corner case.
            self.processRegKeys(associated_objects_list)
            # Perform Windows Handle Update/Replacement Processing.
            return self.processWinHandles(associated_objects_list)
        else:
            return None

    def processWinHandles(self, associated_objects_list):
        """Process any Windows Handles that may be associated with an Action. Replace Handle references with
        actual Object, if possible.
        @param associated_objects_list: the list of associated_objects processed for the Action.
        """
        input_handles = []
        output_handles = []
        input_objects = []
        output_objects = []

        # Add the named object collections if they do not exist.
        if not self.dynamic_bundle.collections.object_collections.has_collection("Handle-mapped Objects"):
            self.dynamic_bundle.add_named_object_collection("Handle-mapped Objects", mixbox.idgen.create_id(prefix="object"))
        if self.options["output_handles"] and not self.dynamic_bundle.collections.object_collections.has_collection("Windows Handles"):
            self.dynamic_bundle.add_named_object_collection("Windows Handles", mixbox.idgen.create_id(prefix="object"))
        # Determine the types of objects we're dealing with.
        for associated_object_dict in associated_objects_list:
            object_type = associated_object_dict["properties"]["xsi:type"]
            object_association_type = associated_object_dict["association_type"]["value"]
            # Check for handle objects.
            if object_type == "WindowsHandleObjectType":
                if object_association_type == "output":
                    output_handles.append(associated_object_dict)
                elif object_association_type == "input":
                    input_handles.append(associated_object_dict)
            # Check for non-handle objects.
            elif object_type != "WindowsHandleObjectType":
                if object_association_type == "output":
                    output_objects.append(associated_object_dict)
                elif object_association_type == "input":
                    input_objects.append(associated_object_dict)
        # Handle the different cases.
        # If no input/output handle, then just return the list unchanged.
        if not input_handles and not output_handles:
            return associated_objects_list
        # Handle the case where there is an input object and output handle.
        # Also handle the case where there is an output handle and output object.
        if len(output_handles) == 1:
            mapped_object = None
            output_handle = output_handles[0]
            if len(input_objects) == 1:
                mapped_object = input_objects[0]
            elif len(output_objects) == 1:
                mapped_object = output_objects[0]
            # Add the handle to the mapping and get the substituted object.
            if mapped_object:
                substituted_object = self.addHandleToMap(output_handle, mapped_object)
                if substituted_object:
                    associated_objects_list.remove(mapped_object)
                    associated_objects_list.remove(output_handle)
                    associated_objects_list.append(substituted_object)
        # Handle the corner case for certain calls with two output handles and input objects or output objects.
        elif len(output_handles) == 2:
            object_list = []
            if len(input_objects) == 2:
                object_list = input_objects
            elif len(output_objects) == 2:
                object_list = output_objects

            for object in object_list:
                if "properties" in object and object["properties"]["xsi:type"] == "WindowsThreadObjectType":
                    for output_handle in output_handles:
                        if "type" in output_handle["properties"] and output_handle["properties"]["type"] == "Thread":
                            substituted_object = self.addHandleToMap(output_handle, object)
                            if substituted_object:
                                associated_objects_list.remove(object)
                                associated_objects_list.remove(output_handle)
                                associated_objects_list.append(substituted_object)
                elif "properties" in object and object["properties"]["xsi:type"] == "ProcessObjectType":
                    for output_handle in output_handles:
                        if "type" in output_handle["properties"] and output_handle["properties"]["type"] == "Process":
                            substituted_object = self.addHandleToMap(output_handle, object)
                            if substituted_object:
                                associated_objects_list.remove(object)
                                associated_objects_list.remove(output_handle)
                                associated_objects_list.append(substituted_object)

        # Handle the case where there is an .
        # Lookup the handle and replace it with the appropriate object if we've seen it before.
        for input_handle in input_handles:
            if "type" in input_handle["properties"]:
                handle_type = input_handle["properties"]["type"]
                handle_id = input_handle["properties"]["id"]
                if handle_type in self.handleMap and handle_id in self.handleMap[handle_type]:
                    merged_objects = False
                    mapped_object = self.handleMap[handle_type][handle_id]
                    # If the input object is of the same type, then "merge" them into a new object.
                    for input_object in input_objects:
                        if input_object["properties"]["xsi:type"] == mapped_object["properties"]["xsi:type"]:
                            merged_dict = defaultdict(dict)
                            for k, v in input_object.items():
                                if isinstance(v, dict):
                                    merged_dict[k].update(v)
                                else:
                                    merged_dict[k] = v
                            for k, v in mapped_object.items():
                                if isinstance(v, dict):
                                    merged_dict[k].update(v)
                                else:
                                    merged_dict[k] = v
                            # Assign the merged object a new ID.
                            merged_dict["id"] = mixbox.idgen.create_id()
                            # Set the association type to that of the input object.
                            merged_dict["association_type"] = input_object["association_type"]
                            # Add the new object to the list of associated objects.
                            associated_objects_list.remove(input_handle)
                            associated_objects_list.remove(input_object)
                            associated_objects_list.append(merged_dict)
                            merged_objects = True
                    # Otherwise, add the existing object via a reference.
                    if not merged_objects:
                        substituted_object = {
                            "idref": mapped_object["id"],
                            "association_type": {"value": "input", "xsi:type": "maecVocabs:ActionObjectAssociationTypeVocab-1.0"},
                        }
                        associated_objects_list.remove(input_handle)
                        associated_objects_list.append(substituted_object)
        return associated_objects_list

    def addHandleToMap(self, handle_dict, object_dict):
        """Add a new Handle/Object pairing to the Handle mappings dictionary.
        @param handle_dict: the dictionary of the Handle to which the object is mapped.
        @param object_dict: the dictionary of the object mapped to the Handle.
        return: the substituted object dictionary
        """
        if "type" in handle_dict["properties"]:
            handle_type = handle_dict["properties"]["type"]
            handle_id = handle_dict["properties"]["id"]
            substituted_object = {"idref": object_dict["id"], "association_type": object_dict["association_type"]}
            if handle_type not in self.handleMap:
                self.handleMap[handle_type] = {}
            self.handleMap[handle_type][handle_id] = object_dict
            # Add the Handle to the Mapped Object as a related object.
            # This is optional, as the handles themselves may not be very useful.
            if self.options["output_handles"]:
                handle_reference_dict = {}
                handle_reference_dict["relationship"] = {"value": "Related_To", "xsi:type": "cyboxVocabs:ObjectRelationshipVocab-1.0"}
                handle_reference_dict["idref"] = handle_dict["id"]
                object_dict["related_objects"] = [handle_reference_dict]
                # Add the Objects to their corresponding Collections.
                self.dynamic_bundle.add_object(Object.from_dict(handle_dict), "Windows Handles")
            self.dynamic_bundle.add_object(Object.from_dict(object_dict), "Handle-mapped Objects")
            return substituted_object
        return None

    def processRegKeys(self, associated_objects_list):
        """Process any Registry Key associated with an action. Special case to handle registry Hives that may refer to Handles.
        @param associated_objects_list: the list of associated_objects processed for the Action.
        """
        for associated_object in associated_objects_list:
            if associated_object["properties"]["xsi:type"] == "WindowsRegistryKeyObjectType":
                if "hive" in associated_object["properties"] and "HKEY_" not in associated_object["properties"]["hive"]:
                    associated_object = self.processRegKeyHandle(associated_object["properties"]["hive"], associated_object)

    def processRegKeyHandle(self, handle_id, current_dict):
        """Process a Registry Key Handle and return the full key, recursing as necessary.
        @param handle_id: the id of the root-level handle
        @param current_dict: the dictionary containing the properties of the current key
        """
        if "RegistryKey" in self.handleMap and handle_id in self.handleMap["RegistryKey"]:
            handle_mapped_key = self.handleMap["RegistryKey"][handle_id]
            if "key" in handle_mapped_key["properties"]:
                if "key" not in current_dict["properties"]:
                    current_dict["properties"]["key"] = ""
                current_dict["properties"]["key"] = handle_mapped_key["properties"]["key"] + "\\" + current_dict["properties"]["key"]
            if "hive" in handle_mapped_key["properties"]:
                # If we find the "HKEY_" then we assume we're done.
                if "HKEY_" in handle_mapped_key["properties"]["hive"]:
                    current_dict["properties"]["hive"] = handle_mapped_key["properties"]["hive"]
                    return current_dict
                # If not, then we assume the hive refers to a Handle so we recurse.
                else:
                    self.processRegKeyHandle(handle_mapped_key["properties"]["hive"], current_dict)
        else:
            return current_dict

    def processAssociatedObject(self, parameter_mapping_dict, parameter_value, associated_object_dict=None):
        """Process a single Associated Object mapping.
        @param parameter_mapping_dict: input parameter to Associated Object mapping dictionary.
        @param parameter_value: the input parameter value (from the API call).
        @param associated_object_dict: optional associated object dict, for special cases.
        """
        if not associated_object_dict:
            associated_object_dict = {}
            associated_object_dict["id"] = mixbox.idgen.create_id(prefix="object")
            associated_object_dict["properties"] = {}
        # Set the Association Type if it has not been set already.
        if "association_type" not in associated_object_dict:
            associated_object_dict["association_type"] = {
                "value": parameter_mapping_dict["association_type"],
                "xsi:type": "maecVocabs:ActionObjectAssociationTypeVocab-1.0",
            }
        # Handle any values that require post-processing (via external functions).
        if "post_processing" in parameter_mapping_dict:
            parameter_value = globals()[parameter_mapping_dict["post_processing"]](parameter_value)

        # Handle the actual element value
        if "associated_object_element" in parameter_mapping_dict and parameter_mapping_dict["associated_object_element"]:
            # Handle simple (non-nested) elements
            if "/" not in parameter_mapping_dict["associated_object_element"]:
                associated_object_dict["properties"][parameter_mapping_dict["associated_object_element"].lower()] = parameter_value
            # Handle complex (nested) elements.
            elif "/" in parameter_mapping_dict["associated_object_element"]:
                split_elements = parameter_mapping_dict["associated_object_element"].split("/")
                if "list__" in split_elements[0]:
                    associated_object_dict["properties"][split_elements[0].lstrip("list__").lower()] = [
                        self.createNestedDict(split_elements[1:], parameter_value)
                    ]
                else:
                    associated_object_dict["properties"][split_elements[0].lower()] = self.createNestedDict(split_elements[1:], parameter_value)
        # Corner case for some Registry Keys
        else:
            associated_object_dict["properties"] = parameter_value
        # Set any "forced" properties that should be set alongside the current
        if "forced" in parameter_mapping_dict:
            self.processAssociatedObject(parameter_mapping_dict["forced"], parameter_mapping_dict["forced"]["value"], associated_object_dict)
        # Finally, set the XSI type if it has not been set already.
        if "associated_object_type" in parameter_mapping_dict and "xsi:type" not in associated_object_dict["properties"]:
            associated_object_dict["properties"]["xsi:type"] = parameter_mapping_dict["associated_object_type"]

        return associated_object_dict

    def createNestedDict(self, list, value):
        """Helper function: returns a nested dictionary for an input list.
        @param list: input list.
        @param value: value to set the last embedded dictionary item to.
        """
        nested_dict = {}

        if len(list) == 1:
            if "list__" in list[0]:
                if isinstance(value, dict):
                    list_element = [value]
                else:
                    list_element = [{list[0].lstrip("list__").lower(): value}]
                return list_element
            else:
                nested_dict[list[0].lower()] = value
                return nested_dict

        for list_item in list:
            next_index = list.index(list_item) + 1
            if "list__" in list_item:
                nested_dict[list_item.lower().lstrip("list__")] = [self.createNestedDict(list[next_index:], value)]
            else:
                nested_dict[list_item.lower()] = self.createNestedDict(list[next_index:], value)
            break

        return nested_dict

    def getParameterValue(self, parameter_list, parameter_name):
        """Finds and returns an API call parameter value from a list.
        @param parameter_list: list of API call parameters.
        @param parameter_name: name of parameter to return value for.
        """
        for parameter_dict in parameter_list:
            if parameter_dict["name"] == parameter_name:
                return parameter_dict["value"]

    def createProcessActions(self, process):
        """Creates the Actions corresponding to the API calls initiated by a process.
        @param process: process from cuckoo dict.
        """
        pos = 1
        pid = process["process_id"]

        for call in process["calls"]:
            # Generate the action collection name and create a new named action collection if one does not exist.
            action_collection_name = str(call["category"]).capitalize() + " Actions"
            self.dynamic_bundle.add_named_action_collection(action_collection_name, mixbox.idgen.create_id(prefix="action"))

            # Generate the Action dictionary.
            action_dict = self.apiCallToAction(call, pos)

            # Add the action ID to the list of Actions spawned by the process.
            if pid in self.pidActionMap:
                action_list = self.pidActionMap[pid].append({"action_id": action_dict["id"]})
            else:
                self.pidActionMap[pid] = [{"action_id": action_dict["id"]}]

            # Add the action to the dynamic analysis Bundle.
            self.dynamic_bundle.add_action(MalwareAction.from_dict(action_dict), action_collection_name)
            # Update the action position
            pos = pos + 1

    # Map the Cuckoo status to that used in the MAEC/CybOX action_status field.
    def mapActionStatus(self, status):
        if status is True or status == 1:
            return "Success"
        elif status is False or status == 0:
            return "Fail"
        else:
            return None

    def createWinExecFileObj(self):
        """Creates a Windows Executable File (PE) object for capturing static analysis output.
        """

        # A mapping of Cuckoo resource type names to their name in MAEC
        resource_type_mappings = {
            "GIF": "Bitmap",
            "RT_ACCELERATOR": "Accelerators",
            "RT_ANICURSOR": "AniCursor",
            "RT_ANIICON": "AniIcon",
            "RT_BITMAP": "Bitmap",
            "RT_CURSOR": "Cursor",
            "RT_DIALOG": "Dialog",
            "RT_DLGINCLUDE": "DLGInclude",
            "RT_FONT": "Font",
            "RT_FONTDIR": "Fontdir",
            "RT_GROUP_CURSOR": "GroupCursor",
            "RT_GROUP_ICON": "GroupIcon",
            "RT_HTML": "HTML",
            "RT_ICON": "Icon",
            "RT_MANIFEST": "Manifest",
            "RT_MENU": "Menu",
            "RT_PLUGPLAY": "PlugPlay",
            "RT_RCDATA": "RCData",
            "RT_STRING": "String",
            "RT_VERSION": "VersionInfo",
            "RT_VXD": "Vxd",
        }

        if len(self.results["static"]) > 0:
            exports = None
            imports = None
            sections = None
            resources = None

            # PE exports.
            if "pe_exports" in self.results["static"] and len(self.results["static"]["pe_exports"]) > 0:
                exports = {}
                exported_function_list = []
                for x in self.results["static"]["pe_exports"]:
                    exported_function_dict = {"function_name": x["name"], "ordinal": x["ordinal"], "entry_point": x["address"]}
                    exported_function_list.append(exported_function_dict)
                exports["exported_functions"] = exported_function_list
            # PE Imports.
            if "pe_imports" in self.results["static"] and len(self.results["static"]["pe_imports"]) > 0:
                imports = []
                for x in self.results["static"]["pe_imports"]:
                    imported_functions = []
                    import_dict = {"file_name": x["dll"], "imported_functions": imported_functions}

                    # Imported functions.
                    for i in x["imports"]:
                        imported_function_dict = {"function_name": i["name"], "virtual_address": i["address"]}
                        imported_functions.append(imported_function_dict)
                    imports.append(import_dict)
            # Resources.
            if "pe_resources" in self.results["static"] and len(self.results["static"]["pe_resources"]) > 0:
                resources = []
                for r in self.results["static"]["pe_resources"]:
                    if r["name"] in resource_type_mappings:
                        resource_dict = {"type": resource_type_mappings[r["name"]]}
                        resources.append(resource_dict)
            # Sections.
            if "pe_sections" in self.results["static"] and len(self.results["static"]["pe_sections"]) > 0:
                sections = []
                for s in self.results["static"]["pe_sections"]:
                    section_dict = {
                        "section_header": {
                            "virtual_size": int(s["virtual_size"], 16),
                            "virtual_address": s["virtual_address"],
                            "name": s["name"],
                            "size_of_raw_data": s["size_of_data"],
                        },
                        "entropy": {"value": s["entropy"]},
                    }
                    sections.append(section_dict)
            # Version info.
            if "pe_versioninfo" in self.results["static"] and len(self.results["static"]["pe_versioninfo"]) > 0:
                if not resources:
                    resources = []
                version_info = {}
                for k in self.results["static"]["pe_versioninfo"]:
                    if not k["value"]:
                        continue
                    if k["name"].lower() == "comments":
                        version_info["comments"] = k["value"]
                    if k["name"].lower() == "companyname":
                        version_info["companyname"] = k["value"]
                    if k["name"].lower() == "productversion":
                        version_info["productversion"] = k["value"]
                    if k["name"].lower() == "productname":
                        version_info["product_name"] = k["value"]
                    if k["name"].lower() == "filedescription":
                        version_info["filedescription"] = k["value"]
                    if k["name"].lower() == "fileversion":
                        version_info["fileversion"] = k["value"]
                    if k["name"].lower() == "internalname":
                        version_info["internalname"] = k["value"]
                    if k["name"].lower() == "langid":
                        version_info["langid"] = k["value"]
                    if k["name"].lower() == "legalcopyright":
                        version_info["legalcopyright"] = k["value"]
                    if k["name"].lower() == "legaltrademarks":
                        version_info["legaltrademarks"] = k["value"]
                    if k["name"].lower() == "originalfilename":
                        version_info["originalfilename"] = k["value"]
                    if k["name"].lower() == "privatebuild":
                        version_info["privatebuild"] = k["value"]
                    if k["name"].lower() == "productname":
                        version_info["productname"] = k["value"]
                    if k["name"].lower() == "productversion":
                        version_info["productversion"] = k["value"]
                    if k["name"].lower() == "specialbuild":
                        version_info["specialbuild"] = k["value"]
                resources.append(version_info)
            object_dict = {
                "id": mixbox.idgen.create_id(prefix="object"),
                "properties": {
                    "xsi:type": "WindowsExecutableFileObjectType",
                    "imports": imports,
                    "exports": exports,
                    "sections": sections,
                    "resources": resources,
                },
            }
        win_exec_file_obj = Object.from_dict(object_dict)
        return win_exec_file_obj

    def createFileStringsObj(self):
        """Creates a File object for capturing strings output."""
        extracted_string_list = []
        for extracted_string in self.results["strings"]:
            extracted_string_list.append({"string_value": self._illegal_xml_chars_RE.sub("?", extracted_string)})
        extracted_features = {"strings": extracted_string_list}
        object_dict = {
            "id": mixbox.idgen.create_id(prefix="object"),
            "properties": {"xsi:type": "FileObjectType", "extracted_features": extracted_features},
        }
        strings_file_obj = Object.from_dict(object_dict)
        return strings_file_obj

    def createFileObj(self, file):
        """Creates a File object.
        @param file: file dict from Cuckoo dict.
        @requires: file object.
        """
        if "ssdeep" in file and file["ssdeep"] is not None:
            hashes_list = [
                {"type": "MD5", "simple_hash_value": file["md5"]},
                {"type": "SHA1", "simple_hash_value": file["sha1"]},
                {"type": "SHA256", "simple_hash_value": file["sha256"]},
                {"type": "SHA512", "simple_hash_value": file["sha512"]},
                {"type": "SSDEEP", "fuzzy_hash_value": file["ssdeep"]},
            ]
        else:
            hashes_list = [
                {"type": "MD5", "simple_hash_value": file["md5"]},
                {"type": "SHA1", "simple_hash_value": file["sha1"]},
                {"type": "SHA256", "simple_hash_value": file["sha256"]},
                {"type": "SHA512", "simple_hash_value": file["sha512"]},
            ]
        object_dict = {
            "id": mixbox.idgen.create_id(prefix="object"),
            "properties": {
                "xsi:type": "FileObjectType",
                "file_name": file["name"],
                "file_path": {"value": file["path"]},
                "file_format": file["type"],
                "size_in_bytes": file["size"],
                "hashes": hashes_list,
            },
        }
        file_obj = Object.from_dict(object_dict)
        return file_obj

    def addSubjectAttributes(self):
        """Add Malware Instance Object Attributes to the Malware Subject."""
        # File Object.
        if self.results["target"]["category"] == "file":
            self.subject.set_malware_instance_object_attributes(self.createFileObj(self.results["target"]["file"]))
        # URL Object.
        elif self.results["target"]["category"] == "url":
            url_object_dict = {
                "id": mixbox.idgen.create_id(prefix="object"),
                "properties": {"xsi:type": "URIObjectType", "value": self.results["target"]["url"]},
            }
            self.subject.set_malware_instance_object_attributes(Object.from_dict(url_object_dict))

    def addAnalyses(self):
        """Adds analysis header."""
        # Add the dynamic analysis.
        dynamic_analysis = Analysis(
            mixbox.idgen.create_id(prefix="analysis"),
            "dynamic",
            "triage",
            [BundleReference.from_dict({"bundle_idref": self.dynamic_bundle.id_})],
        )
        dynamic_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
        dynamic_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
        dynamic_analysis.summary = StructuredText("Cuckoo Sandbox dynamic analysis of the malware instance object.")
        dynamic_analysis.add_tool(
            ToolInformation.from_dict(
                {
                    "id": mixbox.idgen.create_id(prefix="tool"),
                    "name": "Cuckoo Sandbox",
                    "version": self.results["info"]["version"],
                    "vendor": "http://www.cuckoosandbox.org",
                }
            )
        )
        self.subject.add_analysis(dynamic_analysis)

        # Add the static analysis.
        if "static" in self.options and self.options["static"] and "static" in self.results and self.results["static"]:
            static_analysis = Analysis(
                mixbox.idgen.create_id(prefix="analysis"),
                "static",
                "triage",
                [BundleReference.from_dict({"bundle_idref": self.static_bundle.id_})],
            )
            static_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
            static_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
            static_analysis.summary = StructuredText("Cuckoo Sandbox static (PE) analysis of the malware instance object.")
            static_analysis.add_tool(
                ToolInformation.from_dict(
                    {
                        "id": mixbox.idgen.create_id(prefix="tool"),
                        "name": "Cuckoo Sandbox Static Analysis",
                        "version": self.results["info"]["version"],
                        "vendor": "http://www.cuckoosandbox.org",
                    }
                )
            )
            self.subject.add_analysis(static_analysis)
            # Add the static file results.
            self.static_bundle.add_object(self.createWinExecFileObj())
        # Add the strings analysis.
        if "strings" in self.options and self.options["strings"] and "strings" in self.results and self.results["strings"]:
            strings_analysis = Analysis(
                mixbox.idgen.create_id(prefix="analysis"),
                "static",
                "triage",
                [BundleReference.from_dict({"bundle_idref": self.strings_bundle.id_})],
            )
            strings_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
            strings_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
            strings_analysis.summary = StructuredText("Cuckoo Sandbox strings analysis of the malware instance object.")
            strings_analysis.add_tool(
                ToolInformation.from_dict(
                    {
                        "id": mixbox.idgen.create_id(prefix="tool"),
                        "name": "Cuckoo Sandbox Strings",
                        "version": self.results["info"]["version"],
                        "vendor": "http://www.cuckoosandbox.org",
                    }
                )
            )
            self.subject.add_analysis(strings_analysis)
            # Add the strings results.
            self.strings_bundle.add_object(self.createFileStringsObj())
        # Add the VirusTotal analysis.
        if self.options["virustotal"] and "virustotal" in self.results and self.results["virustotal"]:
            virustotal_analysis = Analysis(
                mixbox.idgen.create_id(prefix="analysis"),
                "static",
                "triage",
                [BundleReference.from_dict({"bundle_idref": self.virustotal_bundle.id_})],
            )
            virustotal_analysis.start_datetime = datetime_to_iso(self.results["info"]["started"])
            virustotal_analysis.complete_datetime = datetime_to_iso(self.results["info"]["ended"])
            virustotal_analysis.summary = StructuredText("Virustotal results for the malware instance object.")
            virustotal_analysis.add_tool(
                ToolInformation.from_dict(
                    {"id": mixbox.idgen.create_id(prefix="tool"), "name": "VirusTotal", "vendor": "https://www.virustotal.com/"}
                )
            )
            self.subject.add_analysis(virustotal_analysis)
            # Add the VirusTotal results.
            if "scans" in self.results["virustotal"]:
                for engine, signature in self.results["virustotal"]["scans"].items():
                    if signature["detected"]:
                        self.virustotal_bundle.add_av_classification(
                            AVClassification.from_dict(
                                {
                                    "vendor": engine,
                                    "engine_version": signature["version"],
                                    "definition_version": signature["update"],
                                    "classification_name": signature["result"],
                                }
                            )
                        )

    def addDroppedFiles(self):
        """Adds Dropped files as Objects."""
        objs = self.results["dropped"]
        # don't add the target file to the dropped files listing
        # if self.results["target"]["category"] == "file":
        #    objs.append(self.results["target"]["file"])
        # Add the named object collection.
        self.dynamic_bundle.add_named_object_collection("Dropped Files", mixbox.idgen.create_id(prefix="object"))
        for file in objs:
            self.dynamic_bundle.add_object(self.createFileObj(file), "Dropped Files")

    def output(self):
        """Writes report to disk."""
        outfile = open(os.path.join(self.reports_path, "report.maec-4.1.xml"), "w")
        outfile.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        outfile.write("<!DOCTYPE doc [<!ENTITY comma '&#44;'>]>\n")
        outfile.write("<!--\n")
        outfile.write("Cuckoo Sandbox MAEC 4.1 malware analysis report\n")
        outfile.write("http://www.cuckoosandbox.org\n")
        outfile.write("-->\n")
        outfile.write(self.package.to_xml(True, namespace_dict={"http://www.cuckoosandbox.org": "Cuckoosandbox"}))
        outfile.flush()
        outfile.close()
