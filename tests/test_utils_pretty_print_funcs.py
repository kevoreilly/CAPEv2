# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import random

from lib.cuckoo.common import utils_pretty_print_funcs as pp_fn
from lib.cuckoo.common.path_utils import path_delete

random.seed(1338)


def gen_data_file():
    with open("CAPEv2/tests/utils_pretty_print_funcs_data.py", "a") as f:
        f.write("# fmt: off")

    gen_rnd_data(pp_fn.api_name_ntcreatesection_arg_name_desiredaccess, 0x20, 0xF001F)
    gen_rnd_data(pp_fn.api_name_shgetfolderpathw_arg_name_folder, 0x800, 0x8000)
    gen_rnd_data(pp_fn.api_name_createtoolhelp32snapshot_arg_name_flags, 0, 0x10)
    gen_rnd_data(pp_fn.blobtype, 0x0001, 0x000C)
    gen_rnd_data(pp_fn.algid, 0x0001, 0x2000)
    gen_rnd_data(pp_fn.hookidentifer, 0, 14)
    gen_rnd_data(pp_fn.infolevel, 0, 21)
    gen_rnd_data(pp_fn.disposition, 1, 2)
    gen_rnd_data(pp_fn.createdisposition, 0, 5)
    gen_rnd_data(pp_fn.shareaccess, 1, 5)
    gen_rnd_data(pp_fn.systeminformationclass, 0, 5)
    gen_rnd_data(pp_fn.category_registry_arg_name_type, 0, 11)
    gen_rnd_data(pp_fn.api_name_opensc_arg_name_desiredaccess, 0x0001, 0x0020)
    gen_rnd_data(pp_fn.category_services_arg_name_controlcode, 1, 10)
    gen_rnd_data(pp_fn.category_services_arg_name_errorcontrol, 0, 3)
    gen_rnd_data(pp_fn.category_services_arg_name_starttype, 0, 4)
    gen_rnd_data(pp_fn.category_services_arg_name_servicetype, 130, 131)
    gen_rnd_data(pp_fn.category_services_arg_name_desiredaccess, 0x0001, 0x0100)
    gen_rnd_data(pp_fn.category_registry_arg_name_access_desired_access, 0x0001, 0x100)
    gen_rnd_data(pp_fn.arg_name_protection_and_others, 0x00000001, 0x00000400)
    gen_rnd_data(pp_fn.arg_name_iocontrolcode, 0x00000001, 0x00080000)
    gen_rnd_data(pp_fn.api_name_in_creation, 0x00000001, 0x04000000)
    gen_rnd_data(pp_fn.api_name_move_arg_name_flags, 0x00000001, 0x00000008)
    gen_rnd_data(pp_fn.arg_name_fileattributes, 0x00000001, 0x00008000)
    gen_rnd_data(pp_fn.api_name_nt_arg_name_desiredaccess, 2000000, 40000000)
    gen_rnd_data(pp_fn.api_name_ntopenprocess_arg_name_desiredaccess, 0x0001, 0x80000000)
    gen_rnd_data(pp_fn.api_name_ntopenthread_arg_name_desiredaccess, 0x0001, 0x1FFFFF)
    gen_rnd_data(pp_fn.api_name_cointernet_arg_name_featureentry, 0, 6)
    gen_rnd_data(pp_fn.api_name_cointernet_arg_name_flags, 0x00000001, 0x00000080)
    gen_rnd_data(pp_fn.api_name_socket, 0, 113, arg_name="protocol")
    gen_rnd_data(pp_fn.api_name_internetsetoptiona_arg_name_option, 1, 105)
    gen_rnd_data(pp_fn.arg_name_fileinformationclass, 1, 56)
    gen_rnd_data(pp_fn.arg_name_processinformationclass, 0, 34)
    gen_rnd_data(pp_fn.arg_name_threadinformationclass, 0, 17)
    gen_rnd_data(pp_fn.arg_name_memtype, 20000, 20001)
    gen_rnd_data(pp_fn.arg_name_show, 0, 11)
    gen_rnd_data(pp_fn.arg_name_registry, 80000000, 80000003)


def gen_rnd_data(func, lower, upper, arg_name=None):
    def print_def():
        with open("CAPEv2/tests/utils_pretty_print_funcs_data.py", "a") as f:
            f.write("\ndef " + func.__name__ + "_data():\n    return [\n")

    def print_line():
        with open("CAPEv2/tests/utils_pretty_print_funcs_data.py", "a") as f:
            f.write('        ("' + str(i) + '", "' + val + '"),\n')

    def print_end():
        with open("CAPEv2/tests/utils_pretty_print_funcs_data.py", "a") as f:
            f.write("    ]\n\n")

    print_def()

    sample_range = (upper - lower) / 100
    if sample_range > 2000:
        sample_range_list = range(lower, lower + 2000)
    else:
        sample_range_list = range(lower, upper)

    for i in sample_range_list:
        if sample_range > 2000:
            # choose a number within the range if we're too big
            i = random.randint(lower, upper)
        if arg_name:
            val = func(str(i), arg_name)
        else:
            val = func(str(i))
        if val:
            print_line()

    print_end()


if not os.environ.get("GEN_DATA"):
    import utils_pretty_print_funcs_data as data
else:
    try:
        path_delete("CAPEv2/tests/utils_pretty_print_funcs_data.py")
    except Exception as e:
        print(("Error in cleanup: " + str(e)))
    gen_data_file()


def test_calls():
    if not os.environ.get("GEN_DATA"):
        for val, ret in data.api_name_ntcreatesection_arg_name_desiredaccess_data():
            assert pp_fn.api_name_ntcreatesection_arg_name_desiredaccess(val) == ret
        for val, ret in data.api_name_shgetfolderpathw_arg_name_folder_data():
            assert pp_fn.api_name_shgetfolderpathw_arg_name_folder(val) == ret
        for val, ret in data.api_name_createtoolhelp32snapshot_arg_name_flags_data():
            assert pp_fn.api_name_createtoolhelp32snapshot_arg_name_flags(val) == ret
        for val, ret in data.blobtype_data():
            assert pp_fn.blobtype(val) == ret
        for val, ret in data.algid_data():
            assert pp_fn.algid(val) == ret
        for val, ret in data.hookidentifer_data():
            assert pp_fn.hookidentifer(val) == ret
        for val, ret in data.infolevel_data():
            assert pp_fn.infolevel(val) == ret
        for val, ret in data.disposition_data():
            assert pp_fn.disposition(val) == ret
        for val, ret in data.createdisposition_data():
            assert pp_fn.createdisposition(val) == ret
        for val, ret in data.shareaccess_data():
            assert pp_fn.shareaccess(val) == ret
        for val, ret in data.systeminformationclass_data():
            assert pp_fn.systeminformationclass(val) == ret
        for val, ret in data.category_registry_arg_name_type_data():
            assert pp_fn.category_registry_arg_name_type(val) == ret
        for val, ret in data.api_name_opensc_arg_name_desiredaccess_data():
            assert pp_fn.api_name_opensc_arg_name_desiredaccess(val) == ret
        for val, ret in data.category_services_arg_name_controlcode_data():
            assert pp_fn.category_services_arg_name_controlcode(val) == ret
        for val, ret in data.category_services_arg_name_errorcontrol_data():
            assert pp_fn.category_services_arg_name_errorcontrol(val) == ret
        for val, ret in data.category_services_arg_name_starttype_data():
            assert pp_fn.category_services_arg_name_starttype(val) == ret
        for val, ret in data.category_services_arg_name_servicetype_data():
            assert pp_fn.category_services_arg_name_servicetype(val) == ret
        for val, ret in data.category_services_arg_name_desiredaccess_data():
            assert pp_fn.category_services_arg_name_desiredaccess(val) == ret
        for val, ret in data.category_registry_arg_name_access_desired_access_data():
            assert pp_fn.category_registry_arg_name_access_desired_access(val) == ret
        for val, ret in data.arg_name_protection_and_others_data():
            assert pp_fn.arg_name_protection_and_others(val) == ret
        for val, ret in data.arg_name_iocontrolcode_data():
            assert pp_fn.arg_name_iocontrolcode(val) == ret
        for val, ret in data.api_name_in_creation_data():
            assert pp_fn.api_name_in_creation(val) == ret
        for val, ret in data.api_name_move_arg_name_flags_data():
            assert pp_fn.api_name_move_arg_name_flags(val) == ret
        for val, ret in data.arg_name_fileattributes_data():
            assert pp_fn.arg_name_fileattributes(val) == ret
        for val, ret in data.api_name_nt_arg_name_desiredaccess_data():
            assert pp_fn.api_name_nt_arg_name_desiredaccess(val) == ret
        for val, ret in data.api_name_ntopenprocess_arg_name_desiredaccess_data():
            assert pp_fn.api_name_ntopenprocess_arg_name_desiredaccess(val) == ret
        for val, ret in data.api_name_ntopenthread_arg_name_desiredaccess_data():
            assert pp_fn.api_name_ntopenthread_arg_name_desiredaccess(val) == ret
        for val, ret in data.api_name_cointernet_arg_name_featureentry_data():
            assert pp_fn.api_name_cointernet_arg_name_featureentry(val) == ret
        for val, ret in data.api_name_cointernet_arg_name_flags_data():
            assert pp_fn.api_name_cointernet_arg_name_flags(val) == ret
        # for val, ret in data.api_name_socket_data():
        #     assert pp_fn.api_name_socket(arg_val=val, arg_name="process") == ret
        for val, ret in data.api_name_internetsetoptiona_arg_name_option_data():
            assert pp_fn.api_name_internetsetoptiona_arg_name_option(val) == ret
        for val, ret in data.arg_name_fileinformationclass_data():
            assert pp_fn.arg_name_fileinformationclass(val) == ret
        for val, ret in data.arg_name_processinformationclass_data():
            assert pp_fn.arg_name_processinformationclass(val) == ret
        for val, ret in data.arg_name_threadinformationclass_data():
            assert pp_fn.arg_name_threadinformationclass(val) == ret
        for val, ret in data.arg_name_memtype_data():
            assert pp_fn.arg_name_memtype(val) == ret
        for val, ret in data.arg_name_show_data():
            assert pp_fn.arg_name_show(val) == ret
        for val, ret in data.arg_name_registry_data():
            assert pp_fn.arg_name_registry(val) == ret
