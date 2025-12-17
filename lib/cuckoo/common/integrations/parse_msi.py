import pymsi

def parse_msi_action_type(input_int):
    """
    Parses an MSI Custom Action Type integer into a dictionary of properties.
    """
    # =========================================================================
    # MSI CONSTANTS (Based on C++ Header Definitions)
    # =========================================================================
    if not input_int:
        return {}

    type_dll = 0x00000001  # msidbCustomActionTypeDll
    type_exe = 0x00000002  # msidbCustomActionTypeExe
    type_text_data = 0x00000003  # msidbCustomActionTypeTextData
    type_jscript = 0x00000005  # msidbCustomActionTypeJScript
    type_vbscript = 0x00000006  # msidbCustomActionTypeVBScript
    type_install = 0x00000007  # msidbCustomActionTypeInstall
    type_binary_data = 0x00000000  # msidbCustomActionTypeBinaryData
    type_source_file = 0x00000010  # msidbCustomActionTypeSourceFile
    type_directory = 0x00000020  # msidbCustomActionTypeDirectory
    type_property = 0x00000030  # msidbCustomActionTypeProperty
    type_continue = 0x00000040  # msidbCustomActionTypeContinue (Async/Sync ignore return)
    type_async = 0x00000080  # msidbCustomActionTypeAsync
    type_first_sequence = 0x00000100  # msidbCustomActionTypeFirstSequence
    type_once_per_process = 0x00000200  # msidbCustomActionTypeOncePerProcess
    type_client_repeat = 0x00000300  # msidbCustomActionTypeClientRepeat
    type_in_script = 0x00000400  # msidbCustomActionTypeInScript (Deferred)
    type_rollback = 0x00000100  # msidbCustomActionTypeRollback
    type_commit = 0x00000200  # msidbCustomActionTypeCommit
    type_no_impersonate = 0x00000800  # msidbCustomActionTypeNoImpersonate
    type_64bit_script = 0x00001000  # msidbCustomActionType64BitScript
    type_hide_target = 0x00002000  # msidbCustomActionTypeHideTarget
    type_ts_aware = 0x00004000  # msidbCustomActionTypeTSAware
    type_patch_uninstall = 0x00008000  # msidbCustomActionTypePatchUninstall

    mask_basic_type = 0x7
    mask_source_type = 0x30
    mask_return_type = 0xC0
    mask_execution = 0xF00

    # Mask of all known bits to calculate remainder / check for bogus data
    mask_all_known = (
        mask_basic_type |
        mask_source_type |
        mask_return_type |
        mask_execution |
        type_64bit_script |
        type_hide_target |
        type_ts_aware |
        type_patch_uninstall
    )

    try:
        val = int(input_int)
    except ValueError:
        return {}

    result = {
        "basic_type": "",
        "source": "",
        "return_processing": "",
        "execution": "",
        "flags": [],
        "remainder": 0
    }

    # Basic Type
    b_type = val & mask_basic_type
    if b_type == type_dll:
        result["basic_type"] = "DLL (msidbCustomActionTypeDll)"
    elif b_type == type_exe:
        result["basic_type"] = "EXE (msidbCustomActionTypeExe)"
    elif b_type == type_text_data:
        result["basic_type"] = "Text Data (msidbCustomActionTypeTextData)"
    elif b_type == type_jscript:
        result["basic_type"] = "JScript (msidbCustomActionTypeJScript)"
    elif b_type == type_vbscript:
        result["basic_type"] = "VBScript (msidbCustomActionTypeVBScript)"
    elif b_type == type_install:
        result["basic_type"] = "Install (msidbCustomActionTypeInstall)"
    elif b_type == 0:
        result["basic_type"] = "None/Error (0)"
    else:
        result["basic_type"] = "Unknown Type (%d)" % b_type

    # Source Location
    s_loc = val & mask_source_type
    if s_loc == type_binary_data:
        result["source"] = "Binary Table (msidbCustomActionTypeBinaryData)"
    elif s_loc == type_source_file:
        result["source"] = "Source File (msidbCustomActionTypeSourceFile)"
    elif s_loc == type_directory:
        result["source"] = "Directory (msidbCustomActionTypeDirectory)"
    elif s_loc == type_property:
        result["source"] = "Property (msidbCustomActionTypeProperty)"

    # Return Processing (Bits 6-7)
    r_type = val & mask_return_type
    if r_type == 0:
        # No specific constant exists for 0 (default), labeled as (None) for consistency with MSDN
        result["return_processing"] = "Synchronous, Check Return Code (None)"
    elif r_type == type_continue:
        result["return_processing"] = "Synchronous, Ignore Return Code (msidbCustomActionTypeContinue)"
    elif r_type == type_async:
        result["return_processing"] = "Asynchronous, Wait for Exit (msidbCustomActionTypeAsync)"
    elif r_type == (type_async | type_continue):
        result["return_processing"] = (
            "Asynchronous, Do Not Wait (msidbCustomActionTypeAsync | msidbCustomActionTypeContinue)")

    # Execution Scheduling
    exec_val = val & mask_execution
    exec_parts = []
    is_deferred = (exec_val & type_in_script) == type_in_script
    if is_deferred:
        exec_parts.append("Deferred (msidbCustomActionTypeInScript)")

        # In Deferred execution, bits 0x100 and 0x200 are independent (Rollback/Commit)
        if exec_val & type_rollback:
            exec_parts.append("Rollback (msidbCustomActionTypeRollback)")

        if exec_val & type_commit:
            exec_parts.append("Commit (msidbCustomActionTypeCommit)")

    else:
        # In Immediate execution, 0x300 is a specific combination (msidbCustomActionTypeClientRepeat)
        # https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-execution-scheduling-options
        sched_bits = exec_val & (type_first_sequence | type_once_per_process)

        if sched_bits == type_client_repeat:
            exec_parts.append("ClientRepeat (msidbCustomActionTypeClientRepeat)")
        else:
            # Handle individual bits if it's not the specific ClientRepeat combo
            if exec_val & type_first_sequence:
                exec_parts.append("FirstSequence (msidbCustomActionTypeFirstSequence)")

            if exec_val & type_once_per_process:
                exec_parts.append("OncePerProcess (msidbCustomActionTypeOncePerProcess)")

    # Check for NoImpersonate
    if exec_val & type_no_impersonate:
        exec_parts.append("NoImpersonate (msidbCustomActionTypeNoImpersonate)")

    if not exec_parts:
        result["execution"] = "Immediate (User Context)"
    else:
        result["execution"] = " + ".join(exec_parts)

    # Parse Global Flags
    if val & type_64bit_script:
        result["flags"].append("64-bit Script (msidbCustomActionType64BitScript)")
    if val & type_hide_target:
        result["flags"].append("Hide Target (msidbCustomActionTypeHideTarget)")
    if val & type_ts_aware:
        result["flags"].append("Terminal Server Aware (msidbCustomActionTypeTSAware)")
    if val & type_patch_uninstall:
        result["flags"].append("Patch Uninstall (msidbCustomActionTypePatchUninstall)")

    # Check for bogus / malformed stuffs; remainder is 0 in tested samples
    result["remainder"] = val & ~mask_all_known

    return result

def parse_msi(msi_path: str):
    msi = {}
    with pymsi.Package(msi_path) as package:
        if "CustomAction" in package.tables:
            current_table_obj = package.get("CustomAction")
            msi = {
                "rows": [row for row in current_table_obj.rows],
                "columns": [column.name for column in current_table_obj.columns],
            }
            for row in msi["rows"]:
                row["Enrich"] = parse_msi_action_type(row["Type"])
    return msi


if __name__ == "__main__":
    import sys
    from pprint import pprint as pp
    pp(parse_msi(sys.argv[1]))
# pymsi uses CamelCase for their dict keys, and my function does not. so if you want it to be clean feel free to make it CamelCase
