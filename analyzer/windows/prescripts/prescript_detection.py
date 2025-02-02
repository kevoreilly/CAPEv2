import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from winreg import (
    HKEY_CLASSES_ROOT,
    HKEY_CURRENT_CONFIG,
    HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE,
    HKEY_PERFORMANCE_DATA,
    HKEY_USERS,
    KEY_ALL_ACCESS,
    REG_BINARY,
    REG_DWORD,
    REG_NONE,
    REG_SZ,
    CloseKey,
    CreateKey,
    OpenKey,
    SetValueEx,
)

import pythoncom
import win32api
import win32com.client
from win32com.taskscheduler import taskscheduler

cwd = os.getcwd()
sys.path.append(cwd)

try:
    from lib.common.zip_utils import extract_zip
    from lib.core.compound import create_custom_folders, extract_json_data
    from lib.core.config import Config
except Exception as e:
    print(f"{cwd} with {e}")
    # sys.exit()

ts = pythoncom.CoCreateInstance(
    taskscheduler.CLSID_CTaskScheduler, None, pythoncom.CLSCTX_INPROC_SERVER, taskscheduler.IID_ITaskScheduler
)

scheduler = win32com.client.Dispatch("Schedule.Service")
scheduler.Connect()
root_folder = scheduler.GetFolder("\\")

LIST_OF_VALID_ACTIONS = [
    "run_script",
    "add_file",
    "add_directory",
    "create_registry",
    "modify_registry",
    "create_scheduled_task",
    "create_xml_scheduled_task",
    "modify_scheduled_task",
    "change_execution_dir",
]

ACTIONS_PARAMETERS = {
    "run_script": ["path", "params", "timeout"],
    "add_file": ["src_path", "dst_path", "overwrite"],
    "add_directory": ["path"],
    "create_registry": ["path", "key", "value"],
    "modify_registry": ["path", "key", "value"],
    "create_scheduled_task": [
        "task_name",
        "application_name",
        "priority",
        "working_directory",
        "flags",
        "parameters",
        "comment",
        "creator",
        "account_information",
        "path",
        "trigger_type",
        "start_time",
        "duration",
        "interval",
        "expiration_time",
        "additional_trigger_params",
    ],
    "create_xml_scheduled_task": ["task_name", "xml"],
    "modify_scheduled_task": [
        "task_name",
        "path",
        "new_task_name",
        "comment",
        "action_id",
        "application_name",
        "priority",
        "parameters",
        "working_directory",
        "creator",
        "account_information",
        "flags",
        "trigger",
    ],
    "change_execution_dir": ["path"],
}

Registry_paths = {
    "hkey_classes_root": HKEY_CLASSES_ROOT,
    "hkey_current_user": HKEY_CURRENT_USER,
    "hkey_local_machine": HKEY_LOCAL_MACHINE,
    "hkey_users": HKEY_USERS,
    "hkey_performance_data": HKEY_PERFORMANCE_DATA,
    "hkey_current_config": HKEY_CURRENT_CONFIG,
}


class TASK_ACTION_TYPES(Enum):
    TASK_ACTION_EXEC = 0
    TASK_ACTION_COM_HANDLER = 5
    TASK_ACTION_SEND_EMAIL = 6
    TASK_ACTION_SHOW_MESSAGE = 7


class TASK_TRIGGER_TYPE(Enum):
    TASK_TRIGGER_EVENT = 0
    TASK_TRIGGER_TIME = 1
    TASK_TRIGGER_DAILY = 2
    TASK_TRIGGER_WEEKLY = 3
    TASK_TRIGGER_MONTHLY = 4
    TASK_TRIGGER_MONTHLYDOW = 5
    TASK_TRIGGER_IDLE = 6
    TASK_TRIGGER_REGISTRATION = 7
    TASK_TRIGGER_BOOT = 8
    TASK_TRIGGER_LOGON = 9
    TASK_TRIGGER_SESSION_STATE_CHANGE = 11
    TASK_TRIGGER_CUSTOM_TRIGGER_01 = 12


class TASK_COMPATIBILITY(Enum):
    TASK_COMPATIBILITY_AT = 0
    TASK_COMPATIBILITY_V1 = 1
    TASK_COMPATIBILITY_V2 = 2
    TASK_COMPATIBILITY_V2_1 = 3
    TASK_COMPATIBILITY_V2_2 = 4
    TASK_COMPATIBILITY_V2_3 = 5
    TASK_COMPATIBILITY_V2_4 = 6


class TASK_CREATION(Enum):
    TASK_VALIDATE_ONLY = 1
    TASK_CREATE = 2
    TASK_UPDATE = 4
    TASK_CREATE_OR_UPDATE = 6
    TASK_DISABLE = 8
    TASK_DONT_ADD_PRINCIPAL_ACE = (10,)
    TASK_IGNORE_REGISTRATION_TRIGGERS = 20


class TASK_LOGON_TYPE(Enum):
    TASK_LOGON_NONE = (0,)
    TASK_LOGON_PASSWORD = 1
    TASK_LOGON_S4U = 2
    TASK_LOGON_INTERACTIVE_TOKEN = 3
    TASK_LOGON_GROUP = 4
    TASK_LOGON_SERVICE_ACCOUNT = 5
    TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD = 6


class TASK_PRIORITY(Enum):
    THREAD_PRIORITY_TIME_CRITICAL = 0
    THREAD_PRIORITY_HIGHEST = 1
    THREAD_PRIORITY_ABOVE_NORMAL = 2
    THREAD_PRIORITY_ABOVE_NORMAL2 = 3
    THREAD_PRIORITY_NORMAL = 4
    THREAD_PRIORITY_NORMAL2 = 5
    THREAD_PRIORITY_NORMAL3 = 6
    THREAD_PRIORITY_BELOW_NORMAL = 7
    THREAD_PRIORITY_BELOW_NORMAL2 = 8
    THREAD_PRIORITY_LOWEST = 9
    THREAD_PRIORITY_IDLE = 10


Scheduled_task_flags = [
    taskscheduler.TASK_FLAG_INTERACTIVE,
    taskscheduler.TASK_FLAG_DELETE_WHEN_DONE,
    taskscheduler.TASK_FLAG_DISABLED,
    taskscheduler.TASK_FLAG_HIDDEN,
    taskscheduler.TASK_FLAG_RUN_ONLY_IF_LOGGED_ON,
    taskscheduler.TASK_FLAG_START_ONLY_IF_IDLE,
    taskscheduler.TASK_FLAG_SYSTEM_REQUIRED,
    taskscheduler.TASK_FLAG_KILL_ON_IDLE_END,
    taskscheduler.TASK_FLAG_RESTART_ON_IDLE_RESUME,
    taskscheduler.TASK_FLAG_DONT_START_IF_ON_BATTERIES,
    taskscheduler.TASK_FLAG_KILL_IF_GOING_ON_BATTERIES,
    taskscheduler.TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET,
]

Scheduled_task_priority = [
    taskscheduler.REALTIME_PRIORITY_CLASS,
    taskscheduler.HIGH_PRIORITY_CLASS,
    taskscheduler.NORMAL_PRIORITY_CLASS,
    taskscheduler.IDLE_PRIORITY_CLASS,
]

trigger_flags = [
    taskscheduler.TASK_TRIGGER_FLAG_HAS_END_DATE,
    taskscheduler.TASK_TRIGGER_FLAG_KILL_AT_DURATION_END,
    taskscheduler.TASK_TRIGGER_FLAG_DISABLED,
]

trigger_type = [
    taskscheduler.TASK_TIME_TRIGGER_ONCE,
    taskscheduler.TASK_TIME_TRIGGER_DAILY,
    taskscheduler.TASK_TIME_TRIGGER_WEEKLY,
    taskscheduler.TASK_TIME_TRIGGER_MONTHLYDATE,
    taskscheduler.TASK_TIME_TRIGGER_MONTHLYDOW,
    taskscheduler.TASK_EVENT_TRIGGER_ON_IDLE,
    taskscheduler.TASK_EVENT_TRIGGER_AT_SYSTEMSTART,
    taskscheduler.TASK_EVENT_TRIGGER_AT_LOGON,
]

log = logging.getLogger(__name__)

# All the logs will be also available in logs/pre_script.log
# We don't need to hijack the path of the zip_compound for rules and files destined for us they should use the relative path and it's going to get a copy in the temp cape folder and the prescript one
# We also don't need to cleanup since the zip_compound is going to be reextracted and work appropriately just after this one and overwrite any leftovers

# Format for zip_compound of __configuration.json:
# {
#    "path_to_extract":
#    {
#        "file_name": "path",
#        "yara_file": "prescripts/rules",
#        "script_file": "prescripts/scripts"
#    },
#    "target_file": "target_file_name"
# }
#

# Yara rules metadata commands
# So the metadata field which represent actions to take on a match have the following format al_cape_action#
# The value is then a dictionary of the paramater for this action
#
#


def add_file_to_path(src_path, dst_path, overwrite=False):
    if os.path.exists(dst_path) and overwrite:
        # in case of the src and dst are the same file
        if os.path.samefile(src_path, dst_path):
            log.info("Same file %s already in the victim vm", str(dst_path))
            return
        os.remove(dst_path)
        shutil.copyfile(src=src_path, dst=dst_path)
        log.info("File %s modified in the victim vm", str(dst_path))
    elif os.path.exists(dst_path):
        log.info("File %s already in the victim vm", str(dst_path))
        return
    else:
        shutil.copyfile(src=src_path, dst=dst_path)
        log.info("File %s added to victim vm", str(dst_path))


def run_script(script_path, args, timeout):
    exec = script_path + args
    if script_path.endwith(".py"):
        subprocess.check_output("python " + exec, timeout=timeout, stderr=subprocess.STDOUT)
    else:
        subprocess.check_output(exec, timeout=timeout, stderr=subprocess.STDOUT)
    log.info("Running script %s with parameters %s on the victim vm", str(script_path), str(args))


def add_directory(path):
    os.makedirs(path, exist_ok=True)
    log.info("Folder %s added to victim vm", str(path))


def registry_path_to_winreg(path):
    for value in Registry_paths.keys():
        if value in path:
            return value
    return path


def identify_registry_value_type(value):
    if isinstance(value, bytes):
        return REG_BINARY
    elif isinstance(value, int):
        return REG_DWORD
    elif isinstance(value, None):
        return REG_NONE
    elif isinstance(value, str):
        return REG_SZ
    else:
        return None


def create_registry(path, key, value, value_type):
    path = registry_path_to_winreg(path)
    try:
        RegistryKey = OpenKey(path, key, 0, KEY_ALL_ACCESS)
    except Exception as _:
        RegistryKey = CreateKey(path, key)
    SetValueEx(RegistryKey, key, 0, value_type, value)
    CloseKey(RegistryKey)
    log.info("Created registry %s, with key %s and value %s on the victim vm", str(path), str(key), str(value))


def modify_registry(path, key, value, value_type):
    path = registry_path_to_winreg(path)
    try:
        RegistryKey = OpenKey(path, key, 0, KEY_ALL_ACCESS)
    except Exception as _:
        log.info("The target registry doesn't exist on the victim vm at path %s with key %s", str(path), str(key))
    SetValueEx(RegistryKey, key, 0, value_type, value)
    log.info("Modified registry %s, with key %s to value %s on the victim vm", str(path), str(key), str(value))


def create_scheduled_task(
    task_name,
    application_name,
    priority,
    working_directory,
    flags,
    trigger,
    parameters="",
    idle_time=0,
    comment="",
    creator="",
    account_information=win32api.GetUserName(),
):
    new_task = pythoncom.CoCreateInstance(taskscheduler.CLSID_CTask, None, pythoncom.CLSCTX_INPROC_SERVER, taskscheduler.IID_ITask)
    ts.AddWorkItem(task_name, new_task)  ## task object is modified in place
    new_task.SetFlags(flags)
    if idle_time != 0:
        new_task.SetIdleWait(idle_time, 3600)  # Wait for idle for 1h
    new_task.SetComment(comment)
    new_task.SetApplicationName(application_name)
    new_task.SetPriority(priority)
    new_task.SetParameters(parameters)
    new_task.SetWorkingDirectory(working_directory)
    new_task.SetCreator(creator)
    new_task.SetAccountInformation(account_information, None)
    tr_ind, tr = new_task.CreateTrigger()
    tr.SetTrigger(trigger)
    pf = new_task.QueryInterface(pythoncom.IID_IPersistFile)
    pf.Save(None, 1)
    log.info("Scheduled task %s created on the victim vm", str(task_name))


def create_scheduled_task2(
    task_name,
    application_name,
    priority,
    working_directory,
    flags={},
    parameters="",
    comment="",
    creator="",
    account_information=win32api.GetUserName(),
    path="\\",
    trigger_type=None,
    start_time=datetime.now().time(),
    duration=0,
    interval=0,
    expiration_time=None,
    additional_trigger_params={},
):
    new_task = scheduler.NewTask(0)
    if path != "\\":
        root_folder.CreateFolder(path)
        folder = root_folder.GetFolder(path)
    folder = root_folder
    new_task.RegistrationInfo.Description = comment
    new_task.RegistrationInfo.Author = creator
    new_task.Settings.Enabled = True
    if flags != {}:
        new_task.Settings.RunOnlyIfNetworkAvailable = flags.get("RunOnlyIfNetworkAvailable", False)  #
        new_task.Settings.AllowHardTerminate = flags.get("AllowHardTerminate", False)  #
        new_task.Settings.AllowDemandStart = flags.get("AllowDemandStart", True)  #
        if "RestartInterval" in flags or "RestartCount" in flags:
            new_task.Settings.RestartInterval = flags.get("RestartInterval", "PT24H")
            new_task.Settings.RestartCount = flags.get("RestartCount", 1)
        new_task.Settings.StartWhenAvailable = flags.get("StartWhenAvailable", False)  #
        new_task.Settings.ExecutionTimeLimit = flags.get("ExecutionTimeLimit", "PT0S")
        if "DeleteExpiredTaskAfter" in flags:
            new_task.Settings.DeleteExpiredTaskAfter = flags.get("DeleteExpiredTaskAfter")
        new_task.Settings.WakeToRun = flags.get("WakeToRun", False)  #
        new_task.Settings.DisallowStartIfOnBatteries = flags.get("DisallowStartIfOnBatteries", False)  #
        new_task.Settings.RunOnlyIfIdle = flags.get("RunOnlyIfIdle", False)  #
        new_task.Settings.Hidden = flags.get("Hidden", False)  #
        new_task.Settings.StopIfGoingOnBatteries = flags.get("StopIfGoingOnBatteries", False)  #
        new_task.Settings.IdleSettings.StopOnIdleEnd = flags.get("StopOnIdleEnd", False)  #
        new_task.Settings.IdleSettings.RestartOnIdle = flags.get("RestartOnIdle", False)  #
    new_task.Settings.Priority = priority
    # new_task.Settings.Compatibility
    if trigger_type is not None:
        trigger = new_task.Triggers.Create(trigger_type)
    else:
        trigger = new_task.Trigger.Create(TASK_TRIGGER_TYPE.TASK_TRIGGER_REGISTRATION.value)
    if start_time != 0:
        trigger.StartBoundary = start_time.isoformat()
    if trigger_type in [
        TASK_TRIGGER_TYPE.TASK_TRIGGER_TIME.value,
        TASK_TRIGGER_TYPE.TASK_TRIGGER_DAILY.value,
        TASK_TRIGGER_TYPE.TASK_TRIGGER_WEEKLY.value,
        TASK_TRIGGER_TYPE.TASK_TRIGGER_MONTHLY.value,
        TASK_TRIGGER_TYPE.TASK_TRIGGER_MONTHLYDOW.value,
    ]:
        if expiration_time is not None:
            trigger.EndBoundary = expiration_time.isoformat()
        trigger.Repetition.Duration = duration
        trigger.Repetition.Interval = interval
        trigger.Repetition.StopAtDurationEnd = True
    if trigger_type == TASK_TRIGGER_TYPE.TASK_TRIGGER_DAILY.value:
        trigger.DaysInterval = additional_trigger_params.get("DaysInterval", 1)
    elif trigger_type == TASK_TRIGGER_TYPE.TASK_TRIGGER_WEEKLY.value:
        trigger.DaysOfWeek = additional_trigger_params.get("DaysOfWeek", 127)  # Every day of the week default
        trigger.WeeksInterval = additional_trigger_params.get("WeeksInterval", 1)
    elif trigger_type == TASK_TRIGGER_TYPE.TASK_TRIGGER_MONTHLY.value:
        trigger.DaysOfMonth = additional_trigger_params.get("DaysOfMonth", 1)
        trigger.MonthsOfYear = additional_trigger_params.get("MonthsOfYear", 4095)
        trigger.RunOnLastDayOfMonth = additional_trigger_params.get("RunOnLastDayOfMonth", False)
    elif trigger_type == TASK_TRIGGER_TYPE.TASK_TRIGGER_MONTHLYDOW.value:
        trigger.DaysOfWeek = additional_trigger_params.get("DaysOfWeek", 127)
        trigger.MonthsOfYear = additional_trigger_params.get("MonthsOfYear", 4095)
        trigger.RunOnLastWeekOfMonth = additional_trigger_params.get("RunOnLastWeekOfMonth", True)
        trigger.WeeksOfMonth = additional_trigger_params.get("WeeksOfMonth", 15)
    elif trigger_type == TASK_TRIGGER_TYPE.TASK_TRIGGER_EVENT.value:
        trigger.Delay = additional_trigger_params.get("Delay", "PT5M")
        trigger.Subscription = additional_trigger_params.get("Subscription", "empty_query")
        trigger.ValueQueries = additional_trigger_params.get("ValueQueries", "")
    elif trigger_type in [
        TASK_TRIGGER_TYPE.TASK_TRIGGER_BOOT.value,
        TASK_TRIGGER_TYPE.TASK_TRIGGER_LOGON.value,
        TASK_TRIGGER_TYPE.TASK_TRIGGER_REGISTRATION.value,
    ]:
        trigger.Delay = additional_trigger_params.get("Delay", "PT5M")
        if trigger_type == TASK_TRIGGER_TYPE.TASK_TRIGGER_LOGON.value:
            trigger.UserId = additional_trigger_params.get("UserId", account_information)
    new_task.Principal.DisplayName = creator
    new_task.Principal.UserId = account_information
    Action = new_task.Actions.Create(TASK_ACTION_TYPES.TASK_ACTION_EXEC.value)
    Action.ID = "MyAction"
    Action.Arguments = parameters
    Action.Path = application_name
    Action.WorkingDirectory = working_directory
    folder.RegisterTaskDefinition(task_name, new_task, TASK_CREATION.TASK_CREATE_OR_UPDATE.value, "", "", 0)


def create_scheduled_task_from_xml(task_name, xml_path):
    cmd = ["schtasks", "/create", "/xml", xml_path, "/tn", task_name]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout, result.stderr


def modify_scheduled_task(
    task_name,
    path=None,
    new_task_name=None,
    comment=None,
    action_id=None,
    application_name=None,
    priority=None,
    parameters=None,
    working_directory=None,
    creator=None,
    account_information=None,
    flags=None,
    trigger=None,
):
    if path:
        folder = root_folder.GetFolder(path)
    else:
        folder = root_folder
    for task in folder.GetTasks(0):
        if task.Name == task_name:
            modified_task = task.Definition
            if comment:
                modified_task.RegistrationInfo.Description = comment
            if application_name and parameters and working_directory:
                if modified_task.Actions.Count == 1 and not action_id:
                    modified_task.Actions.clear()
                elif action_id:
                    for index in range(1, modified_task.Actions.Count + 1):
                        if modified_task.Actions.Item(index).Id == action_id:
                            modified_task.Actions.Remove(index)
                Action = modified_task.Actions.Create(TASK_ACTION_TYPES.TASK_ACTION_EXEC.value)
                Action.ID = action_id or "MyAction"
                Action.Arguments = parameters
                Action.WorkingDirectory = working_directory
                Action.Path = application_name
            elif application_name or parameters or working_directory:
                if action_id:
                    for index in range(1, modified_task.Actions.Count + 1):
                        if modified_task.Actions.Item(index).Id == action_id:
                            if not application_name:
                                application_name = modified_task.Actions.Item(index).Path
                            if not working_directory:
                                working_directory = modified_task.Actions.Item(index).WorkingDirectory
                            if not parameters:
                                parameters = modified_task.Actions.Item(index).Arguments
                            modified_task.Actions.Remove(index)
                    Action = modified_task.Actions.Create(TASK_ACTION_TYPES.TASK_ACTION_EXEC.value)
                    Action.ID = action_id
                    Action.Arguments = parameters
                    Action.WorkingDirectory = working_directory
                    Action.Path = application_name
                elif modified_task.Actions.Count == 1:
                    id = modified_task.Actions.Item(1).Id
                    if not application_name:
                        application_name = modified_task.Actions.Item(1).Path
                    if not working_directory:
                        working_directory = modified_task.Actions.Item(1).WorkingDirectory
                    if not parameters:
                        parameters = modified_task.Actions.Item(1).Arguments
                    modified_task.Actions.Remove(1)
                    Action = modified_task.Actions.Create(TASK_ACTION_TYPES.TASK_ACTION_EXEC.value)
                    Action.ID = id or "MyAction"
                    Action.Arguments = parameters
                    Action.WorkingDirectory = working_directory
                    Action.Path = application_name
            if priority:
                modified_task.Settings.Priority = priority
            if creator:
                modified_task.RegistrationInfo.Author = creator
            if account_information:
                modified_task.Principal.UserId = account_information
            if trigger:
                log.info("Not possible to change the trigger at this time")
            if flags:
                if "RunOnlyIfNetworkAvailable" in flags:
                    modified_task.Settings.RunOnlyIfNetworkAvailable = flags.get("RunOnlyIfNetworkAvailable")
                if "AllowHardTerminate" in flags:
                    modified_task.Settings.AllowHardTerminate = flags.get("AllowHardTerminate")
                if "AllowDemandStart" in flags:
                    modified_task.Settings.AllowDemandStart = flags.get("AllowDemandStart")
                if "RestartInterval" in flags:
                    modified_task.Settings.RestartInterval = flags.get("RestartInterval")
                if "RestartCount" in flags:
                    modified_task.Settings.RestartCount = flags.get("RestartCount")
                if "StartWhenAvailable" in flags:
                    modified_task.Settings.StartWhenAvailable = flags.get("StartWhenAvailable")
                if "ExecutionTimeLimit" in flags:
                    modified_task.Settings.ExecutionTimeLimit = flags.get("ExecutionTimeLimit")
                if "DeleteExpiredTaskAfter" in flags:
                    modified_task.Settings.DeleteExpiredTaskAfter = flags.get("DeleteExpiredTaskAfter")
                if "WakeToRun" in flags:
                    modified_task.Settings.WakeToRun = flags.get("WakeToRun")
                if "DisallowStartIfOnBatteries" in flags:
                    modified_task.Settings.DisallowStartIfOnBatteries = flags.get("DisallowStartIfOnBatteries")
                if "RunOnlyIfIdle" in flags:
                    modified_task.Settings.RunOnlyIfIdle = flags.get("RunOnlyIfIdle")
                if "Hidden" in flags:
                    modified_task.Settings.Hidden = flags.get("Hidden")
                if "StopIfGoingOnBatteries" in flags:
                    modified_task.Settings.StopIfGoingOnBatteries = flags.get("StopIfGoingOnBatteries")
                if "StopOnIdleEnd" in flags:
                    modified_task.Settings.IdleSettings.StopOnIdleEnd = flags.get("StopOnIdleEnd")
                if "RestartOnIdle" in flags:
                    modified_task.Settings.IdleSettings.RestartOnIdle = flags.get("RestartOnIdle")
                if "Enabled" in flags:
                    modified_task.Settings.Enabled = flags.get("Enabled")
            if new_task_name:
                folder.RegisterTaskDefinition(new_task_name, modified_task, TASK_CREATION.TASK_UPDATE.value, "", "", 0)
                folder.DeleteTask(task_name, 0)
            else:
                folder.RegisterTaskDefinition(task_name, modified_task, TASK_CREATION.TASK_UPDATE.value, "", "", 0)
    log.info("Scheduled task %s modified on the victim vm", str(task_name))


def create_trigger(
    type, begin_date=date.today(), start_time=datetime.now().time(), duration=0, interval=0, expiration_time=None, flags=None
):
    new_trigger = pythoncom.CoCreateInstance(
        taskscheduler.CLSID_CTask, None, pythoncom.CLSCTX_INPROC_SERVER, taskscheduler.IID_ITask
    )
    _, tr = new_trigger.CreateTrigger()
    tt = tr.GetTrigger()
    tt.TriggerType = type
    if flags:
        tt.Flags = flags
    tt.BeginYear = int(begin_date.strftime("%Y"))
    tt.BeginMonth = int(begin_date.strftime("%m"))
    tt.BeginDay = int(begin_date.strftime("%d"))
    tt.StartMinute = int(start_time.strftime("%M"))
    tt.StartHour = int(start_time.strftime("%H"))
    if expiration_time:
        tt.EndYear = int(expiration_time.strftime("%Y"))
        tt.EndMonth = int(expiration_time.strftime("%m"))
        tt.EndDay = int(expiration_time.strftime("%d"))
    if duration != 0 and duration >= interval:
        tt.MinutesDuration = duration
    if interval:
        tt.MinutesInterval = interval
    return tt


def change_execution_dir(dir):
    log.info("Changing execution directory to %s", dir)
    log.warning("Changing directory not available in prescript testing")


def main(args):
    analysis_config_path = Path(os.path.join(cwd, "analysis.conf"))
    if not analysis_config_path.exists():
        print("Invalid analysis configuration file")
        sample_path = None
    else:
        conf = Config(analysis_config_path)
        sample_path = getattr(conf, "target", None)
    if args.zip and sample_path:
        extract_zip(sample_path, os.environ["TEMP"], "", 0)
        raw_json = extract_json_data(os.environ["TEMP"], "__configuration.json")
        json_dst_flds = raw_json.get("path_to_extract", {})
        target_file = raw_json.get("target_file", "")

        # Move files that are specified in JSON file
        if json_dst_flds:
            for f, dst_fld in json_dst_flds.items():
                oldpath = os.path.join(os.environ["TEMP"], f)
                dst_fld = os.path.expandvars(dst_fld)
                create_custom_folders(dst_fld)
                # If a relative path is provided, take only the basename
                fname = os.path.split(f)[1]
                newpath = os.path.join(dst_fld, fname)

                # We cannot just shutil.move src dirs if src name == dst name.
                if os.path.isdir(oldpath):
                    log.debug("Resolved Dir: %s for folder '%s'", dst_fld, fname)
                    shutil.copytree(oldpath, newpath, dirs_exist_ok=True)
                    shutil.rmtree(oldpath)
                else:
                    log.debug("Resolved Dir: %s for file '%s'", dst_fld, fname)
                    shutil.move(oldpath, newpath)
        fin_target_path = os.path.join(os.environ["TEMP"], target_file)
        sample_path = fin_target_path
    else:
        log.debug("Invalid analysis target for zip compound")
    actions = {}
    if args.actions:
        # Only valid options for parsing are:
        # 1: one big command line argument with a dict as string which get json.loads
        # 2: separated dict with keys delimiter
        # 3: position order with skip value
        # 4: Having argparse do the heavy lifting and having a bunch of flags and conditions
        previous_action = None
        previous_action_key = None
        for action_arg in args.actions:
            if action_arg in LIST_OF_VALID_ACTIONS:
                arg_position = 0
                previous_action = action_arg
                if action_arg not in actions.keys():
                    actions[action_arg] = {}
                    previous_action_key = action_arg
                else:
                    action_added = False
                    index = 0
                    while not action_added:
                        action_to_key = f"{action_arg}{index}"
                        index += 1
                        if action_to_key not in actions.keys():
                            previous_action_key = action_to_key
                            actions[action_to_key] = {}
                            action_added = True
            else:
                if action_arg == "None":
                    arg_position += 1
                    continue
                actions[previous_action_key][ACTIONS_PARAMETERS[previous_action][arg_position]] = action_arg
                arg_position += 1
    for action, params_dict in actions.items():
        try:
            parsed_action = "".join(i for i in action if not i.isdigit())
            if parsed_action not in LIST_OF_VALID_ACTIONS:
                continue
            if parsed_action == LIST_OF_VALID_ACTIONS[0]:
                run_script(
                    script_path=params_dict[ACTIONS_PARAMETERS[parsed_action][0]],
                    args=params_dict[ACTIONS_PARAMETERS[parsed_action][1]],
                    timeout=int(params_dict[ACTIONS_PARAMETERS[parsed_action][2]]),
                )
                log.info("Runned script with %s", str(params_dict))
                # print(f"Runned script with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[1]:
                add_file_to_path(
                    src_path=params_dict[ACTIONS_PARAMETERS[parsed_action][0]],
                    dst_path=params_dict[ACTIONS_PARAMETERS[parsed_action][1]],
                    overwrite=bool(params_dict[ACTIONS_PARAMETERS[parsed_action][2]]),
                )
                log.info(
                    "Adding file from %s to %s", params_dict[ACTIONS_PARAMETERS[parsed_action][0]], params_dict[ACTIONS_PARAMETERS[parsed_action][1]]
                )
                # print(
                #    f"Adding file from {params_dict[ACTIONS_PARAMETERS[parsed_action][0]]} to {params_dict[ACTIONS_PARAMETERS[parsed_action][1]]}"
                # )
            elif parsed_action == LIST_OF_VALID_ACTIONS[2]:
                add_directory(path=params_dict[ACTIONS_PARAMETERS[parsed_action][0]])
                log.info("Created directory with %s", str(params_dict))
                # print(f"Created directory with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[3]:
                value_type = identify_registry_value_type(params_dict[ACTIONS_PARAMETERS[parsed_action][2]])
                create_registry(
                    path=params_dict[ACTIONS_PARAMETERS[parsed_action][0]],
                    key=params_dict[ACTIONS_PARAMETERS[parsed_action][1]],
                    value=params_dict[ACTIONS_PARAMETERS[parsed_action][2]],
                    value_type=value_type,
                )
                log.info("Created registry with %s", str(params_dict))
                # print(f"Created registry with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[4]:
                value_type = identify_registry_value_type(params_dict[ACTIONS_PARAMETERS[parsed_action][2]])
                modify_registry(
                    path=params_dict[ACTIONS_PARAMETERS[parsed_action][0]],
                    key=params_dict[ACTIONS_PARAMETERS[parsed_action][1]],
                    value=params_dict[ACTIONS_PARAMETERS[parsed_action][2]],
                    value_type=value_type,
                )
                log.info("Modified registry with %s", str(params_dict))
                # print(f"Modified registry with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[5]:
                parsed_params_dict = {}
                for param in ACTIONS_PARAMETERS[parsed_action]:
                    if param not in params_dict.keys():
                        continue
                    if params_dict[param] == "" or params_dict[param] is None:
                        continue
                    if param == "priority":
                        parsed_params_dict[param] = int(params_dict[param])  # priority --> int
                    elif param == "flags":
                        format_ready_param = params_dict[param].replace('\\"', '"')
                        parsed_params_dict[param] = json.loads(format_ready_param)  # flags --> dict
                    elif param == "trigger_type":
                        parsed_params_dict[param] = int(params_dict[param])  # trigger_type --> int
                    elif param == "start_time":
                        parsed_params_dict[param] = datetime.strptime(params_dict[param], "%H:%M:%S")  # start_time --> time
                    elif param == "duration":
                        parsed_params_dict[param] = int(params_dict[param])  # duration --> int
                    elif param == "interval":
                        parsed_params_dict[param] = int(params_dict[param])  # interval --> int
                    elif param == "expiration_time":
                        parsed_params_dict[param] = datetime.strptime(params_dict[param], "%H:%M:%S")  # expiration_time --> time
                    elif param == "additional_trigger_params":
                        format_ready_param = params_dict[param].replace('\\"', '"')
                        parsed_params_dict[param] = json.loads(format_ready_param)  # additional_trigger_params --> dict
                    else:
                        parsed_params_dict[param] = params_dict[param]
                create_scheduled_task2(**parsed_params_dict)
                log.info("Created scheduled task with %s", str(params_dict))
                # print(f"Created scheduled task with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[6]:
                create_scheduled_task_from_xml(
                    task_name=params_dict[ACTIONS_PARAMETERS[parsed_action][0]],
                    xml_path=params_dict[ACTIONS_PARAMETERS[parsed_action][1]],
                )
                log.info("Created scheduled task from xml with %s", str(params_dict))
                # print(f"Created scheduled task from xml with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[7]:
                parsed_params_dict = {}
                for param in ACTIONS_PARAMETERS[parsed_action]:
                    if param not in params_dict.keys():
                        continue
                    if param == "priority":
                        parsed_params_dict[param] = int(params_dict[param])  # priority --> int
                    elif param == "action_id":
                        parsed_params_dict[param] = int(params_dict[param])  # action_id --> int
                    elif param == "flags":
                        parsed_params_dict[param] = json.loads(params_dict[param])  # flags --> dict
                    else:
                        parsed_params_dict[param] = params_dict[param]
                modify_scheduled_task(**parsed_params_dict)
                log.info("Modified scheduled task with %s", str(params_dict))
                # print(f"Modified scheduled task with {params_dict}")
            elif parsed_action == LIST_OF_VALID_ACTIONS[8]:
                change_execution_dir(path=params_dict[ACTIONS_PARAMETERS[parsed_action][0]])
                log.info("Changed execution dir to %s", params_dict[ACTIONS_PARAMETERS[parsed_action][0]])
                # print(f"Changed execution dir to {params_dict[ACTIONS_PARAMETERS[parsed_action][0]]}")

        except Exception as e:
            log.debug("Invalid action %s with parameters %s --> %s", str(action), str(params_dict), str(e))
            # print(f"Invalid action {action} with parameters {params_dict} --> {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Example of args to pass --zip --actions action_name param1 param2 action_name param param1
    parser.add_argument("-z", "--zip", help="Zip_compound available", action="store_true", required=False, default=False)
    parser.add_argument("-a", "--actions", help="Actions to take", action="store", nargs="*", required=False, default=None)
    args = parser.parse_args()
    main(args)
