rule SparkRAT
{
    meta:
        author = "t-mtsmt"
        description = "SparkRAT Payload"
        cape_type = "SparkRAT Payload"

    strings:
        $path_00 = "/client/common"
        $path_01 = "/client/config"
        $path_02 = "/client/core"
        $path_03 = "/client/service/basic"
        $path_04 = "/client/service/desktop"
        $path_05 = "/client/service/file"
        $path_06 = "/client/service/process"
        $path_07 = "/client/service/terminal"
        $path_08 = "/modules"
        $path_09 = "/utils"

        $cmd_00 = "PING"
        $cmd_01 = "OFFLINE"
        $cmd_02 = "LOCK"
        $cmd_03 = "LOGOFF"
        $cmd_04 = "HIBERNATE"
        $cmd_05 = "SUSPEND"
        $cmd_06 = "RESTART"
        $cmd_07 = "SHUTDOWN"
        $cmd_08 = "SCREENSHOT"
        $cmd_09 = "TERMINAL_INIT"
        $cmd_10 = "TERMINAL_INPUT"
        $cmd_11 = "TERMINAL_RESIZE"
        $cmd_12 = "TERMINAL_PING"
        $cmd_13 = "TERMINAL_KILL"
        $cmd_14 = "FILES_LIST"
        $cmd_15 = "FILES_FETCH"
        $cmd_16 = "FILES_REMOVE"
        $cmd_17 = "FILES_UPLOAD"
        $cmd_18 = "FILE_UPLOAD_TEXT"
        $cmd_19 = "PROCESSES_LIST"
        $cmd_20 = "PROCESS_KILL"
        $cmd_21 = "DESKTOP_INIT"
        $cmd_22 = "DESKTOP_PING"
        $cmd_23 = "DESKTOP_KILL"
        $cmd_24 = "DESKTOP_SHOT"
        $cmd_25 = "COMMAND_EXEC"

    condition:
        3 of ($path_*) and 3 of ($cmd_*)
}