from __future__ import absolute_import
import ast
import base64
import itertools
import logging
import os
import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import Processing

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)

__author__ = "Jeff White [karttoon] @noottrak"
__email__ = "karttoon@gmail.com"
__version__ = "1.0.12"
__date__ = "25SEP2020"
__credits__ = ["@noottrak", "@doomedraven"]


'''
Standalone usage for dev or quick tests

from modules.processing.curtain import deobfuscate
message = """here_weg"""
print(deobfuscate(message))
'''


def buildBehaviors(entry, behaviorTags):
    # Generates possible code injection variations
    # {Behavior:[["entry1","entry2"],["entry3","entry4"]]}

    codeInject = (
        ("VirtualAlloc", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "HeapAlloc"),
        (
            "CallWindowProcA",
            "CallWindowProcW",
            "DialogBoxIndirectParamA",
            "DialogBoxIndirectParamW",
            "EnumCalendarInfoA",
            "EnumCalendarInfoW",
            "EnumDateFormatsA",
            "EnumDateFormatsW",
            "EnumDesktopWindows",
            "EnumDesktopsA",
            "EnumDesktopsW",
            "EnumLanguageGroupLocalesA",
            "EnumLanguageGroupLocalesW",
            "EnumPropsExA",
            "EnumPropsExW",
            "EnumPwrSchemes",
            "EnumResourceTypesA",
            "EnumResourceTypesW",
            "EnumResourceTypesExA",
            "EnumResourceTypesExW",
            "EnumSystemCodePagesA",
            "EnumSystemCodePagesW",
            "EnumSystemLanguageGroupsA",
            "EnumSystemLanguageGroupsW",
            "EnumSystemLocalesA",
            "EnumSystemLocalesW",
            "EnumThreadWindows",
            "EnumTimeFormatsA",
            "EnumTimeFormatsW",
            "EnumUILanguagesA",
            "EnumUILanguagesW",
            "EnumWindowStationsA",
            "EnumWindowStationsW",
            "EnumWindows",
            "EnumerateLoadedModules",
            "EnumerateLoadedModulesEx",
            "EnumerateLoadedModulesExW",
            "GrayStringA",
            "GrayStringW",
            "NotifyIpInterfaceChange",
            "NotifyTeredoPortChange",
            "NotifyUnicastIpAddressChange",
            "SHCreateThread",
            "SHCreateThreadWithHandle",
            "SendMessageCallbackA",
            "SendMessageCallbackW",
            "SetWinEventHook",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "CreateThread",
        ),
    )

    behaviorCol = {
        "Code Injection": list(itertools.product(*codeInject)),
        "Downloader": (
            ("New-Object", "Net.WebClient", "DownloadFile"),
            ("New-Object", "Net.WebClient", "DownloadString"),
            ("New-Object", "Net.WebClient", "DownloadData"),
            ("WebProxy", "Net.CredentialCache"),
            (
                "Import-Module BitsTransfer",
                "Start-BitsTransfer",
                "Source",
                "Destination",
            ),
            ("New-Object", "Net.Sockets.TCPClient", "GetStream"),
            ("$env:LocalAppData"),
            ("Invoke-WebRequest"),
            ("wget"),
            ("Get-Content"),
        ),
        "Starts Process": (
            ("Start-Process"),
            ("New-Object", "IO.MemoryStream", "IO.StreamReader"),
            ("Diagnostics.Process)::Start"),
        ),
        "Compression": (
            ("Convert", "FromBase64String", "System.Text.Encoding"),
            ("IO.Compression.GzipStream"),
            ("(IO.Compression.CompressionMode)::Decompress"),
            ("IO.Compression.DeflateStream"),
        ),
        "Uses Stealth": (
            ("WindowStyle", "Hidden"),
            ("CreateNoWindow=$true"),
            ("ErrorActionPreference", "SilentlyContinue"),
        ),
        "Key Logging": (("GetAsyncKeyState", "Windows.Forms.Keys")),
        "Screen Scraping": (
            ("New-Object", "Drawing.Bitmap", "Width", "Height"),
            ("(Drawing.Graphics)::FromImage"),
            ("CopyFroMScreen", "Location", "(Drawing.Point)::Empty", "Size"),
        ),
        "Custom Web Fields": (("Headers.Add"), ("SessionKey", "SessiodID")),
        "Persistence": (
            ("New-Object", "-COMObject", "Schedule.Service"),
            ("SCHTASKS"),
        ),
        "Sleeps": (("Start-Sleep")),
        "Uninstalls Apps": (("foreach", "UninstallString")),
        "Obfuscation": (("-Join", "(int)", "-as", "(char)")),
        "Crypto": (
            (
                "New-Object",
                "Security.Cryptography.AESCryptoServiceProvider",
                "Mode",
                "Key",
                "IV",
            ),
            ("CreateEncryptor().TransformFinalBlock"),
            ("CreateDecryptor().TransformFinalBlock"),
        ),
        "Enumeration/Profiling": (
            ("(Environment)::UserDomainName"),
            ("(Environment)::UserName"),
            ("$env:username"),
            ("(Environment)::MachineName"),
            ("(Environment)::GetFolderPath"),
            ("(System.IO.Path)::GetTempPath"),
            ("$env:windir"),
            ("GWMI Win32_NetworkAdapterConfiguration"),
            ("Get-WMIObject Win32_NetworkAdapterConfiguration"),
            ("GWMI Win32_OperatingSystem"),
            ("Get-WMIObject Win32_OperatingSystem"),
            ("(Security.Principal.WindowsIdentity)::GetCurrent"),
            ("(Security.Principal.WindowsBuiltInRole)", "Administrator"),
            ("(System.Diagnostics.Process)::GetCurrentProcess"),
            ("PSVersionTable.PSVersion"),
            ("New-Object", "Diagnostics.ProcessStartInfo"),
            ("GWMI Win32_ComputerSystemProduct"),
            ("Get-WMIObject Win32_ComputerSystemProduct"),
            ("Get-Process -id"),
            ("$env:userprofile"),
            ("(Windows.Forms.SystemInformation)::VirtualScreen"),
        ),
        "Registry": (
            ("HKCU:\\"),
            ("HKLM:\\"),
            ("New-ItemProperty", "-Path", "-Name", "-PropertyType", "-Value"),
        ),
        "Sends Data": (("UploadData", "POST")),
        "AppLocker Bypass": (("regsvr32", "/i:http", "scrobj.dll")),
        "AMSI Bypass": (
            ("Management.Automation.AMSIUtils", "amsiInitFailed"),
            ("Expect100Continue"),
        ),
        "Disables Windows Defender": (
            ("DisableBehaviorMonitoring"),
            ("DisableBlockAtFirstSeen"),
            ("DisableIntrusionPreventionSystem"),
            ("DisableIOAVProtection"),
            ("DisablePrivacyMode"),
            ("DisableRealtimeMonitoring"),
            ("DisableScriptScanning"),
            ("LowThreatDefaultAction"),
            ("ModerateThreatDefaultAction"),
            ("SevereThreatDefaultAction)"),
        ),
        "Clear Logs": (("GlobalSession.ClearLog")),
        "Invokes C# .NET Assemblies": (("Add-Type")),
        "Modifies Shadowcopy": (("Win32_Shadowcopy")),
    }

    for event in entry:
        for message in entry[event]:
            message = entry[event][message]
            for behavior in behaviorCol:
                # Check Behavior Keywords
                for check in behaviorCol[behavior]:
                    if behavior not in behaviorTags and all(value.lower() in message.lower() for value in check):
                        behaviorTags.append(behavior)
                # Check Character Frequency Analysis
                if (
                    behavior == "Obfuscation"
                    and (
                        (
                            message.count("w") >= 500
                            or message.count("4") >= 250
                            or message.count("_") >= 250
                            or message.count("D") >= 250
                            or message.count("C") >= 200
                            or message.count("K") >= 200
                            or message.count("O") >= 200
                            or message.count(":") >= 100
                            or message.count(";") >= 100
                            or message.count(",") >= 100
                            or (message.count("(") >= 50 and message.count(")") >= 50)
                            or (message.count("[") >= 50 and message.count("]") >= 50)
                            or (message.count("{") >= 50 and message.count("}") >= 50)
                        )
                    )
                    and behavior not in behaviorTags
                ):
                    behaviorTags.append(behavior)

    return behaviorTags


def formatReplace(inputString, MODFLAG):
    """
    OLD: ("{1}{0}{2}" -F"AMP","EX","LE")
    NEW: "EXAMPLE"
    """
    # Find group of obfuscated string
    obfGroup = re.search(r"(\"|')(\{[0-9]{1,2}\})+(\"|')[ -fF].+?'.+?'\)(?!(\"|'|;))", inputString).group()
    # There are issues with multiple nested groupings that I haven't been able to solve yet, but doesn't change the final output of the PS script
    # obfGroup = re.search(r"(\"|\')(\{[0-9]{1,2}\})+(\"|\')[ -fF]+?(\"|\').+?(\"|\')(?=\)([!.\"\';)( ]))", inputString).group()

    # Build index and string lists
    indexList = [int(x) for x in re.findall(r"\d+", obfGroup.split("-", 1)[0])]

    # This is to address scenarios where the string built is more PS commands with quotes
    stringList = re.search("(\"|').+", "-".join(obfGroup.split("-")[1:])[:-1]).group()
    stringChr = stringList[0]
    stringList = stringList.replace(f"{stringChr},{stringChr}", "\x00")[1:-1]
    stringList = stringList.replace("'", "\x01").replace('"', "\x02")
    stringList = stringList.replace("\x00", f"{stringChr},{stringChr}")
    stringList = ast.literal_eval(f"[{stringChr}{stringList}{stringChr}]")

    for index, entry in enumerate(stringList):
        stringList[index] = entry.replace("\x01", "'").replace("\x02", '"')

    # Build output string
    stringOutput = ""
    for value in indexList:
        try:
            stringOutput += stringList[value]
        except Exception:
            pass
    stringOutput = f'"{stringOutput}")'
    # Replace original input with obfuscated group replaced

    if MODFLAG == 0:
        MODFLAG = 1
    return inputString.replace(obfGroup, stringOutput), MODFLAG


def charReplace(inputString, MODFLAG):
    """
    OLD: [char]101
    NEW: e
    """
    for value in re.findall(r"\[[Cc][Hh][Aa][Rr]\][0-9]{1,3}", inputString):
        inputString = inputString.replace(value, f'"{chr(int(value.split("]", 2)[1]))}"')
    if MODFLAG == 0:
        MODFLAG = 1
    return inputString, MODFLAG


def spaceReplace(inputString, MODFLAG):
    """
    OLD: $var=    "EXAMPLE"
    NEW: $var= "EXAMPLE"
    """
    return re.sub(" +", " ", inputString), MODFLAG


def joinStrings(inputString, MODFLAG):
    """
    OLD: $var=("EX"+"AMP"+"LE")
    NEW: $var=("EXAMPLE")
    """
    if MODFLAG == 0:
        MODFLAG = 1
    return inputString.replace("'+'", "").replace('"+"', ""), MODFLAG


def removeNull(inputString, MODFLAG):
    # Windows/Unicode null bytes will interfere with regex
    return inputString.replace("\x00", ""), MODFLAG


def removeEscape(inputString, MODFLAG):
    """
    OLD: $var=\'EXAMPLE\'
    NEW: $var='EXAMPLE'
    """
    return inputString.replace("\\'", "'").replace('\\"', '"'), MODFLAG


def removeTick(inputString, MODFLAG):
    """
    OLD: $v`a`r=`"EXAMPLE"`
    NEW: $var="EXAMPLE"
    """
    if MODFLAG == 0:
        MODFLAG = 1
    return inputString.replace("`", ""), MODFLAG


def removeCaret(inputString, MODFLAG):
    """
    OLD: $v^a^r=^"EXAMPLE"^
    NEW: $var="EXAMPLE"
    """
    if MODFLAG == 0:
        MODFLAG = 1
    return inputString.replace("^", ""), MODFLAG


def adjustCase(inputString, MODFLAG):
    """
    OLD: $vAR="ExAmpLE"
    NEW: $var="example"
    """
    return inputString.lower(), MODFLAG


def removeParenthesis(inputString, MODFLAG):
    """
    OLD ('ls11, ')+('tls'))
    NEW: tls11,tls
    """
    matches = re.findall(r"\(('[\w\d\s,\/\-\/\*\.:'+]+')\)", inputString)
    if matches:
        MODFLAG = 1
    for pattern in matches:
        inputString = inputString.replace(f"({pattern})", pattern)  # .replace("'", "")

    matches = re.findall(r"\('[\w\d\s,\/\-\/\*\.:]+", inputString)
    if matches:
        MODFLAG = 1
    for pattern in matches:
        inputString = inputString.replace(f"({pattern}", pattern)

    matches += re.findall(r"'[\w\d\s,\/\-\/\*\.:]+'\)", inputString)
    if matches:
        MODFLAG = 1
    for pattern in matches:
        inputString = inputString.replace(f"{pattern})", pattern)

    return inputString, MODFLAG


def base64FindAndDecode(inputString):
    """
    OLD: TVo=
    NEW: set MZ
    """
    matched = re.findall("[-A-Za-z0-9+]+={1,2}", inputString)
    for pattern in matched:
        try:
            decoded = base64.b64decode(pattern)
            inputString = inputString.replace(pattern, decoded)
        except Exception as e:
            log.error(e)

    return inputString


def replaceDecoder(inputString, MODFLAG):
    """
    OLD: (set GmBtestGmb).replace('GmB',[Char]39)
    NEW: set 'test'
    """
    inputString = inputString.replace("'+'", "")
    inputString = inputString.replace("'|'", "char[124]")

    if "|" in inputString and "replace" not in inputString.rsplit("|", 1)[-1]:
        inputString = inputString.rsplit("|", 1)[0]

    while "replace" in inputString.rsplit(".", 1)[-1].lower() or "replace" in inputString.rsplit("-", 1)[-1].lower():
        inputString = inputString.replace("'+'", "")
        inputString = inputString.replace("'|'", "char[124]")

        if len(inputString.rsplit(".", 1)[-1]) > len(inputString.rsplit("-", 1)[-1]):
            tempString = inputString.rsplit("-", 1)[0]
            replaceString = inputString.rsplit("-", 1)[-1]

            if "[" in replaceString.split(",", 1)[0]:
                firstPart = " ".join(replaceString.split(",", 1)[0].split("[")[1:]).replace("'", "").replace('"', "")

            elif "'" in replaceString.split(",", 1)[0].strip() or '"' in replaceString.split(",", 1)[0].strip():
                firstPart = re.search("('.+?'|\".+?\")", replaceString.split(",", 1)[0]).group().replace("'", "").replace('"', "")

            else:
                firstPart = replaceString.split(",", 1)[0].split("'", 2)[1].replace("'", "").replace('"', "")

        else:
            tempString = inputString.rsplit(".", 1)[0]
            replaceString = inputString.rsplit(".", 1)[-1]
            firstPart = replaceString.split(",", 1)[0].rsplit("(", 1)[-1].replace("'", "").replace('"', "")
        secondPart = replaceString.split(",", 2)[1].split(")", 1)[0].replace("'", "").replace('"', "")
        if "+" in firstPart:
            newFirst = "".join(chr(int(re.search("[0-9]+", entry).group())) for entry in firstPart.split("+"))
            firstPart = newFirst

        if re.search("char", firstPart, re.IGNORECASE):
            firstPart = chr(int(re.search("[0-9]+", firstPart).group()))

        if "+" in secondPart:
            newSecond = "".join(chr(int(re.search("[0-9]+", entry).group())) for entry in secondPart.split("+"))
            secondPart = newSecond

        if re.search("char", secondPart, re.IGNORECASE):
            secondPart = chr(int(re.search("[0-9]+", secondPart).group()))

        tempString = tempString.replace(firstPart, secondPart)
        inputString = tempString

        if "replace" not in inputString.rsplit("|", 1)[-1].lower():
            inputString = inputString.split("|", 1)[0]

    if MODFLAG == 0:
        MODFLAG = 1

    return inputString, MODFLAG


def deobfuscate(MESSAGE):
    """
    This can be used as standalone, for testing and dev of new deobfuscation technics
    Example:
        from modules.processing.curtain import deobfuscate
        message = '''powershell blob goes here'''
        print(deobfuscate(message))

    Parameters:
        MESSAGE (str): powershell code to deobfuscate

    Returns:
        ALTMSG (str): deobfuscated powershell
    """

    MODFLAG = 0

    # Attempt to further decode token replacement/other common obfuscation
    # Original and altered will be saved
    ALTMSG = MESSAGE.strip()

    if re.search("\x00", ALTMSG):
        ALTMSG, MODFLAG = removeNull(ALTMSG, MODFLAG)

    if re.search("(\\\"|\\')", ALTMSG):
        ALTMSG, MODFLAG = removeEscape(ALTMSG, MODFLAG)

    if re.search("`", ALTMSG):
        ALTMSG, MODFLAG = removeTick(ALTMSG, MODFLAG)

    if re.search(r"\^", ALTMSG):
        ALTMSG, MODFLAG = removeCaret(ALTMSG, MODFLAG)

    # strip - ('ls11, ')+('tls')
    # import code;code.interact(local=dict(locals(), **globals()))
    if (
        re.search(r"\(('[\w\d\s,\/\-\/\*\.:'+]+')\)", ALTMSG)
        or re.search(r"\('[\w\d\s,\/\-\/\*\.:]+", ALTMSG)
        or re.search(r"'[\w\d\s,\/\-\/\*\.:]+'\)", ALTMSG)
    ):
        ALTMSG, MODFLAG = removeParenthesis(ALTMSG, MODFLAG)

    while re.search("[\x20]{2,}", ALTMSG):
        ALTMSG, MODFLAG = spaceReplace(ALTMSG, MODFLAG)

    # One run pre charPreplace
    if re.search(r"\[[Cc][Hh][Aa][Rr]\][0-9]{1,3}", ALTMSG):
        ALTMSG, MODFLAG = charReplace(ALTMSG, MODFLAG)

    if re.search(r"(\"\+\"|'\+')", ALTMSG):
        ALTMSG, MODFLAG = joinStrings(ALTMSG, MODFLAG)

    while re.search(r"(\"|')(\{[0-9]{1,2}\})+(\"|')[ -fF].+?'.+?'\)(?!(\"|'|;))", ALTMSG):
        ALTMSG, MODFLAG = formatReplace(ALTMSG, MODFLAG)

    # One run post formatReplace for new strings
    if re.search(r"(\"\+\"|'\+')", ALTMSG):
        ALTMSG, MODFLAG = joinStrings(ALTMSG, MODFLAG)

    if "replace" in ALTMSG.lower():
        try:
            ALTMSG, MODFLAG = replaceDecoder(ALTMSG, MODFLAG)
        except Exception as e:
            log.error("Curtain processing error for entry - %s", e)

    # https://malwaretips.com/threads/how-to-de-obfuscate-powershell-script-commands-examples.76369/
    if re.search(r"-join\s+?\(\s?'(.+)\.split\(.+\)\s+?\|\s+?foreach", MESSAGE, re.I):
        chars = re.findall(r"\d{1,3}", MESSAGE)
        ALTMSG = "".join([chr(int(i)) for i in chars])
        MODFLAG = 1

    if re.search(r"join\(\s?['\"]+\s?,\(\s?['\"].+'\s?\)\s?\|\s?foreach-object\s?.+-bxor\s?(0x[\d\w]+)", MESSAGE, re.I):
        xorkey = re.findall(r"join\(\s?['\"]+\s?,\(\s?['\"].+'\s?\)\s?\|\s?foreach-object\s?.+-bxor\s?(0x[\d\w]+)", MESSAGE, re.I)[
            0
        ]
        chars = re.findall(r"\d{1,3}", MESSAGE)
        ALTMSG = "".join([chr(int(i) ^ int(xorkey, 16)) for i in chars])
        MODFLAG = 1

    if re.search(r'"([{\d{1,3}\}]+)"\-f(.+)\)\)\s+(-replace.*)', MESSAGE, re.I):
        res = re.findall(r'"([{\d{1,3}\}]+)"\-f(.+)\)\)\s+(-replace.*)', MESSAGE, re.I)
        formated, data, replaces = res[0]
        r = formated.format(*data.split("','")).replace("'", "")
        # split by blocks
        blocks = re.findall(r"([\[cHAR\]\d{1,3}\+']+\)),(\[char\]\d{1,3})", MESSAGE, re.I)
        for i in blocks:
            ALTMSG = r.replace(
                "".join([chr(int(i)) for i in re.findall(r"\d{1,3}", i[0])]),
                "".join([chr(int(i)) for i in re.findall(r"\d{1,3}", i[1])]),
            )
            MODFLAG = 1
            # Remove camel case obfuscation as last step
            ALTMSG, MODFLAG = adjustCase(ALTMSG, MODFLAG)

    if MODFLAG == 0:
        ALTMSG = "No alteration of event."

    return ALTMSG


class Curtain(Processing):
    """Parse Curtain log for PowerShell 4104 Events."""

    def run(self):
        self.key = "curtain"
        # Remove some event entries which are commonly found in all samples (noise reduction)
        noise = (
            "$global:?",
            "# Compute file-hash using the crypto object",
            "# Construct the strongly-typed crypto object",
            "HelpInfoURI = 'http://go.microsoft.com/fwlink/?linkid=285758'",
            "[System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($args[0])",
            "[System.Management.ManagementDateTimeConverter]::ToDateTime($args[0])",
            "Set-Location Z:",
            "Set-Location Y:",
            "Set-Location X:",
            "Set-Location W:",
            "Set-Location V:",
            "Set-Location U:",
            "Set-Location T:",
            "Set-Location S:",
            "Set-Location R:",
            "Set-Location Q:",
            "Set-Location P:",
            "Set-Location O:",
            "Set-Location N:",
            "Set-Location M:",
            "Set-Location L:",
            "Set-Location K:",
            "Set-Location J:",
            "Set-Location I:",
            "Set-Location H:",
            "Set-Location G:",
            "Set-Location F:",
            "Set-Location E:",
            "Set-Location D:",
            "Set-Location C:",
            "Set-Location B:",
            "Set-Location A:",
            "Set-Location ..",
            "Set-Location \\",
            "$wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Out-String',[System.Management.Automation.CommandTypes]::Cmdlet)",
            "$str.Substring($str.LastIndexOf('Verbs') + 5)",
            "[Parameter(ParameterSetName='nameSet', Position=0, ValueFromPipelineByPropertyName=$true)]",
            "[ValidateSet('Alias','Cmdlet','Provider','General','FAQ','Glossary','HelpFile'",
            "param([string[]]$paths)",
            "$origin = New-Object System.Management.Automation.Host.Coordinates",
            "Always resolve file paths using Resolve-Path -Relative.",
            "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1))",
            "$this.ServiceName",
            "Read-Host 'Press Enter to continue...' | Out-Null",
            "([System.Management.Automation.CommandTypes]::Script)",
            "if ($myinv -and ($myinv.MyCommand -or ($_.CategoryInfo.Category -ne 'ParserError')))",
            "CmdletsToExport=@(",
            "CmdletsToExport",
            "FormatsToProcess",
            "AliasesToExport",
            "FunctionsToExport",
            "$_.PSParentPath.Replace",
            "$ExecutionContext.SessionState.Path.Combine",
            "get-help about_Command_Precedence",
            '"Get-WmiObject"\nParameterBinding(Get-WmiObject): name="ComputerName"; value="Localhost"\nParameterBinding(Get-WmiObject): name="Class"; value="win32_computersystem"\nCommandInvocation(Out-Default): "Out-Default"\nParameterBinding(Out-Default): name="Transcript"; value="True"\nParameterBinding(Out-Default): name="InputObject";',
        )

        # Determine oldest Curtain log and remove the rest
        curtLog = os.path.join(self.analysis_path, "curtain")
        if not os.path.exists(curtLog):
            return
        curtLog = sorted(list(os.listdir(curtLog)))

        root = False
        for curtain_log in curtLog[::-1]:
            try:
                tree = ET.parse(f"{self.analysis_path}/curtain/{curtain_log}")
                root = tree.getroot()
                os.rename(f"{self.analysis_path}/curtain/{curtain_log}", f"{self.analysis_path}/curtain/curtain.log")
                break
            except Exception:
                # malformed file
                pass

        if not root:
            return

        # Leave only the most recent file
        for file in os.listdir(f"{self.analysis_path}/curtain/"):
            if file != "curtain.log":
                try:
                    os.remove(f"{self.analysis_path}/curtain/{file}")
                except Exception:
                    pass

        pids = {}
        COUNTER = 0
        FILTERED = 0
        messages_by_task = {}

        for item in root:
            # Setup PID Dict
            if item[0][1].text in ["4104", "4103", "4100"]:
                FILTERFLAG = 0

                PID = item[0][10].attrib["ProcessID"]
                # TID = item[0][10].attrib['ThreadID']
                task = item[0][4].text

                MESSAGE = item[1][2].text
                if PID not in pids:
                    pids[PID] = {"pid": PID, "events": [], "filter": []}

                # Checks for unique strings in events to filter out
                if MESSAGE is not None:
                    for entry in noise:
                        if entry in MESSAGE:
                            FILTERFLAG = 1
                            FILTERED += 1
                            pids[PID]["filter"].append({str(FILTERED): MESSAGE.strip()})

                if task in messages_by_task:
                    messages_by_task[task]["message"] = MESSAGE + messages_by_task[task]["message"]
                else:
                    messages_by_task.setdefault(task, {}).update({"message": MESSAGE, "pid": PID})

        new_dict = list(messages_by_task.values())

        for block in new_dict:
            MESSAGE = block["message"]
            pid = block["pid"]
            # Save the record
            if FILTERFLAG == 0 and MESSAGE is not None:
                COUNTER += 1
                ALTMSG = deobfuscate(MESSAGE)

                # Save the output
                pids[pid]["events"].append({str(COUNTER): {"original": MESSAGE.strip(), "altered": ALTMSG}})

        remove = set()

        # Find Curtain PID if it was picked up in log
        for pid, value in pids.items():
            for event in value["events"]:
                for entry in event.values():
                    if (
                        "Process { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog"
                        in entry["original"]
                    ):
                        remove.add(pid)

        # Find empty PID
        for pid, value in pids.items():
            if len(value["events"]) == 0:
                remove.add(pid)

        # Remove PIDs
        for pid in remove:
            del pids[pid]

        # Reorder event counts
        for pid, value in pids.items():
            eventCount = len(pids[pid]["events"])
            tempEvents = [{f"{eventCount - index:02d}": list(entry.values())[0]} for index, entry in enumerate(value["events"])]

            pids[pid]["events"] = tempEvents

            eventCount = len(pids[pid]["filter"])
            tempEvents = [{f"{eventCount - index:02d}": list(entry.values())[0]} for index, entry in enumerate(pids[pid]["filter"])]

            pids[pid]["filter"] = tempEvents

        # Identify behaviors per PID
        for pid, value in pids.items():
            behaviorTags = []
            for entry in value["events"]:
                behaviorTags = buildBehaviors(entry, behaviorTags)
                pids[pid]["behaviors"] = behaviorTags

        return pids
