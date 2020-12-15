#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Main vba2graph file
Version: 0.2

This script creates fancy VBA call graphs from olevba output.

Run Examples:
    $ python vba2graph.py -i [your_olevba_output] -o [output_dir]
    $ python vba2graph.py -f [office_file_with_macro] -o [output_dir]
    $ olevba [malicous_doc_with_macro] | python vba2graph.py

Dependencies:
    - networkx>=2.1
    - regex
    - graphviz>=0.8.4
    - pydot>=1.2.4
    - latest olevba

Notes:
    - Main function is at the buttom :)
"""

# ****************************************************************************
# *                              General Imports                             *
# ****************************************************************************

import os
import sys
import errno
import argparse
import regex as re
from io import StringIO
from subprocess import Popen

# ****************************************************************************
# *                           Dependencies Imports                           *
# ****************************************************************************

import networkx as nx
from networkx.drawing.nx_pydot import write_dot
try:
    from oletools.olevba import VBA_Parser
    # Temporary workaround. Change when oletools 0.56 will be released.
    VBA_Parser.detect_vba_stomping = lambda self: False
    HAVE_OLETOOLS = True
except ImportError:
    HAVE_OLETOOLS = False
# ****************************************************************************
# *                            Initialize Logging                            *
# ****************************************************************************

import logging
logger = logging.getLogger("-vba2graph-")

# ****************************************************************************
# *                                Global Vars                               *
# ****************************************************************************

# possible color names:
#   graphviz.org/doc/info/colors.html
#   wingraphviz.sourceforge.net/wingraphviz/language/fontcolor.htm

LINE_SEP = "\n"

color_schemes = [
    {   # regular theme - boring black on white
        "COLOR_BACKGROUND": "#FFFFFF",
        "COLOR_DEFAULT_BOX": "black",
        "COLOR_DEFAULT_TEXT": "black",
        "COLOR_DEFAULT_EDGES": "black",
        "COLOR_DEFAULT_EDGES_FONT": "black",

        "COLOR_REGULAR_KEYWORD": "black",
        "COLOR_OBFUSCATION_KEYWORD": "#666699",

        "COLOR_CRITICAL_NUM_OF_CALLS": "red",
        "COUNT_CRITICAL_NUM_OF_CALLS": 10,

        "COLOR_PROPERTY": "purple",
        "COLOR_TRIGGERED_CALL_EDGE": "purple",
        "COLOR_AUTORUN_FUNCTIONS": "red",
        "COLOR_EXTERNAL_FUNCTION": "brown"
    },
    {   # darker theme - cyan colors
        "COLOR_BACKGROUND": "#40334E",
        "COLOR_DEFAULT_BOX": "#6A416D",
        "COLOR_DEFAULT_TEXT": "#E9BA69",
        "COLOR_DEFAULT_EDGES": "white",
        "COLOR_DEFAULT_EDGES_FONT": "white",

        "COLOR_REGULAR_KEYWORD": "#9E62E7",
        "COLOR_OBFUSCATION_KEYWORD": "#666699",

        "COLOR_CRITICAL_NUM_OF_CALLS": "red",
        "COUNT_CRITICAL_NUM_OF_CALLS": 10,

        "COLOR_PROPERTY": "#ABDACC",
        "COLOR_TRIGGERED_CALL_EDGE": "#F6C565",
        "COLOR_AUTORUN_FUNCTIONS": "red",
        "COLOR_EXTERNAL_FUNCTION": "#ABDACC"
    },
    {   # 80s theme
        "COLOR_BACKGROUND": "#6075AF",
        "COLOR_DEFAULT_BOX": "#F3879B",
        "COLOR_DEFAULT_TEXT": "#88D3F4",
        "COLOR_DEFAULT_EDGES": "white",
        "COLOR_DEFAULT_EDGES_FONT": "white",

        "COLOR_REGULAR_KEYWORD": "#FFE5D3",
        "COLOR_OBFUSCATION_KEYWORD": "#8999c2",

        "COLOR_CRITICAL_NUM_OF_CALLS": "#F6C565",
        "COUNT_CRITICAL_NUM_OF_CALLS": 10,

        "COLOR_PROPERTY": "#ABDACC",
        "COLOR_TRIGGERED_CALL_EDGE": "#F6C565",
        "COLOR_AUTORUN_FUNCTIONS": "#F6C565",
        "COLOR_EXTERNAL_FUNCTION": "#ABDACC"
    },
    {   # terminal theme
        "COLOR_BACKGROUND": "black",
        "COLOR_DEFAULT_BOX": "#31FF00",
        "COLOR_DEFAULT_TEXT": "#31FF00",
        "COLOR_DEFAULT_EDGES": "#31FF00",
        "COLOR_DEFAULT_EDGES_FONT": "#31FF00",

        "COLOR_REGULAR_KEYWORD": "#31FF00",
        "COLOR_OBFUSCATION_KEYWORD": "#356235",

        "COLOR_CRITICAL_NUM_OF_CALLS": "#c2ffb3",
        "COUNT_CRITICAL_NUM_OF_CALLS": 10,

        "COLOR_PROPERTY": "#c2ffb3",
        "COLOR_TRIGGERED_CALL_EDGE": "#c2ffb3",
        "COLOR_AUTORUN_FUNCTIONS": "#c2ffb3",
        "COLOR_EXTERNAL_FUNCTION": "#c2ffb3"
    }
]

# set default color scheme
color_scheme = color_schemes[0]

# ****************************************************************************
# *                           Keywords Dictionaries                          *
# ****************************************************************************
# Keywords partial source: https://github.com/decalage2/oletools/blob/master/oletools/olevba.py

# Recognize keywords of automatic execution
lst_autorun = [
    'AutoExec', 'AutoOpen', 'DocumentOpen', 'AutoExit', 'AutoClose',
    'Document_Close', 'DocumentBeforeClose', 'DocumentChange', 'AutoNew',
    'Document_New', 'NewDocument', 'Document_Open', 'Document_BeforeClose',
    'Auto_Open', 'Workbook_Open', 'Workbook_Activate', 'Workbook_Deactivate', 'Auto_Close',
    'Workbook_Close', u'\w+_Painted', u'\w+_Change', u'\w+_DocumentBeforePrint',
    u'\w+_DocumentOpen', u'\w+_DocumentBeforeClose', u'\w+_DocumentBeforeSave',
    u'\w+_GotFocus', u'\w+_LostFocus', u'\w+_MouseHover', u'\w+_Resize',
    'App_WorkbookOpen', 'App_NewWorkbook', 'App_WorkbookBeforeClose', 'Workbook_BeforeClose',
    'FileSave', 'CloseWithoutSaving', 'FileOpen', 'FileClose', 'FileExit',
    'Workbook_SheetSelectionChange', 'Workbook_BeforeSave', 'FileTemplates',
    'ViewVBCode', 'ToolsMacro', 'FormatStyle', 'OpenMyMacro', 'HelpAbout',
    u'\w+_Layout', u'\w+_Painting',
    u'\w+_BeforeNavigate2', u'\w+_BeforeScriptExecute', u'\w+_DocumentComplete', u'\w+_DownloadBegin',
    u'\w+_DownloadComplete', u'\w+_FileDownload', u'\w+_NavigateComplete2', u'\w+_NavigateError',
    u'\w+_ProgressChange', u'\w+_PropertyChange', u'\w+_PropertyChange', u'\w+_StatusTextChange',
    u'\w+_TitleChange', u'\w+_MouseMove', u'\w+_MouseEnter', u'\w+_MouseLeave', u'\w+_Activate'
]

# Recognize keywords of possible malicious intent
lst_mal_case_sensetive = [
    "Open", 'Write', 'Put', 'Output', 'Print #', 'Binary', 'FileCopy',
    'CopyFile', 'Kill', 'CreateTextFile', 'ADODB.Stream', 'WriteText',
    'SaveToFile', 'vbNormal', 'vbNormalFocus', 'vbHide',
    'vbMinimizedFocus', 'vbMaximizedFocus', 'vbNormalNoFocus',
    'vbMinimizedNoFocus', u'\w+\.Run', 'MacScript',
    'popen', r'exec[lv][ep]?', 'noexit',
    'ExecutionPolicy', 'noprofile', 'command', 'EncodedCommand',
    'invoke-command', 'scriptblock', 'Invoke-Expression',
    'AuthorizationManager', 'Start-Process', 'Application\.Visible',
    'ShowWindow', 'SW_HIDE', 'MkDir', 'ActiveWorkbook.SaveAs',
    'Application.AltStartupPath', 'CreateObject', 'New-Object',
    'Windows', 'FindWindow', 'libc\.dylib', 'dylib',
    'CreateThread', 'VirtualAlloc', 'VirtualAllocEx', 'RtlMoveMemory',
    'EnumSystemLanguageGroupsW?', u'EnumDateFormats(?:W|(?:Ex){1,2})?',
    'URLDownloadToFileA',  'User-Agent',
    'Net\.WebClient', 'DownloadFile', 'DownloadString',
    'SendKeys', 'AppActivate', 'CallByName',
    'RegOpenKeyExAs', 'RegOpenKeyEx', 'RegCloseKey',
    'RegQueryValueExA', 'RegQueryValueEx', 'RegRead',
    'GetVolumeInformationA', 'GetVolumeInformation', '1824245000',
    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductId',
    'popupkiller', 'SbieDll\.dll', 'SandboxieControlWndClass',
    'currentuser', 'Schmidti', 'AccessVBOM', 'VBAWarnings',
    'ProtectedView', 'DisableAttachementsInPV', 'DisableInternetFilesInPV',
    'DisableUnsafeLocationsInPV', 'blockcontentexecutionfrominternet',
    'VBProject', 'VBComponents', 'CodeModule', 'AddFromString', 'Call', 'GetObject',
    'ExecQuery', 'GetStringValue', 'GetDWORDValue', u'ActiveDocument\.\w+', 'DOMDocument',
    'IXMLDOMElement', 'ComputerName', 'Domain', 'RegRead', 'RegWrite', '#If Mac',
    'appdata', u'WordBasic\.\w+', 'WriteLine',
    'Cells', u'Application\.\w+', 'Sleep', 'Process', u'NormalTemplate\.\w+',
    u'\w+\.Application', 'CommandBars', u'System\.\w+', "setRequestHeader", "Send", "setOption",
    "RecentFiles", "Mozilla", "UserName", "DeleteFile", "Delete", "\.Execute", "\.Content",
    "MsgBox", "\.Quit",  'Run', 'Now', 'Comments', 'PROCESSOR_ARCHITECTURE',
    'CopyFolder', 'winmgmts', 'bin\.base64', '\.CreateKey', '\.Create',
    '\.SpawnInstance_', 'Selection\.WholeStory', '\.CreateShortcut', '\.CreateFolder',
    '\.DynamicInvoke', '\.CreateInstance', '\.MSFConnect', '\.RegisterTaskDefinition',
    'Shell\.Application|ShellExecute|WScript\.Shell|Shell', '\.Load', '\.transformNode',
    'ExecuteExcel4Macro', '.\Show'
]

# Recognize attempts to hide values in form controls and properties
lst_mal_case_sensetive += ["\.caption", "\.text", "\.value", "\.ControlTipText", "\.tag",
    "\.CustomDocumentProperties", "\.AlternativeText"
]

lst_obfuscation_keywords = ['Asc', 'Mid', 'Left', 'Right', 'Tan', 'StrReverse', 'Xor',
    'ChrB', 'ChrW', 'Chr', 'CStr', 'StrConv', 'Replace', 'Int', 'Hex', 'Sqr', 'CByte',
    'Log', 'Rnd'
]

lst_mal_case_sensetive += lst_obfuscation_keywords

lst_mal_case_insensetive = [
    r'SYSTEM\\ControlSet001\\Services\\Disk\\Enum', 'VIRTUAL', 'VMWARE', 'VBOX',
    u'"[\w-_\\/]+\.(?:EXE|PIF|GADGET|MSI|MSP|MSC|VBS|VBE|VB|JSE|JS|WSF|WSC|WSH|WS|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1XML|PS1|PS2XML|PS2|PSC1|PSC2|SCF|LNK|INF|REG)"',
    'FileSystemObject', 'GetSpecialFolder', 'PowerShell', u'SELECT \* FROM \w+', 'deletefolder',
    'regsvr\.32', 'scrobj\.dll', 'cmd\.exe',
    'Environ\(\"ALLUSERSPROFILE\"\)|Environ\(\"TEMP\"\)|Environ\(\"TMP\"\)|Environ',
    'Msxml2\.XMLHTTP|Microsoft\.XMLHTTP|MSXML2\.ServerXMLHTTP|microsoft\.xmlhttp|http'
]

# ****************************************************************************
# *                             Helper Functions                             *
# ****************************************************************************

def list_files_in_dir(dir_path):
    """Creates a list of files paths
    from the files residing inside the dir_path

    Args:
        dir_path (string): Directory to list

    Returns:
        string array: list of file paths from the requested dir
    """
    file_list = []
    for dirpath, dirs, files in os.walk(dir_path):
        for filename in files:
            # ignore hidden files
            if filename.startswith("."):
                continue
            full_file_path = os.path.join(dirpath, filename)
            file_list.append(full_file_path)
    return file_list


# ****************************************************************************
# *                              Debug Functions                             *
# ****************************************************************************


def create_functions_listing(function_dict, code_output_path):
    """Creates a .bas file with a listing of all the recognized VBA functions

    Args:
        function_dict (func_dict[func_name]=func_code): Functions dictionary
        code_output_path (string): Listing output path
    """
    f_output = open(code_output_path, "w")

    for func_name in function_dict:
        # limit func_name size to display
        func_name_limited = func_name[:70]
        prefix_padding = int((77 - len(func_name_limited)) / 2) * " "
        suffix_padding = int(77 - len(prefix_padding) - len(func_name_limited)) * " "

        f_output.write("'" + "*" * 79)
        f_output.write("\n")
        f_output.write("'*" + prefix_padding + func_name_limited + suffix_padding + "*")
        f_output.write("\n")
        f_output.write("'" + "*" * 79)
        f_output.write("\n")
        f_output.write(function_dict[func_name])
        f_output.write("\n")

    f_output.close()

# ****************************************************************************
# *                             Input Functions                              *
# ****************************************************************************

def handle_input(input_path="", is_piped=False, input_content=""):
    """Reads the input and returns the content

    Args:
        input_path (string): path to input file, if applicable
        is_piped (bool): did the input come through pipe
        pipe_input_content (string): the piped input, if applicable

    Returns:
        string: VBA contents of the input
    """
    global logger
    # handle pipe read
    if is_piped:
        logger = logging.getLogger("-pipe-")
        logger.info("Reading content")
        if input_content.startswith("olevba"):
            return handle_olevba_input(input_content)
        else:
            logger.info("Reading as VBA code")
            return input_content

    # handle file read
    else:
        logger = logging.getLogger("-" + input_path + "-")
        return handle_file_input(input_path)


def handle_file_input(input_path):
    """Reads the input file and returns the content

    Args:
        input_path (string): path to input string

    Returns:
        string: contents of the input_path
    """
    logger.info("Reading file")
    with open(input_path, "r") as f_input:
        file_content = f_input.read()
        if file_content.startswith("olevba"):
            return handle_olevba_input(file_content)
        else:
            logger.info("Reading as VBA code")
            return file_content


def handle_olevba_input(file_content):
    """Parses olevba output and returns the VBA code

    Args:
        file_content (string): the content of olevba output

    Returns:
        string: only VBA code
    """
    input_vba_content = ""
    inside_data = False
    inside_code = False
    logger.info("Parsing olevba content")

    content_lines = file_content.split(LINE_SEP)

    for vba_line in content_lines:
        # ignore olevba ascii art
        if vba_line.startswith("+") or vba_line.startswith("|"):
            continue
        if vba_line.startswith("-----"):
            inside_data = False
            inside_code = False
        elif vba_line.startswith("- - - -"):
            inside_data = True
        elif inside_data and inside_code and not vba_line.startswith("(empty macro)"):
            input_vba_content += vba_line + LINE_SEP
        elif vba_line.startswith("VBA MACRO"):
            inside_code = True

    return input_vba_content


# ****************************************************************************
# *                           Processing Functions                           *
# ****************************************************************************

def vba_seperate_lines(input_vba_content):
    """Takes the full VBA input and breaks it into lines

    Args:
        input_vba_content (string): full VBA content

    Returns:
        string[]: array of VBA code lines
    """
    # make sure we normalize different line seperators
    input_vba_content = input_vba_content.replace("\r\n", LINE_SEP)

    # concat VBA lines that were split by " _"
    input_vba_content = input_vba_content.replace(" _" + LINE_SEP, " ")

    # split lines by LINE_SEP
    return input_vba_content.split(LINE_SEP)


def vba_clean_whitespace(vba_content_lines):
    """Removes unnecessary whitespace from the VBA code

    Args:
        vba_content_lines (string[]): Array of VBA code lines

    Returns:
        string[]: Array of VBA code lines, without unnecessary whitespace
    """
    result_vba_lines = []

    # process lines one by one
    for vba_line in vba_content_lines:

        # remove leading and trailing whitespace
        # & reduce multiple whitespaces into one space
        vba_line = " ".join(vba_line.split())

        # check and discard empty lines
        if vba_line == "":
            continue

        result_vba_lines.append(vba_line)

    return result_vba_lines


def vba_clean_metadata(vba_content_lines):
    """Removes unnecessary comments and metadata from the VBA code

    Args:
        vba_content_lines (string[]): VBA code lines without unnecessary whitespace

    Returns:
        string[]: VBA code lines without comments and metadata
    """
    result_vba_lines = []
    # process lines one by one
    for vba_line in vba_content_lines:
        # check and discard empty lines
        if (vba_line.startswith("Attribute") or vba_line.startswith("'")):
            continue

        # crop inline comments
        possible_inline_comment_pos = vba_line.find(" '")
        if possible_inline_comment_pos > -1:
            # look for '"' after the ', in order to find FP inline comment detections
            if vba_line.find('"', possible_inline_comment_pos) < 0:
                inline_comment_pos = possible_inline_comment_pos
                vba_line = vba_line[:inline_comment_pos]

        result_vba_lines.append(vba_line)

    return result_vba_lines


def vba_deobfuscation(vba_content_lines):
    """Solves simple obfuscation techniques

    Args:
        vba_content_lines (string[]): VBA code lines without comments, metadata or spaces

    Returns:
        string[]: clean VBA code lines with less obfuscation
    """
    result_vba_lines = []

    # process lines one by one
    for vba_line in vba_content_lines:
        # Technique #1
        # solve simple string concatenation
        # "Wsc" & "ript" would become "Wscript"
        # Reference maldoc: d050a5b4d8a990951c8a9310ed700dd6
        vba_line = vba_line.replace('" & "', "")
        result_vba_lines.append(vba_line)

    return result_vba_lines


def vba_extract_functions(vba_content_lines):
    """Seperates the input VBA code into functions

    Args:
        vba_content_lines (string[]): VBA code lines without comments, metadata or spaces

    Returns:
        dict[func_name]=func_code: Dictionary of VBA functions found
    """
    vba_func_dict = {}
    inside_function = False
    func_name = ""

    # process lines one by one
    for vba_line in vba_content_lines:
        # ****************************************************************************
        # *                   Handle External Function Declaration                   *
        # ****************************************************************************

        #   Create dummy empty function with func_name:
        #       mcvWGqJifEVHwB (URLDownloadToFileA)
        # Examples:
        #   Private Declare Function NyKQpQhtmrFfWX Lib "kernel32" Alias "lstrcmpA" (ByVal pCaller As Long,..
        #   - would become: NyKQpQhtmrFfWX (lstrcmpA) (External)
        #   Private Declare PtrSafe Function mcvWGqJifEVHwB Lib "urlmon" Alias "URLDownloadToFileA" (ByVal pfsseerwseer As Long,...
        #   - would become: mcvWGqJifEVHwB (URLDownloadToFileA) (External)

        if " Lib " in vba_line and ' Alias ' in vba_line and not inside_function:
            if " Function " in vba_line:
                func_type = " Function "
            else:
                func_type = " Sub "

            declared_func_name = vba_line[vba_line.find(func_type) + len(
                func_type):vba_line.find(" Lib ")]
            external_func_name = vba_line[
                vba_line.find(" Alias \"") + len(" Alias \""):vba_line.find(
                    "\" (",
                    vba_line.find(" Alias \"") + len(" Alias \""))]
            func_name = declared_func_name + " (" + external_func_name + ")" + " (External)"

            if "libc.dylib" in vba_line:
                func_name += "(Mac)"

            vba_func_dict[func_name] = ""
            continue

        #   Create dummy empty function with func_name that do not have Alias:
        # Examples:
        #   Public Declare PtrSafe Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As LongPtr)
        #   - would become: Sleep
        #   Public Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)
        #   - would become: Sleep

        if " Lib " in vba_line and not inside_function:
            if " Function " in vba_line:
                func_type = " Function "
            else:
                func_type = " Sub "
            func_name = vba_line[vba_line.find(func_type) + len(
                func_type):vba_line.find(" Lib ")] + " (External)"

            if "libc.dylib" in vba_line:
                func_name += "(Mac)"

            vba_func_dict[func_name] = ""
            continue

        # ****************************************************************************
        # *                    Handle Regular Function Declaration                   *
        # ****************************************************************************

        # look for function start keywords
        func_start_pos = max(vba_line.find("Sub "), vba_line.find("Function "))

        # Some macros have the word "Function" as string inside a code line.
        # This should remove FP funtions, by checking the line start
        legit_declare_line_start = False
        if vba_line.startswith("Sub") or vba_line.startswith("Function") or vba_line.startswith("Private") or vba_line.startswith("Public"):
            legit_declare_line_start = True

        is_func_end = vba_line.startswith("End Sub") or vba_line.startswith("End Function")

        # check if we've reached the end of a function
        if is_func_end:
            inside_function = False
            continue

        # check if we've hit a new function
        elif legit_declare_line_start and func_start_pos > -1:
            inside_function = True

            # extract function name from declaration
            if "Function " in vba_line:
                func_name = vba_line[(
                    func_start_pos + len("Function ")):vba_line.find("(")]
            elif "Sub " in vba_line:
                func_name = vba_line[(
                    func_start_pos + len("Sub ")):vba_line.find("(")]
            else:
                logger.error("Error parsing function name")
                sys.exit(1)

        # check if we are inside a function code
        elif inside_function:
            if func_name in vba_func_dict:
                # append code to to an existing function
                vba_func_dict[func_name] += LINE_SEP + vba_line
            else:
                # create a new function name inside the dict
                # & add the first line of code
                vba_func_dict[func_name] = vba_line

        # we are in a global section code line
        else:
            pass

    return vba_func_dict


def vba_extract_properties(vba_content_lines):
    """Find and extract the use of VBA Properties, in order to obfuscate macros

    Args:
        vba_content_lines (string[]): VBA code lines without comments, metadata or spaces

    Returns:
        dict[property_name]=property_code: Dictionary of VBA Properties found
    """

    vba_prop_dict = {}
    inside_property = False
    prop_name = ""

    # process lines one by one
    for vba_line in vba_content_lines:

        # look for property start keywords
        prop_start_pos = max(vba_line.find("Property Let "), vba_line.find("Property Get "))

        # look for property end keywords
        is_prop_end = vba_line.startswith("End Property")

        # check if we've reached the end of a property
        if is_prop_end:
            inside_property = False
            continue

        # check if we've hit a new property
        elif prop_start_pos > -1:
            inside_property = True

            # extract property name from declaration
            if "Property Let " in vba_line or "Property Get " in vba_line:
                prop_name = vba_line[(
                    prop_start_pos + len("Property Let ")):vba_line.find("(")] + " (Property)"

            else:
                logger.error("Error parsing property name")
                sys.exit(1)

        # check if we are inside a property code
        elif inside_property:
            if prop_name in vba_prop_dict:
                # append code to to an existing property
                vba_prop_dict[prop_name] += LINE_SEP + vba_line
            else:
                # create a new property name inside the dict
                # & add the first line of code
                vba_prop_dict[prop_name] = vba_line

        # we are in a global section code line
        else:
            pass

    return vba_prop_dict


# ****************************************************************************
# *                        Graph Generation Functions                        *
# ****************************************************************************

def create_call_graph(vba_func_dict):
    """Creates directed graph object (DG) from VBA functions dicitonary

    Args:
        vba_func_dict (dict[func_name]=func_code): Functions dictionary

    Returns:
        networkx.DiGraph: Directed Graph (DG) representing VBA call graph
    """
    DG = nx.DiGraph()
    for func_name in vba_func_dict:
        DG.add_node(func_name, keywords="")
    # analyze function calls
    for func_name in vba_func_dict:

        func_code = vba_func_dict[func_name]
        # split function code into tokens
        func_code_tokens = list(filter(None, re.split('[\"(, \-!?:\r\n)&=.><]+',
                                                 func_code)))
        # inside each function's code, we are looking for a function name
        for func_name1 in vba_func_dict:
            orig_func_name = func_name1
            # in case of a external function declaration,
            # we should use only the Alias from the function name:
            #   mcvWGqJifEVHwB (URLDownloadToFileA)
            #   - would become: mcvWGqJifEVHwB
            space_pos = func_name1.find(" ")
            if space_pos > -1:
                func_name1 = func_name1[:space_pos]

            for i in range(0, func_code_tokens.count(func_name1)):
                # ignore self-edges
                if func_name != func_name1:
                    # found a function call
                    if orig_func_name not in DG[func_name]:
                        DG.add_edge(func_name, orig_func_name, count=1)
                    else:
                        new_count = DG[func_name][orig_func_name]["count"] + 1
                        DG[func_name][orig_func_name]["count"] = new_count
                        DG[func_name][orig_func_name]["label"] = "x" + str(new_count)
                        if new_count >= color_scheme["COUNT_CRITICAL_NUM_OF_CALLS"]:
                            DG[func_name][orig_func_name]["fontcolor"] = color_scheme["COLOR_CRITICAL_NUM_OF_CALLS"]
    return DG


def find_keywords_in_graph(vba_func_dict, DG):
    """Find and highlight possible malicious keywords in graph

    Args:
        vba_func_dict (dict[func_name]=func_code): Functions dictionary
        DG (networkx.DiGraph): Generated directed graph

    Returns:
        networkx.DiGraph: Directed Graph with keywords highlighted in red
    """
    # analyze function calls
    for func_name in vba_func_dict:

        func_code = vba_func_dict[func_name]
        # split function code into lines
        func_code_lines = filter(None, re.split("\n", func_code))

        # handle malicious keywords
        keywords_re_sensetive = "(" + ")|(".join(lst_mal_case_sensetive) + ")"
        keywords_re_insensetive = "(" + ")|(".join(lst_mal_case_insensetive) + ")"

        # iterate over all the words in func_code and match mal_regexes
        dict_items = {}
        for token in func_code_lines:
            match_findall_sensetive = re.findall(keywords_re_sensetive, token)
            match_findall_insensetive = re.findall(keywords_re_insensetive, token, re.IGNORECASE)
            match_findall = match_findall_sensetive + match_findall_insensetive
            if match_findall:
                for match in match_findall:
                    match_list = list(match)

                    # use dictionary dict_items to count occurances of keywords
                    for list_item in match_list:
                        if list_item != "":
                            if list_item not in dict_items:
                                dict_items[list_item] = 1
                            else:
                                dict_items[list_item] = dict_items[list_item] + 1

        # add keywords to graph
        for dic_key in dict_items:
            if dic_key in lst_obfuscation_keywords:
                keyword_color = color_scheme["COLOR_OBFUSCATION_KEYWORD"]
            else:
                keyword_color = color_scheme["COLOR_REGULAR_KEYWORD"]

            keyword_count = dict_items[dic_key]
            if DG.nodes[func_name]["keywords"] != "":
                DG.nodes[func_name]["keywords"] = DG.nodes[func_name]["keywords"] + ","

            DG.nodes[func_name]["keywords"] = DG.nodes[func_name]["keywords"] + "<font color='" + keyword_color + "'>" + dic_key + "[" + str(keyword_count) + "]" + "</font>"

        # handle autorun keywords
        keywords_re = "(" + ")|(".join(lst_autorun) + ")"
        if re.match(keywords_re, func_name, re.IGNORECASE):
            DG.nodes[func_name]["color"] = color_scheme["COLOR_AUTORUN_FUNCTIONS"]
    return DG


def find_change_flow(vba_func_dict, DG):
    """Finds alternative macros call flow that is utilized by malicious macros:
    A _Change event is created for an object, and then the object text is changed using code.
    This creates a dummy call flow without explicitly calling a function.

    Args:
        vba_func_dict (dict[func_name]=func_code): Functions dictionary
        DG (networkx.DiGraph): Generated directed graph

    Returns:
        networkx.DiGraph: Directed Graph with highlighted Change triggers
    """
    # Find all the all the objects that have a _Change event
    # like TextBox1_Change
    changed_objects = []
    for func_name in vba_func_dict:
        if "_Change" in func_name:
            changed_object = func_name.replace("_Change", "")
            changed_objects.append(changed_object)

    # Find  pieces of code that assign to an object, which would
    # cause a _Change event Trigger
    for func_name in vba_func_dict:
        func_code = vba_func_dict[func_name]
        # split function code into lines
        func_code_lines = filter(None, re.split("\n", func_code))
        for func_line in func_code_lines:
            for changed_object in changed_objects:
                # look for .[changed_object] pattern, followd by "="
                found_loc = func_line.find("." + changed_object)
                if found_loc > -1:
                    if func_line.find("=", found_loc) > -1:
                        # we found object with Change event that was assigned a value

                        # show this connection as a function call
                        DG.add_edge(func_name, changed_object + "_Change", label="Triggers", fontcolor=color_scheme["COLOR_TRIGGERED_CALL_EDGE"])
    return DG


def design_graph_dot(DG):
    """Select the design of regular graph nodes (colors and content)

    Args:
        DG (networkx.DiGraph): Generated directed graph

    Returns:
        networkx.DiGraph: Directed Graph with node design and content
    """
    # locate malicious keywords
    for key in DG:
        if "color" not in DG.nodes[key]:
            DG.nodes[key]["color"] = color_scheme["COLOR_DEFAULT_BOX"]
        DG.nodes[key]["fontcolor"] = color_scheme["COLOR_DEFAULT_TEXT"]

        # handle functions without keywords - create box shape
        if DG.nodes[key]["keywords"] == "":
            DG.nodes[key]['shape'] = "box"

            # color external functions
            if "(External)" in key:
                DG.nodes[key]["color"] = color_scheme["COLOR_EXTERNAL_FUNCTION"]

        # handle functions with keywords - create html table
        else:
            DG.nodes[key]["shape"] = "plaintext"
            DG.nodes[key]["margin"] = 0

            header = key
            content = DG.nodes[key]["keywords"]
            DG.nodes[key]["label"] = r"<<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\"><TR><TD><FONT FACE=\"Courier\">" + header + r"</FONT></TD></TR><TR><TD><FONT FACE=\"Courier Bold\">" + content + r"</FONT></TD></TR></TABLE>>"
            # fix a bug in DOT generation
            DG.nodes[key]["keywords"] = ""

            # color VBA properties
            if "(Property)" in key:
                DG.nodes[key]["color"] = color_scheme["COLOR_PROPERTY"]

    # graph background color
    DG.add_node("graph", bgcolor=color_scheme["COLOR_BACKGROUND"])
    DG.add_node("edge", color=color_scheme["COLOR_DEFAULT_EDGES"], fontcolor=color_scheme["COLOR_DEFAULT_EDGES_FONT"])


    return DG


def fix_dot_output(str_dot):
    """ Make changes to NX write_dot output
    Args:
        str_dot (string): output of NX write_dot function
    """

    # change function names that collide with protected DOT keywords
    # reference: https://www.graphviz.org/doc/info/lang.html
    dot_keywords = ["node", "edge", "graph", "digraph", "subgraph", "strict"]

    str_dot_lines = str_dot.split("\n")

    new_str_dot = ""
    # iterate over all the dot file lines and change function names which
    # are reserved DOT keywords
    for cur_line in str_dot_lines:
        new_str_dot_line = cur_line

        pass_line = False
        # check if we are in the first disgraph declaration line
        # example: strict digraph  {
        if "digraph  " in cur_line:
            pass_line = True

        # check if we are in a graph declaration line
        # example: graph [bgcolor="#6075AF"];
        if "bgcolor=" in cur_line:
            pass_line = True

        # check if we are in a generic edge declaration line
        # example: edge [color=white, fontcolor=white];
        if "edge" in cur_line and "keywords" not in cur_line and "count" not in cur_line:
            pass_line = True

        # if we are not in a reserved keyword line, and
        # if we find a reserved keyword in cur line -> add underscore to this function name
        if not pass_line:
            for dot_keyword in dot_keywords:
                re_result = re.search("(?i)" + dot_keyword + " ", cur_line)
                if re_result:
                    found_keyword_with_space = re_result.group()
                    found_keyword = found_keyword_with_space[:-1]
                    replace_keyword_with = found_keyword + "_" + " "
                    new_str_dot_line = new_str_dot_line.replace(found_keyword_with_space, replace_keyword_with)

        new_str_dot += new_str_dot_line + "\n"

    return new_str_dot


def vba2graph_from_vba_object(filepath):
    """ vba2graph as library
    Args:
        filepath (string): path to file
    """
    logger.info("Extracting macros from file")
    if HAVE_OLETOOLS:
        try:
            vba = VBA_Parser(filepath)
        except Exception as e:
            return False
    full_vba_code = ""
    for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
        full_vba_code += 'VBA MACRO %s \n' % vba_filename
        full_vba_code += '- '*39 + '\n'
        # Temporary workaround. Change when oletools 0.56 will be released.
        if isinstance(vba_code, bytes):
            vba_code = vba_code.decode('utf8', errors='replace')
        full_vba_code += vba_code
    vba.close()
    if full_vba_code:
        input_vba_content = handle_olevba_input(full_vba_code)
        return input_vba_content
    return False

def vba2graph_gen(input_vba_content, output_folder="output", input_file_name="vba2graph", color_scheme=color_scheme):

    """ Generage graph from processed vba macros
    Args:
        input_vba_content (string): data generated by handle_olevba_input
        output_folder (string): output folder
        input_file_name (string): base filename
        color_scheme (int): color scheme number [0, 1, 2, 3] (default: 0 - B&W)
    """

    # ****************************************************************************
    # *                               Process Input                              *
    # ****************************************************************************

    vba_content_lines = vba_seperate_lines(input_vba_content)
    vba_content_lines_no_whitespace = vba_clean_whitespace(vba_content_lines)
    vba_content_lines_no_metadata = vba_clean_metadata(
        vba_content_lines_no_whitespace)
    vba_content_deobfuscated = vba_deobfuscation(vba_content_lines_no_metadata)
    vba_func_dict = vba_extract_functions(vba_content_deobfuscated)
    vba_prop_dict = vba_extract_properties(vba_content_lines_no_metadata)

    # treat properties like functions and merge both dictionaries
    vba_func_dict = dict(vba_func_dict.items() | vba_prop_dict.items())

    ##############################################################################
    # at this point, vba_func_dict should contain the code of functions and
    # properties, without comments or whitespaces.
    ##############################################################################

    # ****************************************************************************
    # *                              Generate Graph                              *
    # ****************************************************************************

    DG = create_call_graph(vba_func_dict)
    DG = find_keywords_in_graph(vba_func_dict, DG)
    DG = find_change_flow(vba_func_dict, DG)
    DG = design_graph_dot(DG)

    # ****************************************************************************
    # *                           Generate Output Files                          *
    # ****************************************************************************

    logger.info("Generating output files")

    ############################################
    # Generate functions listing for debugging #
    ############################################

    bas_folder = output_folder + os.sep + "bas"
    try:
        os.makedirs(bas_folder)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            logger.error("Error creating debugging output folder")
    code_output_path = bas_folder + os.sep + input_file_name + '.bas'
    create_functions_listing(vba_func_dict, code_output_path)

    ################################
    # Generate DOT file from graph #
    ################################
    dot_folder = output_folder + os.sep + "dot"
    try:
        os.makedirs(dot_folder)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            logger.error("Error creating DOT output folder")
    dot_output_path = dot_folder + os.sep + input_file_name + '.dot'

    # redirect NetworkX write_dot output to StringIO for further manipulation
    str_io_dot = StringIO()
    write_dot(DG, str_io_dot)
    str_dot = str_io_dot.getvalue().replace('\\', '')
    str_io_dot.close()

    # check if our DOT file is broken (one of the funciton names was reserved keyword)
    str_dot = fix_dot_output(str_dot)

    with open(dot_output_path, 'wb') as the_file:
        the_file.write(str_dot.encode("utf-8", errors="ignore"))

    ##############################
    # Generate PNG file from DOT #
    ##############################
    png_folder = output_folder + os.sep + "png"
    try:
        os.makedirs(png_folder)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            logger.error("Error creating PNG output folder")
    png_output_path = png_folder + os.sep + input_file_name + '.png'
    process = Popen(['dot', '-Tpng', dot_output_path, '-o', png_output_path])
    process.wait()

    ##############################
    # Generate SVG file from DOT #
    ##############################
    svg_folder = output_folder + os.sep + "svg"
    try:
        os.makedirs(svg_folder)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            logger.error("Error creating PNG output folder")
    svg_output_path = svg_folder + os.sep + input_file_name + '.svg'
    process = Popen(['dot', '-Tsvg', dot_output_path, '-o', svg_output_path])
    process.wait()

def main():
    global color_scheme
    # set default output folder
    output_folder = "output"
    input_file_name = "vba2graph"

    # ****************************************************************************
    # *                              Argument Parser                             *
    # ****************************************************************************

    input_vba_content = ""

    # check if the input was sent though the pipe
    is_pipe = not os.isatty(sys.stdin.fileno())

    # argument parser would be modified, depended on if we have input in the pipe
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", required=False, help="output folder (default: \"output\")")
    ap.add_argument("-c", "--colors", required=False, type=int, choices=[0, 1, 2, 3], help="color scheme number [0, 1, 2, 3] (default: 0 - B&W)")

    if is_pipe:
        input_content = sys.stdin.read()
        input_file_name = "piped_file"
        input_vba_content = handle_input(input_path="", is_piped=True, input_content=input_content)
        cmd_args = vars(ap.parse_args())

    else:
        input_group = ap.add_mutually_exclusive_group(required=True)
        input_group.add_argument("-i", "--input", required=False, default=False, help="olevba generated file or .bas file")
        input_group.add_argument("-f", "--file", required=False, default=False, help="Office file with macros")

        cmd_args = vars(ap.parse_args())

        macro_file = False
        if cmd_args.get("input", False):
            file_path = cmd_args.get("input", False)
        elif cmd_args.get("file", False):
            file_path = cmd_args.get("file", False)
            macro_file = True

        # handle files
        if os.path.isfile(file_path):
            if macro_file is False:
                input_vba_content = handle_input(file_path, is_piped=False)
            else:
                input_vba_content = vba2graph_from_vba_object(file_path)

        # handle wrong input
        else:
            logger.error("Invalid input path")
            sys.exit(1)

        input_file_name = os.path.basename(file_path)

    # set selected color scheme
    selected_color_scheme = cmd_args["colors"]
    if selected_color_scheme is not None:
        color_scheme = color_schemes[selected_color_scheme]

    # set selected output folder
    selected_output_folder = cmd_args["output"]
    if selected_output_folder is not None:
        output_folder = cmd_args["output"]

    vba2graph_gen(input_vba_content, output_folder, input_file_name, color_scheme)


if __name__ == '__main__' and __package__ is None:
    logging.basicConfig(level=logging.INFO)
    main()
