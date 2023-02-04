# rule format

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example rule used by capa:

```yaml
rule:
  meta:
    name: hash data with CRC32
    namespace: data-manipulation/checksum/crc32
    authors:
      - moritz.raabe@mandiant.com
    scope: function
    mbc:
      - Data::Checksum::CRC32 [C0032.001]
    examples:
      - 2D3EDC218A90F03089CC01715A9F047F:0x403CBD
      - 7D28CB106CB54876B2A5C111724A07CD:0x402350  # RtlComputeCrc32
      - 7EFF498DE13CC734262F87E6B3EF38AB:0x100084A6
  features:
    - or:
      - and:
        - mnemonic: shr
        - or:
          - number: 0xEDB88320
          - bytes: 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E = crc32_tab
        - number: 8
        - characteristic: nzxor
      - and:
        - number: 0x8320
        - number: 0xEDB8
        - characteristic: nzxor
      - api: RtlComputeCrc32
```

This document defines the available structures and features that you can use as you write capa rules.
We'll start at the high level structure and then dig into the logic structures and features that capa supports.

### table of contents 
- [rule format](#rule-format)
  - [yaml](#yaml)
  - [meta block](#meta-block)
  - [features block](#features-block)
- [extracted features](#extracted-features)
  - [characteristic](#characteristic)
  - [instruction features](#function-features)
    - [namespace](#namespace)
    - [class](#class)
    - [api](#api)
    - [number](#number)
    - [string and substring](#string-and-substring)
    - [bytes](#bytes)
    - [offset](#offset)
    - [mnemonic](#mnemonic)
    - [operand](#operand)
  - [basic block features](#basic-block-features)
  - [function features](#function-features)
  - [file features](#file-features)
    - [string and substring](#file-string-and-substring)
    - [export](#export)
    - [import](#import)
    - [section](#section)
    - [function-name](#function-name)
    - [namespace](#namespace)
    - [class](#class)
  - [global features](#global-features)
    - [os](#os)
    - [arch](#arch)
    - [format](#format)
  - [counting](#counting)
  - [matching prior rule matches and namespaces](#matching-prior-rule-matches-and-namespaces)
  - [descriptions](#descriptions)


## yaml

Rules are YAML files that follow a certain schema.
You should be able to use any YAML editor/syntax highlighting to assist you.

Once you have a draft rule, you can use the [linter](https://github.com/mandiant/capa/blob/master/scripts/lint.py) 
 to check that your rule adheres to best practices.
Then, you should use the [formatter](https://github.com/mandiant/capa/blob/master/scripts/capafmt.py)
 to reformat the rule into a style that's consistent with all other capa rules.
This way, you don't have to worry about the width of indentation while you're focused on logic.
We run the linter and formatter in our Continuous Integration setup so that we can be sure all rules are consistent.

Within the YAML document, the top-level element is a dictionary named `rule`
 with two required children dictionaries:
`meta` and `features`.
There are no other children.

```yaml
rule:
  meta: ...
  features: ...
```

## meta block

The meta block contains metadata that identifies the rule, groups the technique, 
and provides references to additional documentation.
Here's an example:

```yaml
meta:
  name: packed with UPX
  namespace: anti-analysis/packer/upx
  authors:
      - william.ballenthin@mandiant.com
  description: the sample appears to be packed with UPX
  scope: file
  att&ck:
    - Defense Evasion::Obfuscated Files or Information [T1027.002]
  mbc:
      - Anti-Static Analysis::Software Packing
  examples:
    - CD2CBA9E6313E8DF2C1273593E649682
    - Practical Malware Analysis Lab 01-02.exe_:0x0401000
```


Here are the common fields:

  - `name` is required. This string should uniquely identify the rule. More details below.

  - `namespace` is required when a rule describes a technique, and helps us group rules into buckets. More details below.

  - `authors` is a list of names or handles of the rule authors.
  
  - `description` is optional text that describes the intent or interpretation of the rule.

  - `scope` indicates to which feature set this rule applies.
    Here are the legal values:
    - **`file`**: matches features across the whole file.
    - **`function`** (default): match features within each function.
    - **`basic block`**: matches features within each basic block.
      This is used to achieve locality in rules (for example for parameters of a function).
    - **`instruction`**: matches features found at a single instruction.
      This is great to identify structure access or comparisons against magic constants.
      
  - `att&ck` is an optional list of [ATT&CK framework](https://attack.mitre.org/) techniques that the rule implies, like 
`Discovery::Query Registry [T1012]` or `Persistence::Create or Modify System Process::Windows Service [T1543.003]`.
These tags are used to derive the ATT&CK mapping for the sample when the report gets rendered.

  - `mbc` is an optional list of [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown) techniques that the rule implies,
like the ATT&CK list.

  - `maec/malware-category` is required when the rule describes a role, such as `dropper` or `backdoor`.

  - `maec/malware-family` is required when the rule describes a malware family, such as `PlugX` or `Beacon`.
  
  - `maec/analysis-conclusion` is required when the rule describes a disposition, such as `benign` or `malicious`.

  - `examples` is a *required* list of references to samples that the rule should match.
The linter verifies that each rule correctly fires on each sample referenced in a rule's `examples` list.
These example files are stored in the [github.com/mandiant/capa-testfiles](https://github.com/mandiant/capa-testfiles) repository.
`function` and `basic block` scope rules must contain offsets to the respective match locations using the format `<sample name>:<function or basic block offset>`.

  - `references` A list of related information found in a book, article, blog post, etc.

Other fields are not allowed, and the linter will complain about them.

### rule name

The `rule.meta.name` uniquely identifies a rule.
It can be referenced in other rules, so if you change a rule name, be sure to search for cross references.

By convention, the rule name should complete one of the following sentences:
  - "The program/function may..."
  - "The program was..."

To focus rule names we try to omit articles (the/a/an).
For example, prefer `make HTTP request` over `make an HTTP request`.

When the rule describes a specific means to implement a technique, this is typically specified by "via XYZ".
For example, `make HTTP request via WinInet` or `make HTTP request via libcurl`.

When the rule describes a specific programming language or run time, this is typically specified by "in ABC".
  
Therefore, these are good rule names:
  - (The function may) "**make HTTP request via WinInet**"
  - (The function may) "**encrypt data using RC4 via WinCrypt**"
  - (The program was)  "**compiled by MSVC**"
  - (The program may)  "**capture screenshot in Go**"
  
...and, these are bad rule names:
  - "UPX"
  - "encryption with OpenSSL"

### rule namespace

The rule namespace helps us group related rules together.
You'll notice that the file system layout of the rule files matches the namespaces that they contain.
Furthermore, output from capa is ordered by namespace, so all `communication` matches render next to one another.

Namespaces are hierarchical, so the children of a namespace encodes its specific techniques.
In a few words each, the top level namespaces are:

  - [anti-analysis](https://github.com/mandiant/capa-rules/tree/master/anti-analysis/) - packing, obfuscation, anti-X, etc.
  - [c2](https://github.com/mandiant/capa-rules/tree/master/c2/) - commands that may be issued by a controller, such as interactive shell or file transfer
  - [collection](https://github.com/mandiant/capa-rules/tree/master/collection/) - data that may be enumerated and collected for exfiltration
  - [communication](https://github.com/mandiant/capa-rules/tree/master/communication/) - HTTP, TCP, etc.
  - [compiler](https://github.com/mandiant/capa-rules/tree/master/compiler/) - detection of build environments, such as MSVC, Delphi, or AutoIT
  - [data-manipulation](https://github.com/mandiant/capa-rules/tree/master/data-manipulation/) - encryption, hashing, etc.
  - [executable](https://github.com/mandiant/capa-rules/tree/master/executable/) - characteristics of the executable, such as PE sections or debug info
  - [host-interaction](https://github.com/mandiant/capa-rules/tree/master/host-interaction/) - access or manipulation of system resources, like processes or the Registry
  - [impact](https://github.com/mandiant/capa-rules/tree/master/impact/) - end goal
  - [internal](https://github.com/mandiant/capa-rules/tree/master/internal/) - used internally by capa to guide analysis
  - [lib](https://github.com/mandiant/capa-rules/tree/master/lib/) - building blocks to create other rules
  - [linking](https://github.com/mandiant/capa-rules/tree/master/linking/) - detection of dependencies, such as OpenSSL or Zlib
  - [load-code](https://github.com/mandiant/capa-rules/tree/master/load-code/) - runtime load and execution of code, such as embedded PE or shellcode
  - [malware-family](https://github.com/mandiant/capa-rules/tree/master/malware-family/) - detection of malware families
  - [nursery](https://github.com/mandiant/capa-rules/tree/master/nursery/) - staging ground for rules that are not quite polished
  - [persistence](https://github.com/mandiant/capa-rules/tree/master/persistence/) - all sorts of ways to maintain access
  - [runtime](https://github.com/mandiant/capa-rules/tree/master/runtime/) - detection of language runtimes, such as the .NET platform or Go
  - [targeting](https://github.com/mandiant/capa-rules/tree/master/targeting/) - special handling of systems, such as ATM machines
  
We can easily add more top level namespaces as the need arises. 

All namespaces components should be nouns that describe the capability concept, except for possibly the last component.
For example, here's a namespace subtree that describes capabilities for interacting with system hardware:

```
host-interaction/hardware
host-interaction/hardware/storage
host-interaction/hardware/memory
host-interaction/hardware/cpu
host-interaction/hardware/mouse
host-interaction/hardware/keyboard
host-interaction/hardware/keyboard/layout
host-interaction/hardware/cdrom
```

When there are many common operations for a namespace, 
and many ways to implement each operation, 
then the final path component may be a verb that describes the operation.
For example, there are *many* ways to do multiple file operations on Windows, so the namespace subtree looks like:

```
rules/host-interaction/file-system
rules/host-interaction/file-system/create
rules/host-interaction/file-system/delete
rules/host-interaction/file-system/write
rules/host-interaction/file-system/copy
rules/host-interaction/file-system/exists
rules/host-interaction/file-system/read
rules/host-interaction/file-system/list
```

The depth of the namespace tree is not limited, but we've found that 3-4 components is typically sufficient.

## features block

This section declares logical statements about the features that must exist for the rule to match.

There are five structural expressions that may be nested:
  - `and` - all of the children expressions must match
  - `or` - match at least one of the children
  - `not` - match when the child expression does not
  - `N or more` - match at least `N` or more of the children
    - `optional` is an alias for `0 or more`, which is useful for documenting related features. See [write-file.yml](/host-interaction/file-system/write/write-file.yml) for an example.

To add context to a statement, you can add *one* nested description entry in the form `- description: DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

For example, consider the following rule:

```yaml
      - and:
        - description: core of CRC-32 algorithm
        - mnemonic: shr
        - number: 0xEDB88320
        - number: 8
        - characteristic: nzxor
      - api: RtlComputeCrc32
```

For this to match, the function must:
  - contain an `shr` instruction, and
  - reference the immediate constant `0xEDB88320`, which some may recognize as related to the CRC32 checksum, and
  - reference the number `8`, and
  - have an unusual feature, in this case, contain a non-zeroing XOR instruction
If only one of these features is found in a function, the rule will not match.


# extracted features

capa extracts features from multiple scopes, starting with the most specific (instruction) and working towards the most general:

| scope       | best for...                                                                              |
|-------------|------------------------------------------------------------------------------------------|
| instruction | specific combinations of mnemonics, operands, constants, etc. to find magic values       |
| basic block | closely related instructions, such as structure access or function call arguments        |
| function    | collections of API calls, constants, etc. that suggest complete capabilities             |
| file        | high level conclusions, like encryptor, backdoor, or statically linked with some library |
| (global)    | the features available at every scope, like arch or OS                                   |

In general, capa collects and merges the features from lower scopes into higher scopes;
for example, features extracted from individual instructions are merged into the function scope that contains the instructions.
This way, you can use the match results against instructions ("the constant X is for crypto algorithm Y") to recognize function-level capabilities ("crypto function Z").


### characteristic

Characteristics are features that are extracted by the analysis engine.
They are one-off features that seem interesting to the authors.

For example, the `characteristic: nzxor` feature describes non-zeroing XOR instructions.

| characteristic                       | scope                              | description |
|--------------------------------------|------------------------------------|-------------|
| `characteristic: embedded pe`        | file                               | (XOR encoded) embedded PE files. |
| `characteristic: mixed mode` | file | File contains both managed and unmanaged (native) code, often seen in .NET |
| `characteristic: loop`               | function                           | Function contains a loop. |
| `characteristic: recursive call`     | function                           | Function is recursive. |
| `characteristic: calls from`         | function                           | There are unique calls from this function. Best used like: `count(characteristic(calls from)): 3 or more` |
| `characteristic: calls to`           | function                           | There are unique calls to this function. Best used like: `count(characteristic(calls to)): 3 or more` |
| `characteristic: tight loop`         | basic block, function              | A tight loop where a basic block branches to itself. |
| `characteristic: stack string`       | basic block, function              | There is a sequence of instructions that looks like stack string construction. |
| `characteristic: nzxor`              | instruction, basic block, function | Non-zeroing XOR instruction |
| `characteristic: peb access`         | instruction, basic block, function | Access to the process environment block (PEB), e.g. via fs:[30h], gs:[60h] |
| `characteristic: fs access`          | instruction, basic block, function | Access to memory via the `fs` segment. |
| `characteristic: gs access`          | instruction, basic block, function | Access to memory via the `gs` segment. |
| `characteristic: cross section flow` | instruction, basic block, function | Function contains a call/jump to a different section. This is commonly seen in unpacking stubs. |
| `characteristic: indirect call`      | instruction, basic block, function | Indirect call instruction; for example, `call edx` or `call qword ptr [rsp+78h]`. |
| `characteristic: call $+5`           | instruction, basic block, function | Call just past the current instruction. |
| `characteristic: unmanaged call` | instruction, basic block, function | Function contains a call from managed code to unmanaged (native) code, often seen in .NET |

## instruction features

Instruction features stem from individual instructions, such as mnemonics, string references, or function calls.
The following features are relevant at this scope and above:

  - [namespace](#namespace)
  - [class](#class)
  - [api](#api)
  - [number](#number)
  - [string and substring](#string-and-substring)
  - [bytes](#bytes)
  - [offset](#offset)
  - [mnemonic](#mnemonic)
  - [operand](#operand)

Also, the following [characteristics](#characteristic) are relevant at this scope and above:
  - `nzxor`
  - `peb access`
  - `fs access`
  - `gs access`
  - `cross section flow`
  - `indirect call`
  - `call $+5`
  - `unmanaged call`

### namespace
A named namespace used by the logic of the program.

The parameter is a string describing the namespace name, specified like `namespace` or `namespace.nestednamespace`.

Example:

    namespace: System.IO
    namespace: System.Net

### class
A named class used by the logic of the program. This must include the class's namespace if recoverable.

The parameter is a string describing the class, specified like `namespace.class` or `namespace.nestednamespace.class`.

Example:

    class: System.IO.File
    class: System.Net.WebResponse

### api
A call to a named function, probably an import,
though possibly a local function (like `malloc`) extracted via function signature matching like FLIRT.

The parameter is a string describing the function name, specified like  `functionname`, `module.functionname`, or `namespace.class::functioname`.

Windows API functions that take string arguments come in two API versions. For example, `CreateProcessA` takes ANSI strings and `CreateProcessW` takes Unicode strings. capa extracts these API features both with and without the suffix character `A` or `W`. That means you can write a rule to match on both APIs using the base name. If you want to match a specific API version, you can include the suffix.

Example:

    api: kernel32.CreateFile  # matches both Ansi (CreateFileA) and Unicode (CreateFileW) versions
    api: CreateFile
    api: GetEnvironmentVariableW  # only matches on Unicode version
    api: System.IO.File::Delete
    api: System.Net.WebResponse::GetResponseStream

### number
A number used by the logic of the program.
This should not be a stack or structure offset.
For example, a crypto constant.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format.

To help humans understand the meaning of a number, such that the constant `0x40` means `PAGE_EXECUTE_READWRITE`, you may provide a description alongside the definition.
Use the inline syntax (preferred) by ending the line with ` = DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

Examples:

    number: 16
    number: 0x10
    number: 0x40 = PAGE_EXECUTE_READWRITE

Note that capa treats all numbers as unsigned values. A negative number is not a valid feature value.
To match a negative number you may specify its two's complement representation. For example, `0xFFFFFFF0` (`-2`) in a 32-bit file.

If the number is only relevant on a particular architecture, don't hesitate to use a pattern like:

```yml
- and:
  - arch: i386
  - number: 4 = size of pointer
```

### string and substring
A string referenced by the logic of the program.
This is probably a pointer to an ASCII or Unicode string.
This could also be an obfuscated string, for example a stack string.

The parameter is a string describing the string.
This can be the verbatim value or a regex matching the string.

Verbatim values must be surrounded by double quotes and special characters must be escaped.

A special character is one of:
  - a backslash, which should be represented as `string: "\\"`
  - a newline or other non-space whitespace (e.g. tab, CR, LF, etc), which should be represented like `string: "\n"`
  - a double quote, which should be represented as `string: "\""`

capa only matches on the verbatim string, e.g. `"Mozilla"` does NOT match on `"User-Agent: Mozilla/5.0"`. 
To match verbatim substrings with leading/trailing wildcards, use a substring feature, e.g. `substring: "Mozilla"`.
For more complex patterns, use the regex syntax described below.

Regexes should be surrounded with `/` characters. 
By default, capa uses case-sensitive matching and assumes leading and trailing wildcards.
To perform case-insensitive matching append an `i`. To anchor the regex at the start or end of a string, use `^` and/or `$`.
As an example `/mozilla/i` matches on `"User-Agent: Mozilla/5.0"`.

To add context to a string, use the two-line syntax `...description: DESCRIPTION STRING` shown below. The inline syntax is not supported here.
See the [description section](#descriptions) for more details.

Examples:

```yaml
- string: "Firefox 64.0"
- string: "Hostname:\t\t\t%s\nIP adress:\t\t\t%s\nOS version:\t\t\t%s\n"
- string: "This program cannot be run in DOS mode."
  description: MS-DOS stub message
- string: "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
  description: CLSID_CMSTPLUA
- string: /SELECT.*FROM.*WHERE/
  description: SQL WHERE Clause
- string: /Hardware\\Description\\System\\CentralProcessor/i
- substring: "CurrentVersion"
```

Note that regex and substring matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### bytes
A sequence of bytes referenced by the logic of the program. 
The provided sequence must match from the beginning of the referenced bytes and be no more than `0x100` bytes.
The parameter is a sequence of hexadecimal bytes.
To help humans understand the meaning of the bytes sequence, you may provide a description.
For this use the inline syntax by appending your ` = DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

The example below illustrates byte matching given a COM CLSID pushed onto the stack prior to a call to `CoCreateInstance`.

Disassembly:

    push    offset iid_004118d4_IShellLinkA ; riid
    push    1               ; dwClsContext
    push    0               ; pUnkOuter
    push    offset clsid_004118c4_ShellLink ; rclsid
    call    ds:CoCreateInstance

Example rule elements:

    bytes: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = CLSID_ShellLink
    bytes: EE 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = IID_IShellLink

### offset
A structure offset referenced by the logic of the program.
This should not be a stack offset.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format. Negative offsets are supported.
An offset can be followed by an optional description.

If the number is only relevant for a particular architecture, then you can use one of the architecture flavors: `number/x32` or `number/x64`.

Examples:

```yaml
offset: 0xC
offset: 0x14 = PEB.BeingDebugged
offset: -0x4
```

If the offset is only relevant on a particular architecture (such as 32- or 64-bit Intel), don't hesitate to use a pattern like:

```yml
- and:
  - arch: i386
  - offset: 0xC = offset to linked list head
```

### mnemonic

An instruction mnemonic found in the given function.

The parameter is a string containing the mnemonic.

Examples:

    mnemonic: xor
    mnemonic: shl
    

### operand

Number and offset values for specific operand indices.
Use these features when you want to specify the flow of data from a source/destination, like move from a structure or compare against a constant.

Examples:

    operand[0].number: 0x10
    operand[1].offset: 0x2C

## basic block features
Basic block features stem from combinations of features from the instruction scope that are found within the same basic block.

Also, the following [characteristics](#characteristic) are relevant at this scope and above:
  - `tight loop`
  - `stack string`


## function features
Function features stem from combinations of features from the instruction and basic block scopes that are found within the same function.

Also, the following [characteristics](#characteristic) are relevant at this scope and above:
  - `loop`
  - `recursive call`
  - `calls from`
  - `calls to`


## file features

File features stem from the file structure, i.e. PE structure or the raw file data.
The following features are supported at this scope:

  - [string and substring](#file-string-and-substring)
  - [export](#export)
  - [import](#import)
  - [section](#section)
  - [function-name](#function-name)
  - [namespace](#namespace)
  - [class](#class)


### file string and substring
An ASCII or UTF-16 LE string present in the file.

The parameter is a string describing the string.
This can be the verbatim value, a verbatim substring, or a regex matching the string and should use the same formatting used for
[string](#string) features.

Examples:

    string: "Z:\\Dev\\dropper\\dropper.pdb"
    string: "[ENTER]"
    string: /.*VBox.*/
    string: /.*Software\\Microsoft\Windows\\CurrentVersion\\Run.*/i
    substring: "CurrentVersion"

Note that regex and substring matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### export

The name of a routine exported from a shared library.

Examples:

    export: InstallA

### import

The name of a routine imported from a shared library.

Examples:

    import: kernel32.WinExec
    import: WinExec           # wildcard module name
    import: kernel32.#22      # by ordinal
    import: System.IO.File::Exists

### function-name

The name of a recognized statically-linked library, such as recovered via FLIRT, or a name extracted from information contained in the file, such as .NET metadata.
This lets you write rules describing functionality from third party libraries, such as "encrypts data with AES via CryptoPP".

Examples:

    function-name: "?FillEncTable@Base@Rijndael@CryptoPP@@KAXXZ"
    function-name: Malware.Backdoor::Beacon

### section

The name of a section in a structured file.

Examples:

    section: .rsrc


## global features

Global features are extracted at all scopes.
These are features that may be useful to both disassembly and file structure interpretation, such as the targeted OS or architecture.
The following features are supported at this scope:

  - [os](#os)
  - [arch](#arch)
  - [format](#format)

### os

The name of the OS on which the sample runs. This is determined via heuristics applied to the file format (e.g. PE files are for Windows, header fields and notes sections in ELF files indicate Linux/*BSD/etc.).
This lets you group logic that should only be found on some platforms, such as Windows APIs are found only in Windows exectuables.

Examples:

```yml
- or:
  - and:
    description: Windows-specific APIs
    os: windows
    api: CreateFile

  - and:
    description: POSIX-specific APIs
    or:
      - os: linux
      - os: macos 
      - ...
    api: fopen
```

Valid OSes:
  - `windows`
  - `linux`
  - `macos`
  - `hpux`
  - `netbsd`
  - `hurd`
  - `86open`
  - `solaris`
  - `aix`
  - `irix`
  - `freebsd`
  - `tru64`
  - `modesto`
  - `openbsd`
  - `openvms`
  - `nsk`
  - `aros`
  - `fenixos`
  - `cloud`
  - `syllable`
  - `nacl`

### arch

The name of the CPU architecture on which the sample runs.
This lets you group logic that should only be found on some architectures, such as assembly instructions for Intel CPUs.

Valid architectures:
  - `i386` Intel 32-bit
  - `amd64` Intel 64-bit

Note: today capa only explicitly supports Intel architectures (`i386` and `amd64`). 
Therefore, most rules assume Intel instructions and mnemonics.
You don't have to explicitly include this condition in your rules:

```yml
- and:
  - mnem: lea
  - or:
    # this block is not necessary!
    - arch: i386
    - arch: amd64
```

However, this can be useful if you have groups of many architecture-specific offsets, such as:

```yml
- or:
  - and:
    - description: 32-bit structure fields
    - arch: i386
    - offset: 0x12
    - offset: 0x1C
    - offset: 0x20
  - and:
    - description: 64-bit structure fields
    - arch: amd64
    - offset: 0x28
    - offset: 0x30
    - offset: 0x40
```

This can be easier to understand than using many `offset/x32` or `offset/x64` features.

### format

The name of the file format.

Valid formats:
  - `pe`
  - `elf`
  - `dotnet`

## counting

Many rules will inspect the feature set for a select combination of features;
however, some rules may consider the number of times a feature was seen in a feature set.

These rules can be expressed like:

    count(characteristic(nzxor)): 2           # exactly match count==2
    count(characteristic(nzxor)): 2 or more   # at least two matches
    count(characteristic(nzxor)): 2 or fewer  # at most two matches
    count(characteristic(nzxor)): (2, 10)     # match any value in the range 2<=count<=10

    count(mnemonic(mov)): 3
    count(basic blocks): 4

`count` supports inline descriptions, except for [strings](#string), via the following syntax:

    count(number(2 = AF_INET/SOCK_DGRAM)): 2

## matching prior rule matches and namespaces

capa rules can specify logic for matching on other rule matches or namespaces.
This allows a rule author to refactor common capability patterns into their own reusable components.
You can specify a rule match expression like so:
```yaml
  - and:
      - match: create process
      - match: host-interaction/file-system/write
```
Rules are uniquely identified by their `rule.meta.name` property;
this is the value that should appear on the right-hand side of the `match` expression.

capa will refuse to run if a rule dependency is not present during matching.
Similarly, you should ensure that you do not introduce circular dependencies among rules that match one another.

Common rule patterns, such as the various ways to implement "writes to a file", can be refactored into "library rules". 
These are rules with `rule.meta.lib: True`.
By default, library rules will not be output to the user as a rule match, 
but can be matched by other rules.
When no active rules depend on a library rule, these the library rules will not be evaluated - maintaining performance.

## descriptions

All features and statements support an optional description which helps with documenting rules and provides context in capa's output.

For all features except for [strings](#string), the description can be specified inline preceded by ` = `: ` = DESCRIPTION STRING`.
For example:

```yaml
- number: 0x5A4D = IMAGE_DOS_SIGNATURE (MZ)
```

The inline syntax is preferred.
For [strings](#string) or if the description is long or contains newlines, use the two-line syntax.
It uses the `description` tag in the following way: `description: DESCRIPTION STRING`.

For [statements](#features-block) you can add *one* nested description entry to the statement.

For example:

```yaml
- or:
  - string: "This program cannot be run in DOS mode."
    description: MS-DOS stub message
  - number: 0x5A4D
    description: IMAGE_DOS_SIGNATURE (MZ)
  - and:
    - description: documentation of this `and` statement
    - offset: 0x50 = IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
    - offset: 0x34 = IMAGE_NT_HEADERS.OptionalHeader.ImageBase
  - and:
    - offset: 0x50 = IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage
    - offset: 0x30 = IMAGE_NT_HEADERS64.OptionalHeader.ImageBase
```
