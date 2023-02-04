# capa rules

[![Rule linter status](https://github.com/mandiant/capa-rules/workflows/CI/badge.svg)](https://github.com/mandiant/capa-rules/actions?query=workflow%3A%22CI%22)
[![Number of rules](https://img.shields.io/badge/rules-766-blue.svg)](rules)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

This is the standard collection of rules for [capa](https://github.com/mandiant/capa) - the tool to automatically identify capabilities of programs.

## philosophy
Rule writing should be easy and fun! 
A large rule corpus benefits everyone in the community and we encourage all kinds of contributions.

Anytime you see something neat in malware, we want you to think of expressing it in a capa rule.
Then, we'll make it as painless as possible to share your rule here and distribute it to the capa users.

## rule development

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example of a capa rule:

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

capa interpets the content of these rules as it inspects executable files.
If you follow the guidelines of this rule format, then you can teach capa to identify new capabilities.

The [doc/format.md](./doc/format.md) file describes exactly how to construct rules.
Please refer to it as you create rules for capa.


## namespace organization

The organization of this repository mirrors the namespaces of the rules it contains. 
capa uses namespaces to group like things together, especially when it renders its final report.
Namespaces are hierarchical, so the children of a namespace encodes its specific techniques.
In a few words each, the top level namespaces are:

  - [anti-analysis](./anti-analysis/) - packing, obfuscation, anti-X, etc.
  - [c2](./c2/) - commands that may be issued by a controller, such as interactive shell or file transfer
  - [collection](./collection/) - data that may be enumerated and collected for exfiltration
  - [communication](./communication/) - HTTP, TCP, etc.
  - [compiler](./compiler/) - detection of build environments, such as MSVC, Delphi, or AutoIT
  - [data-manipulation](./data-manipulation/) - encryption, hashing, etc.
  - [executable](./executable/) - characteristics of the executable, such as PE sections or debug info
  - [host-interaction](./host-interaction/) - access or manipulation of system resources, like processes or the Registry
  - [impact](./impact/) - end goal
  - [internal](./internal/) - used internally by capa to guide analysis
  - [lib](./lib/) - building blocks to create other rules
  - [linking](./linking/) - detection of dependencies, such as OpenSSL or Zlib
  - [load-code](./load-code/) - runtime load and execution of code, such as embedded PE or shellcode
  - [malware-family](./malware-family/) - detection of malware families
  - [nursery](./nursery/) - staging ground for rules that are not quite polished
  - [persistence](./persistence/) - all sorts of ways to maintain access
  - [runtime](./runtime/) - detection of language runtimes, such as the .NET platform or Go
  - [targeting](./targeting/) - special handling of systems, such as ATM machines
  
We can easily add more top level namespaces as the need arises. 


### library rules
capa supports rules matching other rule matches. 
For example, the following rule set describes various methods of persistence.
Note that the rule `persistence` matches if either `run key` or `service` match against a sample.

```yaml
---
rule:
  meta:
    name: persistence
  features:
    or:
      - match: run key
      - match: service
---
rule:
  meta:
    name: run key
  features:
    string: /CurrentVersion\/Run/i
---
rule:
  meta:
    name: service
  features:
    api: CreateService
```

Using this feature, we can capture common logic into "library rules".
These rules don't get rendered as results but are used as building blocks to create other rules.
For example, there are quite a few ways to write to files on Windows, 
 so the following library rule makes it easy for other rules to thoroughly match file writing.
 
 ```yaml
rule:
  meta:
    name: write file
    lib: True
  features:
    or:
      api: WriteFile
      api: fwrite
      ...
 ```

Set `rule.meta.lib=True` to declare a lib rule and place the rule file into the [lib](./lib/) rule directory.
Library rules should not have a namespace.
Library rules will not be rendered as results.
Capa will only attempt to match lib rules that are referenced by other rules, 
 so there's no performance overhead for defining many reusable library rules.

### rule nursery
The rule [nursery](https://github.com/mandiant/capa-rules/tree/master/nursery) is a staging ground for rules that are not quite polished. Nursery rule logic should still be solid, though metadata may be incomplete. For example, rules that miss a public example of the technique.

The rule engine matches regularly on nursery rules. However, our rule linter only enumerates missing rule data, but will not fail the CI build, because its understood that the rule is incomplete.

We encourage contributors to create rules in the nursery, and hope that the community will work to "graduate" the rule once things are acceptable.

Examples of things that would place a rule into the nursery:
  - no real-world examples
  - missing categorization
  - (maybe) questions about fidelity (e.g. RC4 PRNG algorithm)
