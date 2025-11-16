# CAPE 文件类型与虚拟机扩展配置指南

## 1. Windows 10 已有文件类型支持概览
- CAPE 的分析包列表详见 `docs/book/src/usage/packages.rst`，默认会根据扩展或指定 package 自动匹配。
- 下表列出最常用的格式、所需软件及默认查找路径：

| 格式/场景 | 对应 package | 依赖软件 | 默认可执行路径示例 | 备注 |
| --- | --- | --- | --- | --- |
| 通用 EXE/Service/DLL | `exe`, `service`, `service_dll`, `dll` | 无额外依赖；如需 32 位强制需安装 .NET SDK 内的 `CorFlags.exe` | 样本自身；`CorFlags.exe` 位于 `%ProgramFiles%\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools` | `exe` 包支持 `arguments`、`appdata`、`runasx86` 选项 (`analyzer/.../exe.py`) |
| Word/Word 2016/Viewer | `doc`, `doc2016`, `doc_antivm` | Microsoft Office 2016/365（建议安装 Professional Plus） | `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`；回退到 `WORDVIEW.EXE` (`analyzer/.../doc*.py`) | 需保持 Trusted Location，包会自动添加 `.doc/.docx` |
| Excel/Excel 2016 | `xls`, `xls2016` | 同上 | `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE` (`analyzer/.../xls*.py`) | 支持 `.xls/.xlsx/.xlsm/.xlsb` |
| PowerPoint/Publisher/OneNote/Access | `ppt*`, `pub*`, `one`, `access` | Office 套件对应组件 | `C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE` 等 | 需要在安装时勾选全部桌面组件 |
| PDF | `pdf` | Adobe Acrobat Reader DC | `C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe` 或 `...\Reader\AcroRd32.exe` (`analyzer/.../pdf.py`) | 建议关闭自动更新提示以免干扰 |
| Java (JAR/Applet) | `jar`, `applet` | JRE/JDK 8+ | `C:\Program Files\Java\jre1.8.0_xxx\bin\java.exe` (`analyzer/.../jar.py`) | `class=` 选项可运行 manifest 之外的入口 |
| 浏览器/URL | `chrome`, `chromium`, `edge`, `firefox`, `tor_browser`, `chromium_ext`, `firefox_ext`, `crx` | 对应浏览器（Chrome/Edge/Firefox/Tor）并启用开发者模式 | Chrome: `C:\Program Files\Google\Chrome\Application\chrome.exe`; Edge: `C:\Program Files\Microsoft\Edge\Application\msedge.exe` (`analyzer/.../chrome.py`, `archive.py:44-54`) | 扩展包需准备 profile/extension 目录 |
| 压缩/光盘镜像 | `archive`, `zip`, `zip_compound`, `rar`, `msix` | 7-Zip（完整版）、WinRAR、PowerShell 5+ | `C:\Program Files\7-Zip\7z.exe`, `C:\Program Files\WinRAR\WinRAR.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (`archive.py:37-100`, `msix.py:17-60`) | `archive` 会递归提取并按扩展再次派发 |
| 脚本/LOLBIN | `hta`, `js`, `js_antivm`, `vbs`, `vbejse`, `wsf`, `ps1`, `batch`, `autoit`, `nodejs`, `inf`, `Ie4uinit`, `rdp` 等 | Windows 系统组件 + 可选 AutoIt3/NodeJS | AutoIt: `C:\Program Files (x86)\AutoIt3\autoit3.exe`; NodeJS: `%ProgramFiles%\nodejs\node.exe`; 系统组件位于 `%SystemRoot%` (`autoit.py`, `nodejs.py`, `inf.py`, `Ie4uinit.py`, `rdp.py`) | 建议把脚本解释器加入 PATH，避免 `get_path` 失败 |

> 提示：`conf/default/web.conf.default` 的 `[packages]` 段要求 Windows VM 打上 `win10` 或 `win11` 标签，特别是 `msix` 包必须在 Win10+ 虚机运行。

## 2. Windows 10 扩展安装建议
1. **Office**：安装 Office 2016/365（含 Access/Publisher/OneNote）并确保路径位于 `C:\Program Files\Microsoft Office\root\Office16`，以便 `doc*/xls*/ppt*/pub*` 包通过通配路径匹配。
2. **Adobe Reader**：安装最新 Acrobat Reader DC，禁用自动更新提示，保证 `AcroRd32.exe` 可被 `pdf` 包发现 (`analyzer/.../pdf.py:12-35`).
3. **Java**：安装 JRE 8u341+ 或更高版本（如 JDK 17），并保持默认目录，供 `jar`/`applet` 包调用 (`analyzer/.../jar.py`).
4. **7-Zip & WinRAR**：完整安装到默认目录，`archive` 包默认调用 `7z.exe`，失败时再尝试 `WinRAR.exe` (`archive.py:37-101`).
5. **浏览器**：安装 Chrome、Edge、Firefox、Tor Browser，启用开发者模式（Chrome/Tor）以支持 `chromium_ext`/`crx`/`tor_browser` 包；确保 profile 目录可写。
6. **脚本运行时**：
   - AutoIt：安装 AutoIt3 并把 `autoit3.exe` 拷贝到 `analyzer/windows/bin/autoit3.exe` 或系统 PATH (`autoit.py:8-15`).
   - NodeJS：安装 NodeJS LTS（默认 `C:\Program Files\nodejs`），供 `nodejs` 包运行 `.js` 脚本 (`nodejs.py:9-21`).
   - 其它 LOLBin（cmstp.exe、ie4uinit.exe、mstsc.exe 等）均来源于 Windows 自带路径 (`inf.py:19-30`, `Ie4uinit.py:17-35`, `rdp.py:8-17`).
7. **PowerShell & 证书**：保持 Windows 10 自带 PowerShell 5/7，并为 `msix` 包准备 `data\msix.ps1`；若处理签名/证书样本，需允许侧载。

## 3. 扩展文件类型的步骤
1. **确认包存在**：查阅 `analyzer/windows/modules/packages`，若已有 package，仅需保证依赖软件存在。
2. **缺失包处理**：若要支持新格式，可参考现有包实现（继承 `Package` 类，设置 `PATHS` + `start`），然后在 `docs/book/src/usage/packages.rst` 登记。
3. **Demux 配置**：必要时把新扩展加入 `lib/cuckoo/common/demux.py` 的 `demux_extensions_list`，以便自动识别；Linux/脚本类型需匹配 `VALID_TYPES` (`demux.py:43-158`).
4. **Web 提交**：在 `web.conf` 中把 package 添加到 `[package_exclusion]` 之外，并在 `[packages]` 里指定所需 VM 标签，确保任务调度正确。

## 4. Linux 虚拟机支持脚本/ELF
虽然官方提示“Linux guests doesn't have official CAPE support!” (`docs/book/src/installation/guest/linux.rst:5`)，但可通过下述步骤扩展：
1. **准备网络**：依据 `conf/qemu.conf`/`kvm.conf` 为 `ubuntu_x32`, `ubuntu_x64`, `ubuntu_arm`, `ubuntu_mips`, `ubuntu_mipsel` 等虚机创建 TAP 接口 (`docs/.../linux.rst:13-31`).
2. **安装依赖**：在 Linux 虚机执行 `apt install python3-pip systemtap-runtime`、`pip install pyinotify Pillow pyscreenshot pyautogui` 等命令（x64 需额外启用 i386 架构）(`docs/.../linux.rst:43-69`).
3. **系统调优**：禁用 UFW、防火墙、NTP、自动更新并移除多余软件，确保噪声最小 (`docs/.../linux.rst:75-101`).
4. **Agent 启动**：把 `agent.py` 加入 `crontab` 或 systemd，保证开机自启 (`docs/.../linux.rst:70-74`).
5. **Tracee 集成**：在客体中 `docker pull aquasec/tracee:0.20.0` 并标记 `latest`，配合 `auxiliary.conf`/`processing.conf` 开启 eBPF 事件 (`docs/.../linux.rst:108-122`).
6. **Web GUI**：在 `conf/default/web.conf.default` 的 `[linux]` 段启用 `enabled = yes` 或至少 `static_only = yes`，并在虚机配置中设置 `platform = linux` 以允许脚本提交调度。
7. **Demux**：`lib/cuckoo/common/demux.py` 的 `VALID_TYPES` 包含 `Bourne-Again/POSIX shell script/ELF`，只要 Linux 虚机可用，就能运行 `.sh/.elf` 等脚本 (`demux.py:114-123`).

## 5. Android 现状与可行方案
- 官方知识库指出：APK 属于 Android 操作系统软件，Windows 无法原生执行，因此 CAPE 当前无法直接在 Windows 虚机分析 APK/捕获其网络流量（参见 `KnowledgeBaseBot/all_texts.json` 中 “Android APK analysis with CAPE” 条目）。
- 可选方案：
  1. 在 CAPE 之外部署专门的 Android 沙箱（如 Android x86 + Frida/mitm），仅把抓取的 PCAP/文件导回 CAPE 进行静态/网络分析。
  2. 若坚持统一调度，可在 `conf/qemu.conf` 声明一个 Android x86 虚机，并自定义 analyzer/guest agent（需自行实现，因为 `agent.py` 目前仅针对 Windows/Linux）。
  3. 或者使用 APK->DEX->JAR 的转换方式，借助 `jar` 包进行静态执行，但无法覆盖 Android Framework 行为。

## 6. 扩展虚拟机（全平台）检查清单
1. **为每种 OS 创建配置段**（`kvm.conf`/`qemu.conf`/`virtualbox.conf`），设置 `label`, `platform`, `ip`, `arch`, `tags`（Windows 必须写 `win10/win11`）。
2. **在 Web 包映射中声明所需标签**，例如 `msix = win10,win11`，Linux 包使用 `linux_x64` 标签便于选择 (`web.conf.default:204-223`).
3. **确保快照处于开机+agent 运行状态**（`docs/book/src/installation/guest/saving.rst`），并在 hypervisor 中启用支持快照的格式（KVM 用 QCOW2）。
4. **脚本/ELF 调度**：在提交任务时选择 `platform=linux` 或 `package=generic`，系统会依据魔数自动派发。
5. **Android**：如果自行实验，需记录在自定义 AGENTS.md 并说明“非官方支持”。

---
本文件旨在将 Windows 10 已装环境与潜在 Linux/Android 扩展步骤集中记录，方便后续按场景补齐依赖。EOF
