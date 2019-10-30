/* Copyright (C) 2016 Will Metcalf william.metcalf@gmail.com 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

rule Neutrino_Memory
{
   meta:
       malfamily = "neutrino"

   strings:
       $Neutrino_CVE_2015_2419 = { 4d 4f 56 25 32 30 25 35 42 45 43 58 2b 30 43 25 35 44 25 32 43 45 41 58 }
       $Neutrino_CVE_2013_2551 = { 64 61 73 68 73 74 79 6c 65 2e 61 72 72 61 79 2e 6c 65 6e 67 74 68 25 32 30 25 33 44 25 32 30 30 25 32 30 2d 25 32 30 31 25 33 42 }
       $Neutrino_CVE_2014_6332 = {63 68 72 77 25 32 38 30 31 25 32 39 25 32 36 63 68 72 77 25 32 38 32 31 37 36 25 32 39 25 32 36 63 68 72 77 25 32 38 30 31 25 32 39 25 32 36 63 68 72 77 25 32 38 30 30 25 32 39 25 32 36 63 68 72 77 25 32 38 30 30 25 32 39 25 32 36 63 68 72 77 25 32 38 30 30 25 32 39 25 32 36 63 68 72 77 25 32 38 30 30 25 32 39 25 32 36 63 68 72 77 25 32 38 30 30 25 32 39}

       $Neutrino_Memory_Gen1_1 = "FWS" ascii wide
       $Neutrino_Memory_Gen1_2 = "exploitWrappers:nw" ascii wide
       $Neutrino_Memory_Gen1_3 = "%payloadRc4Key" ascii wide

       $Neutrino_Memory_Gen2_1 = "WScript.Shell" ascii wide
       $Neutrino_Memory_Gen2_2 = "%payloadUrl%" ascii wide
       $Neutrino_Memory_Gen2_3 = "%payloadRc4Key" ascii wide

       $Neutrino_Memory_2551_2_1 = "exp('%payloadUrl%','%payloadRc4Key%');" ascii wide
       $Neutrino_Memory_2551_2_2 = "dashstyle.array.length"

       $Neutrino_Memory_File_Check1 = "[START] checking process ..." ascii wide
       $Neutrino_Memory_File_Check2 = "=== Checking element:" ascii wide
       $Neutrino_Memory_File_Check3 = "Software for checking: " ascii wide
       $Neutrino_Memory_File_Check4 = "res://C:\\Program Files (x86)\\FFDec\\Uninstall.exe/#" ascii wide
       $Neutrino_Memory_File_Check5 = "res://C:\\Program Files\\Bitdefender Agent\\ProductAgentService.exe/#" ascii wide
       $Neutrino_Memory_File_Check6 = "res://C:\\Program Files (x86)\\Wireshark\\wireshark.exe/#" ascii wide

       $Neutrino_Memory_2016_0189_1 = "leakMem" ascii wide fullword
       $Neutrino_Memory_2016_0189_2 = "u0008" ascii wide
       $Neutrino_Memory_2016_0189_3 = "u4141" ascii wide
       $Neutrino_Memory_2016_0189_4 = "redim" ascii wide
       $Neutrino_Memory_2016_0189_5 = "Preserve" ascii wide
       $Neutrino_Memory_2016_0189_6 = "exploit" fullword ascii wide
       $Neutrino_Memory_2016_0189_7 = "fire" ascii wide



   condition:
       $Neutrino_CVE_2015_2419 or $Neutrino_CVE_2013_2551 or $Neutrino_CVE_2014_6332 or all of ($Neutrino_Memory_Gen1*) or all of ($Neutrino_Memory_Gen2*) or all of ($Neutrino_Memory_2551_2*) or all of ($Neutrino_Memory_File_Check*) or all of ($Neutrino_Memory_2016_0189*)
}
