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

rule SunDown_EK_Memory
{
        meta:
                malfamily = "SunDown"
        strings:
            $sundownslight1 = "silverlight" nocase ascii wide
            $sundownslight2 = "shell32=909090" nocase ascii wide

            $sundownflash1 = "d27cdb6e-ae6d-11cf-96b8-444553540000" nocase ascii wide
            $sundownflash2 = "exec=" nocase ascii wide
            $sundownflash3 = "9090909090909090909090909090909090909090909090909090909090909090909090EB" nocase ascii wide

        condition:
                all of ($sundownflash*) or all of ($sundownslight*)
}
rule SunDown_EK_Memory2
{
    strings:
        $shellcode1 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 71 33 C9 64 8B 71 30 8B 76 0C 8B 76 1C 8B 5E 08 8B 7E 20 8B 36 66 [50-300] 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21 21}
    condition:
        $shellcode1
}
