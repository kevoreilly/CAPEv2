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

rule CVE_2015_0016_M1
{
    strings:
        $s1 = "MSTSWebProxy.MSTSWebProxy" nocase ascii wide
        $s2 = ".StartRemoteDesktop" nocase ascii wide
        $s3 = "Scripting.FileSystemObject" nocase ascii wide
        $s4 = "CreateObject" nocase ascii wide
        $vb1 = /language\s*=\s*[\x22\x27]?vbscript/ nocase ascii wide
        $vb2 = "text/vbscript" nocase ascii wide
    condition:
        all of ($s*) and any of ($vb*)
}
