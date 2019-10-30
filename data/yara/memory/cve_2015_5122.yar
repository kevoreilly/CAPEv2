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

rule Exploit_HT_CVE_2015_5122
{
   strings:
       $fwshdr = "FWS" ascii
       $s1 = "FindVP" ascii fullword
       $s2 = "CopyBAToVector" ascii fullword
       $s3 = "Payload" ascii fullword
       $s4 = "TryExpl" ascii fullword
   condition:
         for any i in (1..#fwshdr) : ( for all of ($s*) : ($ in (@fwshdr[i]..@fwshdr[i] + uint32(@fwshdr[i] + 0x4) + 8)) and uint16(@fwshdr[i] + uint32(@fwshdr[i] + 0x4) + 6) == 0x0000)
}
