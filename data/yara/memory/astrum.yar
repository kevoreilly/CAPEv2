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

rule Flash_Exploit_Astrum_EK
{
   meta:
       malfamily = "AstrumEK"
   strings:
       $fwshdr = "FWS" ascii
       $s1 = "reverse_nibbles" ascii fullword
       $s2 = "exp" ascii fullword
       $s4 = {a2 a6 25 ff 01 a8 74 [-] a2 a1 a5 a9 74}
       $s5 = {24 04 a4 24 00}
       $s6 = "fl1" ascii fullword
       $s7 = "xuri" ascii fullword
   condition:
         for any i in (1..#fwshdr) : ( for all of ($s*) : ($ in (@fwshdr[i]..@fwshdr[i] + uint32(@fwshdr[i] + 0x4) + 8)) and uint16(@fwshdr[i] + uint32(@fwshdr[i] + 0x4) + 6) == 0x0000)
}

