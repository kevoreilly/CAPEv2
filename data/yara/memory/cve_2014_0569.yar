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

rule Exploit_CVE_2014_0569
{
   strings:
       $fwshdr = "FWS" ascii
       $s1 = "pawn2c" ascii nocase fullword
       $s2 = {25 80 20 25 fe 07 2d 05 41 03 25 fe 07}
       $s3 = "casi32" ascii nocase fullword
       $s4 = "atomicCompareAndSwapLength" ascii nocase fullword
   condition:
         for any i in (1..#fwshdr) : ( for all of ($s*) : ($ in (@fwshdr[i]..@fwshdr[i] + uint32(@fwshdr[i] + 0x4) + 8)) and uint16(@fwshdr[i] + uint32(@fwshdr[i] + 0x4) + 6) == 0x0000)
}
