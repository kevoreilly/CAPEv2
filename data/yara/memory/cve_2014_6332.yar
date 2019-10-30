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

rule Exploit_CVE_2014_6332
{
   strings:
      $m1s1 = "chrw(01)&chrw(2176)&chrw(01)&chrw(00)&chrw(00)&chrw(00)&chrw(00)&chrw(00)" ascii wide nocase
      $m1s2 = "chrw(32767)" ascii wide nocase

      $m2s1 = "(0)=&h6C64746E&" nocase ascii wide
      $m2s2 = "%uC789%uC783%u891A%u66FE%u84AD%u74E4%uFE0C%uFECC%uC0C8%u04E0%uE008%uEBAA%u90EE" nocase ascii wide
      $m2s3 = "redim" nocase ascii wide
      $m2s4 = "Preserve" nocase ascii wide

      $m3s1 = "chrw(2176)" nocase ascii wide
      $m3s2 = "chrw(32767)" nocase ascii wide
      $m3s3 = "redim" nocase ascii wide
      $m3s4 = "Preserve" nocase ascii wide
 
      $m4s1 = {18 00 00 00 01 00 80 08 01 00 00 00 00 00 00 00 00 00 00 00 FF FF FF 7F 00 00 00 00}
      $m4s2 = "redim" nocase ascii wide fullword
      $m4s3 = "preserve" nocase ascii wide fullword
      $m4s4 = "vbscript" nocase ascii wide

   condition:
      all of ($m1*) or all of ($m2*) or all of ($m3*) or all of ($m4*)
}
