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

rule CVE_2016_0189_Generic{

  strings:
      $s1 = "leakMem" fullword ascii wide nocase

      $t1_1 = "%u0008%u4141%u4141%u4141" ascii wide nocase
      $t1_2 = "%25u0008%25u4141%25u4141%25u4141" ascii wide nocase

      $t2_1 = "ReDim Preserve" ascii wide nocase
      $t2_2 = "ReDim%20Preserve" ascii wide nocase

      $t3_1 = "(1, 2000)" ascii wide nocase
      $t3_2 = "%281%2c%202000%29" ascii wide nocase

      $t4_1 = "1, 24000)" ascii wide nocase
      $t4_2 = "%281%2c%202000%29" ascii wide nocase

   condition:
       all of ($s*) and any of ($t1_*) and any of ($t2_*) and any of ($t3_*) and any of ($t4_*)
}

