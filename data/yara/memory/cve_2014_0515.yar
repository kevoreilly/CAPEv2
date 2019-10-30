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

rule CVE_2014_0515
{
   strings:
       $s1 = {00 43 72 79 73 74 61 6C 6C 69 7A 65 A0 0C 6E 61 6D 65 73 70 61 63 65}
       $cvalloc = {00 A2 07 64 65 66 61 75 6C 74 56 61 6C 75 65 00}
   condition:
       $s1 and for any i in (1..#cvalloc) : (uint32(@cvalloc[i] + 0x14) > 2000000000)
}
