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

rule CVE_2016_3298_Mem
{
  meta:
      malfamily = "CVE-2016-3298"

  strings:
       $res1="res://" nocase ascii wide
       $res2=/res\x3a\x2f\x2f([a-z]\x3a\x5c+)?Progra[^\x22\x27\x00-\x1f#\x3b]*\.(dll|exe)\x2f+#(24|16|11)\x2f/ ascii nocase wide

       $mhres="mhtml:res:/" nocase ascii wide

       $mf1="mhtml:file:/" nocase ascii wide
       $mf2=/mhtml\x3afile\x3a\x2f([a-z]\x3a\x5c|progra)/ ascii wide nocase
  condition:
       $res1 and #res2 > 3 or all of ($mf*) or $mhres
}

