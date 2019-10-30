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

rule EITest_Compromised_Site_Injection
{
   meta:
       malfamily = "EITest"
   strings:
       $eitest0 = "<div style = \"position: absolute;z-index:-1; left:" ascii wide
       $eitest1 = "px; opacity:0;filter:alpha(opacity=0); -moz-opacity:0;\">" ascii wide
       $eitest2 = "clsid:d27cdb6e-ae6d-11cf-96b8-444553540000" ascii wide
       $eitest3 = "bgcolor=\"#ffffff\"" ascii wide
       $eitest4 = "wmode=\"opaque\"/></object>" ascii wide
   condition:
       $eitest0 and $eitest1 in (@eitest0[1]..filesize) and $eitest2 in (@eitest1[1]..filesize) and $eitest3 in (@eitest2[1]..filesize)  and $eitest4 in (@eitest3[1]..filesize)
}

