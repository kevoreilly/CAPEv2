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

rule Exploit_CVE_2015_2419
{
    strings:
        $s1 = "MOV [ECX+0C],EAX" nocase ascii wide
        $s2 = "\"lIll\":\"kernel32" nocase ascii wide
        $s3 = "\"lIlll\":\"virtualprotect" nocase ascii wide
        $s4 = "prototype" nocase ascii wide
        $s5 = "stringify" nocase ascii wide
    condition:
        all of ($s*)
}

rule Exploit_CVE_2015_2419_M2
{
    strings:
         $s1="150104,149432,152680,3202586,214836,3204663,361185,285227,103426,599295,365261,226292,410596,180980,226276,179716,320389,175621,307381,792144,183476" ascii wide
         $s2="122908,122236,125484,2461125,208055,1572649,249826,271042,98055,62564,162095,163090,340146,172265,163058,170761,258290,166489,245298,172955,82542" ascii wide
         $s3="{\"17416\":4080636,\"17496\":4080636,\"17631\":4084748,\"17640\":4084748,\"17689\":4080652,\"17728\":4088844,\"17801\":4088844,\"17840\":4088840,\"17905\":4088840}" ascii wide
         $s4="Uint32Array" ascii wide nocase
         $s5="CollectGarbage" ascii wide nocase
    condition:
        all of ($s*)
}
