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

rule CVE_2015_2545
{
    strings:
        $anchor2 = "%%BoundingBox" nocase

        $s2 = /4d5a90000.{0,1000}546869732070726f6772616d/ nocase
        $s3 = "28000e1358000e13bebafeca414141414141414141414141414141410300000041414141414141414141414124000e1300000000ffffff7" nocase
        $s4 = "6064a1000000008b4004250000ffff6681384d5a751781783c00020000730e8b503c03d066813a50457502eb072d00000100ebdb8b7a1c8b722c03f003fe83ed04" nocase

    condition:
        $anchor2 and (($s2 in (@anchor2[1]..filesize)) or ($s3 in (@anchor2[1]..filesize)) or ($s4 in (@anchor2[1]..filesize)))
}

