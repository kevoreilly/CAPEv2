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

rule Angler_EK_Landing_Memory
{
   meta:
       malfamily = "angler"

   strings:
       $angk1 = {20 76 61 72 20 6B 6F 20 3D 20 27 4B 61 74 70 65 72 74 6B 79 2E 27 2E 72 65 70 6C 61 63 65 28 2F 74 2F 67 2C 27 73 27 29 3B}
       $angk2 = {27 49 65 56 69 72 27 20 2B 20 27 74 75 61 6C 4B 65 79 62 6F 61 27 20 2B 20 27 72 64 50 6C 75 67 69 6E}

       $angfls1 = {3D 22 6D 6F 76 69 65 22 20 76 61 6C 75 65 3D 22 68 74 74 70 3A 2F 2F 27 20 2B 20 67 65 74}
       $angfls2 = {22 46 6C 61 73 68 56 61 72 73 22 20 76 61 6C 75 65 3D 22 65 78 65 63 3D 27 20 2B 20 67 65 74 44 61 74 61 28}
       $angfls3 = {28 29 20 2B 20 27 2F 27 20 2B 20 67 65 74}

       $angde1 = "sA = cryptKey.split('')" ascii wide
       $angde2 = "keySize; j++){newLine += line[keyArray[j]];}endStr = endStr + newLine;}endStr=endStr.replace(" ascii wide

       $angflv21 = "'http://' + getKolaio() + '/'" ascii wide
       $angflv22 = "FlashVars" ascii wide

       $angsl1 = "http://'+getKolaio()+'/'" ascii wide
       $angsl2 = "application/x-silverlight-2" ascii wide

       $angIEexpm11 = "{17416:4080636,17496:4080636,17631:4084748,17640:4084748,17689:4080652,17728:4088844,17801:4088844,17840:4088840,17905:4088840}" ascii wide
       $angIEexpm12 = "MOV [ECX+0C]" ascii wide
       $angIEexpm13 = "122908,122236,125484,2461125,208055" ascii wide
       $angIEexpm15 = "virtualprotect" ascii wide fullword
   condition:
       any of ($angk*) or all of ($angfls*) or all of ($angde*) or all of ($angflv2*) or all of ($angsl*) or all of ($angIEexpm*)
}
