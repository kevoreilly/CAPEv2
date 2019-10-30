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

rule Nuclear_EK_Landing_Memory
{
   meta:
       malfamily = "nuclear"

   strings:
       $nuclm1 = "window.runer = true" ascii wide
       $nuclm2 = "function flash_run(fu," ascii wide
       $nuclm3 = " + fu + " ascii wide
       $nuclm4 = "FlashVars" ascii wide
   condition:
       all of ($nuclm*) 
}
