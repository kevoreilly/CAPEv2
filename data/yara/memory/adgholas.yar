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

rule AdGholas_mem
{
  meta:
      malfamily = "AdGholas"

  strings:
       $a1 = "(3e8)!=" ascii wide
       $a2 = /href=\x22\.\x22\+[a-z]+\,mimeType\}/ ascii wide
       $a3 = /\+[a-z]+\([\x22\x27]divx[^\x22\x27]+torrent[^\x22\x27]*[\x22\x27]\.split/ ascii wide
       $a4 = "chls" nocase ascii wide
       $a5 = "saz" nocase ascii wide
       $a6 = "flac" nocase ascii wide
       $a7 = "pcap" nocase ascii wide

  condition:
       all of ($a*)
}

rule AdGholas_mem_MIME
{
  meta:
      malfamily = "AdGholas"

  strings:

       $b1=".300000000" ascii nocase wide fullword
       $b2=".saz" ascii nocase wide fullword
       $b3=".py" ascii nocase wide fullword
       $b4=".pcap" ascii nocase wide fullword
       $b5=".chls" ascii nocase wide fullword
  condition:
       all of ($b*)
}

//expensive
rule AdGholas_mem_antisec
{
  meta:
      malfamily = "AdGholas"

  strings:
      $vid1 = "res://c:\\windows\\system32\\atibtmon.exe" nocase ascii wide
      $vid2 = "res://c:\\windows\\system32\\aticfx32.dll" nocase ascii wide
      $vid3 = "res://c:\\windows\\system32\\drivers\\ati2mtag.sys" nocase ascii wide
      $vid4 = "res://c:\\windows\\system32\\drivers\\atihdmi.sys" nocase ascii wide
      $vid5 = "res://c:\\windows\\system32\\drivers\\atikmdag.sys" nocase ascii wide
      $vid6 = "res://c:\\windows\\system32\\drivers\\igdkmd32.sys" nocase ascii wide
      $vid7 = "res://c:\\windows\\system32\\drivers\\igdkmd64.sys" nocase ascii wide
      $vid8 = "res://c:\\windows\\system32\\drivers\\igdpmd32.sys" nocase ascii wide
      $vid9 = "res://c:\\windows\\system32\\drivers\\igdpmd64.sys" nocase ascii wide
      $vid10 = "res://c:\\windows\\system32\\drivers\\mfeavfk.sys" nocase ascii wide
      $vid11 = "res://c:\\windows\\system32\\drivers\\mfehidk.sys" nocase ascii wide
      $vid12 = "res://c:\\windows\\system32\\drivers\\mfenlfk.sys" nocase ascii wide
      $vid13 = "res://c:\\windows\\system32\\drivers\\nvhda32v.sys" nocase ascii wide
      $vid14 = "res://c:\\windows\\system32\\drivers\\nvhda64v.sys" nocase ascii wide
      $vid15 = "res://c:\\windows\\system32\\drivers\\nvlddmkm.sys" nocase ascii wide
      $vid16 = "res://c:\\windows\\system32\\drivers\\pci.sys" nocase ascii wide
      $vid17 = "res://c:\\windows\\system32\\igd10umd32.dll" nocase ascii wide
      $vid18 = "res://c:\\windows\\system32\\igd10umd64.dll" nocase ascii wide
      $vid19 = "res://c:\\windows\\system32\\igdumd32.dll" nocase ascii wide
      $vid20 = "res://c:\\windows\\system32\\igdumd64.dll" nocase ascii wide
      $vid21 = "res://c:\\windows\\system32\\igdumdim32.dll" nocase ascii wide
      $vid22 = "res://c:\\windows\\system32\\igdumdim64.dll" nocase ascii wide
      $vid23 = "res://c:\\windows\\system32\\igdusc32.dll" nocase ascii wide
      $vid24 = "res://c:\\windows\\system32\\igdusc64.dll" nocase ascii wide
      $vid25 = "res://c:\\windows\\system32\\nvcpl.dll" nocase ascii wide
      $vid26 = "res://c:\\windows\\system32\\opencl.dll" nocase ascii wide
      $antisec0 = "\\adclarity toolbar\\tbhelper.dll" nocase ascii wide
      $antisec1 = "\\charles\\charles.exe" nocase ascii wide
      $antisec2 = "\\debugging tools for windows (x86)\\windbg.exe" nocase ascii wide
      $antisec3 = "\\effetech http sniffer\\ehsniffer.exe" nocase ascii wide
      $antisec4 = "\\emet 4.0\\emet_gui.exe" nocase ascii wide
      $antisec5 = "\\emet 4.1\\emet_gui.exe" nocase ascii wide
      $antisec6 = "\\emet 5.0\\emet_gui.exe" nocase ascii wide
      $antisec7 = "\\emet 5.1\\emet_gui.exe" nocase ascii wide
      $antisec8 = "\\emet 5.2\\emet_gui.exe" nocase ascii wide
      $antisec9 = "\\fiddler2\\fiddler.exe" nocase ascii wide
      $antisec10 = "\\fiddler\\fiddler.exe" nocase ascii wide
      $antisec11 = "\\fiddlercoreapi\\fiddlercore.dll" nocase ascii wide
      $antisec12 = "\\geoedge\\geoproxy\\geoproxy.exe" nocase ascii wide
      $antisec13 = "\\geoedge\\geovpn\\bin\\geovpn.exe" nocase ascii wide
      $antisec14 = "\\geosurf by biscience toolbar\\tbhelper.dll" nocase ascii wide
      $antisec15 = "\\httpwatch\\httpwatch.dll" nocase ascii wide
      $antisec16 = "\\ieinspector\\httpanalyzerfullv6\\hookwinsockv6.dll" nocase ascii wide
      $antisec17 = "\\ieinspector\\httpanalyzerfullv7\\hookwinsockv7.dll" nocase ascii wide
      $antisec18 = "\\ieinspector\\iewebdeveloperv2\\iewebdeveloperv2.dll" nocase ascii wide
      $antisec19 = "\\invincea\\browser protection\\invbrowser.exe" nocase ascii wide
      $antisec20 = "\\invincea\\enterprise\\invprotect.exe" nocase ascii wide
      $antisec21 = "\\invincea\\threat analyzer\\fips\\nss\\lib\\ssl3.dll" nocase ascii wide
      $antisec22 = "\\malwarebytes anti-exploit\\mbae.exe" nocase ascii wide
      $antisec23 = "\\malwarebytes anti-malware\\mbam.exe" nocase ascii wide
      $antisec24 = "\\nirsoft\\smartsniff\\smsniff.exe" nocase ascii wide
      $antisec25 = "\\oracle\\virtualbox guest additions\\vboxtray.exe" nocase ascii wide
      $antisec26 = "\\parallels\\parallels tools\\prl_cc.exe" nocase ascii wide
      $antisec27 = "\\proxifier\\proxifier.exe" nocase ascii wide
      $antisec28 = "\\proxy labs\\proxycap\\pcapui.exe" nocase ascii wide
      $antisec29 = "\\sandboxie\\sbiedll.dll" nocase ascii wide
      $antisec30 = "\\softperfect network protocol analyzer\\snpa.exe" nocase ascii wide
      $antisec31 = "\\ufasoft\\sockschain\\sockschain.exe" nocase ascii wide
      $antisec32 = "\\vmware\\vmware tools\\vmtoolsd.exe" nocase ascii wide
      $antisec33 = "\\wireshark\\wireshark.exe" nocase ascii wide
      $antisec34 = "\\york\\york.exe" nocase ascii wide
      $antisec35 = "res://c:\\python27\\python.exe" nocase ascii wide
      $antisec36 = "res://c:\\python34\\python.exe" nocase ascii wide
      $antisec37 = "res://c:\\python35\\python.exe" nocase ascii wide
      $antisec38 = "res://c:\\windows\\system32\\drivers\\bdfsfltr.sys" nocase ascii wide
      $antisec39 = "res://c:\\windows\\system32\\drivers\\bdsandbox.sys" nocase ascii wide
      $antisec40 = "res://c:\\windows\\system32\\drivers\\eamon.sys" nocase ascii wide
      $antisec41 = "res://c:\\windows\\system32\\drivers\\eamonm.sys" nocase ascii wide
      $antisec42 = "res://c:\\windows\\system32\\drivers\\ehdrv.sys" nocase ascii wide
      $antisec43 = "res://c:\\windows\\system32\\drivers\\hmpalert.sys" nocase ascii wide
      $antisec44 = "res://c:\\windows\\system32\\drivers\\nvhda32v.sys" nocase ascii wide
      $antisec45 = "res://c:\\windows\\system32\\drivers\\nvhda64v.sys" nocase ascii wide
      $antisec46 = "res://c:\\windows\\system32\\drivers\\nvlddmkm.sys" nocase ascii wide
      $antisec47 = "res://c:\\windows\\system32\\drivers\\prl_fs.sys" nocase ascii wide
      $antisec48 = "res://c:\\windows\\system32\\drivers\\pssdklbf.sys" nocase ascii wide
      $antisec49 = "res://c:\\windows\\system32\\drivers\\tmactmon.sys" nocase ascii wide
      $antisec50 = "res://c:\\windows\\system32\\drivers\\tmcomm.sys" nocase ascii wide
      $antisec51 = "res://c:\\windows\\system32\\drivers\\tmevtmgr.sys" nocase ascii wide
      $antisec52 = "res://c:\\windows\\system32\\drivers\\tmtdi.sys" nocase ascii wide
      $antisec53 = "res://c:\\windows\\system32\\drivers\\vboxdrv.sys" nocase ascii wide
      $antisec54 = "res://c:\\windows\\system32\\drivers\\vmci.sys" nocase ascii wide
      $antisec55 = "res://c:\\windows\\system32\\pcapwsp.dll" nocase ascii wide
      $antisec56 = "res://c:\\windows\\system32\\prxerdrv.dll" nocase ascii wide
      $antisec57 = "res://c:\\windows\\system32\\socketspy.dll" nocase ascii wide
      $antisec58 = "res://c:\\windows\\system32\\vboxservice.exe" nocase ascii wide
      $antisec59 = "res://c:\\windows\\system32\\vmsrvc.exe" nocase ascii wide
      $antisec60 = "res://c:\\windows\\system32\\vmusrvc.exe" nocase ascii wide
      $antisec61 = "res://hookwinsockv6.dll" nocase ascii wide
      $antisec62 = "res://hookwinsockv7.dll" nocase ascii wide
      $antisec63 = "res://httpwatch.dll" nocase ascii wide
      $antisec64 = "res://invguestie.dll" nocase ascii wide
      $antisec66 = "res://invredirhostie.dll" nocase ascii wide
      $antisec67 = "res://mbae.dll" nocase ascii wide
      $antisec68 = "res://pcapwsp.dll" nocase ascii wide
      $antisec69 = "res://prxerdrv.dll" nocase ascii wide
      $antisec70 = "res://sbiedll.dll" nocase ascii wide
      $antisec71 = "res://sboxdll.dll" nocase ascii wide
      $antisec72 = "res://socketspy.dll" nocase ascii wide
      $antisec73 = "res://xproxyplugin.dll" nocase ascii wide
  condition:
       any of ($vid*) and 20 of ($antisec*)
}
    
rule AdGholas_mem_antisec_M2
{
  meta:
      malfamily = "AdGholas"
  strings:
      $s1 = "ActiveXObject(\"Microsoft.XMLDOM\")" nocase ascii wide
      $s2 = "loadXML" nocase ascii wide fullword
      $s3 = "parseError.errorCode" nocase ascii wide
      $s4 = /res\x3a\x2f\x2f[\x27\x22]\x2b/ nocase ascii wide
      $s5 = /\x251e3\x21\s*\x3d\x3d\s*[a-zA-Z]+\x3f1\x3a0/ nocase ascii wide 
  condition:
      all of ($s*)
}

rule AdGholas_mem_MIME_M2
{
  meta:
      malfamily = "AdGholas"
  strings:
      $s1 = "halog" nocase ascii wide fullword 
      $s2 = "pcap" nocase ascii wide fullword
      $s3 = "saz" nocase ascii wide fullword
      $s4 = "chls" nocase ascii wide fullword
      $s5 = /return[^\x3b\x7d\n]+href\s*=\s*[\x22\x27]\x2e[\x27\x22]\s*\+\s*[^\x3b\x7d\n]+\s*,\s*[^\x3b\x7d\n]+\.mimeType/ nocase ascii wide
      $s6 = /\x21==[a-zA-Z]+\x3f\x210\x3a\x211/ nocase ascii wide
  condition:
      all of ($s*)
}
