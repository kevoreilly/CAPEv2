# Copyright (C) 2015 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class Static_Java(Signature):
    name = "static_java"
    description = "JAR file contains suspicious characteristics"
    severity = 2
    weight = 0
    categories = ["java", "static", "exploit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    def run(self):
        reflection = 0
        exploit = 0

        # https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-a-daily-grind-filtering-java-vulnerabilities.pdf
        # https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-java-vulnerabilities.pdf
        # https://www.virusbtn.com/virusbulletin/archive/2013/06/vb201306-Java-null

        functions = [".invoke(",".getMethod(","class.forName(",".getClass(",".getField(",".getConstructor(",".newInstance("]
        permissions = ["setSecurityManager","getSecurityManager","doPrivileged","AllPermission"]

        if "static" in self.results and "java" in self.results["static"] and "decompiled" in self.results["static"]["java"]:
            decompiled = self.results["static"]["java"]["decompiled"]
            for functions in functions:
                reflection += decompiled.count(functions)    
            if reflection > 0:           
                self.data.append({"obfuscation_reflection" : "Contains %s occurrences of potential Java reflection indirect function call obfuscation" % (reflection)})
                self.weight += 1

            # Checks for strings in clear, reversed & hex formattings. Hex conversion code from http://stackoverflow.com/questions/12214801/print-a-string-as-hex-bytes)
            for permissions in permissions:
                if permissions in decompiled or permissions[::-1] in decompiled or ''.join(x.encode('hex') for x in permissions) in decompiled or ':'.join(x.encode('hex') for x in permissions) in decompiled or ' '.join(x.encode('hex') for x in permissions) in decompiled:
                    self.data.append({"security_permissions" : "Contains %s potentially used to modify the security level" % (permissions)})
                    self.severity = 3
                    self.weight += 1

            if "URL(" in decompiled or "URLEncoder.encode(" in decompiled or "openConnection(" in decompiled:
                self.data.append({"http" : "Contains ability to make HTTP connections" })
                self.weight += 1

            if ".exec(" in decompiled or ".getRuntime(" in decompiled:
                self.data.append({"execute" : "Contains ability to run executable code" })
                self.severity = 3
                self.weight += 1

            if "OutputStream" in decompiled and ".ser" in decompiled:
                self.data.append({"serialized_object" : "Contains use of a Java serialized object" })
                self.weight += 1

            # Check individual string length for possible obfuscation
            for string in decompiled.split():
                if len(string) > 150:
                    self.data.append({"string_length" : "Contains very large strings indicative of obfuscation" })
                    self.severity = 3
                    self.weight += 1
                    break

            # Specific Exploit Detections
            # http://stopmalvertising.com/malware-reports/watering-hole-attack-cve-2012-4792-and-cve-2012-0507.html
            if "AtomicReferenceArray" in decompiled:
                self.data.append({"cve_2012-0507" : "AtomicReferenceArray type confusion exploit code" })
                exploit += 1

            # http://blogs.technet.com/b/mmpc/archive/2012/11/21/an-analysis-of-dorkbot-s-infection-vectors-part-2.aspx
            if "sun.awt.SunToolkit" in decompiled and "getField" in decompiled:
                self.data.append({"cve_2012-4681" : "com.sun.beans.finder.MethodFinder findMethod exploit code" })
                exploit += 1

            # http://blogs.technet.com/b/mmpc/archive/2012/11/15/a-technical-analysis-on-new-java-vulnerability-cve-2012-5076.aspx
            if "ManagedObjectManagerFactory" in decompiled and "GenericConstructor" in decompiled:
                self.data.append({"cve_2012-5076" : "com.sun.org.glassfish.gmbal vulnerable class exploit code" })
                exploit += 1

            # http://blogs.technet.com/b/mmpc/archive/2013/01/20/a-technical-analysis-of-a-new-java-vulnerability-cve-2013-0422.aspx
            if "MethodHandles.Lookup" in decompiled:
                self.data.append({"cve_2013-0422" : "MethodHandles insecure class exploit code" })
                exploit += 1

            # https://community.rapid7.com/community/metasploit/blog/2013/02/25/java-abused-in-the-wild-one-more-time
            if "Introspector.elementFromComplex" in decompiled:
                self.data.append({"cve_2013-0431" : "Introspector.elementFromComplex remote code execution exploit code" })
                exploit += 1

            # https://www.trustwave.com/Resources/SpiderLabs-Blog/Fresh-Coffee-Served-by-CoolEK/
            if "ColorSpace" in decompiled and "BufferedImage" in decompiled:
                self.data.append({"cve_2013-1493" : "Color conversion memory corruption exploit code" })
                exploit += 1

            if "MethodHandle" in decompiled and "findStaticSetter" in decompiled:
                self.data.append({"cve_2013-2423" : "findStaticSetter type confusion exploit code" })
                exploit += 1

            # http://research.zscaler.com/2014/07/dissecting-cve-2013-2460-java-exploit.html
            if "ProviderFactory" in decompiled and "getDefaultFactory" in decompiled:
                self.data.append({"cve_2013-2460" : "ProviderSkeleton insecure invoke method exploit code" })
                exploit += 1

            # http://malware.dontneedcoffee.com/2013/08/cve-2013-2465-integrating-exploit-kits.html
            if "DataBufferByte" in decompiled and "BufferedImage" in decompiled and "getNumComponents" in decompiled and "SinglePixelPackedSampleModel" in decompiled or "MultiPixelPackedSampleModel" in decompiled:
                self.data.append({"cve_2013-2465" : "storeImageArray invalid array indexing exploit code" })
                exploit += 1

            if "getNumDataElements" in decompiled and "AlphaCompositeClass" in decompiled:
                self.data.append({"cve_2013-2471" : "getNumDataElements memory corruption exploit code" })
                exploit += 1

            if exploit > 0:
                self.description += " and possible exploit code."
                self.severity = 3
                self.weight += 1


        if self.weight:
            return True

        return False
