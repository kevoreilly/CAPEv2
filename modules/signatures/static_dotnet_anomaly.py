# Copyright (C) 2015 KillerInstinct
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

def decode_b64(data):
    '''Automatically handle buffering when decoding base64
    @param data: base64 encoded string
    @return: string or None
    '''
    data = data.strip().rstrip().replace(" ", "")
    datalen = len(data) % 4
    # Invalid Base64 data, try removing a byte
    if datalen == 1:
        data = data[:-1]
    # Add a proper buffer
    elif datalen == 2:
        data += "=="
    elif datalen == 3:
        data += "="

    decoded = None
    try:
        decoded = data.decode("base64")
    except Exception as e:
        pass

    return decoded

class DotNetAnomaly(Signature):
    name = "static_dotnet_anomaly"
    description = "Anomalous .NET characteristics"
    severity = 2
    weight = 0
    categories = ["static"]
    authors = ["KillerInstinct"]
    minimum = "1.3"

    def run(self):
        if not "static" in self.results or not "dotnet" in self.results["static"]:
            return False

        if "assemblyinfo" in self.results["static"]["dotnet"] and self.results["static"]["dotnet"]["assemblyinfo"]:
            if self.results["static"]["dotnet"]["assemblyinfo"]["version"]:
                version = self.results["static"]["dotnet"]["assemblyinfo"]["version"].split(".")
                if version:
                    nullversion = True
                    for vernum in version:
                        if vernum != "0":
                            nullversion = False
                    if nullversion:
                        self.weight += 1
                        self.data.append({"anomalous_version": "Assembly version is set to 0"})

        if "customattrs" in self.results["static"]["dotnet"] and self.results["static"]["dotnet"]["customattrs"]:
            for attr in self.results["static"]["dotnet"]["customattrs"]:
                valLength = len(attr["value"])
                if valLength > 512:
                    self.data.append({"large_attribute": "Attribute \"{0}\" is abnormally large.".format(
                        attr["name"])})
                    self.weight += 1
                    buf = decode_b64(attr["value"])
                    if buf and (buf.startswith("MZ") or "!This program cannot be run in" in buf):
                        self.data.append({"encoded_pe": "Attribute \"{0}\" has a base64 encoded PE.".format(
                            attr["name"])})
                        self.weight += 1
                        self.severity = 3

        if self.weight:
            return True

        return False
