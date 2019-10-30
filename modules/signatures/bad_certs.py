# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class BadCerts(Signature):
    name = "bad_certs"
    description = "The executable used a known stolen/malicious Authenticode signature"
    severity = 3
    weight = 3
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        md5_indicators = []
        sha1_indicators = [
            # Buhtrap from http://www.welivesecurity.com/2015/04/09/operation-buhtrap/
            "cf5a43d14c6ad0c7fdbcbe632ab7c789e39443ee",
            "e9af1f9af597a9330c52a7686bf70b0094ad7616",
            "3e1a6e52a1756017dd8f03ff85ec353273b20c66",
            "efad94fc87b2b3a652f1a98901204ea8fbeef474",
            # Stolen Sony cert
            "8df46b5fdac2eb3b4757f99866c199ff2b13427a",
            # Stolen Bit9 cert
            "555d2d20851e849f0c109e243cf8a5da1f9995d7",
            # Sysprint AG cert used in Turla
            "24215864f128972b2622172dee6282460799ca46",
            # Stolen Source Medical Solutions cert
            "b501aab2ffc3bddb7e847c4acee4be41de38f16e",
            # Adobe stolen cert
            "fdf01dd3f37c66ac4c779d92623c77814a07fe4c",
            # used in a Dridex sample: KASHTAN OOO
            "401909e89a0e59335b624e147719f0b88d51705a",
            # used in a Punkey sample: MOGLIANI & SON LIMITED
            "c5d386f697777643751ec33b6b689eef71791293",
            # used in Duqu2: HON HAI PRECISION INDUSTRY CO. LTD.
            "c7938dd4bec741574683b4f3dd54717f98e54c90",
            # HackingTeam Dump
            "2e8734348c03390d24faf96e86bb01b39e3ad4db",
            "b7c646e3a433986e165ba45b209da4a2c4111939",
            "fdc9281ab92d4fb85a03254dcb62d1c29a803fb1",
            "2a1da6dc8635e6c725cccbe6c035eec813fbeb2e",
            # Wild Neutron (Stolen Acer Incorporated cert)
            "0d859141ee9a0c6e725ffe6bcfc99f3efcc3fc07",
            # Used in Dridex, BIZNES AVTOMATYKA
            "9a9c618cc8f50e9ffb24b6cc8b34858fa65e778c",
            # Stolen ThreatTrack cert
            "8138b44330354e413dc52af1dbfca8ba1c0f6c0a",
            # eDellRoot Signed File http://en.community.dell.com/dell-blogs/direct2dell/b/direct2dell/archive/2015/11/23/response-to-concerns-regarding-edellroot-certificate
            "98a04e4163357790c4a79e6d713ff0af51fe6927",
            # Spymel Cert (SBO INVEST)
            "3a8412582563f43dd28aa1f31cdd0d0c6d78fd60",
            # DIDZHITAL ART cert used for Kovter
            "a286affc5f6e92bdc93374646676ebc49e21bcae",
            # Tiks IT cert used for Kovter
            "78d98ccccc41e0dea1791d24595c2e90f796fd48",
            ]
        if "static" in self.results and "pe" in self.results["static"]:
            if "digital_signers" in self.results["static"]["pe"] and self.results["static"]["pe"]["digital_signers"]:
                for sign in self.results["static"]["pe"]["digital_signers"]:
                    for md5 in md5_indicators:
                        if md5 == sign["md5_fingerprint"]:
                            self.data.append(sign)
                            return True
                    for sha1 in sha1_indicators:
                        if sha1 == sign["sha1_fingerprint"]:
                            self.data.append(sign)
                            return True

        return False
