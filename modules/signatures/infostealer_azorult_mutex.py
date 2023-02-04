# Copyright (C) 2020 ditekshen
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


class AzorultMutexes(Signature):
    name = "azorult_mutexes"
    description = "Creates Azorult infostealer mutexes"
    severity = 3
    categories = ["infostealer"]
    families = ["Azorult"]
    authors = ["ditekshen"]
    minimum = "1.3"
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            "^A0390EB6-186C3DFC-798FF402-221C3238-5DFB3C3C5$",
            "^A0579FBD-F72D679B-BBDA7BB0-42C1A06E-AF0E2704E$",
            "^A18F76D5-A343A2EC-65A1B3B6-7937E9B3-372FBE424$",
            "^A22AAB90F-86C3DFC7-7F9EE4A7-0CDCD91E-00006F77$",
            "^A4F9B003-E86C3DFC-7C5D002C-92C5FC31-A388ED0A2$",
            "^A5B62575D-86C3DFC7-E8C0C114-66B0A125-88127645$",
            "^A731955B-686C3DFC-78994B1E-B27BCB54-EF72C215C$",
            "^A8A37382-486C3DFC-7F9E6E2A-C5235B3D-1A8B65B89$",
            "^AD9E5869-5343A2EC-6E9A182F-DEF6C275-F70D0A4FE$",
            "^AD9E58695-343A2EC6-E9A182FD-EF6C275F-70D0A4FE$",
            "^AE71028F6-86C3DFC7-24A6BCBA-71C79E6C-EE87A6BE$",
            "^AF38125D-586C3DFC-798FF402-221C3238-5AEFD1836$",
            "^UA9D9D10-9343A2EC-689B2AFB-87F3B18F-0E80C0038$",
            "^A18F76D5-A343A2EC-6B65A1E5-26353D99-2C33950D0$",
            "^AB44752F-986C3DFC-781E6ACB-DCC4B5F4-90575096C$",
            "^AB44752F9-86C3DFC7-00000000-CC4B5F49-ECD36880$",
            "^A0579FBD-F72D679B-B8F5E95A-99994E32-03E28DA46$",
            "^AB44752F9-86C3DFC7-81E6ACBD-CC4B5F49-0575096C$",
            "^A655F590-D86C3DFC-7C5D002C-92C5FC31-AD42377F5$",
            "^A22AAB90-F86C3DFC-77F9EE4A-70CDCD91-E00006F77$",
            "^ABC2F5A06-343A2EC6-86C21C34-6661E33D-4923F55B$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False
