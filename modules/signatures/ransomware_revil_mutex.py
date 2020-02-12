# Copyright (C) 2019 ditekshen
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

class RevilMutexes(Signature):
    name = "revil_mutexes"
    description = "Creates known REvil/Sodinokibi ransomware mutexes"
    severity = 3
    categories = ["ransomware"]
    families = ["REvil", "Sodinokibi"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
            "^(Global|Local)\\\\112983B0-B4C9-4F9B-96C4-E5394FB8A5B4$",
            "^(Global|Local)\\\\1DB960B8-E5C3-F077-5D68-EEE2E637EE0B$",
            "^(Global|Local)\\\\206D87E0-0E60-DF25-DD8F-8E4E7D1E3BF0$",
            "^(Global|Local)\\\\3555A3D6-37B3-0919-F7BE-F3AAB5B6644A$",
            "^(Global|Local)\\\\552FFA80-3393-423d-8671-7BA046BB5906$",
            "^(Global|Local)\\\\6CAC559B-02B4-D929-3675-2706BBB8CF66$",
            "^(Global|Local)\\\\859B4E91-BAF1-3DBB-E616-E9E99E851136$",
            "^(Global|Local)\\\\879EBE58-4C9F-A6BE-96A3-4C51826CEC2F$",
            "^(Global|Local)\\\\95B97D2B-4513-2041-E8A5-AC7446F12075$",
            "^(Global|Local)\\\\BF29B630-7648-AADF-EC8A-94647D2349D6$",
            "^(Global|Local)\\\\C126B3B3-6B51-F91C-6FDF-DD2C70FA45E6$",
            "^(Global|Local)\\\\C19C0A84-FA11-3F9C-C3BC-0BCB16922ABF$",
            "^(Global|Local)\\\\C817795D-7756-05BF-A69E-6ED0CE91EAC4$",
            "^(Global|Local)\\\\D382D713-AA87-457D-DDD3-C3DDD8DFBC96$",
            "^(Global|Local)\\\\DAE678E1-967E-6A19-D564-F7FCA6E7AEBC$",
            "^(Global|Local)\\\\FB864EC7-B361-EA6D-545C-E1A167CCBE95$",
            "^(Global|Local)\\\\FDC9FA6E-8257-3E98-2600-E72145612F09$",
        ]

        for indicator in indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.data.append({"mutex": match_mutex})
                return True

        return False
