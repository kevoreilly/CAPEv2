# Copyright (C) 2012, 2015 Benjamin K., Kevin R., Claudio "nex" Guarnieri
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

class BuildLangID(Signature):
    name = "origin_langid"
    description = "Unconventionial binary language"
    severity = 2
    authors = ["Benjamin K.", "Kevin R.", "nex"]
    categories = ["origin"]
    minimum = "1.3"

    def run(self):
        languages = [
            {"language" : "Albanian", "code" : "0x041C"},
            {"language" : "Arabic (Algeria)", "code" : "0x0401"},
            {"language" : "Arabic (Bahrain)", "code" : "0x3C01"},
            {"language" : "Arabic (Egypt)", "code" : "0x0C01"},
            {"language" : "Arabic (Iraq)", "code" : "0x0801"},
            {"language" : "Arabic (Jordan)", "code" : "0x2C01"},
            {"language" : "Arabic (Kuwait)", "code" : "0x3401"},
            {"language" : "Arabic (Lebanon)", "code" : "0x3001"},
            {"language" : "Arabic (Libya)", "code" : "0x1001"},
            {"language" : "Arabic (Morocco)", "code" : "0x1801"},
            {"language" : "Arabic (Oman)", "code" : "0x2001"},
            {"language" : "Arabic (Qatar)", "code" : "0x4001"},
            {"language" : "Arabic (Saudi Arabia)", "code" : "0x0401"},
            {"language" : "Arabic (Syria)", "code" : "0x2801"},
            {"language" : "Arabic (Qatar)", "code" : "0x4001"},
            {"language" : "Arabic (Tunisia)", "code" : "0x1C01"},
            {"language" : "Arabic (UAE)", "code" : "0x3801"},
            {"language" : "Arabic (Yemen)", "code" : "0x2401"},
            {"language" : "Bosnian", "code" : "0x201A"},
            {"language" : "Bulgarian", "code" : "0x0402"},
            {"language" : "Chinese", "code" : "0x0C04"},
            {"language" : "Chinese (Simplified)", "code" : "0x0804"},
            {"language" : "Chinese (Traditional)", "code" : "0x7C04"},
            {"language" : "Croatian", "code" : "0x041A"},
            {"language" : "Estonian", "code" : "0x0425"},
            {"language" : "Georgian", "code" : "0x0437"},
            {"language" : "Greenlandic", "code" : "0x046F"},
            {"language" : "Hebrew", "code" : "0x040d"},
            {"language" : "Kazac", "code" : "0x043F"},
            {"language" : "Khmer (Cambodia)", "code" : "0x0453"},
            {"language" : "Kiche (Guatemala)", "code" : "0x0486"},
            {"language" : "Kyrgyz (Kyrgyzstan)", "code" : "0x0440"},
            {"language" : "Latvian", "code" : "0x0426"},
            {"language" : "Lao", "code" : "0x0454"},
            {"language" : "Lithuanian", "code" : "0x0427"},
            {"language" : "Persian (Iran)", "code" : "0x0429"},
            {"language" : "Polish", "code" : "0x0415"},
            {"language" : "Portuguese (Brazil)", "code" : "0x0416"},
            {"language" : "Romanian", "code" : "0x0418"},
            {"language" : "Russian", "code" : "0x0419"},
            {"language" : "Serbian", "code" : "0x7C1A"},
            {"language" : "Slovak", "code" : "0x041B"},
            {"language" : "Slovenian", "code" : "0x0424"},
            {"language" : "Spanish (Argentina)", "code" : "0x2C0A"},
            {"language" : "Spanish (Bolivia)", "code" : "0x400A"},
            {"language" : "Spanish (Chile)", "code" : "0x340A"},
            {"language" : "Spanish (Columbia)", "code" : "0x240A"},
            {"language" : "Spanish (Costa Rica)", "code" : "0x140A"},
            {"language" : "Spanish (Dominican Republic)", "code" : "0x1C0A"},
            {"language" : "Spanish (Ecuador)", "code" : "0x300A"},
            {"language" : "Spanish (El Salvador)", "code" : "0x440A"},
            {"language" : "Spanish (Guatemala)", "code" : "0x100A"},
            {"language" : "Spanish (Honduras)", "code" : "0x480A"},
            {"language" : "Spanish (Mexico)", "code" : "0x080A"},
            {"language" : "Spanish (Nicaragua)", "code" : "0x4C0A"},
            {"language" : "Spanish (Panama)", "code" : "0x180A"},
            {"language" : "Spanish (Paraguay)", "code" : "0x3C0A"},
            {"language" : "Spanish (Peru)", "code" : "0x280A"},
            {"language" : "Spanish (Puerto Rico)", "code" : "0x500A"},
            {"language" : "Spanish (Uruguay)", "code" : "0x380A"},
            {"language" : "Spanish (Venezuela)", "code" : "0x200A"},
            {"language" : "Syriac", "code" : "0x045A"},
            {"language" : "Tamil", "code" : "0x0449"},
            {"language" : "Turkish", "code" : "0x041F"},
            {"language" : "Ukrainian", "code" : "0x0422"},
            {"language" : "Urdu", "code" : "0x0820"},
            {"language" : "Urdu (Pakistan)", "code" : "0x0420"},
            {"language" : "Uzbek (Cyrillic)", "code" : "0x0843"},
            {"language" : "Uzbek (Latin)", "code" : "0x0443"},
            {"language" : "Vietnamese", "code" : "0x042A"}
        ]

        if "static" in self.results and "pe" in self.results["static"]:
            if "versioninfo" in self.results["static"]["pe"]:
                for info in self.results["static"]["pe"]["versioninfo"]:
                    if info["name"] == "Translation":
                        try:
                            lang, charset = info["value"].strip().split(" ")
                            for language in languages:
                                if language["code"] == lang:
                                    self.description += ": %s" % language["language"]
                                    return True
                        except:
                            pass

        return False
