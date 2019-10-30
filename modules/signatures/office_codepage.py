# Copyright (C) 2016 Kevin Ross
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

class Office_Code_Page(Signature):
    name = "office_code_page"
    description = "The office file has a unconventional code page"
    severity = 2
    categories = ["office","static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    reference = ["https://msdn.microsoft.com/en-us/library/windows/desktop/dd317756%28v=vs.85%29.aspx"]

    def run(self):

        codepages = [
            {"language" : "Arabic (ASMO 708)", "code" : "708"},
            {"language" : "Arabic (ASMO-449+, BCON V4)", "code" : "709"},
            {"language" : "Arabic - Transparent Arabic", "code" : "710"},
            {"language" : "Arabic (Transparent ASMO); Arabic (DOS)", "code" : "720"},
            {"language" : "OEM Baltic; Baltic (DOS)", "code" : "775"},
            {"language" : "OEM Cyrillic (primarily Russian)", "code" : "855"},
            {"language" : "OEM Turkish; Turkish (DOS)", "code" : "857"},
            {"language" : "OEM Arabic; Arabic (864)", "code" : "864"},
            {"language" : "OEM Russian; Cyrillic (DOS)", "code" : "866"},
            {"language" : "ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)", "code" : "936"},
            {"language" : "ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5)", "code" : "950"},
            {"language" : "IBM EBCDIC Turkish (Latin 5)", "code" : "1026"},
            {"language" : "ANSI Cyrillic; Cyrillic (Windows)", "code" : "1251"},
            {"language" : "ANSI Turkish; Turkish (Windows)", "code" : "1254"},
            {"language" : "ANSI Arabic; Arabic (Windows)", "code" : "1256"},
            {"language" : "ANSI/OEM Vietnamese; Vietnamese (Windows)", "code" : "1257"},
            {"language" : "MAC Traditional Chinese (Big5); Chinese Traditional (Mac)", "code" : "10002"},
            {"language" : "Arabic (Mac)", "code" : "10004"},
            {"language" : "Cyrillic (Mac)", "code" : "10007"},
            {"language" : "MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac)", "code" : "10008"},
            {"language" : "Romanian (Mac)", "code" : "10010"},
            {"language" : "Turkish (Mac)", "code" : "10017"},
            {"language" : "Croatian (Mac)", "code" : "10082"},
            {"language" : "CNS Taiwan; Chinese Traditional (CNS)", "code" : "20000"},
            {"language" : "Eten Taiwan; Chinese Traditional (Eten)", "code" : "20002"},
            {"language" : "IBM EBCDIC Arabic", "code" : "20420"},
            {"language" : "Russian (KOI8-R); Cyrillic (KOI8-R)", "code" : "20866"},
            {"language" : "IBM EBCDIC Cyrillic Russian", "code" : "20880"},
            {"language" : "IBM EBCDIC Turkish", "code" : "20905"},
            {"language" : "Simplified Chinese (GB2312); Chinese Simplified (GB2312-80)", "code" : "20936"},
            {"language" : "IBM EBCDIC Cyrillic Serbian-Bulgarian", "code" : "21025"},
            {"language" : "Ukrainian (KOI8-U); Cyrillic (KOI8-U)", "code" : "21866"},
            {"language" : "ISO 8859-4 Baltic", "code" : "28594"},
            {"language" : "ISO 8859-5 Cyrillic", "code" : "28595"},
            {"language" : "ISO 8859-6 Arabic", "code" : "28596"},
            {"language" : "ISO 8859-9 Turkish", "code" : "28599"},
            {"language" : "ISO 8859-13 Estonian", "code" : "28603"},
            {"language" : "ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022)", "code" : "50227"},
            {"language" : "ISO 2022 Traditional Chinese", "code" : "50229"},
            {"language" : "EBCDIC Simplified Chinese Extended and Simplified Chinese", "code" : "50935"},
            {"language" : "EBCDIC Simplified Chinese", "code" : "50936"},
            {"language" : "EUC Traditional Chinese", "code" : "51950"},
            {"language" : "HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ)", "code" : "52936"},
            {"language" : "GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)", "code" : "54936"},
            {"language" : "ISCII Devanagari", "code" : "57002"},
            {"language" : "ISCII Bangla", "code" : "57003"},
            {"language" : "ISCII Tamil", "code" : "57004"},
            {"language" : "ISCII Telugu", "code" : "57005"},
            {"language" : "ISCII Assamese", "code" : "57006"},
            {"language" : "ISCII Odia", "code" : "57007"},
            {"language" : "ISCII Kannada", "code" : "57008"},
            {"language" : "ISCII Malayalam", "code" : "57009"},
            {"language" : "ISCII Gujarati", "code" : "57010"},
            {"language" : "ISCII Punjabi", "code" : "57011"}
        ]

        if "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    codepage = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["codepage"]
                    for codepages in codepages:
                        if codepages["code"] == codepage:
                            self.description += ": %s" % codepages["language"]
                            return True

        return False
