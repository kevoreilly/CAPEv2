# Copyright (C) 2021 bartblaze
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


class CookiesStealer(Signature):
    name = "infostealer_cookies"
    description = "Harvests cookies for information gathering"
    severity = 3
    categories = ["infostealer"]
    authors = ["bartblaze"]
    minimum = "0.5"
    ttps = ["T1539"]  # MITRE v6,7,8

    def run(self):
        indicators = [
            ".*\\\\Chromium\\\\User Data\\\\.*\\\\Cookies$",
            ".*\\\\Google\\\\Chrome\\\\User Data\\\\.*\\\\Cookies$",
            ".*\\\\Microsoft\\\\Windows\\\\INetCookies$",
            ".*\\\\Packages\\\\.*\\\\AC\\\\.*\\\\MicrosoftEdge\\\\Cookies$",
            ".*\\\\UCBrowser\\\\User Data_i18n\\\\.*\\\\Cookies.9$",
            ".*\\\\Yandex\\\\YandexBrowser\\\\User Data\\\\.*\\\\Cookies$",
            ".*\\\\Apple Computer\\\\Safari\\\\Cookies\\\\Cookies.binarycookies$",
            ".*\\\\Microsoft\\\\Windows\\\\Cookies$",
            ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\cookies.sqlite$",
            ".*\\\\Opera Software\\\\Opera Stable\\\\Cookies$",
            ".*\\\\Brave-Browser\\\\User Data\\\\.*\\\\Cookies$",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"cookie": match})
                return True

        return False
