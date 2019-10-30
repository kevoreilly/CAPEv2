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

class ResourceLangID(Signature):
    name = "origin_resource_langid"
    description = "Unconventionial language used in binary resources"
    severity = 2
    authors = ["Optiv"]
    categories = ["origin"]
    minimum = "1.3"

    def run(self):
        safe_langs = [
            "SYS",
            "INVARIANT",
            "NEUTRAL",
            "DEFAULT",
            "ENGLISH",
            "FRENCH",
            "GERMAN",
            "DUTCH",
            "ITALIAN",
            "SWEDISH",
        ]

        if "static" in self.results and "pe" in self.results["static"]:
            if "resources" in self.results["static"]["pe"]:
                for resource in self.results["static"]["pe"]["resources"]:
                    splitlangs = []
                    splitlangs.append(resource["sublanguage"].split("_"))
                    buf = resource["language"]
                    if buf:
                        splitlangs.append(buf.split("_"))
                    for splitlang in splitlangs:
                        if len(splitlang) > 1 and splitlang[1] not in safe_langs:
                            lang = ""
                            if len(splitlang) == 2:
                                lang = splitlang[1].title()
                            elif len(splitlang) > 2:
                                lang = splitlang[1].title() + " (" + ' '.join([x.title() for x in splitlang[2:]]) + ")"
                            self.description += ": %s" % lang
                            return True

        return False
