# Copyright (C) 2016 KillerInstinct
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

try:
    import re2 as re
except:
    import re

from lib.cuckoo.common.abstracts import Signature

class JS_SuspiciousRedirect(Signature):
    name = "js_suspicious_redirect"
    description = "Executes JavaScript that contains a suspicious redirect"
    severity = 2
    categories = ["exploit_kit"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.styleRE = r".*\<style\>(?:[^\.]+)?\.(?P<styleName>[^\{]+).*\</style>"
        self.iframeRE = r"\<iframe src=(?:(?:\"|')(?P<redir>[^\"']+)(?:\"|'))"
        self.ret = False

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["COleScript_Compile", "COleScript_ParseScriptText",
                           "CDocument_write", "JsEval"])

    def on_call(self, call, process):
        if call["api"] == "CDocument_write":
            buf = self.get_argument(call, "Buffer")
        elif call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        buf = buf.strip()
        if "style" in buf.lower() and "iframe" in buf.lower() and len(buf) < 500:
            check = re.match(self.styleRE, buf)
            if check:
                style = check.group("styleName")
                hclass1 = "class=\"{0}\"".format(style)
                hclass2 = "class='{0}'".format(style)
                if hclass1 in buf or hclass2 in buf:
                    redirect = re.search(self.iframeRE, buf)
                    if redirect:
                        self.ret = True
                        self.severity = 3
                        self.data.append({"Info": "Javascript generated CSS styling for a div "
                                                  "containing an iframe redirect."})
                        self.data.append({"Redirect": redirect.group("redir")})

    def on_complete(self):
        if self.ret:
            return True

        return False
