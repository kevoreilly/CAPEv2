# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com 
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

class RIG_JS(Signature):
    name = "rig_js"
    description = "Executes obfuscated JavaScript indicative of RIG Exploit Kit"
    weight = 3
    severity = 3
    categories = ["exploit_kit"]
    families = ["RIG"]
    authors = ["Will Metcalf"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_categories = set(["browser"])
    # backward compat
    filter_apinames = set(["JsEval", "COleScript_Compile", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            buf = self.get_argument(call, "Javascript")
        else:
            buf = self.get_argument(call, "Script")

        str1=["Y2hydygyMTc2K","NocncoMjE3Ni","jaHJ3KDIxNzYp"]
        str2=["Y2hydygzMjc2Ny","NocncoMzI3Njcp","jaHJ3KDMyNzY3K"]
        str3=["Y2hydygwMS","NocncoMDEp","jaHJ3KDAxK"]
        str4=["Y2hydygwMC","NocncoMDAp","jaHJ3KDAwK"]

        str5=["IklJbGwiOiJNT1YgW0VDWCswQ10sRUFYI","JJSWxsIjoiTU9WIFtFQ1grMENdLEVBWC","iSUlsbCI6Ik1PViBbRUNYKzBDXSxFQVgi"]
        str6=["TjNOTlhRWGlXUFdOV2VYaVhpVzNOTllNWGhYaF","4zTk5YUVhpV1BXTldlWGlYaVczTk5ZTVhoWGhY","OM05OWFFYaVdQV05XZVhpWGlXM05OWU1YaFhoW"]
        if "VBscript" in buf and "String.fromCharCode" in buf and "window.execScript" in buf and any(e in buf for e in str1) and any(e in buf for e in str2) and any(e in buf for e in str3) and any(e in buf for e in str4):
            return True
        if any(e in buf for e in str5) or any(e in buf for e in str6):
            return True
        # Rig-V Browser Fingerprinting
        if "if(\'getBoxObjectFor\'" in buf and "mozInnerScreenX" in buf and "isFirefox++" and "if(\'WebKitCSSMatrix\'" in buf and "webkitStorageInfo" in buf and "isChrome++" in buf and "=\'sandbox\'" in buf and "createElement(\'iframe\')" in buf and "history.pushState" in buf and "documentElement.webkitRequestFullScreen" in buf and "isIE++" in buf and "\'FileReader\'" in buf:
            return True
