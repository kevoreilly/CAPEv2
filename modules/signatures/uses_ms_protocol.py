# Copyright (C) 2022 bartblaze
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


class UsesMSProtocol(Signature):
    name = "uses_ms_protocol"
    description = "Uses a Microsoft default handler or protocol."
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    references = ["https://blog.syss.com/posts/abusing-ms-office-protos/"]

    def run(self):
        utilities = [
            "ms-aad-brokerplugin",
            "ms-access",
            "ms-actioncenter",
            "ms-appinstaller",
            "ms-apprep",
            "ms-availablenetworks",
            "ms-calculator",
            "ms-chat",
            "ms-clock",
            "ms-contact-support",
            "ms-cortana",
            "ms-cxh",
            "ms-cxh-full",
            "ms-default-location",
            "ms-device-enrollment",
            "ms-drive-to",
            "ms-edu-secureassessment",
            "ms-excel",
            "ms-gamebar",
            "ms-gamebarservices",
            "ms-gamingoverlay",
            "ms-get-started",
            "ms-getoffice",
            "ms-holographicfirstrun",
            "ms-inputapp",
            "ms-ipmessaging",
            "ms-mobileplans",
            "ms-msdt",
            "ms-officeapp",
            "ms-officecmd",
            "ms-oobenetwork",
            "ms-paint",
            "ms-penworkspace",
            "ms-people",
            "ms-perception-simulation",
            "ms-phone",
            "ms-photos",
            "ms-playto-miracast",
            "ms-powerpoint",
            "ms-projection",
            "ms-publisher",
            "ms-quick-assist",
            "ms-rd",
            "ms-retaildemo-launchbioenrollm",
            "ms-retaildemo-launchstart",
            "ms-screenclip",
            "ms-screensketch",
            "ms-settings",
            "ms-settings-airplanemode",
            "ms-settings-bluetooth",
            "ms-settings-cellular",
            "ms-settings-connectabledevices",
            "ms-settings-displays-topology",
            "ms-settings-e-mailandaccounts",
            "ms-settings-language",
            "ms-settings-location",
            "ms-settings-lock",
            "ms-settings-mobilehotspot",
            "ms-settings-notifications",
            "ms-settings-power",
            "ms-settings-privacy",
            "ms-settings-proximity",
            "ms-settings-screenrotation",
            "ms-settings-wifi",
            "ms-settings-workplace",
            "ms-sttoverlay",
            "ms-sway",
            "ms-taskswitcher",
            "ms-to-do",
            "ms-todo",
            "ms-unistore-e-mail",
            "ms-virtualtouchpad",
            "ms-voip-call",
            "ms-voip-video",
            "ms-walk-to",
            "ms-wcrv",
            "ms-whiteboard-cmd",
            "ms-whiteboard-preview",
            "ms-windows-search",
            "ms-windows-store",
            "ms-windows-store2",
            "ms-word",
            "ms-wpc",
            "ms-wpdrmv",
            "ms-xbet-survey",
            "ms-xbl-3d8b930f",
            "ms-xgpueject",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command": cmdline})

        return ret
