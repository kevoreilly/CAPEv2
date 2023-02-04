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


class AntiSandboxForegroundWindow(Signature):
    name = "antisandbox_foregroundwindows"
    description = (
        "Checks whether any human activity is being performed " "by constantly checking whether the foreground window changed"
    )
    severity = 2
    categories = ["anti-sandbox"]
    # Migrated by @CybercentreCanada
    authors = ["Cuckoo Technologies", "@CybercentreCanada"]
    minimum = "1.2"
    evented = True

    filter_apinames = set(["GetForegroundWindow", "NtDelayExecution"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.get_foreground_window_count = 0
        self.nt_delay_execution_count = 0

    def on_call(self, call, _):
        if call["api"] == "GetForegroundWindow":
            self.get_foreground_window_count += 1
            if self.pid:
                self.mark_call()
        elif call["api"] == "GetForegroundWindow":
            self.nt_delay_execution_count += 1
            if self.pid:
                self.mark_call()

    def on_complete(self):
        # The check for NtDelayExecution may not be necessary, but then
        # this signature has more potential of triggering a false positive.
        if self.get_foreground_window_count > 100 and self.nt_delay_execution_count > 100:
            return True
