# Copyright (C) 2020 bartblaze
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
import os
from lib.common.abstracts import Package

# While this should work, it is an experimental rule - do a PR if you see fit!
class INP(Package):
    """Inpage (Urdu/Arabic) Word Processor analysis package."""

    PATHS = [("ProgramFiles", "InPage Urdu Professional", "Inpage.exe"), ("ProgramFiles", "Concept Software Pvt. Ltd", "InPage Urdu Professional", "Inpage.exe")]

    def start(self, path):
        inp = self.get_path("Inpage.exe")
        #Rename file to file.inp so it can open properly.
        ext = os.path.splitext(path)[-1].lower()
        if ext != ".inp":
          new_path = path + ".inp"
          os.rename(path, new_path)
          path = new_path
        return self.execute(inp, '"%s"' % path, path)
