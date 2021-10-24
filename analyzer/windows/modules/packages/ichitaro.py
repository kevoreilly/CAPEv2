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
import os
from lib.common.abstracts import Package

# While this should work, it is an experimental rule - do a PR if you see fit! Viewer only.
class ichitaro(Package):
    """Ichitaro (Japanese) Word Processor analysis package."""

    PATHS = [("ProgramFiles", "JustSystems", "TaroView", "TAROVIEW.EXE")]

    def start(self, path):
        ichitaro = self.get_path("TAROVIEW.EXE")
        #Rename file to file.inp so it can open properly.
        ext = os.path.splitext(path)[-1].lower()
        if ext != ".jtd":
          new_path = path + ".jtd"
          os.rename(path, new_path)
          path = new_path
        return self.execute(ichitaro, '"%s"' % path, path)
