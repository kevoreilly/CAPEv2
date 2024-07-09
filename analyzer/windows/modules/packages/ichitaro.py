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

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


# While this should work, it is an experimental package - do a PR if you see fit! Ichitaro Viewer only.
class ichitaro(Package):
    """Ichitaro (Japanese) Word Processor analysis package."""

    PATHS = [("ProgramFiles", "JustSystems", "TaroView", "TAROVIEW.EXE")]
    summary = "Open a .jtd file using Ichitaro viewer."
    description = """Use 'TaroView\\TAROVIEW.EXE <sample>' to open a .jtd file.
    The .jtd file extension will be added automatically."""

    def start(self, path):
        ichitaro = self.get_path("TAROVIEW.EXE")
        # Rename file to file.jtd so it can open properly.
        path = check_file_extension(path, ".jtd")
        return self.execute(ichitaro, f'"{path}"', path)
