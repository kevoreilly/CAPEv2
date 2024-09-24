import unittest

from modules.packages.ps1 import PS1


class TestPS1(unittest.TestCase):
    def test_get_paths(self):
        """By default, the first path should be powershell.exe"""
        package_name = "modules.packages.ps1"
        __import__(package_name, globals(), locals(), ["dummy"])
        ps1_module = PS1()
        paths = ps1_module.get_paths()
        assert paths[0][-1] == "powershell.exe"
        all_paths = set([path[-1] for path in paths])
        assert "pwsh.exe" not in all_paths

    def test_get_paths_powershell_core(self):
        """When option pwsh selected, the first path should be pwsh.exe"""
        options = {"pwsh": True}
        package_name = "modules.packages.ps1"
        __import__(package_name, globals(), locals(), ["dummy"])
        ps1_module = PS1(options=options)
        paths = ps1_module.get_paths()
        assert paths[0][-1] == "pwsh.exe"
        all_paths = set([path[-1] for path in paths])
        assert "powershell.exe" in all_paths
