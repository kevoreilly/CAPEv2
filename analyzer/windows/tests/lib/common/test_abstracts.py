import importlib
import unittest
from unittest.mock import MagicMock, patch

from lib.common import abstracts


class TestPackageConfiguration(unittest.TestCase):
    def test_private_package_configuration(self):
        # test analysis package
        package_module = self.__class__.__module__
        # and its private configuration module
        module_name = f"data.packages.{package_module}"

        class TestPackage(abstracts.Package):
            pass

        test_pkg = TestPackage(package_module)

        # private package configuration function with 2 args
        configure_called = False

        def configure(package, target):
            self.assertIs(package, test_pkg)
            self.assertEqual(target, self.id())
            nonlocal configure_called
            configure_called = True

        mock_module = MagicMock()
        mock_module.configure = configure

        with patch.object(importlib, "import_module", return_value=mock_module) as m:
            # do the private package configuration
            test_pkg.configure_from_data(self.id())
            # check it imported the private configuration module
            m.assert_called_once_with(module_name)
        self.assertTrue(configure_called)
