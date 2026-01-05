import sys
import unittest

import pytest

if sys.platform == "linux":
    import analyzer
    from analyzer import PROCESS_LIST, SEEN_LIST

@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux")
class TestAnalyzer(unittest.TestCase):

    def test_add_pids(self):
        """Test add_pids with a variety of valid types"""
        # Check that both sets are empty
        self.assertEqual(PROCESS_LIST, set())
        self.assertEqual(SEEN_LIST, set())

        pids = [123, 456, 789]
        # Add a list of PIDs
        analyzer.add_pids([str(pids[0]), pids[1]])
        # Add a set of PIDs
        analyzer.add_pids(set([pids[0], pids[2]]))
        # Add a tuple of PIDs
        analyzer.add_pids((pids[1], pids[2]))

        self.assertEqual(PROCESS_LIST, set(pids))
        self.assertEqual(SEEN_LIST, set(pids))


    def test_add_pids_invalid_var(self):
        """Test add_pids with an invalid type"""
        with self.assertRaises(TypeError):
            analyzer.add_pids(analyzer.add_pids)
