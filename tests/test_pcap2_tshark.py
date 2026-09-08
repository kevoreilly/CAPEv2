import unittest
from unittest.mock import patch, MagicMock, mock_open
from modules.processing.network import Pcap2

class TestPcap2Tshark(unittest.TestCase):
    def setUp(self):
        self.pcap_path = "mock.pcap"
        self.network_path = "mock_network_dir"
        self.tlsmaster = {
            (b"client_random_1", b"server_random_1"): b"master_secret_1"
        }

    @patch("subprocess.run")
    @patch("modules.processing.network.path_mkdir")
    @patch("modules.processing.network.path_exists")
    @patch("modules.processing.network.path_delete")
    @patch("modules.processing.network.path_write_file")
    def test_pcap2_http_parsing(self, mock_write_file, mock_delete, mock_exists, mock_mkdir, mock_run):
        # Setup mocks first
        print("Setting up mocks...")
        mock_exists.return_value = True
        mock_mkdir.return_value = None
        mock_delete.return_value = None
        mock_write_file.return_value = None

        # Disable passlist filtering
        import modules.processing.network as network_module
        network_module.enabled_passlist = False
        print(f"enabled_passlist set to: {network_module.enabled_passlist}")

        # Create Pcap2 after patches are applied
        pcap2 = Pcap2(self.pcap_path, self.tlsmaster, self.network_path)
        print(f"Pcap2 created successfully")

        # Mock tshark JSON output
        mock_tshark_json = [
            {
                "_source": {
                    "layers": {
                        "tcp.stream": ["0"],
                        "ip.src": ["192.168.1.10"],
                        "tcp.srcport": ["12345"],
                        "ip.dst": ["104.244.42.1"],
                        "tcp.dstport": ["443"],
                        "frame.time_epoch": ["1786193741.123"],
                        "http.request.method": ["GET"],
                        "http.request.uri": ["/index.html"],
                        "http.host": ["example.com"],
                        "http.request.line": ["GET /index.html HTTP/1.1\r\n", "Host: example.com\r\n"]
                    }
                }
            },
            {
                "_source": {
                    "layers": {
                        "tcp.stream": ["0"],
                        "ip.src": ["104.244.42.1"],
                        "tcp.srcport": ["443"],
                        "ip.dst": ["192.168.1.10"],
                        "tcp.dstport": ["12345"],
                        "frame.time_epoch": ["1786193741.150"],
                        "http.response.code": ["200"],
                        "http.response.line": ["HTTP/1.1 200 OK\r\n", "Content-Type: text/html\r\n"],
                        "http.file_data_raw": ["4d5a900003000000"]  # MZ header in hex
                    }
                }
            }
        ]

        import json
        mock_process = MagicMock()
        mock_process.stdout = json.dumps(mock_tshark_json).encode()
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        print(f"Mock subprocess.run configured")

        # Run Pcap2
        try:
            print(f"Calling pcap2.run()...")
            results = pcap2.run()
            print(f"Results keys: {list(results.keys())}")
            print(f"Results: {results}")
            print(f"Mock exists called: {mock_exists.called}, call_count: {mock_exists.call_count}")
            print(f"Mock run called: {mock_run.called}, call_count: {mock_run.call_count}")
        except Exception as e:
            print(f"Exception during run: {e}")
            import traceback
            traceback.print_exc()
            raise

        # Debug: Check if mock was called
        self.assertTrue(mock_exists.called, "path_exists mock was never called!")
        print(f"mock_exists.call_args_list: {mock_exists.call_args_list}")

        # Assertions
        self.assertIn("https_ex", results)
        self.assertEqual(len(results["https_ex"]), 1)

        flow = results["https_ex"][0]
        self.assertEqual(flow["src"], "192.168.1.10")
        self.assertEqual(flow["sport"], 12345)
        self.assertEqual(flow["dst"], "104.244.42.1")
        self.assertEqual(flow["dport"], 443)
        self.assertEqual(flow["method"], "GET")
        self.assertEqual(flow["host"], "example.com")
        self.assertEqual(flow["uri"], "/index.html")
        self.assertEqual(flow["status"], 200)
        self.assertEqual(flow["request"], b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n")
        self.assertEqual(flow["response"], b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
