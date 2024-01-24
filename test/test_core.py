import unittest

from pyssh._core.packets import _conn_setup


# TEST _conn_setup_version_exchange

class test__client_base(unittest.TestCase):
    def test__protocol_version_exchange(self):
        test_case = b"SSH-2.0-billsSSH_3.6.3q3\r\n"
        self.assertTrue(_conn_setup.protocol_version_exchange(test_case))

        test_case = b"SSH-2.0-billsSSH_3.6.3q3 comments\r\n"
        self.assertTrue(_conn_setup.protocol_version_exchange(test_case))

        test_case = b"SSH-1.0-billsSSH_3.6.3q3\r\n"
        self.assertRaises(NotImplementedError, _conn_setup.protocol_version_exchange, test_case)

    def test__binary_packet_protocol(self):     # TODO: Implement
        ...


if __name__ == '__main__':
    unittest.main()
