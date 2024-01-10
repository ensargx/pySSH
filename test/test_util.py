import unittest

from pyssh.util import mpint, name_list

class test__mpint(unittest.TestCase):
    def test__mpint(self):
        test_case = 0x1234567890abcdef
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\x08\x12\x34\x56\x78\x90\xab\xcd\xef")

        test_case = 0x1234567890abcdef1234567890abcdef
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\x10\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd\xef")

        test_case = 0x00
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\x00")

        test_case = 0x09a378f9b2e332a7
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\x08\x09\xa3\x78\xf9\xb2\xe3\x32\xa7")

        test_case = 0x80
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\x02\x00\x80")

        test_case = -0x1234
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\02\xed\xcc")

        test_case = -0xdeadbeef
        self.assertEqual(mpint(test_case), b"\x00\x00\x00\x05\xff\x21\x52\x41\x11")

    def test__name_list(self):
        test_case = ()
        self.assertEqual(name_list(test_case), b"\x00\x00\x00\x00")

        test_case = ("zlib",)
        self.assertEqual(name_list(test_case), b"\x00\x00\x00\x04\x7a\x6c\x69\x62")

        test_case = ("zlib", "none")
        self.assertEqual(name_list(test_case), b"\x00\x00\x00\x09\x7a\x6c\x69\x62\x2c\x6e\x6f\x6e\x65")
                                            #      00  00  00  09  7a  6c  69  62  2c  6e  6f  6e  65

if __name__ == '__main__':
    unittest.main()