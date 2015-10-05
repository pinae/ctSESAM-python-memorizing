#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from packer import Packer
from base64 import b64decode, b64encode


class TestPacker(unittest.TestCase):
    def test_compress(self):
        packed_data = Packer.compress("Some packable information")
        self.assertEqual(b'AAAAGXjaC87PTVUoSEzOTkzKSVXIzEvLL8pNLMnMzwMAedUJrg==', b64encode(packed_data))

    def test_decompress(self):
        self.assertEqual(
            b'Some packable information',
            Packer.decompress(b64decode("AAAAGXjaC87PTVUoSEzOTkzKSVXIzEvLL8pNLMnMzwMAedUJrg==")))


if __name__ == '__main__':
    unittest.main()
