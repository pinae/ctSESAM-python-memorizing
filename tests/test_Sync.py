#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from Sync import Sync
from base64 import b64decode
from Crypter import Crypter
from Packer import Packer

import json
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac


class TestSync(unittest.TestCase):
    def test_pull(self):
        sync = Sync("https://ersatzworld.net/ctpwdgen-server/", 'inter', 'op')
        blob = sync.pull()
        crypter = Crypter('1234')
        synced_data = json.loads(str(Packer.decompress(crypter.decrypt(b64decode(blob)[1:])), encoding='utf-8'))
        self.assertEqual([], synced_data.keys())
        self.assertEqual({}, synced_data['Die Höhle'])
        self.assertEqual([], synced_data)
        self.assertEqual("ABC", blob)

    def test_push(self):
        pass


if __name__ == '__main__':
    unittest.main()
