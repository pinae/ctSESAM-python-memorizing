#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from kgk_manager import KgkManager
from crypter import Crypter


class TestKgkManager(unittest.TestCase):
    def test_str(self):
        kgkm = KgkManager()
        self.assertEqual("<KGK: , salt: >", str(kgkm))
        kgkm.salt2 = b"\x01"*32
        kgkm.iv2 = b"\x02"*16
        self.assertEqual("<KGK: , salt: , iv2: 02020202020202020202020202020202, " +
                         "salt2: 0101010101010101010101010101010101010101010101010101010101010101>",
                         str(kgkm))
        kgkm.salt = b"\x03"*32
        kgkm.kgk = b"\x04"*64
        self.assertEqual("<KGK: 04040404040404040404040404040404040404040404040404040404040404040404040404040404040" +
                         "404040404040404040404040404040404040404040404, " +
                         "salt: 0303030303030303030303030303030303030303030303030303030303030303, " +
                         "iv2: 02020202020202020202020202020202, " +
                         "salt2: 0101010101010101010101010101010101010101010101010101010101010101>",
                         str(kgkm))

    def test_get_kgk_has_kgk(self):
        kgkm = KgkManager()
        self.assertEqual(b'', kgkm.get_kgk())
        self.assertFalse(kgkm.has_kgk())
        kgkm.kgk = b"\xE4"*64
        kgkm.kgk_crypter = Crypter(Crypter.createIvKey(b'1234', b'pepper', iterations=3))
        self.assertEqual(b"\xE4"*64, kgkm.get_kgk())
        self.assertTrue(kgkm.has_kgk())

    def test_get_iv2(self):
        kgkm = KgkManager()
        kgkm.iv2 = b"\x02"*16
        self.assertEqual(b"\x02"*16, kgkm.get_iv2())

    def test_get_salt2(self):
        kgkm = KgkManager()
        kgkm.salt2 = b"\x3A"*32
        self.assertEqual(b"\x3A"*32, kgkm.get_salt2())

    def test_fresh_iv2(self):
        kgkm = KgkManager()
        kgkm.iv2 = b"\x02"*16
        self.assertEqual(b"\x02"*16, kgkm.get_iv2())
        kgkm.fresh_iv2()
        self.assertNotEqual(b"\x02"*16, kgkm.get_iv2())
        self.assertEqual(16, len(kgkm.get_iv2()))

    def test_fresh_salt2(self):
        kgkm = KgkManager()
        kgkm.salt2 = b"\x3A"*32
        self.assertEqual(b"\x3A"*32, kgkm.get_salt2())
        kgkm.fresh_salt2()
        self.assertNotEqual(b"\x3A"*32, kgkm.get_salt2())
        self.assertEqual(32, len(kgkm.get_salt2()))
