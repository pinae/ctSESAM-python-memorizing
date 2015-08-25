# coding=utf-8
"""
Test for CtSESAM class.
"""
import unittest
from PasswordManager import CtSesam


class TestCtSesam(unittest.TestCase):
    def test_default(self):
        manager = CtSesam()
        self.assertEqual("5#%KiUvEE7", manager.generate('foo', 'some.domain'))

    def test_custom_character_set(self):
        manager = CtSesam()
        manager.set_password_character_set('abcdefghijklmnopqrstuvwxyzABCDUFGHJKLMNPQRTEVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.')
        self.assertEqual("5#%KiEvUU7", manager.generate('foo', 'some.domain'))

    def test_custom_salt(self):
        manager = CtSesam()
        manager.set_salt(b'qanisaoerna56745678eornsiarteonstiaroenstiaeroh')
        self.assertEqual("CQz7kgz%C.", manager.generate('foo', 'some.domain'))

    def test_long(self):
        manager = CtSesam()
        self.assertEqual("5#%KiUvEE7}t<d:Y=Lzn;dKzaG0qU/t)", manager.generate('foo', 'some.domain', length=32))
