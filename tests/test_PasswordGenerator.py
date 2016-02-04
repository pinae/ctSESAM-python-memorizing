# coding=utf-8
"""
Test for CtSESAM class.
"""
import unittest
from password_generator import CtSesam
from password_setting import PasswordSetting


class TestCtSesam(unittest.TestCase):
    def test_default(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_full_template("5;xaxnxxAoxx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("]ew26XW.X<", manager.generate(setting))

    def test_custom_character_set(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_extra_character_set(
            'abcdefghijklmnopqrstuvwxyzABCDUFGHJKLMNPQRTEVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.')
        setting.set_full_template("6;oxxxxxxxxx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("5#%KiEvUU7", manager.generate(setting))

    def test_custom_salt(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt(b'qanisaoerna56745678eornsiarteonstiaroenstiaeroh')
        setting.set_full_template("6;oxAxxaxxnx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual(")hN8ol<;6<", manager.generate(setting))

    def test_long(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_full_template("5;Aanoxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("Ba0=}#K.X<$/eS0AuGjRm>(\"dnDnvZCx", manager.generate(setting))
