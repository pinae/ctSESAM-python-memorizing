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
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("]#]Y6Q-+)T", manager.generate(setting))

    def test_custom_character_set(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_custom_character_set(
            'abcdefghijklmnopqrstuvwxyzABCDUFGHJKLMNPQRTEVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("5#%KiEvUU7", manager.generate(setting))

    def test_custom_salt(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt(b'qanisaoerna56745678eornsiarteonstiaroenstiaeroh')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("]#]Y6Q-+)T", manager.generate(setting))

    def test_long(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_length(32)
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("]#]Y6Q-+)TCus§&8[kEw5O.pJsTjOC#}", manager.generate(setting))
