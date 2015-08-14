#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
import os
import json
from PasswordSettingsManager import PasswordSettingsManager
from PasswordSetting import PasswordSetting
from Crypter import Crypter
from Packer import Packer


class TestPasswordSettingsManager(unittest.TestCase):
    def setUp(self):
        self.manager = PasswordSettingsManager(os.path.expanduser('~/.ctSESAM_test.pws'))

    # noinspection PyUnresolvedReferences
    def tearDown(self):
        file = os.path.expanduser('~/.ctSESAM_test.pws')
        if os.path.isfile(file):
            try:
                import win32con
                import win32api
                win32api.SetFileAttributes(file, win32con.FILE_ATTRIBUTE_NORMAL)
            except ImportError:
                pass
            os.remove(file)

    def test_get_setting(self):
        setting = self.manager.get_setting('abc.de')
        self.assertEqual(PasswordSetting, type(setting))
        self.assertEqual('abc.de', setting.get_domain())
        self.assertIn('abc.de', self.manager.get_domain_list())

    def test_save_settings_to_file(self):
        self.manager.get_setting('abc.de')
        new_setting = PasswordSetting('hugo.com')
        new_setting.set_length(12)
        self.manager.save_setting(new_setting)
        self.manager.save_settings_to_file('xyz')
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'br')
        crypter = Crypter('xyz')
        data = json.loads(Packer.decompress(crypter.decrypt(f.read())).decode('utf8'))
        f.close()
        self.assertEqual('abc.de', data['settings'][0]['domain'])
        self.assertEqual(10, data['settings'][0]['length'])
        self.assertEqual('hugo.com', data['settings'][1]['domain'])
        self.assertEqual(12, data['settings'][1]['length'])
