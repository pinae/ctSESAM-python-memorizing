#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch
import os
import json
import struct
from PasswordSettingsManager import PasswordSettingsManager
from PasswordSetting import PasswordSetting
from Crypter import Crypter
from Packer import Packer
from base64 import b64encode


class MockSyncManager(object):
    """
    We do not really want to sync.
    """
    def pull(self):
        """
        Returns some mock data tor the sync test.

        :return: base64 mock data blob
        :rtype: (bool, str)
        """
        remote_data = {
            'unit.test': {
                'domain': 'unit.test',
                'length': 12,
                'iterations': 5001,
                'notes': 'another note!',
                'salt': 'cGVwcGVy',
                'usedCharacters': 'abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789',
                'cDate': '2011-02-12T11:07:31',
                'mDate': '2013-07-12T14:46:11'
            },
            'some.domain': {
                'domain': 'some.domain',
                'length': 4,
                'iterations': 4097,
                'salt': 'cGVwcGVy',
                'usedCharacters': '6478593021',
                'cDate': '2013-06-17T04:03:41',
                'mDate': '2014-08-02T10:37:11'
            },
            'third.domain': {
                'domain': 'third.domain',
                'length': 10,
                'iterations': 4098,
                'salt': 'cGVwcGVy',
                'usedCharacters': 'aeiou',
                'cDate': '2013-06-17T04:03:41',
                'mDate': '2014-08-02T10:37:11'
            }
        }
        salt = os.urandom(32)
        crypter = Crypter(salt, 'xyz')
        return True, str(b64encode(b'\x00' + salt + crypter.encrypt(
            Packer.compress(json.dumps(remote_data).encode('utf-8')))), encoding='utf-8')


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
        self.manager.set_setting(new_setting)
        self.manager.save_settings_to_file('xyz')
        with open(os.path.expanduser('~/.ctSESAM_test.pws'), 'br') as f:
            data = f.read()
        crypter = Crypter(data[:32], 'xyz')
        sync_settings_len = struct.unpack('!I', data[32:36])[0]
        data = json.loads(Packer.decompress(crypter.decrypt(data[36+sync_settings_len:])).decode('utf8'))
        self.assertEqual('abc.de', data['settings']['abc.de']['domain'])
        self.assertEqual(10, data['settings']['abc.de']['length'])
        self.assertEqual('hugo.com', data['settings']['hugo.com']['domain'])
        self.assertEqual(12, data['settings']['hugo.com']['length'])

    def test_load_settings_from_file(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'length': 11,
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'length': 4,
                    'usedCharacters': '6478593021',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        crypter = Crypter(salt, 'xyz')
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        f.write(salt + struct.pack('!I', 0) + crypter.encrypt(Packer.compress(json.dumps(settings).encode('utf-8'))))
        f.close()
        self.manager.load_settings_from_file('xyz')
        self.assertIn('unit.test', self.manager.get_domain_list())
        self.assertIn('some.domain', self.manager.get_domain_list())
        self.assertEqual(11, self.manager.get_setting('unit.test').get_length())
        self.assertEqual(5000, self.manager.get_setting('unit.test').get_iterations())
        self.assertEqual('Nice note!', self.manager.get_setting('unit.test').get_notes())
        self.assertEqual(4, self.manager.get_setting('some.domain').get_length())
        self.assertEqual('6478593021', self.manager.get_setting('some.domain').get_character_set())

    def test_set_setting(self):
        setting = self.manager.get_setting('hugo.me')
        setting.set_length(6)
        self.manager.set_setting(setting)
        self.assertIn('hugo.me', self.manager.get_domain_list())
        self.assertEqual(6, self.manager.get_setting('hugo.me').get_length())

    def test_delete_setting(self):
        setting = self.manager.get_setting('hugo.me')
        setting.set_length(6)
        self.manager.set_setting(setting)
        self.assertIn('hugo.me', self.manager.get_domain_list())
        self.manager.delete_setting(setting)
        self.assertNotIn('hugo.me', self.manager.get_domain_list())

    def test_get_domain_list(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'length': 11,
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'salt': 'cGVwcGVy',
                    'usedCharacters': 'abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789' +
                                      '#!"§$%&/()[]{}=-_+*<>;:.',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'length': 4,
                    'iterations': 4096,
                    'salt': 'cGVwcGVy',
                    'usedCharacters': '6478593021',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        crypter = Crypter(salt, 'xyz')
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        data = json.dumps(settings).encode('utf-8')
        f.write(salt + struct.pack('!I', 0) + crypter.encrypt(Packer.compress(data)))
        f.close()
        self.manager.load_settings_from_file('xyz')
        self.assertEqual(settings['settings']['unit.test'],
                         self.manager.get_settings_as_dict()['settings']['unit.test'])
        self.assertEqual(settings['settings']['some.domain'],
                         self.manager.get_settings_as_dict()['settings']['some.domain'])
        self.assertEqual(settings, self.manager.get_settings_as_dict())

    def test_get_export_data(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'length': 11,
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'salt': 'cGVwcGVy',
                    'usedCharacters': 'abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789' +
                                      '#!"§$%&/()[]{}=-_+*<>;:.',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'length': 4,
                    'iterations': 4096,
                    'salt': 'cGVwcGVy',
                    'usedCharacters': '6478593021',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        crypter = Crypter(salt, 'xyz')
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        f.write(salt + struct.pack('!I', 0) + crypter.encrypt(
            Packer.compress(json.dumps(settings).encode('utf-8'))))
        f.close()
        self.manager.load_settings_from_file('xyz')
        self.assertEqual(
            b64encode(b'\x00' + salt + crypter.encrypt(
                Packer.compress(json.dumps(settings['settings']).encode('utf-8')))),
            self.manager.get_export_data('xyz', salt=salt)
        )

    def test_update_from_sync(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'length': 11,
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'salt': 'cGVwcGVy',
                    'usedCharacters': 'abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789' +
                                      '#!"§$%&/()[]{}=-_+*<>;:.',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'length': 4,
                    'iterations': 4096,
                    'salt': 'cGVwcGVy',
                    'usedCharacters': '6478593021',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        crypter = Crypter(salt, 'xyz')
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        f.write(salt + struct.pack('!I', 0) + crypter.encrypt(
            Packer.compress(json.dumps(settings).encode('utf-8'))))
        f.close()
        self.manager.load_settings_from_file('xyz')
        self.manager.sync_manager = MockSyncManager()
        self.manager.update_from_sync('xyz')
        self.assertEqual(['unit.test', 'some.domain', 'third.domain'], self.manager.get_domain_list())
        self.assertEqual(5001, self.manager.get_setting('unit.test').get_iterations())
        self.assertEqual(4096, self.manager.get_setting('some.domain').get_iterations())
        self.assertEqual(4098, self.manager.get_setting('third.domain').get_iterations())
