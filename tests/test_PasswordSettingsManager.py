#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
import os
import json
import struct
from kgk_manager import KgkManager
from preference_manager import PreferenceManager
from password_settings_manager import PasswordSettingsManager
from password_setting import PasswordSetting
from crypter import Crypter
from packer import Packer
from base64 import b64encode, b64decode


class MockSyncManager(object):
    """
    We do not really want to sync.
    """
    def __init__(self, kgk):
        self.kgk_manager = KgkManager()
        self.kgk_manager.set_preference_manager(PreferenceManager(os.path.expanduser('~/.ctSESAM_test_extra.pws')))
        self.kgk_manager.kgk = kgk

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
        kgk_block = self.kgk_manager.create_and_save_new_kgk_block(self.kgk_manager.get_kgk_crypter(b'xyz', salt))
        settings_crypter = PasswordSettingsManager.get_settings_crypter(self.kgk_manager)
        return True, str(b64encode(b'\x01' + salt + kgk_block + settings_crypter.encrypt(
            Packer.compress(json.dumps(remote_data).encode('utf-8')))), encoding='utf-8')

    def get_binary_sync_settings(self):
        """
        :return:
        :rtype: bytes
        """
        return b''

    def has_settings(self):
        """
        :return:
        :rtype: bool
        """
        return True


class TestPasswordSettingsManager(unittest.TestCase):
    def setUp(self):
        self.preference_manager = PreferenceManager(os.path.expanduser('~/.ctSESAM_test.pws'))
        self.manager = PasswordSettingsManager(self.preference_manager)

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

    def test_store_local_settings(self):
        abc_setting = self.manager.get_setting('abc.de')
        abc_setting.set_template('xAxonaxxxx')
        self.manager.set_setting(abc_setting)
        new_setting = PasswordSetting('hugo.com')
        new_setting.set_template('xonxAxxaxxxx')
        self.manager.set_setting(new_setting)
        kgk_manager = KgkManager()
        kgk_manager.set_preference_manager(self.preference_manager)
        kgk_manager.create_new_kgk()
        salt = os.urandom(32)
        kgk_manager.create_and_save_new_kgk_block(Crypter(Crypter.createIvKey(b'xyz', salt, iterations=3)))
        self.manager.store_local_settings(kgk_manager)
        with open(os.path.expanduser('~/.ctSESAM_test.pws'), 'br') as f:
            data = f.read()
        settings_crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        decrypted_settings = settings_crypter.decrypt(data[144:])
        sync_settings_len = struct.unpack('!I', decrypted_settings[:4])[0]
        data = json.loads(Packer.decompress(decrypted_settings[4+sync_settings_len:]).decode('utf8'))
        self.assertEqual('abc.de', data['settings']['abc.de']['domain'])
        self.assertEqual('xAxonaxxxx', data['settings']['abc.de']['passwordTemplate'])
        self.assertEqual('hugo.com', data['settings']['hugo.com']['domain'])
        self.assertEqual('xonxAxxaxxxx', data['settings']['hugo.com']['passwordTemplate'])

    def test_load_settings_from_file(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'passwordTemplate': 'xxxxxxxxxxo',
                    'extras': '#OWspx6;3gov0/1',
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'passwordTemplate': 'oxxx',
                    'extras': '6478593021',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        data = json.dumps(settings).encode('utf-8')
        kgk_manager = KgkManager()
        kgk_manager.set_preference_manager(self.preference_manager)
        kgk_manager.create_new_kgk()
        kgk_block = kgk_manager.create_and_save_new_kgk_block(Crypter(Crypter.createIvKey(b'xyz', salt, iterations=3)))
        crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        f.write(salt + kgk_block + crypter.encrypt(struct.pack('!I', 0) + Packer.compress(data)))
        f.close()
        self.preference_manager.read_file()
        self.manager.load_local_settings(kgk_manager)
        self.assertIn('unit.test', self.manager.get_domain_list())
        self.assertIn('some.domain', self.manager.get_domain_list())
        self.assertEqual('xxxxxxxxxxo', self.manager.get_setting('unit.test').get_template())
        self.assertEqual(5000, self.manager.get_setting('unit.test').get_iterations())
        self.assertEqual('Nice note!', self.manager.get_setting('unit.test').get_notes())
        self.assertEqual('oxxx', self.manager.get_setting('some.domain').get_template())
        self.assertEqual('6478593021', self.manager.get_setting('some.domain').get_character_set())

    def test_set_setting(self):
        setting = self.manager.get_setting('hugo.me')
        setting.set_template('xonxAa')
        self.manager.set_setting(setting)
        self.assertIn('hugo.me', self.manager.get_domain_list())
        self.assertEqual(6, self.manager.get_setting('hugo.me').get_length())

    def test_delete_setting(self):
        setting = self.manager.get_setting('hugo.me')
        setting.set_template('xonxAa')
        self.manager.set_setting(setting)
        self.assertIn('hugo.me', self.manager.get_domain_list())
        self.manager.delete_setting(setting)
        self.assertNotIn('hugo.me', self.manager.get_domain_list())

    def test_get_domain_list(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'extras': '#!"§$%&/()[]{}=-_+*<>;:.',
                    'passwordTemplate': 'xxxaoxxAxxn',
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'salt': 'cGVwcGVy',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'extras': '#!"§$%&/()[]{}=-_+*<>;:.',
                    'passwordTemplate': 'xxxo',
                    'iterations': 4096,
                    'salt': 'cGVwcGVy',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        data = json.dumps(settings).encode('utf-8')
        kgk_manager = KgkManager()
        kgk_manager.set_preference_manager(self.preference_manager)
        kgk_manager.create_new_kgk()
        kgk_block = kgk_manager.create_and_save_new_kgk_block(Crypter(Crypter.createIvKey(b'xyz', salt, iterations=3)))
        crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        f.write(salt + kgk_block + crypter.encrypt(struct.pack('!I', 0) + Packer.compress(data)))
        f.close()
        self.preference_manager.read_file()
        self.manager.load_local_settings(kgk_manager)
        self.assertIn('settings', self.manager.get_settings_as_dict())
        self.assertIn('unit.test', self.manager.get_settings_as_dict()['settings'])
        self.assertEqual(settings['settings']['unit.test'],
                         self.manager.get_settings_as_dict()['settings']['unit.test'])
        self.assertIn('some.domain', self.manager.get_settings_as_dict()['settings'])
        self.assertEqual(settings['settings']['some.domain'],
                         self.manager.get_settings_as_dict()['settings']['some.domain'])
        self.assertEqual(settings, self.manager.get_settings_as_dict())

    def test_get_export_data(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'extras': '#!"§$%&/()[]{}=-_+*<>;:.',
                    'passwordTemplate': 'xnxoaAxxxx',
                    'iterations': 5000,
                    'notes': 'Nice note!',
                    'salt': 'cGVwcGVy',
                    'cDate': '2011-02-12T11:07:31',
                    'mDate': '2011-02-12T11:07:32'
                },
                'some.domain': {
                    'domain': 'some.domain',
                    'extras': '6478593021',
                    'passwordTemplate': 'xnxoaA',
                    'iterations': 4096,
                    'salt': 'cGVwcGVy',
                    'cDate': '2013-06-17T04:03:41',
                    'mDate': '2014-08-02T10:37:12'
                }
            },
            'synced': []
        }
        salt = os.urandom(32)
        kgk_manager = KgkManager()
        kgk_manager.set_preference_manager(self.preference_manager)
        kgk_manager.create_new_kgk()
        kgk_block = kgk_manager.create_and_save_new_kgk_block(Crypter(Crypter.createIvKey(b'xyz', salt, iterations=3)))
        crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        f.write(salt + kgk_block +
                crypter.encrypt(struct.pack('!I', 0) + Packer.compress(json.dumps(settings).encode('utf-8'))))
        f.close()
        self.preference_manager.read_file()
        self.manager.load_local_settings(kgk_manager)
        data = b64decode(self.manager.get_export_data(kgk_manager))
        self.assertEqual(b'\x01', data[:1])
        salt = data[1:33]
        kgk_crypter = Crypter(Crypter.createIvKey(b'xyz', salt, iterations=3))
        kgk_manager2 = KgkManager()
        kgk_manager2.set_preference_manager(self.preference_manager)
        kgk_manager2.decrypt_kgk(data[33:145], kgk_crypter)
        settings_crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager2)
        self.assertEqual(
            settings['settings'],
            json.loads(str(Packer.decompress(settings_crypter.decrypt(data[145:])), encoding='utf-8')))

    def test_update_from_sync(self):
        settings = {
            'settings': {
                'unit.test': {
                    'domain': 'unit.test',
                    'passwordTemplate': 'xxaAnoxxxxx',
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
                    'passwordTemplate': 'oanA',
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
        kgk_manager = KgkManager()
        kgk_manager.set_preference_manager(self.preference_manager)
        kgk_manager.create_new_kgk()
        kgk_block = kgk_manager.create_and_save_new_kgk_block(
            Crypter(Crypter.createIvKey('xyz'.encode('utf-8'), salt)))
        crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        f = open(os.path.expanduser('~/.ctSESAM_test.pws'), 'bw')
        f.write(salt + kgk_block +
                crypter.encrypt(struct.pack('!I', 0) + Packer.compress(json.dumps(settings).encode('utf-8'))))
        f.close()
        self.preference_manager.read_file()
        self.manager.sync_manager = MockSyncManager(kgk_manager.get_kgk())
        self.manager.load_settings(kgk_manager, 'xyz')
        self.assertIn('unit.test', self.manager.get_domain_list())
        self.assertIn('some.domain', self.manager.get_domain_list())
        self.assertIn('third.domain', self.manager.get_domain_list())
        self.assertEqual(5001, self.manager.get_setting('unit.test').get_iterations())
        self.assertEqual(4096, self.manager.get_setting('some.domain').get_iterations())
        self.assertEqual(4098, self.manager.get_setting('third.domain').get_iterations())
        file = os.path.expanduser('~/.ctSESAM_test_extra.pws')
        if os.path.isfile(file):
            try:
                import win32con
                import win32api
                win32api.SetFileAttributes(file, win32con.FILE_ATTRIBUTE_NORMAL)
            except ImportError:
                pass
            os.remove(file)
