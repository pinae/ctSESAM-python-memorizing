#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
The PasswordSettingsManager handles the settings and manages storage and synchronization.
"""

import os
import json
import struct
from datetime import datetime
from PasswordSetting import PasswordSetting
from Crypter import Crypter
from Packer import Packer
from SyncManager import SyncManager
from base64 import b64decode, b64encode

PASSWORD_SETTINGS_FILE = os.path.expanduser('~/.ctSESAM.pws')


class PasswordSettingsManager(object):
    """
    Use this class to manage password settings. It can save the settings locally to the settings file and it can
    export them to be sent to a sync server.

    :param settings_file: Filename of the settings file. Defaults to PASSWORD_SETTINGS_FILE as defined in the source
    :type settings_file: str
    """
    def __init__(self, settings_file=PASSWORD_SETTINGS_FILE):
        self.settings_file = settings_file
        self.remote_data = None
        self.settings = []
        self.sync_manager = SyncManager()
        self.update_remote = False

    def load_settings(self, password):
        """
        Loads settings from local file and from a sync server if possible.

        :param password: masterpassword
        :type password: str
        """
        self.load_settings_from_file(password)
        self.update_from_sync(password)

    def load_settings_from_file(self, password):
        """
        This loads the saved settings. It is a good idea to call this method the minute you have a password.

        :param password: masterpassword
        :type password: str
        """
        if os.path.isfile(self.settings_file):
            file = open(self.settings_file, 'br')
            data = file.read()
            crypter = Crypter(data[:32], password)
            sync_settings_len = struct.unpack('!I', data[32:36])[0]
            if sync_settings_len > 0:
                self.sync_manager.load_binary_sync_settings(crypter.decrypt(data[36:36+sync_settings_len]))
            saved_settings = json.loads(str(Packer.decompress(crypter.decrypt(data[36+sync_settings_len:])),
                                            encoding='utf-8'))
            for domain_name in saved_settings['settings'].keys():
                data_set = saved_settings['settings'][domain_name]
                found = False
                i = 0
                while i < len(self.settings):
                    setting = self.settings[i]
                    if setting.get_domain() == domain_name:
                        found = True
                        if datetime.strptime(data_set['mDate'], "%Y-%m-%dT%H:%M:%S") > setting.get_m_date():
                            setting.load_from_dict(data_set)
                            setting.set_synced(setting.get_domain() in saved_settings['synced'])
                    i += 1
                if not found:
                    new_setting = PasswordSetting(domain_name)
                    new_setting.load_from_dict(data_set)
                    new_setting.set_synced(new_setting.get_domain() in saved_settings['synced'])
                    self.settings.append(new_setting)
            file.close()
        else:
            self.sync_manager.ask_for_sync_settings()

    def store_settings(self, password):
        """
        Stores settings locally and remotely.

        :param password: masterpassword
        :type password: str
        :return:
        """
        self.save_settings_to_file(password)
        self.update_sync_server_if_necessary(password)

    # noinspection PyUnresolvedReferences
    def save_settings_to_file(self, password):
        """
        This actually saves the settings to a file on the disk. The file is encrypted so you need to supply the
        password.

        :param password: masterpassword
        :type password: str
        """
        salt = os.urandom(32)
        crypter = Crypter(salt, password)
        file = open(self.settings_file, 'bw')
        encrypted_sync_settings = crypter.encrypt(self.sync_manager.get_binary_sync_settings())
        file.write(salt + struct.pack('!I', len(encrypted_sync_settings)) + encrypted_sync_settings +
                   crypter.encrypt(Packer.compress(json.dumps(self.get_settings_as_dict()))))
        file.close()
        try:
            import win32con
            import win32api
            win32api.SetFileAttributes(self.settings_file, win32con.FILE_ATTRIBUTE_HIDDEN)
        except ImportError:
            pass

    def update_sync_server_if_necessary(self, password):
        """
        Checks if the sync server needs to be updated. If necessary it does a push.

        :param password: masterpassword
        :type password: str
        """
        if self.update_remote:
            if self.sync_manager.push(self.get_export_data(password)):
                self.set_all_settings_to_synced()

    def get_setting(self, domain):
        """
        This function always returns a setting. If no setting was stored for the given domain a new PasswordSetting
        object is created.

        :param domain: The "domain" is the identifier of a settings object.
        :type domain: str
        :return: a setting object
        :rtype: PasswordSetting
        """
        for setting in self.settings:
            if setting.get_domain() == domain:
                return setting
        setting = PasswordSetting(domain)
        self.settings.append(setting)
        return setting

    def set_setting(self, setting):
        """
        This saves the supplied setting only in memory. Call save_settings_to_file if you want to have it saved to
        disk.

        :param PasswordSetting setting: the setting which should be saved
        """
        for i, existing_setting in enumerate(self.settings):
            if existing_setting.get_domain() == setting.get_domain():
                self.settings.pop(i)
        self.settings.append(setting)
        self.update_remote = True

    def delete_setting(self, setting):
        """
        This removes the setting from the internal list. Call save_settings_to_file if you want to have the change
        saved to disk.

        :param setting: PasswordSetting object
        :type setting: PasswordSetting
        """
        i = 0
        while i < len(self.settings):
            existing_setting = self.settings[i]
            if existing_setting.get_domain() == setting.get_domain():
                self.settings.pop(i)
            else:
                i += 1

    def get_domain_list(self):
        """
        This gives you a list of saved domains.

        :return: a list of domain names
        :rtype: [str]
        """
        return [setting.get_domain() for setting in self.settings]

    def get_settings_as_dict(self):
        """
        Constructs a dictionary with a list of settings (no PasswordSetting objects but dicts) and a list of
        domain names of synced domains.

        :return: a dictionary
        :rtype: dict
        """
        settings_list = {'settings': {}, 'synced': []}
        for setting in self.settings:
            settings_list['settings'][setting.get_domain()] = setting.to_dict()
            if setting.is_synced():
                settings_list['synced'].append(setting.get_domain())
        return settings_list

    def get_export_data(self, password, salt=None):
        """
        This gives you a base64 encoded string of encrypted settings data (the blob).

        :param password: masterpassword
        :type password: str
        :param salt: salt for the encryption: This is for testing only! Do not set it normally!
        :type salt: bytes
        :return: encrypted settings blob
        :rtype: str
        """
        settings_list = self.get_settings_as_dict()['settings']
        if self.remote_data:
            for domain_name in self.remote_data.keys():
                data_set = self.remote_data[domain_name]
                if 'deleted' in data_set and data_set['deleted']:
                    for i, setting_dict in enumerate(settings_list):
                        if setting_dict['domain'] == setting_dict['domain'] and datetime.strptime(
                                data_set['mDate'], "%Y-%m-%dT%H:%M:%S") > datetime.strptime(
                                setting_dict['mDate'], "%Y-%m-%dT%H:%M:%S"):
                            settings_list[i] = data_set
                if domain_name not in settings_list.keys():
                    settings_list[domain_name] = {
                        'mDate': datetime.now(),
                        'deleted': True
                    }
        if not salt:
            salt = os.urandom(32)
        crypter = Crypter(salt, password)
        return b64encode(b'\x00' + salt + crypter.encrypt(Packer.compress(json.dumps(settings_list))))

    def update_from_sync(self, password):
        """
        Call this method to pull settings from the sync server.

        :param password: the masterpassword
        :type password: str
        """
        pull_successful, data = self.sync_manager.pull()
        if pull_successful and len(data) > 0:
            binary_data = b64decode(data)
            data_version = binary_data[:1]
            if data_version == b'\x00':
                encryption_salt = binary_data[1:33]
                encrypted_data = binary_data[33:]
                crypter = Crypter(encryption_salt, password)
                self.remote_data = json.loads(
                    str(Packer.decompress(crypter.decrypt(encrypted_data)), encoding='utf-8'))
                self.update_remote = False
                for domain_name in self.remote_data.keys():
                    data_set = self.remote_data[domain_name]
                    found = False
                    i = 0
                    while i < len(self.settings):
                        setting = self.settings[i]
                        if setting.get_domain() == domain_name:
                            found = True
                            if datetime.strptime(data_set['mDate'], "%Y-%m-%dT%H:%M:%S") > setting.get_m_date():
                                if 'deleted' in data_set and data_set['deleted']:
                                    self.settings.pop(i)
                                else:
                                    setting.load_from_dict(data_set)
                                    setting.set_synced(True)
                                    self.update_remote = True
                                    i += 1
                            else:
                                i += 1
                        else:
                            i += 1
                    if not found:
                        new_setting = PasswordSetting(domain_name)
                        new_setting.load_from_dict(data_set)
                        new_setting.set_synced(True)
                        self.settings.append(new_setting)
                for setting in self.settings:
                    found = False
                    for domain_name in self.remote_data.keys():
                        data_set = self.remote_data[domain_name]
                        if setting.get_domain() == domain_name:
                            found = True
                            if setting.get_m_date() >= datetime.strptime(data_set['mDate'], "%Y-%m-%dT%H:%M:%S"):
                                self.update_remote = True
                    if not found:
                        self.update_remote = True
            else:
                print("Unknown data format version! Could not update.")

    def set_all_settings_to_synced(self):
        """
        Convenience function for marking all saved settings as synced. Call this after a successful update at the
        sync server.
        """
        for setting in self.settings:
            setting.set_synced(True)
